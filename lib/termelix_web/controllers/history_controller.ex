defmodule TermelixWeb.HistoryController do
  @moduledoc """
  Ports command history (`/terminal/command_history`, frontend `command-history-api.ts`) and
  recent activity (`/activity/*`, frontend `dashboard-api.ts` recent-activity calls).

  The `Authenticate` plug has already run, so the owner is `conn.assigns.current_user_id`; a
  `userId` in the body is never trusted. Neither table carries secret fields, so records are
  returned as-is.

  Two Node behaviours are intentionally not ported, matching the current breadth of this port:
  the `requireDataAccess`/`isUserDataUnlocked` DEK gate (these tables hold no encrypted fields)
  and the in-memory per-`(user,host,type)` rate limiter on activity logging (a stateless port
  simply records every call). RBAC-shared hosts are likewise not honoured — both activity
  logging and command-history saves are gated on owned hosts only, consistent with
  `Termelix.Hosts`.
  """
  use Phoenix.Controller, formats: [:json]

  import TermelixWeb.ControllerHelpers

  alias Termelix.{History, Settings}

  # Commands matching any of these are echoed back to the client but never persisted
  # (mirrors the sensitive-pattern guard in `terminal.ts`).
  @sensitive_patterns [
    ~r/passw(or)?d/i,
    ~r/\bsecret\b/i,
    ~r/\btoken\b/i,
    ~r/\bapi.?key\b/i,
    ~r/PASS(WORD)?=/i,
    ~r/AWS_SECRET/i,
    ~r/mysql\b.*-p/i,
    ~r/sudo\s+-S\b/,
    ~r/htpasswd/i,
    ~r/sshpass/i,
    ~r/curl\b.*-u\s/i,
    ~r/export\b.*(?:PASSWORD|SECRET|TOKEN|KEY)=/i
  ]

  @activity_types ~w(terminal file_manager server_stats tunnel)

  # --- command history ------------------------------------------------------

  # POST /terminal/command_history
  def save_command(conn, params) do
    user_id = conn.assigns.current_user_id
    host_id = params["hostId"]
    command = params["command"]

    if not truthy?(host_id) or not non_empty_string?(command) do
      error(conn, 400, "Missing required parameters")
    else
      case parse_id(host_id) do
        :error ->
          error(conn, 400, "Invalid request parameters")

        {:ok, host_id} ->
          trimmed = String.trim(command)

          cond do
            # Same ownership gate as log_activity/2 below: a caller must not record (or even
            # echo) commands against a host they do not own.
            not History.host_owned?(user_id, host_id) ->
              error(conn, 404, "Host not found or access denied")

            suppress_save?(user_id, host_id, trimmed) ->
              conn |> put_status(201) |> json(skipped_record(user_id, host_id, trimmed))

            true ->
              record = History.record_command(user_id, host_id, trimmed)
              conn |> put_status(201) |> json(to_json(record))
          end
      end
    end
  end

  # GET /terminal/command_history/:hostId
  # The Node route ignores the `limit` query param (uses the repository default), so we do too.
  def list_commands(conn, %{"hostId" => host_id}) do
    case parse_id(host_id) do
      :error ->
        error(conn, 400, "Invalid request parameters")

      {:ok, id} ->
        json(conn, History.list_unique_commands(conn.assigns.current_user_id, id))
    end
  end

  # POST /terminal/command_history/delete
  def delete_command(conn, params) do
    user_id = conn.assigns.current_user_id
    host_id = params["hostId"]
    command = params["command"]

    if not truthy?(host_id) or not non_empty_string?(command) do
      error(conn, 400, "Missing required parameters")
    else
      case parse_id(host_id) do
        :error ->
          error(conn, 400, "Invalid request parameters")

        {:ok, host_id} ->
          History.delete_command(user_id, host_id, String.trim(command))
          json(conn, %{success: true})
      end
    end
  end

  # DELETE /terminal/command_history/:hostId
  def clear_commands(conn, %{"hostId" => host_id}) do
    case parse_id(host_id) do
      :error ->
        error(conn, 400, "Invalid request")

      {:ok, id} ->
        History.clear_commands(conn.assigns.current_user_id, id)
        json(conn, %{success: true})
    end
  end

  # --- recent activity ------------------------------------------------------

  # GET /activity/recent
  def recent_activity(conn, params) do
    limit = parse_limit(params["limit"])

    activities =
      conn.assigns.current_user_id
      |> History.list_activity(limit)
      |> Enum.map(&to_json/1)

    json(conn, activities)
  end

  # POST /activity/log
  def log_activity(conn, params) do
    user_id = conn.assigns.current_user_id
    type = params["type"]
    host_id = params["hostId"]
    host_name = params["hostName"]

    # An unparsable hostId was never a valid host id — treat it like a nonexistent one.
    host_id =
      case parse_id(host_id) do
        {:ok, id} -> id
        :error -> nil
      end

    cond do
      not truthy?(type) or not truthy?(params["hostId"]) or not truthy?(host_name) ->
        error(conn, 400, "Missing required fields: type, hostId, hostName")

      type not in @activity_types ->
        error(
          conn,
          400,
          "Invalid activity type. Must be 'terminal', 'file_manager', 'server_stats', " <>
            "or 'tunnel'"
        )

      is_nil(host_id) or not History.host_owned?(user_id, host_id) ->
        error(conn, 404, "Host not found or access denied")

      true ->
        record = History.record_activity(user_id, type, host_id, host_name)
        History.trim_activity(user_id, 100)
        json(conn, %{message: "Activity logged", id: record.id})
    end
  end

  # DELETE /activity/reset
  def reset_activity(conn, _params) do
    History.clear_activity(conn.assigns.current_user_id)
    json(conn, %{message: "Recent activity cleared"})
  end

  # --- helpers --------------------------------------------------------------

  # A save is suppressed (echoed, not persisted) when the command looks sensitive, the global
  # `command_history_enabled` setting is off, or the owned host opts out via
  # `enable_command_history == false`. `or` short-circuits, so the host is only queried when
  # the cheaper checks pass — matching the Node route's ordering.
  defp suppress_save?(user_id, host_id, command) do
    sensitive?(command) or not history_enabled?() or
      History.command_history_flag(user_id, host_id) == false
  end

  defp sensitive?(command), do: Enum.any?(@sensitive_patterns, &Regex.match?(&1, command))

  # `getBoolean("command_history_enabled", true)`: a missing value falls back to true, and a
  # stored value counts as enabled only when it is exactly "true" or "1".
  defp history_enabled? do
    case Settings.get_value("command_history_enabled") do
      nil -> true
      value -> value == "true" or value == "1"
    end
  end

  # The `{ id: 0, userId, hostId, command, executedAt }` echo the Node route returns when a
  # save is suppressed.
  defp skipped_record(user_id, host_id, command) do
    %{id: 0, userId: user_id, hostId: host_id, command: command, executedAt: History.iso_now()}
  end

  # `Number(req.query.limit) || 20`: absent, non-numeric, or zero falls back to 20.
  defp parse_limit(value) do
    case value do
      v when is_integer(v) and v != 0 -> v
      v when is_binary(v) -> parse_limit_string(v)
      _ -> 20
    end
  end

  defp parse_limit_string(value) do
    case Integer.parse(value) do
      {n, _rest} when n != 0 -> n
      _ -> 20
    end
  end

  defp to_json(struct), do: struct |> Map.from_struct() |> Map.drop([:__meta__])

  # Node's `!value` falsiness: nil, 0, "" and false are all rejected.
  defp truthy?(nil), do: false
  defp truthy?(0), do: false
  defp truthy?(""), do: false
  defp truthy?(false), do: false
  defp truthy?(_), do: true

  defp non_empty_string?(value) when is_binary(value), do: String.trim(value) != ""
  defp non_empty_string?(_), do: false
end
