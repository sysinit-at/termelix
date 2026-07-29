defmodule TermelixWeb.AlertRuleController do
  @moduledoc """
  Ports the `/alert-rules` CRUD surface (`database/routes/alert-rules-routes.ts`) the frontend
  `alerts-api.ts` calls. A rule pairs a trigger type (threshold/status/health/login) with an
  optional host scope and a set of linked notification channels. The `Authenticate` plug has run,
  so ownership is `conn.assigns.current_user_id` — a body `userId` is never trusted.

  Only the `*_threshold` triggers are evaluated by the background engine so far; the others are
  accepted and stored (their evaluators are deferred). Response shapes reproduce the Node
  repository mapper (snake_case + `0/1` + `channels`) via `Termelix.Alerts.rule_json/2`. As in the
  Node route, `POST` echoes the request's `channels` array while `PUT` returns the persisted
  (ownership-filtered) links.
  """
  use Phoenix.Controller, formats: [:json]

  alias Termelix.Alerts

  @valid_triggers ~w(host_offline host_online cpu_threshold memory_threshold disk_threshold
                     health_check_failure health_check_recovery user_login)

  # GET /alert-rules
  def index(conn, _params) do
    user_id = conn.assigns.current_user_id

    rows =
      user_id
      |> Alerts.list_alert_rules()
      |> Enum.map(fn {rule, channel_ids} -> Alerts.rule_json(rule, channel_ids) end)

    json(conn, rows)
  end

  # POST /alert-rules
  def create(conn, params) do
    user_id = conn.assigns.current_user_id

    with {:ok, name} <- require_name(params["name"]),
         {:ok, trigger} <- require_trigger(params["triggerType"]),
         :ok <- validate_threshold_value(params["thresholdValue"]),
         :ok <- validate_duration(params["thresholdDurationSeconds"]) do
      channels = params["channels"] || []

      try do
        {:ok, rule, _linked} =
          Alerts.create_alert_rule(%{
            userId: user_id,
            hostId: params["hostId"],
            name: name,
            enabled: params["enabled"] != false,
            triggerType: trigger,
            thresholdValue: params["thresholdValue"],
            thresholdDurationSeconds: params["thresholdDurationSeconds"],
            cooldownMinutes: params["cooldownMinutes"] || 15,
            channels: channels,
            now: iso_now()
          })

        conn |> put_status(201) |> json(Alerts.rule_json(rule, channels))
      rescue
        _ -> error(conn, 500, "Failed to create alert rule")
      end
    else
      {:error, message} -> error(conn, 400, message)
    end
  end

  # PUT /alert-rules/:id
  def update(conn, %{"id" => id} = params) do
    user_id = conn.assigns.current_user_id

    with {:ok, rule_id} <- parse_id(id),
         %{} = _existing <- Alerts.find_alert_rule_for_user(rule_id, user_id),
         :ok <- validate_trigger_update(params["triggerType"]) do
      try do
        case Alerts.update_alert_rule(rule_id, user_id, rule_changes(params)) do
          {:ok, rule, channel_ids} -> json(conn, Alerts.rule_json(rule, channel_ids))
          nil -> error(conn, 404, "Alert rule not found")
        end
      rescue
        _ -> error(conn, 500, "Failed to update alert rule")
      end
    else
      nil -> error(conn, 404, "Alert rule not found")
      {:error, :invalid_id} -> error(conn, 404, "Alert rule not found")
      {:error, :invalid_trigger} -> error(conn, 400, "Invalid triggerType")
    end
  end

  # DELETE /alert-rules/:id
  def delete(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    with {:ok, rule_id} <- parse_id(id),
         true <- Alerts.delete_alert_rule(rule_id, user_id) do
      json(conn, %{success: true})
    else
      _ -> error(conn, 404, "Alert rule not found")
    end
  end

  # --- change building --------------------------------------------------------

  # Only the keys the caller actually sent become changes (Node's spread-of-present-fields).
  defp rule_changes(params) do
    %{now: iso_now()}
    |> put_present(params, "name", :name, &String.trim/1)
    |> put_present(params, "hostId", :hostId, & &1)
    |> put_present(params, "enabled", :enabled, & &1)
    |> put_present(params, "triggerType", :triggerType, & &1)
    |> put_present(params, "thresholdValue", :thresholdValue, & &1)
    |> put_present(params, "thresholdDurationSeconds", :thresholdDurationSeconds, & &1)
    |> put_present(params, "cooldownMinutes", :cooldownMinutes, & &1)
    |> put_present(params, "channels", :channels, & &1)
  end

  defp put_present(changes, params, key, field, transform) do
    case Map.fetch(params, key) do
      {:ok, value} -> Map.put(changes, field, transform_value(transform, value))
      :error -> changes
    end
  end

  # A `nil` value passes through untouched (so a null threshold/host clears the field).
  defp transform_value(_transform, nil), do: nil
  defp transform_value(transform, value), do: transform.(value)

  # --- validation -------------------------------------------------------------

  defp require_name(name) when is_binary(name) do
    if String.trim(name) == "", do: {:error, "name is required"}, else: {:ok, String.trim(name)}
  end

  defp require_name(_), do: {:error, "name is required"}

  defp require_trigger(trigger) when is_binary(trigger) do
    if trigger in @valid_triggers, do: {:ok, trigger}, else: {:error, "Invalid triggerType"}
  end

  defp require_trigger(_), do: {:error, "Invalid triggerType"}

  defp validate_trigger_update(nil), do: :ok
  defp validate_trigger_update(trigger) when trigger in @valid_triggers, do: :ok
  defp validate_trigger_update(_), do: {:error, :invalid_trigger}

  defp validate_threshold_value(value) when is_number(value) do
    if value < 0 or value > 100,
      do: {:error, "thresholdValue must be between 0 and 100"},
      else: :ok
  end

  defp validate_threshold_value(_), do: :ok

  defp validate_duration(value) when is_number(value) do
    if value < 0, do: {:error, "thresholdDurationSeconds must be >= 0"}, else: :ok
  end

  defp validate_duration(_), do: :ok

  # --- shared -----------------------------------------------------------------

  defp parse_id(id) when is_integer(id) and id > 0, do: {:ok, id}

  defp parse_id(id) when is_binary(id) do
    case Integer.parse(id) do
      {n, ""} when n > 0 -> {:ok, n}
      _ -> {:error, :invalid_id}
    end
  end

  defp parse_id(_), do: {:error, :invalid_id}

  defp iso_now, do: DateTime.utc_now() |> DateTime.truncate(:millisecond) |> DateTime.to_iso8601()

  defp error(conn, status, message), do: conn |> put_status(status) |> json(%{error: message})
end
