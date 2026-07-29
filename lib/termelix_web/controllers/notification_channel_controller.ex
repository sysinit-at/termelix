defmodule TermelixWeb.NotificationChannelController do
  @moduledoc """
  Ports the `/notification-channels` CRUD + test surface (`database/routes/alert-rules-routes.ts`)
  the frontend `alerts-api.ts` calls. Channels are the delivery targets an alert rule fans out
  to; two types are accepted, `webhook` and `ntfy`, each with a JSON `config` (stored as a
  string). The `Authenticate` plug has run, so ownership is `conn.assigns.current_user_id` — a
  body `userId` is never trusted, and every lookup/mutation is user-scoped.

  Response shapes reproduce the Node repository mappers (snake_case + `0/1` booleans) via
  `Termelix.Alerts.channel_json/1`.
  """
  use Phoenix.Controller, formats: [:json]

  alias Termelix.Alerts
  alias Termelix.Alerts.Notifier

  # GET /notification-channels
  def index(conn, _params) do
    user_id = conn.assigns.current_user_id

    rows =
      user_id
      |> Alerts.list_notification_channels()
      |> Enum.map(&Alerts.channel_json/1)

    json(conn, rows)
  end

  # POST /notification-channels
  def create(conn, params) do
    user_id = conn.assigns.current_user_id

    with {:ok, name} <- require_name(params["name"]),
         {:ok, type} <- require_type(params["type"]),
         {:ok, config} <- require_config(type, params["config"]) do
      {:ok, channel} =
        Alerts.create_notification_channel(%{
          userId: user_id,
          name: name,
          type: type,
          config: Jason.encode!(config),
          enabled: params["enabled"] != false
        })

      conn |> put_status(201) |> json(Alerts.channel_json(channel))
    else
      {:error, message} -> error(conn, 400, message)
    end
  end

  # PUT /notification-channels/:id
  def update(conn, %{"id" => id} = params) do
    user_id = conn.assigns.current_user_id

    with {:ok, channel_id} <- parse_id(id),
         %{} = _existing <- Alerts.find_notification_channel_for_user(channel_id, user_id),
         :ok <- validate_type(params["type"]) do
      changes = channel_changes(params)

      if map_size(changes) == 0 do
        json(conn, %{success: true})
      else
        case Alerts.update_notification_channel(channel_id, user_id, changes) do
          {:ok, channel} -> json(conn, Alerts.channel_json(channel))
          nil -> error(conn, 404, "Channel not found")
        end
      end
    else
      nil -> error(conn, 404, "Channel not found")
      {:error, :invalid_id} -> error(conn, 404, "Channel not found")
      {:error, :invalid_type} -> error(conn, 400, "type must be 'webhook' or 'ntfy'")
    end
  end

  # DELETE /notification-channels/:id
  def delete(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    with {:ok, channel_id} <- parse_id(id),
         true <- Alerts.delete_notification_channel(channel_id, user_id) do
      json(conn, %{success: true})
    else
      _ -> error(conn, 404, "Channel not found")
    end
  end

  # POST /notification-channels/:id/test
  def test(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    with {:ok, channel_id} <- parse_id(id),
         %{} = channel <- Alerts.find_notification_channel_for_user(channel_id, user_id) do
      send_test(conn, channel)
    else
      _ -> error(conn, 404, "Channel not found")
    end
  end

  # --- test dispatch ----------------------------------------------------------

  defp send_test(conn, channel) do
    case Jason.decode(channel.config) do
      {:ok, %{} = config} ->
        result =
          case channel.type do
            "webhook" -> Notifier.send_webhook(config, test_payload())
            "ntfy" -> Notifier.send_ntfy(config, test_payload())
            _ -> :ok
          end

        case result do
          :ok -> json(conn, %{success: true})
          {:error, reason} -> json(conn, %{success: false, error: reason_message(reason)})
        end

      _ ->
        conn |> put_status(400) |> json(%{success: false, error: "Invalid channel config"})
    end
  end

  defp test_payload do
    %{
      hostName: "Test Host",
      hostId: 0,
      triggerType: "test",
      message: "This is a test notification from Termelix",
      severity: "info",
      timestamp: iso_now(),
      ruleId: 0,
      ruleName: "Test"
    }
  end

  # --- validation -------------------------------------------------------------

  defp require_name(name) when is_binary(name) do
    if String.trim(name) == "", do: {:error, "name is required"}, else: {:ok, String.trim(name)}
  end

  defp require_name(_), do: {:error, "name is required"}

  defp require_type(type) when type in ["webhook", "ntfy"], do: {:ok, type}
  defp require_type(_), do: {:error, "type must be 'webhook' or 'ntfy'"}

  defp require_config("ntfy", %{} = config) do
    cond do
      not is_binary(config["url"]) -> {:error, "ntfy config requires url"}
      not is_binary(config["topic"]) -> {:error, "ntfy config requires topic"}
      true -> {:ok, config}
    end
  end

  defp require_config("webhook", %{} = config) do
    if is_binary(config["url"]), do: {:ok, config}, else: {:error, "webhook config requires url"}
  end

  defp require_config(_type, _config), do: {:error, "config is required"}

  defp validate_type(nil), do: :ok
  defp validate_type(type) when type in ["webhook", "ntfy"], do: :ok
  defp validate_type(_), do: {:error, :invalid_type}

  # Only the keys the caller actually sent are updated (Node's spread-of-present-fields).
  defp channel_changes(params) do
    %{}
    |> put_present(params, "name", :name, &String.trim/1)
    |> put_present(params, "type", :type, & &1)
    |> put_present(params, "config", :config, &Jason.encode!/1)
    |> put_present(params, "enabled", :enabled, & &1)
  end

  defp put_present(changes, params, key, field, transform) do
    case Map.fetch(params, key) do
      {:ok, value} -> Map.put(changes, field, transform.(value))
      :error -> changes
    end
  end

  # --- shared -----------------------------------------------------------------

  defp parse_id(id) when is_integer(id) and id > 0, do: {:ok, id}

  defp parse_id(id) when is_binary(id) do
    case Integer.parse(id) do
      {n, ""} when n > 0 -> {:ok, n}
      _ -> {:error, :invalid_id}
    end
  end

  defp parse_id(_), do: {:error, :invalid_id}

  defp reason_message({:http_status, status}), do: "HTTP #{status}"
  defp reason_message(reason) when is_binary(reason), do: reason
  defp reason_message(reason), do: inspect(reason)

  defp iso_now, do: DateTime.utc_now() |> DateTime.truncate(:millisecond) |> DateTime.to_iso8601()

  defp error(conn, status, message), do: conn |> put_status(status) |> json(%{error: message})
end
