defmodule Termelix.Alerts.Notifier do
  @moduledoc """
  Outbound alert delivery — the port of `utils/notification-sender.ts`. Two channel types are
  implemented over `Req`: `webhook` (JSON POST/PUT of the alert payload) and `ntfy` (the message
  body POSTed to `<url>/<topic>` with Title/Priority/Tags headers). Any other type is a
  structured no-op (`{:error, :unsupported_channel}`) — the Node backend only sends these two;
  other types are DEFERRED.

  Delivery attempts the request once and, on a transport error or non-2xx status, retries once
  (Node's `fetchWithRetry`). The 3s inter-attempt delay Node used is dropped so the path stays
  deterministic; the second attempt fires immediately.

  Tests inject a `Req.Test` plug through the `:alerts_req_options` app env (a keyword list
  merged into every `Req.request/1` call), mirroring how `Termelix.System`/`Termelix.Homepage`
  stub outbound HTTP. In production the app env is empty and real requests go out.

  A `payload` is the `AlertPayload` map (atom keys): `hostName`, `hostId`, `triggerType`,
  `value`, `threshold`, `message`, `severity`, `timestamp`, `ruleId`, `ruleName`.
  """
  require Logger

  alias Termelix.Net.Egress

  @receive_timeout 10_000

  @ntfy_priority %{"info" => 2, "warning" => 3, "critical" => 5}

  @typedoc "A notification channel as `{type, config_json, enabled}` (atom-keyed map or struct)."
  @type channel :: %{optional(atom()) => term()}

  @doc """
  Dispatch `payload` to `channel` (a `NotificationChannel` struct or a map with `:type`,
  `:config`, `:enabled`). A disabled channel or an unparseable config is a silent `:ok` (Node
  logs and returns). Returns `:ok` on success, `{:error, reason}` on a delivery failure.
  """
  @spec send_notification(channel(), map()) :: :ok | {:error, term()}
  def send_notification(channel, payload) do
    cond do
      not enabled?(channel) ->
        :ok

      true ->
        case parse_config(channel_field(channel, :config)) do
          {:ok, config} ->
            dispatch(channel_field(channel, :type), config, payload)

          :error ->
            Logger.warning("Alert notification: unparseable channel config")
            :ok
        end
    end
  end

  @doc """
  Send a `webhook` notification: JSON POST (or PUT) of `payload` to `config["url"]`, merging any
  `config["headers"]` over the default `content-type: application/json`.
  """
  @spec send_webhook(map(), map()) :: :ok | {:error, term()}
  def send_webhook(config, payload) do
    url = config["url"]
    headers = normalize_headers(config["headers"])
    method = method_atom(config["method"])

    request_with_retry(
      method: method,
      url: url,
      headers: headers,
      json: payload
    )
  end

  @doc """
  Send an `ntfy` notification: POST `payload.message` (raw body) to `<url>/<topic>` with the
  Termelix Title, severity-mapped Priority, and severity Tags headers (plus `Authorization: Bearer`
  when `config["token"]` is set).
  """
  @spec send_ntfy(map(), map()) :: :ok | {:error, term()}
  def send_ntfy(config, payload) do
    url = config["url"]
    topic = config["topic"]
    token = config["token"]
    ntfy_url = String.trim_trailing(to_string(url), "/") <> "/" <> to_string(topic)

    # ntfy takes the raw message as the request body (text/plain); do NOT send an
    # application/json content-type — the body is not JSON.
    headers =
      %{
        "title" => "[Termelix] #{payload.hostName}: #{payload.ruleName}",
        "priority" => Integer.to_string(Map.get(@ntfy_priority, payload.severity, 3)),
        "tags" => ntfy_tags(payload.severity)
      }
      |> maybe_auth(token)

    request_with_retry(
      method: :post,
      url: ntfy_url,
      headers: headers,
      body: payload.message
    )
  end

  # --- internals --------------------------------------------------------------

  defp dispatch("webhook", config, payload), do: send_webhook(config, payload)
  defp dispatch("ntfy", config, payload), do: send_ntfy(config, payload)
  defp dispatch(_type, _config, _payload), do: {:error, :unsupported_channel}

  # One attempt, one immediate retry on failure (Node's fetchWithRetry, minus the sleep).
  defp request_with_retry(opts) do
    case do_request(opts) do
      :ok ->
        :ok

      {:error, _first} ->
        case do_request(opts) do
          :ok ->
            :ok

          {:error, reason} ->
            Logger.warning("Alert notification delivery failed after retry: #{inspect(reason)}")
            {:error, reason}
        end
    end
  end

  defp do_request(opts) do
    # `redirect: false` is load-bearing, not a preference: the Egress check below vets only the
    # configured channel URL, so a 302 to `http://169.254.169.254/...` would sail through if Req
    # followed it. Refusing to follow keeps the single check sufficient — a 3xx surfaces as a
    # non-2xx status, which `send_request/1` already treats as a delivery failure.
    opts =
      Keyword.merge(
        [receive_timeout: @receive_timeout, retry: false, redirect: false] ++ req_options(),
        opts
      )

    # Checked HERE rather than in the two `send_*` functions: this is the only place a request
    # actually leaves, so it is the only place that cannot be bypassed by a third channel type
    # added later — and defect 42's whole shape was a URL reaching `Req` without ever passing a
    # check that existed somewhere else.
    with :ok <- Egress.check(to_string(Keyword.get(opts, :url))) do
      send_request(opts)
    else
      {:error, reason} = error ->
        Logger.warning(
          "Alert notification refused: #{reason} (#{inspect(Keyword.get(opts, :url))})"
        )

        error
    end
  end

  defp send_request(opts) do
    case Req.request(opts) do
      {:ok, %Req.Response{status: status}} when status in 200..299 -> :ok
      {:ok, %Req.Response{status: status}} -> {:error, {:http_status, status}}
      {:error, reason} -> {:error, reason}
    end
  rescue
    error -> {:error, error}
  end

  defp req_options, do: Application.get_env(:termelix, :alerts_req_options, [])

  defp enabled?(channel), do: channel_field(channel, :enabled) in [true, 1, "1"]

  # Support both a `NotificationChannel` struct (camelCase :config) and a plain map (:config).
  defp channel_field(channel, :config), do: Map.get(channel, :config)
  defp channel_field(channel, :type), do: Map.get(channel, :type)
  defp channel_field(channel, :enabled), do: Map.get(channel, :enabled)

  defp parse_config(json) when is_binary(json) do
    case Jason.decode(json) do
      {:ok, %{} = config} -> {:ok, config}
      _ -> :error
    end
  end

  defp parse_config(%{} = config), do: {:ok, config}
  defp parse_config(_), do: :error

  defp normalize_headers(headers) when is_map(headers) do
    Map.merge(%{"content-type" => "application/json"}, stringify_headers(headers))
  end

  defp normalize_headers(_), do: %{"content-type" => "application/json"}

  defp stringify_headers(headers) do
    Map.new(headers, fn {k, v} -> {to_string(k), to_string(v)} end)
  end

  defp method_atom("PUT"), do: :put
  defp method_atom("put"), do: :put
  defp method_atom(_), do: :post

  defp ntfy_tags("critical"), do: "rotating_light"
  defp ntfy_tags("warning"), do: "warning"
  defp ntfy_tags(_), do: "information_source"

  defp maybe_auth(headers, token) when is_binary(token) and token != "",
    do: Map.put(headers, "authorization", "Bearer #{token}")

  defp maybe_auth(headers, _token), do: headers
end
