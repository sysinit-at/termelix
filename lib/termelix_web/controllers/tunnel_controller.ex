defmodule TermelixWeb.TunnelController do
  @moduledoc """
  Ports the tunnel control plane the frontend drives via `tunnelApi` (base `/ssh`, port 30003
  in the Node split — see `docs/AUTH_HOST_CONTRACT.md`). Callers in `src/ui/api/tunnel-api.ts`:
  `getTunnelStatuses` (`GET /ssh/tunnel/status`), `subscribeTunnelStatuses`
  (`GET /ssh/tunnel/status/stream`, an `EventSource`), `connectTunnel`
  (`POST /ssh/tunnel/connect`), `disconnectTunnel` (`POST /ssh/tunnel/disconnect`), and
  `cancelTunnel` (`POST /ssh/tunnel/cancel`). `GET /ssh/tunnel/status/:tunnel_name` is exposed
  for parity with the Node route (the frontend indexes the map client-side).

  The `Authenticate` plug has run, so the owning user is `conn.assigns.current_user_id`; a body
  `userId` is never trusted and source credentials are resolved server-side by
  `Termelix.Tunnels`. Status is scoped to the requesting user (see the context moduledoc).

  The status stream is a real SSE endpoint: it subscribes to the `"tunnels:status"` PubSub
  topic, emits the same `event: statuses\\ndata: <json>\\n\\n` frames Node did, and heartbeats
  every 30s. `connect`/`disconnect`/`cancel` are fire-and-broadcast like the Node routes — the
  HTTP reply just acknowledges the request; the real outcome arrives over the stream.
  """
  use Phoenix.Controller, formats: [:json]

  alias Termelix.Tunnels

  # GET /ssh/tunnel/status
  def status(conn, _params) do
    json(conn, Tunnels.statuses_for_user(conn.assigns.current_user_id))
  end

  # GET /ssh/tunnel/status/stream  (Server-Sent Events)
  def status_stream(conn, _params) do
    user_id = conn.assigns.current_user_id
    Phoenix.PubSub.subscribe(Termelix.PubSub, "tunnels:status")

    conn =
      conn
      |> put_resp_header("cache-control", "no-store, no-transform")
      |> put_resp_header("x-accel-buffering", "no")
      |> put_resp_content_type("text/event-stream")
      |> Plug.Conn.send_chunked(200)

    case Plug.Conn.chunk(conn, snapshot_frame(user_id)) do
      {:ok, conn} -> stream_loop(conn, user_id)
      {:error, _} -> conn
    end
  end

  # GET /ssh/tunnel/status/:tunnel_name
  def status_by_name(conn, %{"tunnel_name" => name}) do
    case Tunnels.status_for(conn.assigns.current_user_id, name) do
      nil -> error(conn, 404, "Tunnel not found")
      status -> json(conn, %{name: name, status: status})
    end
  end

  # POST /ssh/tunnel/connect  body = TunnelConfig
  def connect(conn, params) do
    user_id = conn.assigns.current_user_id
    name = params["name"]

    cond do
      not present?(name) ->
        error(conn, 400, "Invalid tunnel configuration")

      not valid_tunnel_config?(name, params) ->
        error(conn, 400, "Tunnel configuration does not match tunnel name")

      true ->
        case Tunnels.connect(user_id, params) do
          {:ok, tunnel_name} ->
            json(conn, %{message: "Connection request received", tunnelName: tunnel_name})

          {:error, :access_denied} ->
            error(conn, 403, "Access denied to this host")

          {:error, :invalid} ->
            error(conn, 400, "Invalid tunnel configuration")

          # Rejecting rather than silently rewriting the bind host only helps if the caller is
          # told why; falling into the catch-all made it a generic 500.
          {:error, :bind_host_not_allowed} ->
            error(
              conn,
              400,
              "bindHost must be a loopback address unless an admin enables non-loopback binds"
            )

          {:error, _} ->
            error(conn, 500, "Failed to connect tunnel")
        end
    end
  end

  # POST /ssh/tunnel/disconnect  body {tunnelName}
  def disconnect(conn, params) do
    with_tunnel_name(conn, params, fn name ->
      Tunnels.disconnect(conn.assigns.current_user_id, name)
      json(conn, %{message: "Disconnect request received", tunnelName: name})
    end)
  end

  # POST /ssh/tunnel/cancel  body {tunnelName}
  # Cancelling a retrying/failed tunnel is a stop, same as disconnect (Node parity).
  def cancel(conn, params) do
    with_tunnel_name(conn, params, fn name ->
      Tunnels.disconnect(conn.assigns.current_user_id, name)
      json(conn, %{message: "Cancel request received", tunnelName: name})
    end)
  end

  # --- SSE loop -------------------------------------------------------------

  defp stream_loop(conn, user_id) do
    receive do
      {:tunnel_status, _name, _status} ->
        case Plug.Conn.chunk(conn, snapshot_frame(user_id)) do
          {:ok, conn} -> stream_loop(conn, user_id)
          {:error, _} -> conn
        end
    after
      30_000 ->
        case Plug.Conn.chunk(conn, ": keepalive\n\n") do
          {:ok, conn} -> stream_loop(conn, user_id)
          {:error, _} -> conn
        end
    end
  end

  defp snapshot_frame(user_id) do
    data = Jason.encode!(Tunnels.statuses_for_user(user_id))
    "event: statuses\ndata: #{data}\n\n"
  end

  # --- tunnel-name validation (port of routes.ts `validateTunnelConfig`) -----

  # tunnelName = `hostId::tunnelIndex::displayName::sourcePort::endpointHost::endpointPort`.
  # A legacy (non-6-part) name is accepted as-is; a modern name must agree with the config.
  defp valid_tunnel_config?(name, params) do
    case String.split(name, "::") do
      [host_id, tunnel_index, _display, source_port, endpoint_host, endpoint_port] ->
        same?(host_id, params["sourceHostId"]) and
          same?(tunnel_index, params["tunnelIndex"]) and
          same?(source_port, params["sourcePort"]) and
          endpoint_host == to_string(params["endpointHost"] || "") and
          same?(endpoint_port, params["endpointPort"])

      _ ->
        true
    end
  end

  defp same?(str, value), do: str == to_string(value)

  # --- helpers --------------------------------------------------------------

  defp with_tunnel_name(conn, params, fun) do
    case params["tunnelName"] do
      name when is_binary(name) and name != "" -> fun.(name)
      _ -> error(conn, 400, "Tunnel name required")
    end
  end

  defp present?(v), do: is_binary(v) and String.trim(v) != ""

  defp error(conn, status, message), do: conn |> put_status(status) |> json(%{error: message})
end
