defmodule TermelixWeb.OriginCheck do
  @moduledoc """
  Origin header check for the WebSocket upgrade endpoints.

  WebSocket handshakes are plain GETs, so browsers will send cross-origin upgrade requests
  unless the server rejects them; the session cookie rides along. The check:

    * no `origin` header → allow (native/non-browser clients don't send one);
    * same-origin (scheme, host, and port — with default-port normalization) → allow;
    * the exact origin string appears in `Application.get_env(:termelix, :allowed_origins)`
      (populated from the `ALLOWED_ORIGINS` env var, default `[]`) → allow;
    * anything else → deny.
  """

  import Plug.Conn

  @doc "Whether the connection's `origin` header permits the WebSocket upgrade."
  @spec allowed?(Plug.Conn.t()) :: boolean()
  def allowed?(conn) do
    case get_req_header(conn, "origin") do
      [] -> true
      [origin | _] -> same_origin?(origin, conn) or origin in configured_origins()
    end
  end

  defp same_origin?(origin, conn) do
    case URI.parse(origin) do
      %URI{scheme: scheme, host: host, port: port} when is_binary(scheme) and is_binary(host) ->
        scheme_equivalent?(scheme, conn.scheme) and
          host == conn.host and
          effective_port(scheme, port) == effective_port(Atom.to_string(conn.scheme), conn.port)

      _ ->
        false
    end
  end

  # ws/wss origins map onto the http/https scheme of the request.
  defp scheme_equivalent?(origin_scheme, conn_scheme) do
    case String.downcase(origin_scheme) do
      "ws" -> conn_scheme == :http
      "wss" -> conn_scheme == :https
      s -> s == Atom.to_string(conn_scheme)
    end
  end

  defp effective_port(_scheme, port) when is_integer(port), do: port

  defp effective_port(scheme, nil) do
    case String.downcase(scheme) do
      s when s in ["http", "ws"] -> 80
      s when s in ["https", "wss"] -> 443
      _ -> nil
    end
  end

  defp configured_origins do
    Application.get_env(:termelix, :allowed_origins, []) || []
  end
end
