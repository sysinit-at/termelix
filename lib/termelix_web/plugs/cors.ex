defmodule TermelixWeb.Plugs.Cors do
  @moduledoc """
  Credentialed CORS with an allowlist: only same-origin requests and origins in the
  `ALLOWED_ORIGINS` env var (see `TermelixWeb.OriginCheck`) get `access-control-*` headers.
  Requests carrying a disallowed `Origin` header are rejected outright — not just hidden
  from the browser — so a malicious same-site page cannot ride the `jwt` cookie into
  state-changing API calls. Requests without an `Origin` header (native clients,
  same-origin GETs) pass through untouched.
  """
  import Plug.Conn

  # `x-reauth-password` carries the admin's own password for the cross-user data export.
  # It is a header rather than a query param because that route is a GET and `?password=`
  # would be written to every reverse-proxy access log.
  @allow_headers "content-type,authorization,x-electron-app,x-admin-target-user," <>
                   "x-internal-auth-token,x-internal-auth,x-reauth-password"
  @allow_methods "GET,POST,PUT,PATCH,DELETE,OPTIONS"

  def init(opts), do: opts

  def call(conn, _opts) do
    case get_req_header(conn, "origin") do
      [origin | _] ->
        if TermelixWeb.OriginCheck.allowed?(conn) do
          conn
          |> put_resp_header("access-control-allow-origin", origin)
          |> put_resp_header("access-control-allow-credentials", "true")
          |> put_resp_header("vary", "Origin")
          |> handle_preflight()
        else
          conn
          |> put_resp_content_type("application/json")
          |> send_resp(403, Jason.encode!(%{error: "Origin not allowed"}))
          |> halt()
        end

      _ ->
        conn
    end
  end

  defp handle_preflight(%Plug.Conn{method: "OPTIONS"} = conn) do
    conn
    |> put_resp_header("access-control-allow-methods", @allow_methods)
    |> put_resp_header("access-control-allow-headers", @allow_headers)
    |> put_resp_header("access-control-max-age", "86400")
    |> send_resp(204, "")
    |> halt()
  end

  defp handle_preflight(conn), do: conn
end
