defmodule TermelixWeb.Plugs.Authenticate do
  @moduledoc """
  Authenticates a request from the `jwt` cookie (browsers) or `Authorization: Bearer`
  header (native clients), matching `auth-manager.ts`'s `createAuthMiddleware`.

  On success assigns `:current_user`, `:current_user_id`, and `:jwt_claims`. On failure it
  responds with the original's `{error, code?}` envelope and clears the `jwt` cookie for the
  invalid/expired/session cases (which the frontend treats as a logout trigger).
  """
  import Plug.Conn

  alias Termelix.Accounts

  def init(opts), do: opts

  def call(conn, _opts) do
    case extract_token(conn) do
      nil ->
        reject(conn, :missing)

      "tmx_" <> _ ->
        # API-key auth (tmx_ prefix) is a separate scheme, not yet ported.
        reject(conn, :missing)

      token ->
        case Accounts.verify_token(token) do
          {:ok, %{user: user, claims: claims}} ->
            conn
            |> assign(:current_user, user)
            |> assign(:current_user_id, user.id)
            |> assign(:jwt_claims, claims)

          {:error, reason} ->
            reject(conn, reason)
        end
    end
  end

  @doc "Extract the bearer/cookie token from a connection (also used by the WS socket)."
  @spec extract_token(Plug.Conn.t()) :: String.t() | nil
  def extract_token(conn) do
    conn = fetch_cookies(conn)

    case conn.cookies["jwt"] do
      cookie when is_binary(cookie) and cookie != "" ->
        cookie

      _ ->
        case get_req_header(conn, "authorization") do
          ["Bearer " <> token | _] -> token
          _ -> nil
        end
    end
  end

  # --- rejection --------------------------------------------------------------

  defp reject(conn, :missing), do: send_error(conn, 401, "Missing authentication token")

  defp reject(conn, :totp_required),
    do: send_error(conn, 401, "TOTP verification required", "TOTP_REQUIRED")

  defp reject(conn, :session_not_found),
    do: conn |> clear_jwt_cookie() |> send_error(401, "Session not found", "SESSION_NOT_FOUND")

  defp reject(conn, :session_expired),
    do: conn |> clear_jwt_cookie() |> send_error(401, "Session has expired", "SESSION_EXPIRED")

  defp reject(conn, :user_not_found), do: send_error(conn, 401, "User not found")

  defp reject(conn, reason) when reason in [:invalid, :expired],
    do: conn |> clear_jwt_cookie() |> send_error(401, "Invalid token")

  defp reject(conn, _other), do: send_error(conn, 401, "Invalid token")

  defp send_error(conn, status, message, code \\ nil) do
    body = if code, do: %{error: message, code: code}, else: %{error: message}

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
    |> halt()
  end

  @doc "Clear the `jwt` cookie with the same options the original uses."
  def clear_jwt_cookie(conn) do
    delete_resp_cookie(conn, "jwt",
      http_only: true,
      same_site: "Lax",
      secure: https?(conn),
      path: "/"
    )
  end

  # `TermelixWeb.Plugs.TrustedProxy` folds a trusted proxy's `x-forwarded-proto` into
  # `conn.scheme`, so reading the header again here would only re-admit the untrusted value.
  defp https?(conn), do: conn.scheme == :https
end
