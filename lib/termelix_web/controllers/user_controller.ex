defmodule TermelixWeb.UserController do
  @moduledoc "Ports the `/users` auth surface the React frontend depends on."
  use Phoenix.Controller, formats: [:json]

  import Plug.Conn
  import TermelixWeb.AuthHelpers
  import TermelixWeb.ControllerHelpers, only: [client_ip: 1]

  alias Termelix.{Accounts, RateLimiter, WsTickets}

  @day 86_400

  # Scopes a `POST /users/ws-ticket` request may mint a WebSocket ticket for. Each maps to a
  # `"#{scope}_ws"` Phoenix.Token salt the matching WS-upgrade controller verifies.
  @ws_ticket_scopes ~w(ssh)

  # POST /users/create
  def create(conn, params) do
    ip = remote_ip_string(conn)

    case RateLimiter.check_register(ip) do
      {:error, retry_after} ->
        conn
        |> put_status(429)
        |> json(%{
          error: "Too many registration attempts. Please try again later.",
          remainingTime: retry_after
        })

      :ok ->
        RateLimiter.record_register_attempt(ip)
        do_create(conn, params)
    end
  end

  defp do_create(conn, params) do
    username = params["username"]
    password = params["password"]

    case Accounts.register_user(username, password) do
      {:ok, user, first?} ->
        json(conn, %{
          message: "User created",
          is_admin: first?,
          toast: %{type: "success", message: "User created: #{user.username}"}
        })

      {:error, :registration_disabled} ->
        error(conn, 403, "Registration is currently disabled")

      {:error, :missing_fields} ->
        error(conn, 400, "Username and password are required")

      {:error, :password_too_short} ->
        error(conn, 400, "Password must be at least 8 characters")

      {:error, :username_taken} ->
        error(conn, 409, "Username already exists")

      {:error, :encryption_setup_failed} ->
        error(conn, 500, "Failed to setup user security - user creation cancelled")

      {:error, _} ->
        error(conn, 500, "Failed to create user")
    end
  end

  # POST /users/login
  def login(conn, params) do
    username = params["username"]
    password = params["password"]
    remember_me = params["rememberMe"] == true

    if is_nil(username) or is_nil(password) do
      error(conn, 400, "Invalid username or password")
    else
      ip = remote_ip_string(conn)

      case RateLimiter.check_login(ip, username) do
        {:error, retry_after} ->
          conn
          |> put_status(429)
          |> json(%{
            error: "Too many login attempts. Please try again later.",
            remainingTime: retry_after
          })

        :ok ->
          if Accounts.password_login_allowed?() do
            do_login(conn, ip, username, password, remember_me)
          else
            error(conn, 403, "Password authentication is currently disabled")
          end
      end
    end
  end

  defp do_login(conn, ip, username, password, remember_me) do
    case Accounts.authenticate(username, password) do
      {:error, :not_found} ->
        RateLimiter.record_login_failure(ip, username)
        error(conn, 401, "Invalid username or password")

      {:error, :external_auth} ->
        RateLimiter.record_login_failure(ip, username)
        error(conn, 403, "This user uses external authentication")

      {:error, :invalid} ->
        RateLimiter.record_login_failure(ip, username)
        error(conn, 401, "Invalid username or password")

      {:ok, %{totpEnabled: true} = user} ->
        # 2FA required (trusted-device bypass not yet ported): return the interim token.
        RateLimiter.reset_login(ip, username)
        temp_token = Accounts.pending_totp_token(user)

        json(conn, %{
          success: true,
          requires_totp: true,
          temp_token: temp_token,
          rememberMe: remember_me
        })

      {:ok, user} ->
        RateLimiter.reset_login(ip, username)
        issue_session(conn, user, remember_me)
    end
  end

  defp issue_session(conn, user, remember_me) do
    ttl_seconds =
      if remember_me, do: 30 * @day, else: Accounts.session_timeout_hours() * 3600

    {device_type, device_info} = device(conn)
    {:ok, token, _session} = Accounts.create_session(user, device_type, device_info, ttl_seconds)

    body =
      %{success: true, is_admin: user.isAdmin, username: user.username}
      |> maybe_put_token(conn, token)

    conn
    |> put_jwt_cookie(token, ttl_seconds)
    |> json(body)
  end

  # GET /users/me
  def me(conn, _params) do
    user = conn.assigns.current_user
    reporting = Termelix.ErrorReporting.status()

    json(conn, %{
      userId: user.id,
      username: user.username,
      is_admin: user.isAdmin,
      is_oidc: user.isOidc,
      is_dual_auth: present?(user.passwordHash) and present?(user.oidcIdentifier),
      totp_enabled: user.totpEnabled == true,
      # Ask the first admin who logs in to opt in/out of error reporting; the flag clears
      # for everyone once any admin has decided, and never fires while no Sentry DSN is
      # configured (there would be nothing to opt in to).
      prompt_error_reporting:
        user.isAdmin == true and reporting.available and not reporting.decided
    })
  end

  # POST /users/logout
  def logout(conn, _params) do
    case conn.assigns[:jwt_claims] do
      %{"sessionId" => sid} when is_binary(sid) -> Accounts.revoke_session(sid)
      _ -> Accounts.revoke_all_sessions(conn.assigns.current_user.id)
    end

    conn
    |> clear_jwt_cookie()
    |> json(%{success: true, message: "Logged out successfully"})
  end

  # GET /users/me/token
  # Echo the current session JWT back to WebView clients that cannot read the httpOnly
  # cookie themselves. Reads only the `jwt` cookie (bearer clients get null), matching Node.
  def token(conn, _params) do
    conn = fetch_cookies(conn)
    json(conn, %{token: conn.cookies["jwt"] || nil})
  end

  # POST /users/ws-ticket
  # Mint a short-lived, scoped, single-use `Phoenix.Token` for a native WebSocket upgrade (the
  # SSH terminal). The reusable account JWT authenticates this normal POST;
  # the ticket it returns is scoped — via the `"#{scope}_ws"` salt — to a single WS upgrade,
  # expires in 30s, and is consumed on first use (`Termelix.WsTickets`). Unlike the 24h account
  # JWT it replaced, the ticket can therefore ride safely
  # in the `?ticket=` query param the in-WebView WebSocket must use (server access logs, WebView
  # page) without becoming an account-takeover vector — even a logged copy is dead after its one
  # upgrade (or 30s, whichever comes first).
  def ws_ticket(conn, %{"scope" => scope}) when scope in @ws_ticket_scopes do
    ticket = WsTickets.mint(conn.assigns.current_user_id, scope)
    json(conn, %{ticket: ticket})
  end

  def ws_ticket(conn, _params), do: error(conn, 400, "Invalid or missing ws-ticket scope")

  # --- unauthenticated bootstrap endpoints ---

  # GET /users/setup-required
  def setup_required(conn, _params),
    do: json(conn, %{setup_required: Accounts.user_count() == 0})

  # GET /users/registration-allowed
  def registration_allowed(conn, _params),
    do: json(conn, %{allowed: Accounts.registration_allowed?()})

  # GET /users/password-login-allowed
  def password_login_allowed(conn, _params),
    do: json(conn, %{allowed: Accounts.password_login_allowed?()})

  # --- helpers ---

  # `TermelixWeb.Plugs.TrustedProxy` has already resolved this: the forwarded client address when
  # a *trusted* proxy sent it, the direct peer otherwise. Reading the raw header here would let an
  # attacker reset their own budget; ignoring it entirely (as this did before the plug existed)
  # collapsed every client behind a reverse proxy onto the proxy's address, which made
  # `{:login, ip, username}` a lockout vector and `{:register, ip}` a single global bucket.
  defp remote_ip_string(conn), do: client_ip(conn)

  defp maybe_put_token(body, conn, token) do
    if native_app?(conn), do: Map.put(body, :token, token), else: body
  end

  defp present?(v) when is_binary(v), do: String.trim(v) != ""
  defp present?(_), do: false

  defp error(conn, status, message) do
    conn |> put_status(status) |> json(%{error: message})
  end
end
