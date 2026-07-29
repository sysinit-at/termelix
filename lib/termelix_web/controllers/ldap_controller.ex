defmodule TermelixWeb.LdapController do
  @moduledoc """
  LDAP login (`POST /users/ldap/login`), the Elixir port of `ldap-auth-routes.ts`.

  A NEW controller (rather than adding an action to `UserController`) so the golden auth
  controller stays untouched. `Termelix.Ldap.login/3` does the directory work and find-or-create;
  on success this mints a real session and sets the `jwt` cookie exactly like
  `UserController.issue_session`, then returns the LDAP route's `{success, message}` body the
  `ldapLogin` frontend caller expects — unless the account has TOTP enabled, in which case it
  returns the same `requires_totp` interim-token body as `UserController.do_login/5` and no
  cookie, leaving `POST /users/totp/verify-login` to finish the login.
  """
  use Phoenix.Controller, formats: [:json]

  import Plug.Conn
  import TermelixWeb.AuthHelpers
  import TermelixWeb.ControllerHelpers, only: [client_ip: 1, error: 3]

  alias Termelix.{Accounts, Ldap, RateLimiter}

  @day 86_400

  # POST /users/ldap/login
  def login(conn, params) do
    provider_id = Ldap.normalize_provider_id(params["providerId"])
    username = params["username"]
    password = params["password"]
    remember_me = params["rememberMe"] == true

    if is_nil(provider_id) or blank?(username) or blank?(password) do
      error(conn, 400, "providerId, username, and password are required")
    else
      ip = client_ip(conn)

      # The same per-IP+username budget as the password path (`UserController.login`): every
      # attempt below performs a live directory bind, so without this the route is an
      # unthrottled password-spray oracle that can also trip directory-side lockouts.
      case RateLimiter.check_login(ip, username) do
        {:error, retry_after} ->
          conn
          |> put_status(429)
          |> json(%{
            error: "Too many login attempts. Please try again later.",
            remainingTime: retry_after
          })

        :ok ->
          do_login(conn, ip, provider_id, username, password, remember_me)
      end
    end
  end

  defp do_login(conn, ip, provider_id, username, password, remember_me) do
    case Ldap.login(provider_id, username, password) do
      {:ok, %{totpEnabled: true} = user} ->
        # A directory bind is only the first factor: an LDAP-provisioned user who enabled 2FA
        # must clear it here exactly as on the password path, or username+password alone would
        # mint a full (30-day-capable) session while the UI still advertises 2FA as on. Body is
        # byte-identical to `user_controller.ex:117` so the SPA's existing TOTP step applies.
        RateLimiter.reset_login(ip, username)

        json(conn, %{
          success: true,
          requires_totp: true,
          temp_token: Accounts.pending_totp_token(user),
          rememberMe: remember_me
        })

      {:ok, user} ->
        RateLimiter.reset_login(ip, username)
        issue_session(conn, user, remember_me)

      {:error, :provider_not_found} ->
        error(conn, 404, "LDAP provider not found")

      {:error, :misconfigured} ->
        error(conn, 500, "LDAP provider is misconfigured")

      {:error, :invalid_credentials} ->
        RateLimiter.record_login_failure(ip, username)
        error(conn, 401, "Invalid username or password")

      {:error, :not_allowed} ->
        error(conn, 403, "User not allowed")

      {:error, :registration_disabled} ->
        error(conn, 403, "Registration is disabled")

      {:error, :encryption_setup_failed} ->
        error(conn, 500, "Failed to setup user security")

      {:error, _other} ->
        error(conn, 500, "LDAP authentication failed")
    end
  end

  # Mirrors UserController.issue_session's session + cookie mechanics, but returns the LDAP
  # route's own `{success, message}` body (native clients also get the token, as elsewhere in
  # this port, since they cannot read the httpOnly cookie).
  defp issue_session(conn, user, remember_me) do
    ttl_seconds =
      if remember_me, do: 30 * @day, else: Accounts.session_timeout_hours() * 3600

    {device_type, device_info} = device(conn)
    {:ok, token, _session} = Accounts.create_session(user, device_type, device_info, ttl_seconds)

    body =
      %{success: true, message: "Login successful"}
      |> maybe_put_token(conn, token)

    conn
    |> put_jwt_cookie(token, ttl_seconds)
    |> json(body)
  end

  defp maybe_put_token(body, conn, token) do
    if native_app?(conn), do: Map.put(body, :token, token), else: body
  end

  defp blank?(nil), do: true
  defp blank?(str) when is_binary(str), do: String.trim(str) == ""
  defp blank?(_), do: false
end
