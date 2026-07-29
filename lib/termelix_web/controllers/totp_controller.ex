defmodule TermelixWeb.TotpController do
  @moduledoc """
  Ports the TOTP 2FA surface (`user-totp-routes.ts`): `POST /users/totp/setup`,
  `/users/totp/enable`, `/users/totp/disable` (all authenticated) and the unauthenticated
  second login step `/users/totp/verify-login`.

  For the authenticated actions the `Authenticate` plug has run, so the acting user is
  `conn.assigns.current_user` — a body `userId` is never trusted. `verify-login` is
  unauthenticated by design: it validates the interim `pendingTOTP` token itself, then mints
  a real session and sets the `jwt` cookie exactly like `UserController.issue_session`
  (response shape per `AUTH_HOST_CONTRACT.md` §3).
  """
  use Phoenix.Controller, formats: [:json]

  import Plug.Conn
  import TermelixWeb.AuthHelpers

  alias Termelix.{Accounts, RateLimiter, Totp}

  @day 86_400

  # POST /users/totp/setup
  def setup(conn, _params) do
    case Totp.setup(conn.assigns.current_user) do
      {:ok, %{secret: secret, otpauth_url: otpauth_url}} ->
        json(conn, %{secret: secret, qr_code: qr_data_uri(otpauth_url)})

      {:error, :already_enabled} ->
        error(conn, 400, "TOTP is already enabled")
    end
  end

  # POST /users/totp/enable
  def enable(conn, params) do
    code = params["totp_code"]

    if blank?(code) do
      error(conn, 400, "TOTP code is required")
    else
      case Totp.enable(conn.assigns.current_user, code) do
        {:ok, backup_codes} ->
          json(conn, %{message: "TOTP enabled successfully", backup_codes: backup_codes})

        {:error, :password_login_disabled} ->
          error(
            conn,
            409,
            "Cannot enable 2FA while password login is disabled. Enable password login first."
          )

        {:error, :already_enabled} ->
          error(conn, 400, "TOTP is already enabled")

        {:error, :not_initiated} ->
          error(conn, 400, "TOTP setup not initiated")

        {:error, :rate_limited, retry_after} ->
          rate_limited(conn, retry_after)

        {:error, :invalid_code} ->
          error(conn, 401, "Invalid TOTP code")
      end
    end
  end

  # POST /users/totp/disable
  # A budget is checked here, *before* `Totp.disable/4`, because that function only reaches its
  # own `check_totp` after the password comparison (`totp.ex:132-147`) — which left the password
  # check an unthrottled oracle for anyone holding a session cookie.
  #
  # It is the `:reauth` budget, NOT `:totp`: the TOTP bucket gates logging in, so charging a
  # fumbled password here to it would lock the user out of the front door for something they
  # did while already signed in.
  def disable(conn, params) do
    user = conn.assigns.current_user

    case RateLimiter.check_reauth(user.id) do
      {:error, retry_after} -> rate_limited(conn, retry_after)
      :ok -> do_disable(conn, user, params)
    end
  end

  defp do_disable(conn, user, params) do
    case Totp.disable(user, params["password"], params["totp_code"]) do
      :ok ->
        json(conn, %{message: "TOTP disabled successfully"})

      {:error, {:missing_credentials, true}} ->
        error(conn, 400, "A TOTP code is required")

      {:error, {:missing_credentials, false}} ->
        error(conn, 400, "Both password and TOTP code are required")

      {:error, :incorrect_password} ->
        RateLimiter.record_reauth_failure(user.id)
        error(conn, 401, "Incorrect password")

      {:error, :not_enabled} ->
        error(conn, 400, "TOTP is not enabled")

      {:error, :rate_limited, retry_after} ->
        rate_limited(conn, retry_after)

      {:error, :invalid_reauth} ->
        error(conn, 401, "Incorrect password or invalid TOTP code")
    end
  end

  # POST /users/totp/verify-login
  def verify_login(conn, params) do
    temp_token = params["temp_token"]
    code = params["totp_code"]
    remember_me = params["rememberMe"] == true

    cond do
      blank?(temp_token) or blank?(code) ->
        error(conn, 400, "Token and TOTP code are required")

      true ->
        case Totp.verify_login(temp_token, code) do
          {:ok, user} ->
            issue_session(conn, user, remember_me)

          {:error, :invalid_token} ->
            error(conn, 401, "Invalid temporary token")

          {:error, :user_not_found} ->
            error(conn, 404, "User not found")

          {:error, :not_enabled} ->
            error(conn, 400, "TOTP not enabled for this user")

          {:error, :session_expired} ->
            conn
            |> put_status(401)
            |> json(%{error: "Session expired - please log in again", code: "SESSION_EXPIRED"})

          {:error, :rate_limited, retry_after} ->
            rate_limited(conn, retry_after)

          {:error, :invalid_code, remaining} ->
            conn
            |> put_status(401)
            |> json(%{error: "Invalid TOTP code", remainingAttempts: remaining})
        end
    end
  end

  # --- session issuance (mirrors UserController.issue_session) ---------------

  defp issue_session(conn, user, remember_me) do
    ttl_seconds =
      if remember_me, do: 30 * @day, else: Accounts.session_timeout_hours() * 3600

    {device_type, device_info} = device(conn)
    {:ok, token, _session} = Accounts.create_session(user, device_type, device_info, ttl_seconds)

    body =
      %{
        success: true,
        is_admin: user.isAdmin,
        username: user.username,
        userId: user.id,
        is_oidc: user.isOidc == true,
        totp_enabled: user.totpEnabled == true
      }
      |> maybe_put_token(conn, token)

    conn
    |> put_jwt_cookie(token, ttl_seconds)
    |> json(body)
  end

  # --- helpers ---------------------------------------------------------------

  # Render the otpauth URL to a PNG data URI (the frontend's `qr_code` field), the EQRCode
  # analogue of the Node route's `QRCode.toDataURL`.
  defp qr_data_uri(otpauth_url) do
    png = otpauth_url |> EQRCode.encode() |> EQRCode.png()
    "data:image/png;base64," <> Base.encode64(png)
  end

  defp maybe_put_token(body, conn, token) do
    if native_app?(conn), do: Map.put(body, :token, token), else: body
  end

  defp blank?(nil), do: true
  defp blank?(str) when is_binary(str), do: String.trim(str) == ""
  defp blank?(_), do: false

  defp error(conn, status, message), do: conn |> put_status(status) |> json(%{error: message})

  # Contract 429 shape for TOTP lockout (`code: "TOTP_RATE_LIMITED"` discriminates it).
  defp rate_limited(conn, retry_after) do
    conn
    |> put_status(429)
    |> json(%{
      error: "Too many TOTP attempts. Please try again later.",
      code: "TOTP_RATE_LIMITED",
      remainingTime: retry_after
    })
  end
end
