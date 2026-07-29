defmodule TermelixWeb.UserSessionController do
  @moduledoc """
  Ports the active-session surface (`user-session-routes.ts`) and the per-user data
  access/unlock surface (`user-data-access-routes.ts`).

  Sessions: a user sees their own live sessions; an admin sees every session, enriched with
  the owning username and a `isCurrentSession` flag against the JWT's `sessionId`. Revocation
  deletes the row and is ownership-enforced (admins may revoke any). `revoke-all` optionally
  spares the current session and, for admins, may target another user.

  Data access: `data-status` reports whether the server can decrypt the user's data;
  `unlock-data` re-verifies the password (on the login rate-limit budget) and refreshes the
  session token. Because the v3 DEK is system-wrapped (not password-derived), "unlock" is a
  password check plus a token refresh — the data is already reachable — so `data-status` is
  effectively always unlocked once a DEK exists.
  """
  use Phoenix.Controller, formats: [:json]

  import Plug.Conn
  import TermelixWeb.AuthHelpers, only: [put_jwt_cookie: 3]
  import TermelixWeb.ControllerHelpers, only: [client_ip: 1]

  alias Termelix.{Accounts, Admin, Audit, RateLimiter, Sessions}
  alias Termelix.Crypto.UserKeyManager

  # GET /users/sessions
  def sessions(conn, _params) do
    user = conn.assigns.current_user
    current_sid = current_session_id(conn)

    if user.isAdmin == true do
      usernames = Map.new(Admin.list_users(), &{&1.id, &1.username})

      sessions =
        Sessions.list_all()
        |> Enum.map(&render_session(&1, current_sid, Map.get(usernames, &1.userId, "Unknown")))

      json(conn, %{sessions: sessions})
    else
      sessions =
        user.id
        |> Sessions.list_for_user()
        |> Enum.map(&render_session(&1, current_sid, :omit))

      json(conn, %{sessions: sessions})
    end
  end

  # DELETE /users/sessions/:sessionId
  def revoke_session(conn, %{"sessionId" => session_id}) do
    user = conn.assigns.current_user

    case Sessions.get(session_id) do
      nil ->
        error(conn, 404, "Session not found")

      session ->
        if user.isAdmin != true and session.userId != user.id do
          error(conn, 403, "Not authorized to revoke this session")
        else
          Accounts.revoke_session(session_id)

          Audit.log(user, "revoke_session", "session", %{
            resource_id: session_id,
            details: Jason.encode!(%{targetUserId: session.userId}),
            ip_address: client_ip(conn),
            user_agent: header(conn, "user-agent", "")
          })

          json(conn, %{success: true, message: "Session revoked successfully"})
        end
    end
  end

  # POST /users/sessions/revoke-all
  def revoke_all(conn, params) do
    user = conn.assigns.current_user
    target = params["targetUserId"]
    except_current? = params["exceptCurrent"] == true

    case resolve_revoke_target(user, target) do
      {:error, :forbidden} ->
        error(conn, 403, "Not authorized to revoke sessions for other users")

      {:ok, revoke_user_id} ->
        except_sid = if except_current?, do: current_session_id(conn), else: nil
        count = Sessions.revoke_all_for_user(revoke_user_id, except_sid)

        target_user =
          if revoke_user_id == user.id, do: user, else: Accounts.get_user(revoke_user_id)

        Audit.log(user, "revoke_all_sessions", "session", %{
          resource_id: revoke_user_id,
          resource_name: target_user && target_user.username,
          details: Jason.encode!(%{revokedCount: count, exceptCurrent: except_current?}),
          ip_address: client_ip(conn),
          user_agent: header(conn, "user-agent", "")
        })

        json(conn, %{message: "#{count} session(s) revoked successfully", count: count})
    end
  end

  # GET /users/data-status
  def data_status(conn, _params) do
    unlocked = UserKeyManager.try_get_user_dek(conn.assigns.current_user.id) != nil

    json(conn, %{
      unlocked: unlocked,
      message: if(unlocked, do: "Data is unlocked", else: "Data is locked")
    })
  end

  # POST /users/unlock-data
  # This endpoint verifies the account password, so without a limiter a stolen cookie turned
  # confirm-your-password into a full-rate password oracle (AGENTS.md: auth-like endpoints go
  # through `Termelix.RateLimiter`).
  #
  # It uses the `:reauth` budget, shared with `POST /users/totp/disable` — one bucket across
  # both, so guesses cannot be spread over two endpoints to double the allowance. Two things it
  # deliberately is NOT:
  #
  #   * not the login bucket. Failing here would otherwise lock the user out of logging in
  #     because of something they fumbled while already signed in.
  #   * not keyed on the IP. The attacker this exists to stop is holding a stolen session
  #     cookie and can rotate source addresses for a fresh allowance; the account is the thing
  #     under attack, so the account is the key.
  def unlock_data(conn, params) do
    user = conn.assigns.current_user
    password = params["password"]

    if missing_password?(password) do
      error(conn, 400, "Password is required")
    else
      case RateLimiter.check_reauth(user.id) do
        {:error, retry_after} ->
          conn
          |> put_status(429)
          |> json(%{
            error: "Too many login attempts. Please try again later.",
            remainingTime: retry_after
          })

        :ok ->
          verify_password_and_unlock(conn, user, password)
      end
    end
  end

  defp verify_password_and_unlock(conn, user, password) do
    case Accounts.authenticate(user.username, password) do
      {:ok, _user} ->
        RateLimiter.reset_reauth(user.id)

        conn
        |> maybe_refresh_session(user)
        |> json(%{success: true, message: "Data unlocked successfully"})

      {:error, _reason} ->
        RateLimiter.record_reauth_failure(user.id)
        error(conn, 401, "Invalid password")
    end
  end

  # --- session rendering -----------------------------------------------------

  defp render_session(session, current_sid, username) do
    base = %{
      id: session.id,
      userId: session.userId,
      deviceType: session.deviceType,
      deviceInfo: session.deviceInfo,
      createdAt: session.createdAt,
      expiresAt: session.expiresAt,
      lastActiveAt: session.lastActiveAt,
      isRevoked: false,
      isCurrentSession: session.id == current_sid
    }

    case username do
      :omit -> base
      name -> Map.put(base, :username, name)
    end
  end

  # --- revoke-all target resolution ------------------------------------------

  # Mirrors the Node branch: admins may target anyone; a non-admin may only target themselves
  # (an explicit foreign targetUserId is refused), and an absent/self target revokes own.
  defp resolve_revoke_target(user, target) do
    cond do
      present?(target) and user.isAdmin == true -> {:ok, target}
      present?(target) and target != user.id -> {:error, :forbidden}
      true -> {:ok, user.id}
    end
  end

  # --- unlock helpers --------------------------------------------------------

  defp maybe_refresh_session(conn, user) do
    case current_session_id(conn) do
      sid when is_binary(sid) ->
        case Sessions.refresh_token(user.id, sid) do
          {:ok, token, ttl} -> put_jwt_cookie(conn, token, ttl)
          :error -> conn
        end

      _ ->
        conn
    end
  end

  # --- request helpers -------------------------------------------------------

  defp current_session_id(conn) do
    case conn.assigns[:jwt_claims] do
      %{"sessionId" => sid} -> sid
      _ -> nil
    end
  end

  defp header(conn, name, default) do
    case get_req_header(conn, name) do
      [v | _] -> v
      _ -> default
    end
  end

  # JS `!password`: only nil / "" count as missing (whitespace is truthy, so it proceeds to fail auth).
  defp missing_password?(p), do: is_nil(p) or p == ""

  defp present?(v), do: is_binary(v) and v != ""

  defp error(conn, status, message), do: conn |> put_status(status) |> json(%{error: message})
end
