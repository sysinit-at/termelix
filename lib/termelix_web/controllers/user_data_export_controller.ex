defmodule TermelixWeb.UserDataExportController do
  @moduledoc """
  User data export (`utils/user-data-export.ts` + the routes that serve it).

  Two entry points:

    * `admin_export` — `GET /users/admin/export/:userId`, the contract the frontend's
      `adminExportUserData` calls. Admin-gated (`conn.assigns.current_user.isAdmin`), and the
      target user's DEK must be unlocked (`423 TARGET_DATA_LOCKED` otherwise, matching Node).
      Secrets are DEK-decrypted (`format: :plaintext`); the export is audit-logged.

    * `export` — `GET /users/data-export`, the signed-in user exporting their **own** data
      (ownership = `conn.assigns.current_user`).

  Both return the `UserExportData` JSON shape with a `Content-Disposition` attachment header.

  ## Handing out plaintext secrets is gated

  A plaintext export is the whole secret set of a user in the clear, so it is never implicit:

    * The self export defaults to `format=encrypted` (ciphertext envelopes — a safe backup).
      `?format=plaintext` is the explicit opt-in and still needs the caller's own DEK unlocked.
    * The admin cross-user export additionally requires a **password re-auth** in the
      `x-reauth-password` header. `isAdmin` alone is a standing capability: a stolen admin
      token or an unattended browser would otherwise be enough to walk off with every other
      user's credentials. The password travels in a header, never a query parameter — this is
      a GET, and `?password=` would be written to every reverse-proxy access log.
    * Both routes are rate-limited (`Termelix.RateLimiter`), which also caps re-auth guessing.

  ## Deviation (noted)

  Node's self-export (`POST /database/export`) materialises a full `.termelix-export.sqlite`.
  Rebuilding that byte-compatibly in Elixir is impractical, so the port serves the JSON shape
  only (see `Termelix.UserDataExport`). The task explicitly permits this.
  """
  use Phoenix.Controller, formats: [:json]

  import Plug.Conn
  import TermelixWeb.ControllerHelpers, only: [client_ip: 1, error: 3]

  alias Termelix.{Accounts, Audit, RateLimiter, UserDataExport}
  alias Termelix.Crypto.UserKeyManager

  @reauth_header "x-reauth-password"

  # `Termelix.RateLimiter` has no export bucket family and is not extended from here, so the
  # login family carries these buckets under a synthetic username (10 attempts per 10 minutes
  # per IP + identity). The prefix keeps them out of any real user's login bucket.
  @rate_prefix "user-data-export"

  # GET /users/admin/export/:userId
  def admin_export(conn, %{"userId" => target_user_id}) do
    admin = conn.assigns.current_user

    if admin.isAdmin == true do
      case Accounts.get_user(target_user_id) do
        nil -> error(conn, 404, "User not found")
        target -> admin_export_target(conn, admin, target)
      end
    else
      error(conn, 403, "Admin access required")
    end
  end

  # Node gates the export on the target's DEK being unlocked (`423 TARGET_DATA_LOCKED`); the
  # export itself decrypts secrets under that DEK. The re-auth runs last, behind the rate
  # limit that protects it — the cheap 404/423 answers then stay exactly what they were, and
  # bcrypt only runs for a request that would otherwise succeed.
  defp admin_export_target(conn, admin, target) do
    with :ok <- target_unlocked(conn, target),
         :ok <- rate_limit(conn, "admin:#{admin.id}"),
         :ok <- reauthenticated(conn, admin) do
      case UserDataExport.export_user_data(target.id,
             format: :plaintext,
             include_credentials: true
           ) do
        {:ok, export} ->
          Audit.log(admin, "admin_export_user_data", "user", %{
            resource_id: target.id,
            resource_name: target.username,
            ip_address: client_ip(conn),
            details: Jason.encode!(%{format: "plaintext"})
          })

          respond_with_download(conn, export, target.username)

        {:error, :locked} ->
          target_locked(conn)

        {:error, :user_not_found} ->
          error(conn, 404, "User not found")
      end
    else
      {:error, refused} -> refused
    end
  end

  # GET /users/data-export
  def export(conn, params) do
    user = conn.assigns.current_user

    case UserDataExport.parse_format(params["format"]) do
      :error ->
        error(conn, 400, "Invalid export format")

      {:ok, format} ->
        case rate_limit(conn, "self:#{user.id}") do
          :ok -> export_own_data(conn, user, format)
          {:error, refused} -> refused
        end
    end
  end

  defp export_own_data(conn, user, format) do
    case UserDataExport.export_user_data(user.id, format: format, include_credentials: true) do
      {:ok, export} ->
        Audit.log(user, "export_user_data", "user", %{
          resource_id: user.id,
          resource_name: user.username,
          ip_address: client_ip(conn),
          details: Jason.encode!(%{format: format})
        })

        respond_with_download(conn, export, user.username)

      # Only reachable for `format=plaintext`: an encrypted export needs no DEK.
      {:error, :locked} ->
        session_expired(conn)

      {:error, :user_not_found} ->
        error(conn, 404, "User not found")
    end
  end

  # --- gates ------------------------------------------------------------------

  defp target_unlocked(conn, target) do
    if unlocked?(target.id), do: :ok, else: {:error, target_locked(conn)}
  end

  # Every attempt counts against the bucket (not just failures — the export itself is what is
  # being throttled), hence `record_login_failure/2` on the `:ok` path.
  defp rate_limit(conn, identity) do
    ip = client_ip(conn)
    key = "#{@rate_prefix}:#{identity}"

    case RateLimiter.check_login(ip, key) do
      :ok ->
        RateLimiter.record_login_failure(ip, key)
        :ok

      {:error, retry_after} ->
        {:error,
         conn
         |> put_status(429)
         |> json(%{
           error: "Too many export attempts. Please try again later.",
           remainingTime: retry_after
         })}
    end
  end

  defp reauthenticated(conn, admin) do
    case get_req_header(conn, @reauth_header) do
      [password | _] when is_binary(password) and password != "" ->
        verify_reauth(conn, admin, password)

      _ ->
        {:error, refuse(conn, "Password confirmation required", "REAUTH_REQUIRED")}
    end
  end

  # The password guesses here go on the SAME `:reauth` budget as `/users/unlock-data` and
  # `/users/totp/disable`. The export's own bucket throttles the export; it does not stop an
  # attacker with a stolen admin session from guessing the admin's password through this header
  # while leaving every other password-confirmation surface untouched.
  defp verify_reauth(conn, admin, password) do
    case RateLimiter.check_reauth(admin.id) do
      {:error, retry_after} ->
        {:error,
         conn
         |> put_status(429)
         |> json(%{
           error: "Too many password confirmation attempts. Please try again later.",
           remainingTime: retry_after
         })}

      :ok ->
        do_verify_reauth(conn, admin, password)
    end
  end

  defp do_verify_reauth(conn, admin, password) do
    case Accounts.authenticate(admin.username, password) do
      {:ok, _admin} ->
        RateLimiter.reset_reauth(admin.id)
        :ok

      # An OIDC-only admin has no password to prove; cross-user export stays closed to them
      # rather than falling back to the session token that this check exists to distrust.
      {:error, :external_auth} ->
        {:error,
         refuse(
           conn,
           "Password confirmation is unavailable for externally authenticated accounts",
           "REAUTH_UNAVAILABLE"
         )}

      {:error, _reason} ->
        RateLimiter.record_reauth_failure(admin.id)

        Audit.log(admin, "admin_export_user_data", "user", %{
          ip_address: client_ip(conn),
          success: false,
          error_message: "password confirmation failed"
        })

        {:error, refuse(conn, "Password confirmation failed", "REAUTH_FAILED")}
    end
  end

  # --- helpers ----------------------------------------------------------------

  defp unlocked?(user_id), do: UserKeyManager.try_get_user_dek(user_id) != nil

  defp respond_with_download(conn, export, username) do
    conn
    |> put_resp_header(
      "content-disposition",
      ~s(attachment; filename="termelix-user-#{username}-export.json")
    )
    |> json(export)
  end

  defp target_locked(conn) do
    conn
    |> put_status(423)
    |> json(%{
      error: "Target user's data stays locked until their next login",
      code: "TARGET_DATA_LOCKED"
    })
  end

  defp session_expired(conn) do
    conn
    |> put_status(401)
    |> json(%{error: "Session expired - please log in again", code: "SESSION_EXPIRED"})
  end

  # 403 rather than 401: the session is valid, it just does not by itself authorise this. A 401
  # would make the SPA's axios interceptor tear the admin's session down.
  defp refuse(conn, message, code) do
    conn |> put_status(403) |> json(%{error: message, code: code})
  end
end
