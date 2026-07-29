defmodule TermelixWeb.AdminController do
  @moduledoc """
  Ports the admin user-management surface: the listing (`/users/list`), admin flag toggles
  (`/users/make-admin`, `/users/remove-admin`), admin-create (`/users/admin-create`), the
  count (`/users/count`) and the cascading delete (`/users/delete-user`) from
  `user-admin-routes.ts` + `users.ts`.

  `/users/list` is authenticated but *not* admin-gated — regular users hit it to pick sharing
  targets — so management-only fields (`data_unlocked`, `totp_enabled`) are added only when the
  requester is an admin. Every other action is gated by `TermelixWeb.Plugs.RequireAdmin` in the
  router: the mutations answer `403 {error: "Not authorized"}`, the count/error-reporting scope
  `403 {error: "Admin access required"}` (matching Node). Successful admin mutations are written
  to the audit trail.
  """
  use Phoenix.Controller, formats: [:json]

  import Plug.Conn
  import TermelixWeb.ControllerHelpers, only: [client_ip: 1]

  alias Termelix.{Accounts, Admin, Audit}

  # GET /users/list  (authenticated; admin-only fields added for admin requesters)
  def list(conn, _params) do
    requester = conn.assigns.current_user
    admin? = requester.isAdmin == true

    users =
      Enum.map(Admin.list_users(), fn u ->
        base = %{
          userId: u.id,
          username: u.username,
          is_admin: u.isAdmin,
          is_oidc: u.isOidc,
          password_hash: if(present?(u.passwordHash), do: "set", else: nil)
        }

        if admin? do
          Map.merge(base, %{
            data_unlocked: Admin.data_unlocked?(u.id),
            totp_enabled: u.totpEnabled == true
          })
        else
          base
        end
      end)

    json(conn, %{users: users})
  end

  # GET /users/count  (admin only, :admin_access pipeline)
  def count(conn, _params), do: json(conn, %{count: Accounts.user_count()})

  # GET /users/error-reporting  (admin only) — the Sentry opt-in state.
  def error_reporting_status(conn, _params), do: json(conn, Termelix.ErrorReporting.status())

  # POST /users/error-reporting  body {enabled: bool}  (admin only) — opt in or out; also
  # answers the first-admin-login prompt (any decision clears it for every admin). The
  # consent change and its audit row are one transaction (`record_decision/3`): if the
  # audit row cannot be written, the change is rolled back and the request fails.
  def set_error_reporting(conn, params) do
    if is_boolean(params["enabled"]) do
      conn.assigns.current_user
      |> Termelix.ErrorReporting.record_decision(params["enabled"], request_meta(conn))
      |> case do
        {:ok, status} -> json(conn, status)
        {:error, _reason} -> error(conn, 500, "Failed to record the consent change")
      end
    else
      error(conn, 400, "enabled must be a boolean")
    end
  end

  # POST /users/make-admin
  def make_admin(conn, params) do
    with {:ok, {id, username}} <- resolve_identifier(params),
         %{} = target <- fetch_target(id, username) do
      cond do
        target.isAdmin == true ->
          error(conn, 400, "User is already an admin")

        true ->
          {:ok, updated} = Admin.set_admin(target, true)
          audit(conn, "make_admin", updated)
          json(conn, %{message: "User #{updated.username} is now an admin"})
      end
    else
      {:error, :missing_identifier} -> error(conn, 400, "User ID or username is required")
      nil -> error(conn, 404, "User not found")
    end
  end

  # POST /users/remove-admin
  def remove_admin(conn, params) do
    admin_user = conn.assigns.current_user

    with {:ok, {id, username}} <- resolve_identifier(params),
         :ok <- refuse_self(admin_user, id, username),
         %{} = target <- fetch_target(id, username) do
      cond do
        target.isAdmin != true ->
          error(conn, 400, "User is not an admin")

        true ->
          {:ok, updated} = Admin.set_admin(target, false)
          audit(conn, "remove_admin", updated)
          json(conn, %{message: "Admin status removed from #{updated.username}"})
      end
    else
      {:error, :missing_identifier} -> error(conn, 400, "User ID or username is required")
      {:error, :self} -> error(conn, 400, "Cannot remove your own admin status")
      nil -> error(conn, 404, "User not found")
    end
  end

  # POST /users/admin-create
  def admin_create(conn, params) do
    case Accounts.admin_create_user(params["username"], params["password"]) do
      {:ok, user} ->
        audit(conn, "create_user", user)

        json(conn, %{
          message: "User created",
          toast: %{type: "success", message: "User created: #{user.username}"}
        })

      {:error, :missing_fields} ->
        error(conn, 400, "Username and password are required")

      {:error, :username_taken} ->
        error(conn, 409, "Username already exists")

      {:error, :encryption_setup_failed} ->
        error(conn, 500, "Failed to setup user security - user creation cancelled")

      {:error, _} ->
        error(conn, 500, "Failed to create user")
    end
  end

  # DELETE /users/delete-user
  def delete_user(conn, params) do
    admin_user = conn.assigns.current_user
    username = params["username"]

    with :ok <- require_username(username),
         :ok <- refuse_self_delete(admin_user, username),
         %{} = target <- Accounts.get_user_by_username(username),
         :ok <- guard_last_admin(target) do
      Admin.delete_user_and_related_data(target.id)
      audit(conn, "delete_user", target)
      json(conn, %{message: "User #{username} deleted successfully"})
    else
      {:error, :missing_username} -> error(conn, 400, "Username is required")
      {:error, :self} -> error(conn, 400, "Cannot delete your own account")
      {:error, :last_admin} -> error(conn, 403, "Cannot delete the last admin user")
      nil -> error(conn, 404, "User not found")
    end
  end

  # --- guards ----------------------------------------------------------------

  defp resolve_identifier(params) do
    id = trimmed(params["userId"])
    username = trimmed(params["username"])

    if id || username, do: {:ok, {id, username}}, else: {:error, :missing_identifier}
  end

  defp require_username(username) do
    if nonblank?(username), do: :ok, else: {:error, :missing_username}
  end

  # make/remove-admin identify the target by id first, else username (`getUserByPreferredIdentifier`).
  defp fetch_target(id, _username) when is_binary(id), do: Accounts.get_user(id)

  defp fetch_target(_id, username) when is_binary(username),
    do: Accounts.get_user_by_username(username)

  defp refuse_self(admin_user, id, username) do
    if (id && admin_user.id == id) or (username && admin_user.username == username),
      do: {:error, :self},
      else: :ok
  end

  defp refuse_self_delete(admin_user, username) do
    if admin_user.username == username, do: {:error, :self}, else: :ok
  end

  defp guard_last_admin(%{isAdmin: true}) do
    if Admin.count_admins() <= 1, do: {:error, :last_admin}, else: :ok
  end

  defp guard_last_admin(_target), do: :ok

  # --- audit -----------------------------------------------------------------

  defp audit(conn, action, target) do
    meta =
      conn
      |> request_meta()
      |> Map.merge(%{resource_id: target.id, resource_name: target.username})

    Audit.log(conn.assigns.current_user, action, "user", meta)
  end

  defp request_meta(conn) do
    %{
      ip_address: client_ip(conn),
      user_agent: header(conn, "user-agent", "")
    }
  end

  defp header(conn, name, default) do
    case get_req_header(conn, name) do
      [v | _] -> v
      _ -> default
    end
  end

  # --- small value helpers ---------------------------------------------------

  defp trimmed(v) when is_binary(v) do
    case String.trim(v) do
      "" -> nil
      t -> t
    end
  end

  defp trimmed(_), do: nil

  defp nonblank?(v) when is_binary(v), do: String.trim(v) != ""
  defp nonblank?(_), do: false

  defp present?(v) when is_binary(v), do: v != ""
  defp present?(_), do: false

  defp error(conn, status, message), do: conn |> put_status(status) |> json(%{error: message})
end
