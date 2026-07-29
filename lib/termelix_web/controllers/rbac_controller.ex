defmodule TermelixWeb.RbacController do
  @moduledoc """
  Ports the `/rbac` surface (`rbac.ts`, the roles / user-roles / host-access parts): roles CRUD,
  the permissions catalog, user-role assign / unassign / list, and host-sharing grants
  (share, list access, update, revoke, list shared-with-me).

  Admin-gated actions (roles CRUD, the permissions catalog, user-role assign/remove) require
  `conn.assigns.current_user.isAdmin`; a non-admin gets `403 {error: "Admin access required"}`.
  Host-sharing actions instead gate on `Rbac.can_manage_host_sharing/2` (owner, a live `manage`
  grant, or admin bypass).

  `list_roles/2` is the one route that is deliberately NOT admin-gated: the share modal calls
  it to populate its "grant which role" dropdown for every host owner. It scopes its response
  instead — see the comment on the action.

  Deferred (see `Termelix.Rbac`): per-recipient secret snapshots on share (grants are recorded
  without secret propagation), permission-cache invalidation, and snippet sharing.
  """
  use Phoenix.Controller, formats: [:json]

  import TermelixWeb.ControllerHelpers

  alias Termelix.Rbac

  @share_levels Rbac.share_levels()

  # --- roles ----------------------------------------------------------------

  # GET /rbac/roles
  #
  # Not admin-gated on purpose: the share modal calls this for any host owner to fill its
  # role dropdown (and swallows failures, so a blanket 403 would empty it with no error).
  # The response carries the authorization model, so it is scoped instead — an admin sees
  # every role in full, everyone else only the roles they may actually grant on a share.
  def list_roles(conn, _params) do
    roles =
      if admin?(conn) do
        Enum.map(Rbac.list_roles(), &full_role/1)
      else
        Rbac.list_roles() |> Enum.reject(&truthy(&1.isSystem)) |> Enum.map(&grantable_role/1)
      end

    json(conn, %{roles: roles})
  end

  defp full_role(r) do
    %{
      id: r.id,
      name: r.name,
      displayName: r.displayName,
      description: r.description,
      isSystem: r.isSystem,
      permissions: parse_permissions(r.permissions),
      createdAt: r.createdAt,
      updatedAt: r.updatedAt
    }
  end

  # Grantable = a non-system role: system roles are auto-assigned (see `assign_user_role/2`)
  # and the modal filters them out anyway. Only the fields the dropdown reads are returned —
  # descriptions and permission grants stay admin-only.
  defp grantable_role(r),
    do: %{id: r.id, name: r.name, displayName: r.displayName, isSystem: r.isSystem}

  # GET /rbac/permissions/catalog
  # Admin-gated by `TermelixWeb.Plugs.RequireAdmin` in the router's `:admin_access`
  # pipeline, not here. An in-action check as well would be dead code that reads like a
  # guard; `test/termelix_web/admin_pipeline_test.exs` anchors this route to that pipeline
  # so it cannot quietly lose the gate.
  def permissions_catalog(conn, _params), do: json(conn, %{catalog: Rbac.permission_catalog()})

  # POST /rbac/roles
  # Admin-gated by `TermelixWeb.Plugs.RequireAdmin` in the router's `:admin_access`
  # pipeline, not here. An in-action check as well would be dead code that reads like a
  # guard; `test/termelix_web/admin_pipeline_test.exs` anchors this route to that pipeline
  # so it cannot quietly lose the gate.
  def create_role(conn, params), do: do_create_role(conn, params)

  defp do_create_role(conn, params) do
    case Rbac.create_role(%{
           name: params["name"],
           displayName: params["displayName"],
           description: presence(params["description"]),
           permissions: nil
         }) do
      {:ok, role_id} ->
        conn
        |> put_status(201)
        |> json(%{success: true, roleId: role_id, message: "Role created successfully"})

      {:error, changeset} ->
        role_create_error(conn, changeset)
    end
  end

  # Map the changeset errors back to the exact messages the hand-rolled checks produced,
  # in the same precedence (blank name/displayName → format → duplicate).
  defp role_create_error(conn, changeset) do
    name_errors = error_messages(changeset, :name)
    display_errors = error_messages(changeset, :displayName)

    cond do
      "can't be blank" in name_errors or display_errors != [] ->
        error(conn, 400, "Role name and display name are required")

      "has invalid format" in name_errors ->
        error(
          conn,
          400,
          "Role name must contain only lowercase letters, numbers, underscores, and hyphens"
        )

      "has already been taken" in name_errors ->
        error(conn, 409, "A role with this name already exists")

      true ->
        error(conn, 400, "Role name and display name are required")
    end
  end

  defp error_messages(changeset, field) do
    changeset.errors
    |> Keyword.get_values(field)
    |> Enum.map(fn {message, _opts} -> message end)
  end

  # PUT /rbac/roles/:id
  # Admin-gated by `TermelixWeb.Plugs.RequireAdmin` in the router's `:admin_access`
  # pipeline, not here. An in-action check as well would be dead code that reads like a
  # guard; `test/termelix_web/admin_pipeline_test.exs` anchors this route to that pipeline
  # so it cannot quietly lose the gate.
  def update_role(conn, params), do: do_update_role(conn, params)

  defp do_update_role(conn, %{"id" => id} = params) do
    role_id = to_int(id)
    display_name = params["displayName"]
    has_description = Map.has_key?(params, "description")
    has_permissions = Map.has_key?(params, "permissions")
    permissions = params["permissions"]

    cond do
      is_nil(role_id) ->
        error(conn, 400, "Invalid role ID")

      not truthy(display_name) and not has_description and not has_permissions ->
        error(
          conn,
          400,
          "At least one field (displayName, description or permissions) is required"
        )

      has_permissions and not list_of_strings?(permissions) ->
        error(conn, 400, "permissions must be an array of strings")

      has_permissions and invalid_permissions(permissions) != [] ->
        conn
        |> put_status(400)
        |> json(%{error: "Unknown permissions", invalid: invalid_permissions(permissions)})

      true ->
        updates =
          %{}
          |> put_if(truthy(display_name), :displayName, display_name)
          |> put_if(has_description, :description, presence(params["description"]))
          |> put_if(has_permissions, :permissions, Jason.encode!(permissions))

        case Rbac.update_role(role_id, updates) do
          {:ok, _role} -> json(conn, %{success: true, message: "Role updated successfully"})
          {:error, :not_found} -> error(conn, 404, "Role not found")
        end
    end
  end

  # DELETE /rbac/roles/:id
  # Admin-gated by `TermelixWeb.Plugs.RequireAdmin` in the router's `:admin_access`
  # pipeline, not here. An in-action check as well would be dead code that reads like a
  # guard; `test/termelix_web/admin_pipeline_test.exs` anchors this route to that pipeline
  # so it cannot quietly lose the gate.
  def delete_role(conn, params), do: do_delete_role(conn, params)

  defp do_delete_role(conn, %{"id" => id}) do
    case to_int(id) do
      nil ->
        error(conn, 400, "Invalid role ID")

      role_id ->
        case Rbac.get_role(role_id) do
          nil ->
            error(conn, 404, "Role not found")

          %{isSystem: true} ->
            error(conn, 403, "Cannot delete system roles")

          _role ->
            Rbac.delete_role(role_id)
            json(conn, %{success: true, message: "Role deleted successfully"})
        end
    end
  end

  # --- user roles -----------------------------------------------------------

  # GET /rbac/users/:userId/roles  (self, or any user if admin)
  def list_user_roles(conn, %{"userId" => target_user_id}) do
    current = conn.assigns.current_user

    if target_user_id == current.id or truthy(current.isAdmin) do
      json(conn, %{roles: Rbac.list_user_roles(target_user_id)})
    else
      error(conn, 403, "Access denied")
    end
  end

  # POST /rbac/users/:userId/roles
  # Admin-gated by `TermelixWeb.Plugs.RequireAdmin` in the router's `:admin_access`
  # pipeline, not here. An in-action check as well would be dead code that reads like a
  # guard; `test/termelix_web/admin_pipeline_test.exs` anchors this route to that pipeline
  # so it cannot quietly lose the gate.
  def assign_user_role(conn, params), do: do_assign_user_role(conn, params)

  defp do_assign_user_role(conn, %{"userId" => target_user_id} = params) do
    role_id = params["roleId"]

    cond do
      not is_integer(role_id) ->
        error(conn, 400, "Role ID is required")

      is_nil(Rbac.get_user(target_user_id)) ->
        error(conn, 404, "User not found")

      true ->
        case Rbac.get_role(role_id) do
          nil ->
            error(conn, 404, "Role not found")

          %{isSystem: true} ->
            error(
              conn,
              403,
              "System roles (admin, user) are automatically assigned and cannot be manually assigned"
            )

          _role ->
            case Rbac.assign_role_to_user(target_user_id, role_id, conn.assigns.current_user_id) do
              :ok ->
                json(conn, %{success: true, message: "Role assigned successfully"})

              {:error, :already_assigned} ->
                error(conn, 409, "Role already assigned")
            end
        end
    end
  end

  # DELETE /rbac/users/:userId/roles/:roleId
  # Admin-gated by `TermelixWeb.Plugs.RequireAdmin` in the router's `:admin_access`
  # pipeline, not here. An in-action check as well would be dead code that reads like a
  # guard; `test/termelix_web/admin_pipeline_test.exs` anchors this route to that pipeline
  # so it cannot quietly lose the gate.
  def remove_user_role(conn, params), do: do_remove_user_role(conn, params)

  defp do_remove_user_role(conn, %{"userId" => target_user_id, "roleId" => role_id_param}) do
    case to_int(role_id_param) do
      nil ->
        error(conn, 400, "Invalid role ID")

      role_id ->
        case Rbac.get_role(role_id) do
          nil ->
            error(conn, 404, "Role not found")

          %{isSystem: true} ->
            error(
              conn,
              403,
              "System roles (admin, user) are automatically assigned and cannot be removed"
            )

          _role ->
            Rbac.remove_role_from_user(target_user_id, role_id)
            json(conn, %{success: true, message: "Role removed successfully"})
        end
    end
  end

  # --- host sharing ---------------------------------------------------------

  # POST /rbac/host/:id/share
  def share_host(conn, %{"id" => id} = params) do
    user = conn.assigns.current_user

    with {:host, host_id} when not is_nil(host_id) <- {:host, to_int(id)},
         {:targets, targets} when not is_nil(targets) <-
           {:targets, parse_share_targets(params["targets"])},
         level = Map.get(params, "permissionLevel", "connect"),
         {:level, true} <- {:level, level in @share_levels},
         {:allowed, {true, _owner}} <- {:allowed, Rbac.can_manage_host_sharing(user, host_id)},
         {:found, %{} = host} <- {:found, Rbac.get_host(host_id)},
         :ok <- validate_targets(targets, host.userId) do
      expires_at = expiry_from_duration(params["durationHours"])

      results =
        Enum.map(targets, fn t ->
          {access_id, created} =
            Rbac.upsert_host_access(%{
              hostId: host_id,
              grantedBy: user.id,
              permissionLevel: level,
              expiresAt: expires_at,
              targetType: t.type,
              targetUserId: if(t.type == :user, do: t.id),
              targetRoleId: if(t.type == :role, do: t.id)
            })

          %{type: t.type, id: t.id, accessId: access_id, created: created}
        end)

      json(conn, %{
        success: true,
        message: "Host shared successfully",
        permissionLevel: level,
        expiresAt: expires_at,
        results: results
      })
    else
      {:host, nil} ->
        error(conn, 400, "Invalid host ID")

      {:targets, nil} ->
        error(
          conn,
          400,
          "targets must be a non-empty array of { type: 'user'|'role', id } entries"
        )

      {:level, false} ->
        conn
        |> put_status(400)
        |> json(%{error: "Invalid permission level", validLevels: @share_levels})

      {:allowed, {false, _}} ->
        error(conn, 403, "You may not share this host")

      {:found, nil} ->
        error(conn, 404, "Host not found")

      {:error, status, body} ->
        conn |> put_status(status) |> json(body)
    end
  end

  # GET /rbac/host/:id/access
  def host_access_list(conn, %{"id" => id}) do
    user = conn.assigns.current_user

    case to_int(id) do
      nil ->
        error(conn, 400, "Invalid host ID")

      host_id ->
        case Rbac.can_manage_host_sharing(user, host_id) do
          {true, is_owner} ->
            json(conn, %{accessList: Rbac.list_host_access(host_id), isOwner: is_owner})

          {false, _} ->
            error(conn, 403, "You may not manage sharing on this host")
        end
    end
  end

  # PATCH /rbac/host/:id/access/:accessId
  def update_host_access(conn, %{"id" => id, "accessId" => access_id_param} = params) do
    user = conn.assigns.current_user
    host_id = to_int(id)
    access_id = to_int(access_id_param)

    cond do
      is_nil(host_id) or is_nil(access_id) ->
        error(conn, 400, "Invalid ID")

      not manage_allowed?(user, host_id) ->
        error(conn, 403, "You may not manage sharing on this host")

      true ->
        do_update_host_access(conn, host_id, access_id, params)
    end
  end

  defp do_update_host_access(conn, host_id, access_id, params) do
    has_level = Map.has_key?(params, "permissionLevel")
    has_duration = Map.has_key?(params, "durationHours")
    level = params["permissionLevel"]

    cond do
      not has_level and not has_duration ->
        error(conn, 400, "At least one of permissionLevel or durationHours is required")

      has_level and level not in @share_levels ->
        conn
        |> put_status(400)
        |> json(%{error: "Invalid permission level", validLevels: @share_levels})

      true ->
        case Rbac.find_host_access(access_id, host_id) do
          nil ->
            error(conn, 404, "Access grant not found")

          grant ->
            update =
              %{}
              |> put_if(has_level, :permissionLevel, level)
              |> put_if(has_duration, :expiresAt, expiry_from_duration(params["durationHours"]))

            Rbac.update_host_access_grant(access_id, host_id, update)

            json(conn, %{
              success: true,
              message: "Access updated",
              expiresAt: update[:expiresAt] || grant.expiresAt
            })
        end
    end
  end

  # DELETE /rbac/host/:id/access/:accessId
  def revoke_host_access(conn, %{"id" => id, "accessId" => access_id_param}) do
    user = conn.assigns.current_user
    host_id = to_int(id)
    access_id = to_int(access_id_param)

    cond do
      is_nil(host_id) or is_nil(access_id) ->
        error(conn, 400, "Invalid ID")

      not manage_allowed?(user, host_id) ->
        error(conn, 403, "You may not manage sharing on this host")

      true ->
        Rbac.revoke_host_access(access_id, host_id)
        json(conn, %{success: true, message: "Access revoked"})
    end
  end

  # GET /rbac/shared-hosts
  def shared_hosts(conn, _params) do
    user_id = conn.assigns.current_user_id
    role_ids = Rbac.list_user_role_ids(user_id)
    json(conn, %{sharedHosts: Rbac.list_shared_hosts(user_id, role_ids)})
  end

  # --- share-target parsing / validation ------------------------------------

  # A non-empty array of {type: "user", id: <non-empty string>} | {type: "role", id: <integer>}.
  defp parse_share_targets(targets) when is_list(targets) and targets != [] do
    parsed =
      Enum.reduce_while(targets, [], fn
        %{"type" => "user", "id" => id}, acc when is_binary(id) ->
          if String.trim(id) != "",
            do: {:cont, [%{type: :user, id: id} | acc]},
            else: {:halt, nil}

        %{"type" => "role", "id" => id}, acc when is_integer(id) ->
          {:cont, [%{type: :role, id: id} | acc]}

        _, _ ->
          {:halt, nil}
      end)

    if parsed, do: Enum.reverse(parsed), else: nil
  end

  defp parse_share_targets(_), do: nil

  # Returns :ok or {:error, status, body}; stops on the first offending target (as Node does).
  defp validate_targets(targets, owner_id) do
    Enum.reduce_while(targets, :ok, fn target, :ok ->
      case check_target(target, owner_id) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp check_target(%{type: :user, id: id}, owner_id) do
    cond do
      id == owner_id -> {:error, 400, %{error: "Cannot share a host with its owner"}}
      is_nil(Rbac.get_user(id)) -> {:error, 404, %{error: "Target user not found", targetId: id}}
      true -> :ok
    end
  end

  defp check_target(%{type: :role, id: id}, _owner_id) do
    if is_nil(Rbac.get_role(id)),
      do: {:error, 404, %{error: "Target role not found", targetId: id}},
      else: :ok
  end

  # --- helpers --------------------------------------------------------------

  defp manage_allowed?(user, host_id) do
    match?({true, _}, Rbac.can_manage_host_sharing(user, host_id))
  end

  defp parse_permissions(perms) when is_binary(perms) and perms != "" do
    case Jason.decode(perms) do
      {:ok, list} when is_list(list) -> list
      _ -> []
    end
  end

  defp parse_permissions(_), do: []

  defp list_of_strings?(v), do: is_list(v) and Enum.all?(v, &is_binary/1)

  defp invalid_permissions(perms), do: Enum.reject(perms, &Rbac.valid_permission?/1)

  # new Date(now + durationHours h).toISOString() when durationHours is a positive number; else null.
  defp expiry_from_duration(hours) when is_number(hours) and hours > 0 do
    DateTime.utc_now() |> DateTime.add(round(hours * 3600), :second) |> DateTime.to_iso8601()
  end

  defp expiry_from_duration(_), do: nil

  defp put_if(map, true, key, value), do: Map.put(map, key, value)
  defp put_if(map, false, _key, _value), do: map

  defp admin?(conn), do: truthy(conn.assigns.current_user.isAdmin)

  defp presence(v), do: if(present?(v), do: v)

  defp to_int(id) when is_integer(id), do: id

  defp to_int(id) when is_binary(id) do
    case Integer.parse(id) do
      {n, _} -> n
      :error -> nil
    end
  end

  defp to_int(_), do: nil

  # JS `!!string`: non-nil, non-empty (whitespace counts as present).
  defp present?(v) when is_binary(v), do: v != ""
  defp present?(_), do: false

  defp truthy(nil), do: false
  defp truthy(false), do: false
  defp truthy(""), do: false
  defp truthy(_), do: true
end
