defmodule Termelix.Rbac do
  @moduledoc """
  RBAC + host sharing. Ports `rbac.ts` together with `role-repository.ts` and
  `rbac-access-repository.ts` (the roles / user-roles / host-access surface).

  Data model: `roles` (with a JSON-string `permissions` column), `user_roles`
  ((user, role) assignments), and `host_access` (a permission-level grant on a host to a
  user or a role). Timestamps are written as ISO-8601 strings, matching the rest of the port.

  Deferred (noted, not implemented here):
    * Per-recipient secret snapshots — the Node share path calls `SharedHostSecretsManager`
      to re-encrypt the host's secrets for each recipient so a shared host is actually
      connectable. Grants are recorded here without that propagation; connecting to a shared
      host will land with the shared-secrets subsystem.
    * Permission-cache invalidation — Node keeps an in-process permission cache and busts it
      on role edits/assignments. There is no such cache in the port, so nothing to invalidate.
    * Snippet sharing (`snippet_access`) — a separate subsystem; not part of this task.
  """
  import Ecto.Query, only: [from: 2, dynamic: 2]

  alias Termelix.Hosts
  alias Termelix.Repo
  alias Termelix.Schema.{Role, UserRole, HostAccess, Host, User}

  @share_levels ~w(connect view edit manage)
  @level_rank %{"connect" => 1, "view" => 2, "edit" => 3, "manage" => 4}

  # Single source of truth for role permission strings (ports permission-catalog.ts). The
  # role editor renders this and role updates validate against it; wildcards `*` and
  # `<group>.*` are accepted.
  @permission_catalog [
    %{
      group: "hosts",
      permissions: ~w(hosts.view hosts.create hosts.edit hosts.delete hosts.share)
    },
    %{
      group: "snippets",
      permissions: ~w(snippets.view snippets.create snippets.edit snippets.delete snippets.share)
    },
    %{
      group: "credentials",
      permissions: ~w(credentials.view credentials.create credentials.edit credentials.delete)
    },
    %{
      group: "admin",
      permissions:
        ~w(admin.users.view admin.users.manage admin.roles.manage admin.settings.manage admin.sessions.manage)
    }
  ]

  @valid_permissions @permission_catalog
                     |> Enum.flat_map(fn %{group: g, permissions: ps} -> ["#{g}.*" | ps] end)
                     |> then(&["*" | &1])
                     |> MapSet.new()

  @doc "The grouped permission catalog (for `GET /rbac/permissions/catalog`)."
  def permission_catalog, do: @permission_catalog

  @doc "The share permission levels, lowest-to-highest privilege."
  def share_levels, do: @share_levels

  @doc "Whether a permission string is known (a catalog entry or an accepted wildcard)."
  @spec valid_permission?(term()) :: boolean()
  def valid_permission?(perm) when is_binary(perm), do: MapSet.member?(@valid_permissions, perm)
  def valid_permission?(_), do: false

  # --- roles ----------------------------------------------------------------

  @doc "All roles, system roles then by name (matches the Node ordering)."
  @spec list_roles() :: [Role.t()]
  def list_roles, do: Repo.all(from r in Role, order_by: [asc: r.isSystem, asc: r.name])

  @spec get_role(integer() | nil) :: Role.t() | nil
  def get_role(nil), do: nil
  def get_role(id), do: Repo.get(Role, id)

  @spec get_role_by_name(String.t()) :: Role.t() | nil
  def get_role_by_name(name), do: Repo.get_by(Role, name: name)

  @doc """
  Insert a role. `attrs` carries `name`, `displayName`, `description`, `permissions`.
  Validation runs through `Role.changeset/2`; the `roles.name` UNIQUE constraint turns the
  create race into `{:error, changeset}` (with `has already been taken` on `:name`) instead
  of a crash or a duplicate. Returns `{:ok, role_id}` or `{:error, changeset}`.
  """
  @spec create_role(map()) :: {:ok, integer()} | {:error, Ecto.Changeset.t()}
  def create_role(attrs) do
    now = iso_now()

    %Role{}
    |> Role.changeset(%{
      name: attrs.name,
      displayName: attrs.displayName,
      description: attrs.description,
      isSystem: false,
      permissions: attrs.permissions,
      createdAt: now,
      updatedAt: now
    })
    |> Repo.insert()
    |> case do
      {:ok, role} -> {:ok, role.id}
      {:error, changeset} -> {:error, changeset}
    end
  end

  @doc """
  Apply the already-shaped `updates` (a map of camelCase field atoms) to a role, always
  bumping `updatedAt`. Returns `{:ok, role}`, or `{:error, :not_found}` when the role does
  not exist (replacing the controller's check-then-update race).
  """
  @spec update_role(integer(), map()) ::
          {:ok, Role.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_role(role_id, updates) do
    case get_role(role_id) do
      nil ->
        {:error, :not_found}

      %Role{} = role ->
        role
        |> Role.update_changeset(Map.put(updates, :updatedAt, iso_now()))
        |> Repo.update()
    end
  end

  @doc "Delete a role and cascade its user_roles / host_access rows (as Node's deleteRole does)."
  @spec delete_role(integer()) :: :ok
  def delete_role(role_id) do
    Repo.delete_all(from ur in UserRole, where: ur.roleId == ^role_id)
    Repo.delete_all(from ha in HostAccess, where: ha.roleId == ^role_id)
    Repo.delete_all(from r in Role, where: r.id == ^role_id)
    :ok
  end

  # --- user roles -----------------------------------------------------------

  @spec find_user_role(String.t(), integer()) :: UserRole.t() | nil
  def find_user_role(user_id, role_id),
    do: Repo.get_by(UserRole, userId: user_id, roleId: role_id)

  @doc """
  Assign a role to a user. The (user_id, role_id) unique index turns the assign race into
  `{:error, :already_assigned}` (→ the route's 409) instead of a duplicate row.
  """
  @spec assign_role_to_user(String.t(), integer(), String.t()) ::
          :ok | {:error, :already_assigned | Ecto.Changeset.t()}
  def assign_role_to_user(user_id, role_id, granted_by) do
    %UserRole{}
    |> UserRole.changeset(%{
      userId: user_id,
      roleId: role_id,
      grantedBy: granted_by,
      grantedAt: iso_now()
    })
    |> Repo.insert()
    |> case do
      {:ok, _} ->
        :ok

      {:error, changeset} ->
        if unique_violation?(changeset, :userId),
          do: {:error, :already_assigned},
          else: {:error, changeset}
    end
  end

  @spec remove_role_from_user(String.t(), integer()) :: :ok
  def remove_role_from_user(user_id, role_id) do
    Repo.delete_all(from ur in UserRole, where: ur.userId == ^user_id and ur.roleId == ^role_id)
    :ok
  end

  @doc "A user's roles joined to role details (shape of Node's `listUserRoles`)."
  @spec list_user_roles(String.t()) :: [map()]
  def list_user_roles(user_id) do
    Repo.all(
      from ur in UserRole,
        join: r in Role,
        on: ur.roleId == r.id,
        where: ur.userId == ^user_id,
        select: %{
          id: ur.id,
          roleId: r.id,
          roleName: r.name,
          roleDisplayName: r.displayName,
          description: r.description,
          isSystem: r.isSystem,
          grantedAt: ur.grantedAt
        }
    )
  end

  @spec list_user_role_ids(String.t()) :: [integer()]
  def list_user_role_ids(user_id),
    do: Repo.all(from ur in UserRole, where: ur.userId == ^user_id, select: ur.roleId)

  # --- users / hosts (lookups the share path needs) -------------------------

  @spec get_user(String.t() | nil) :: User.t() | nil
  def get_user(nil), do: nil
  def get_user(id), do: Repo.get(User, id)

  @doc "A host by id regardless of owner (Node's `findHostUpdateState`)."
  @spec get_host(integer()) :: Host.t() | nil
  def get_host(host_id), do: Repo.get(Host, host_id)

  # --- host access ----------------------------------------------------------

  @doc """
  Whether `user` may manage sharing on a host (owner, a live `manage` grant, or admin bypass).
  Returns `{allowed?, is_owner?}` — ports `canManageHostSharing` → `canAccessHost(.., "manage")`.
  Admin bypass grants access but is NOT ownership (`is_owner?` stays false), matching Node.
  """
  @spec can_manage_host_sharing(User.t(), integer()) :: {boolean(), boolean()}
  def can_manage_host_sharing(%User{} = user, host_id) do
    cond do
      host_owned_by?(host_id, user.id) ->
        {true, true}

      true ->
        role_ids = list_user_role_ids(user.id)

        case find_active_host_access(host_id, user.id, role_ids) do
          %HostAccess{permissionLevel: level} ->
            if level_rank(level) >= level_rank("manage"),
              do: {true, false},
              else: {admin?(user), false}

          nil ->
            {admin?(user), false}
        end
    end
  end

  @doc "The access list for a host (users + roles), newest first — shape of `RbacAccessListItem`."
  @spec list_host_access(integer()) :: [map()]
  def list_host_access(host_id) do
    from(ha in HostAccess,
      left_join: u in User,
      on: ha.userId == u.id,
      left_join: r in Role,
      on: ha.roleId == r.id,
      left_join: gb in User,
      on: ha.grantedBy == gb.id,
      where: ha.hostId == ^host_id,
      order_by: [desc: ha.createdAt],
      select: %{
        id: ha.id,
        userId: ha.userId,
        roleId: ha.roleId,
        username: u.username,
        roleName: r.name,
        roleDisplayName: r.displayName,
        grantedBy: ha.grantedBy,
        grantedByUsername: gb.username,
        permissionLevel: ha.permissionLevel,
        expiresAt: ha.expiresAt,
        createdAt: ha.createdAt
      }
    )
    |> Repo.all()
    |> Enum.map(fn row ->
      Map.put(row, :targetType, if(row.userId, do: "user", else: "role"))
    end)
  end

  @doc """
  Create-or-update a grant for a target. `input` carries `hostId`, `grantedBy`,
  `permissionLevel`, `expiresAt`, and either `{targetType: :user, targetUserId}` or
  `{targetType: :role, targetRoleId}`. Returns `{access_id, created?}`.
  """
  @spec upsert_host_access(map()) :: {integer(), boolean()}
  def upsert_host_access(input) do
    case find_host_access_by_target(input) do
      %HostAccess{id: id} ->
        Repo.update_all(from(ha in HostAccess, where: ha.id == ^id),
          set: [permissionLevel: input.permissionLevel, expiresAt: input.expiresAt]
        )

        {id, false}

      nil ->
        {user_id, role_id} =
          case input.targetType do
            :user -> {input.targetUserId, nil}
            :role -> {nil, input.targetRoleId}
          end

        row =
          Repo.insert!(%HostAccess{
            hostId: input.hostId,
            userId: user_id,
            roleId: role_id,
            grantedBy: input.grantedBy,
            permissionLevel: input.permissionLevel,
            expiresAt: input.expiresAt,
            createdAt: iso_now(),
            accessCount: 0
          })

        {row.id, true}
    end
  end

  @spec find_host_access(integer(), integer()) :: HostAccess.t() | nil
  def find_host_access(access_id, host_id),
    do: Repo.get_by(HostAccess, id: access_id, hostId: host_id)

  @doc "Apply `update` (map of camelCase field atoms) to a grant scoped by id + host."
  @spec update_host_access_grant(integer(), integer(), map()) :: :ok
  def update_host_access_grant(access_id, host_id, update) do
    Repo.update_all(
      from(ha in HostAccess, where: ha.id == ^access_id and ha.hostId == ^host_id),
      set: Map.to_list(update)
    )

    :ok
  end

  @spec revoke_host_access(integer(), integer()) :: :ok
  def revoke_host_access(access_id, host_id) do
    Repo.delete_all(from ha in HostAccess, where: ha.id == ^access_id and ha.hostId == ^host_id)
    :ok
  end

  @doc """
  Hosts shared with the user (directly or via a role), non-expired, newest first.

  `port` is the *effective SSH* port, not the raw column: a row left behind by the removed
  remote-desktop feature stores 3389/5900/23 in `port` and the real SSH port in `ssh_port`.
  The select is DB-side, so `connectionType`/`sshPort` are fetched only to feed
  `Hosts.effective_ssh_port/1` and are dropped again — the shape the recipient sees is
  unchanged.
  """
  @spec list_shared_hosts(String.t(), [integer()]) :: [map()]
  def list_shared_hosts(user_id, role_ids) do
    now = iso_now()

    from(ha in HostAccess,
      join: h in Host,
      on: ha.hostId == h.id,
      join: u in User,
      on: h.userId == u.id,
      where: ^active_access_filter(user_id, role_ids, now),
      order_by: [desc: ha.createdAt],
      select: %{
        id: h.id,
        name: h.name,
        ip: h.ip,
        port: h.port,
        connectionType: h.connectionType,
        sshPort: h.sshPort,
        username: h.username,
        folder: h.folder,
        tags: h.tags,
        permissionLevel: ha.permissionLevel,
        expiresAt: ha.expiresAt,
        grantedBy: ha.grantedBy,
        ownerUsername: u.username
      }
    )
    |> Repo.all()
    |> Enum.map(fn row ->
      row
      |> Map.put(:port, Hosts.effective_ssh_port(row))
      |> Map.drop([:connectionType, :sshPort])
    end)
  end

  # --- internals ------------------------------------------------------------

  defp host_owned_by?(host_id, user_id),
    do: Repo.exists?(from h in Host, where: h.id == ^host_id and h.userId == ^user_id)

  # The Node port treats a user with the DB `isAdmin` flag as admin. Node additionally honors
  # the `admin`/`super_admin` role names; that role-name path is deferred with the wider
  # permission-manager work.
  defp admin?(%User{isAdmin: true}), do: true
  defp admin?(_), do: false

  defp find_active_host_access(host_id, user_id, role_ids) do
    filter = active_access_filter(user_id, role_ids, iso_now())

    Repo.one(
      from ha in HostAccess,
        where: ha.hostId == ^host_id,
        where: ^filter,
        limit: 1
    )
  end

  defp find_host_access_by_target(%{targetType: :user, targetUserId: uid, hostId: host_id}),
    do:
      Repo.one(
        from ha in HostAccess, where: ha.hostId == ^host_id and ha.userId == ^uid, limit: 1
      )

  defp find_host_access_by_target(%{targetType: :role, targetRoleId: rid, hostId: host_id}),
    do:
      Repo.one(
        from ha in HostAccess, where: ha.hostId == ^host_id and ha.roleId == ^rid, limit: 1
      )

  # "granted to this user or one of their roles" AND "not expired".
  defp active_access_filter(user_id, role_ids, now) do
    scope =
      if role_ids == [] do
        dynamic([ha], ha.userId == ^user_id)
      else
        dynamic([ha], ha.userId == ^user_id or ha.roleId in ^role_ids)
      end

    dynamic([ha], ^scope and (is_nil(ha.expiresAt) or ha.expiresAt >= ^now))
  end

  defp level_rank(level), do: Map.get(@level_rank, level, 0)

  # Whether the changeset failed on the unique constraint covering `field`.
  defp unique_violation?(changeset, field) do
    Enum.any?(changeset.errors, fn
      {^field, {"has already been taken", _}} -> true
      _ -> false
    end)
  end

  defp iso_now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
