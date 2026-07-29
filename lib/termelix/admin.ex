defmodule Termelix.Admin do
  @moduledoc """
  Admin-only user-management queries — the data-layer side of `user-admin-routes.ts` and the
  `/users/delete-user` handler in `users.ts`.

  User creation lives in `Termelix.Accounts` (`admin_create_user/2`); this module adds the
  listing, admin-flag toggle, admin-count guard, and the cascading full deletion
  (`delete-user-data.ts`).
  """
  import Ecto.Query, only: [from: 2]

  alias Termelix.Repo
  alias Termelix.Schema.{User, Setting}
  alias Termelix.Crypto.UserKeyManager

  @doc "Every user, ordered by username."
  @spec list_users() :: [User.t()]
  def list_users, do: Repo.all(from(u in User, order_by: [asc: u.username]))

  @doc "Set (or clear) a user's admin flag."
  @spec set_admin(User.t(), boolean()) :: {:ok, User.t()} | {:error, Ecto.Changeset.t()}
  def set_admin(%User{} = user, is_admin?) do
    user |> Ecto.Changeset.change(isAdmin: is_admin?) |> Repo.update()
  end

  @doc "Number of admin users (guards last-admin deletion)."
  @spec count_admins() :: non_neg_integer()
  def count_admins, do: Repo.aggregate(from(u in User, where: u.isAdmin == true), :count, :id)

  @doc """
  Whether the server can currently decrypt this user's data — the port's analogue of
  `DataCrypto.canUserAccessData` / `AuthManager.isUserUnlocked`. Because the v3 DEK is
  system-wrapped (not password-derived), this is true whenever a DEK exists.
  """
  @spec data_unlocked?(String.t()) :: boolean()
  def data_unlocked?(user_id), do: UserKeyManager.try_get_user_dek(user_id) != nil

  @doc """
  Delete a user and all data that belongs to them (`deleteUserAndRelatedData`).

  Rows in FK tables (`sessions`, `ssh_data`, `ssh_credentials`, roles, …) are removed by
  SQLite `ON DELETE CASCADE`. Audit rows are handled explicitly via
  `Termelix.Audit.delete_by_user_id/1` — their FK is `ON DELETE SET NULL` so consent
  records can outlive the actor: the user's ordinary audit trail is erased as before,
  while consent rows are anonymized and retained. The `settings` table has no FK, so its
  per-user rows (the wrapped DEK, legacy wraps, and `user_%_<id>` preferences) are deleted
  explicitly, and the cached DEK is invalidated.
  """
  @spec delete_user_and_related_data(String.t()) :: :ok
  def delete_user_and_related_data(user_id) do
    # First sweep: stop the bleeding while the rows still exist.
    Termelix.Revocation.revoke_user(user_id, :user_deleted)

    Repo.delete_all(from(s in Setting, where: like(s.key, ^"user_%_#{user_id}")))
    Termelix.Audit.delete_by_user_id(user_id)
    UserKeyManager.invalidate(user_id)

    result =
      case Repo.get(User, user_id) do
        nil -> :ok
        %User{} = user -> Repo.delete!(user) && :ok
      end

    # Second sweep, and the one that actually closes the hole. Between the first sweep and
    # here the account was still valid, so an in-flight request could check out a fresh pooled
    # connection or open a tunnel against rows that had not been deleted yet — revocation
    # would have reported success while a connection it had just closed came back. Only after
    # the rows are gone is there nothing left to re-authorize with. Idempotent, so the common
    # case (nothing recreated) costs two empty registry selects.
    Termelix.Revocation.revoke_user(user_id, :user_deleted)

    result
  end
end
