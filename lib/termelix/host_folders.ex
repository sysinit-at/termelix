defmodule Termelix.HostFolders do
  @moduledoc """
  SSH host folder (`ssh_folders`) access for a user — the Elixir port of
  `host-folder-repository.ts`.

  Folders are hierarchical: a nested folder is stored as the path `"parent / child"`, so a
  rename or delete of `"parent"` also has to move/remove every `"parent / %"` descendant. The
  same folder path also lives inline on `ssh_data.folder` and `ssh_credentials.folder`, so a
  rename fans out across all three tables (matching the Node repository).

  All reads and writes are scoped to the owning `userId` (ownership enforced in every query).
  As in `Termelix.Hosts.delete_host`, deleting a folder's hosts does not fan out to the
  dependent tables (bookmarks, transfers, command history, …) or notify the stats server —
  that cascade/RBAC cleanup is deferred with the rest of the breadth work.

  Timestamps use `DateTime.to_iso8601/1` to match the Node repository's `new Date().toISOString()`.
  """
  import Ecto.Query, only: [from: 2]

  alias Termelix.Repo
  alias Termelix.Schema.{Host, SshCredential, SshFolder}

  @doc "All of a user's SSH host folders (ownership enforced), ordered by id."
  @spec list_folders(String.t()) :: [SshFolder.t()]
  def list_folders(user_id) do
    Repo.all(from f in SshFolder, where: f.userId == ^user_id, order_by: [asc: f.id])
  end

  @doc """
  Insert or update a folder's metadata (color/icon). When the folder does not exist it is
  created; when it does, only the color/icon keys present in `params` are written (mirroring
  drizzle's undefined-skip). `updatedAt` is always bumped. Returns `{folder, created?}`.
  """
  @spec upsert_metadata(String.t(), String.t(), map()) :: {SshFolder.t(), boolean()}
  def upsert_metadata(user_id, name, params) do
    case find_folder(user_id, name) do
      nil ->
        now = iso_now()

        folder =
          Repo.insert!(
            SshFolder.changeset(%SshFolder{}, %{
              userId: user_id,
              name: name,
              color: params["color"],
              icon: params["icon"],
              createdAt: now,
              updatedAt: now
            })
          )

        {folder, true}

      %SshFolder{} = existing ->
        changes =
          %{updatedAt: iso_now()}
          |> put_if_present(params, "color")
          |> put_if_present(params, "icon")

        {existing |> Ecto.Changeset.change(changes) |> Repo.update!(), false}
    end
  end

  @doc """
  Rename a folder for the user, fanning the rename out across the folder's own row, its
  descendants (`"oldName / %"`), and the inline `folder` column on hosts and credentials. The
  exact match becomes `newName`; a descendant's `"oldName / "` prefix becomes `"newName / "`.
  Returns `%{updated_hosts: n, updated_credentials: n}` (the counts the Node route echoes).
  """
  @spec rename_folder(String.t(), String.t(), String.t()) ::
          %{updated_hosts: non_neg_integer(), updated_credentials: non_neg_integer()}
  def rename_folder(user_id, old_name, new_name) do
    now = iso_now()
    old_prefix = old_name <> " / "
    child_like = old_prefix <> "%"
    new_prefix = new_name <> " / "
    # substr/2 is 1-indexed; start just past the "oldName / " prefix.
    offset = String.length(old_prefix) + 1

    {updated_hosts, _} =
      from(h in Host,
        where: h.userId == ^user_id and (h.folder == ^old_name or like(h.folder, ^child_like)),
        update: [
          set: [
            folder:
              fragment(
                "CASE WHEN ? = ? THEN ? ELSE ? || substr(?, ?) END",
                h.folder,
                ^old_name,
                ^new_name,
                ^new_prefix,
                h.folder,
                ^offset
              ),
            updatedAt: ^now
          ]
        ]
      )
      |> Repo.update_all([])

    {updated_credentials, _} =
      from(c in SshCredential,
        where: c.userId == ^user_id and (c.folder == ^old_name or like(c.folder, ^child_like)),
        update: [
          set: [
            folder:
              fragment(
                "CASE WHEN ? = ? THEN ? ELSE ? || substr(?, ?) END",
                c.folder,
                ^old_name,
                ^new_name,
                ^new_prefix,
                c.folder,
                ^offset
              ),
            updatedAt: ^now
          ]
        ]
      )
      |> Repo.update_all([])

    from(f in SshFolder,
      where: f.userId == ^user_id and (f.name == ^old_name or like(f.name, ^child_like)),
      update: [
        set: [
          name:
            fragment(
              "CASE WHEN ? = ? THEN ? ELSE ? || substr(?, ?) END",
              f.name,
              ^old_name,
              ^new_name,
              ^new_prefix,
              f.name,
              ^offset
            ),
          updatedAt: ^now
        ]
      ]
    )
    |> Repo.update_all([])

    %{updated_hosts: updated_hosts, updated_credentials: updated_credentials}
  end

  @doc """
  Delete every host in a folder (the folder itself and its `"folderName / %"` descendants),
  then delete the matching `ssh_folders` rows. Ownership enforced. Returns the number of
  hosts deleted (the `deletedCount` the frontend expects).
  """
  @spec delete_folder_hosts(String.t(), String.t()) :: non_neg_integer()
  def delete_folder_hosts(user_id, folder_name) do
    child_like = folder_name <> " / %"

    {count, _} =
      Repo.delete_all(
        from h in Host,
          where:
            h.userId == ^user_id and (h.folder == ^folder_name or like(h.folder, ^child_like))
      )

    Repo.delete_all(
      from f in SshFolder,
        where: f.userId == ^user_id and (f.name == ^folder_name or like(f.name, ^child_like))
    )

    count
  end

  # --- helpers --------------------------------------------------------------

  defp find_folder(user_id, name) do
    Repo.one(from f in SshFolder, where: f.userId == ^user_id and f.name == ^name, limit: 1)
  end

  defp put_if_present(changes, params, key) do
    if Map.has_key?(params, key) do
      Map.put(changes, String.to_existing_atom(key), params[key])
    else
      changes
    end
  end

  defp iso_now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
