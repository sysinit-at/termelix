defmodule Termelix.FileManagerMeta do
  @moduledoc """
  File-manager metadata (recent / pinned / shortcuts) for a user — the Elixir port of
  `file-manager-bookmark-repository.ts`. Every read and write is scoped to the owning user
  (ownership is enforced in every query); a body `userId` is never trusted.

  `recent` is upsert-on-(user,host,path): re-opening a file bumps its `lastOpened` rather than
  inserting a duplicate — this is the "open recording" path. `pinned` and `shortcuts` are
  create-if-absent: a duplicate (user,host,path) is rejected (`:exists` → 409 upstream).

  Timestamp fields are written as JS-style ISO 8601 strings (matching the Node repository's
  `new Date().toISOString()`), so the `desc` ordering on those text columns stays a
  like-for-like chronological string comparison.
  """
  import Ecto.Query, only: [from: 2]

  alias Termelix.Repo
  alias Termelix.Schema.{FileManagerRecent, FileManagerPinned, FileManagerShortcut}

  @default_recent_limit 20

  # --- recent ---------------------------------------------------------------

  @doc "The user's recent files for a host, newest first, capped at `limit` (default 20)."
  @spec list_recent(String.t(), integer(), pos_integer()) :: [FileManagerRecent.t()]
  def list_recent(user_id, host_id, limit \\ @default_recent_limit) do
    Repo.all(
      from r in FileManagerRecent,
        where: r.userId == ^user_id and r.hostId == ^host_id,
        order_by: [desc: r.lastOpened],
        limit: ^limit
    )
  end

  @doc """
  Record a file open: bump `lastOpened` on an existing (user,host,path) row, else insert one
  with the resolved name. Mirrors `upsertRecent`.
  """
  @spec upsert_recent(String.t(), integer(), String.t(), String.t() | nil) :: :ok
  def upsert_recent(user_id, host_id, path, name) do
    now = iso_now()

    case Repo.get_by(FileManagerRecent, userId: user_id, hostId: host_id, path: path) do
      nil ->
        Repo.insert!(%FileManagerRecent{
          userId: user_id,
          hostId: host_id,
          path: path,
          name: resolve_name(path, name),
          lastOpened: now
        })

      %FileManagerRecent{} = existing ->
        existing |> Ecto.Changeset.change(lastOpened: now) |> Repo.update!()
    end

    :ok
  end

  @doc "Delete an owned recent entry by (host, path). Idempotent. Mirrors `deleteRecentForHostPath`."
  @spec delete_recent(String.t(), integer(), String.t()) :: :ok
  def delete_recent(user_id, host_id, path) do
    Repo.delete_all(
      from r in FileManagerRecent,
        where: r.userId == ^user_id and r.hostId == ^host_id and r.path == ^path
    )

    :ok
  end

  # --- pinned ---------------------------------------------------------------

  @doc "The user's pinned files for a host, newest first. Mirrors `listPinnedForHost`."
  @spec list_pinned(String.t(), integer()) :: [FileManagerPinned.t()]
  def list_pinned(user_id, host_id) do
    Repo.all(
      from p in FileManagerPinned,
        where: p.userId == ^user_id and p.hostId == ^host_id,
        order_by: [desc: p.pinnedAt]
    )
  end

  @doc """
  Pin a file. Returns `:ok` on insert, or `:exists` when the (user,host,path) is already
  pinned (→ 409 upstream). Mirrors `createPinned`.
  """
  @spec create_pinned(String.t(), integer(), String.t(), String.t() | nil) :: :ok | :exists
  def create_pinned(user_id, host_id, path, name) do
    if exists?(FileManagerPinned, user_id, host_id, path) do
      :exists
    else
      Repo.insert!(%FileManagerPinned{
        userId: user_id,
        hostId: host_id,
        path: path,
        name: resolve_name(path, name),
        pinnedAt: iso_now()
      })

      :ok
    end
  end

  @doc "Delete an owned pinned entry by (host, path). Idempotent. Mirrors `deletePinnedForHostPath`."
  @spec delete_pinned(String.t(), integer(), String.t()) :: :ok
  def delete_pinned(user_id, host_id, path) do
    Repo.delete_all(
      from p in FileManagerPinned,
        where: p.userId == ^user_id and p.hostId == ^host_id and p.path == ^path
    )

    :ok
  end

  # --- shortcuts ------------------------------------------------------------

  @doc "The user's shortcuts for a host, newest first. Mirrors `listShortcutsForHost`."
  @spec list_shortcuts(String.t(), integer()) :: [FileManagerShortcut.t()]
  def list_shortcuts(user_id, host_id) do
    Repo.all(
      from s in FileManagerShortcut,
        where: s.userId == ^user_id and s.hostId == ^host_id,
        order_by: [desc: s.createdAt]
    )
  end

  @doc """
  Add a shortcut. Returns `:ok` on insert, or `:exists` when the (user,host,path) shortcut
  already exists (→ 409 upstream). Mirrors `createShortcut`.
  """
  @spec create_shortcut(String.t(), integer(), String.t(), String.t() | nil) :: :ok | :exists
  def create_shortcut(user_id, host_id, path, name) do
    if exists?(FileManagerShortcut, user_id, host_id, path) do
      :exists
    else
      Repo.insert!(%FileManagerShortcut{
        userId: user_id,
        hostId: host_id,
        path: path,
        name: resolve_name(path, name),
        createdAt: iso_now()
      })

      :ok
    end
  end

  @doc "Delete an owned shortcut by (host, path). Idempotent. Mirrors `deleteShortcutForHostPath`."
  @spec delete_shortcut(String.t(), integer(), String.t()) :: :ok
  def delete_shortcut(user_id, host_id, path) do
    Repo.delete_all(
      from s in FileManagerShortcut,
        where: s.userId == ^user_id and s.hostId == ^host_id and s.path == ^path
    )

    :ok
  end

  # --- helpers --------------------------------------------------------------

  defp exists?(schema, user_id, host_id, path) do
    Repo.exists?(
      from x in schema,
        where: x.userId == ^user_id and x.hostId == ^host_id and x.path == ^path
    )
  end

  # Port of `resolveBookmarkName`: `name || path.split("/").pop() || "Unknown"`.
  defp resolve_name(_path, name) when is_binary(name) and name != "", do: name

  defp resolve_name(path, _name) do
    case path |> String.split("/") |> List.last() do
      last when is_binary(last) and last != "" -> last
      _ -> "Unknown"
    end
  end

  # JS `new Date().toISOString()` shape ("YYYY-MM-DDTHH:MM:SS.sssZ").
  defp iso_now do
    DateTime.utc_now() |> DateTime.truncate(:millisecond) |> DateTime.to_iso8601()
  end
end
