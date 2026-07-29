defmodule Termelix.OpenTabs do
  @moduledoc """
  Persistence of a user's open terminal/file tabs (`user_open_tabs`) — the Elixir port of
  `open-tab-repository.ts`. Every read and write is scoped to the owning user (ownership is
  enforced in every query).

  `updatedAt` is written as a JS-style ISO 8601 timestamp (matching the Node repository's
  `new Date().toISOString()`) so the TTL cutoff comparison in `list_recent_for_user/2` stays
  consistent. `createdAt` is written in the SQLite `CURRENT_TIMESTAMP` shape, matching the
  DB default the Node insert relies on.
  """
  import Ecto.Query, only: [from: 2]

  alias Termelix.Repo
  alias Termelix.Schema.UserOpenTab

  @doc """
  The user's tabs updated after `cutoff` (an ISO 8601 string), ordered by tab order —
  mirrors `listRecentForUser`.
  """
  @spec list_recent_for_user(String.t(), String.t()) :: [UserOpenTab.t()]
  def list_recent_for_user(user_id, cutoff) do
    Repo.all(
      from t in UserOpenTab,
        where: t.userId == ^user_id and t.updatedAt > ^cutoff,
        order_by: [asc: t.tabOrder]
    )
  end

  @doc """
  Insert or update a single tab from the raw (string-keyed) request body. On update the tab's
  `backendSessionId` is preserved when the body omits the key (matching the Node `!== undefined`
  guard) and overwritten otherwise; `hostId`/`backendSessionId` default to null on insert.
  """
  @spec upsert_for_user(String.t(), map()) :: :ok
  def upsert_for_user(user_id, params) do
    id = params["id"]

    case get_owned(user_id, id) do
      nil ->
        Repo.insert!(
          UserOpenTab.changeset(%UserOpenTab{}, %{
            id: id,
            userId: user_id,
            tabType: params["tabType"],
            hostId: params["hostId"],
            label: params["label"],
            tabOrder: params["tabOrder"],
            backendSessionId: params["backendSessionId"],
            createdAt: sqlite_now(),
            updatedAt: iso_now()
          })
        )

      %UserOpenTab{} = existing ->
        Repo.update_all(
          from(t in UserOpenTab, where: t.id == ^id and t.userId == ^user_id),
          set: [
            tabType: params["tabType"],
            hostId: params["hostId"],
            label: params["label"],
            tabOrder: params["tabOrder"],
            backendSessionId: backend_session_id(params, existing),
            updatedAt: iso_now()
          ]
        )
    end

    :ok
  end

  @doc """
  Bulk-replace all of the user's tabs with `tabs` (a list of raw string-keyed maps): delete the
  existing set, then insert the supplied one — in one transaction, so a bad entry cannot leave
  the user with no tabs. Mirrors `replaceForUser` — the sync/reorder path.
  """
  @spec replace_for_user(String.t(), [map()]) :: :ok
  def replace_for_user(user_id, tabs) do
    now_iso = iso_now()
    now_sqlite = sqlite_now()

    Repo.transaction(fn ->
      Repo.delete_all(from t in UserOpenTab, where: t.userId == ^user_id)

      entries =
        Enum.map(tabs, fn tab ->
          %{
            id: tab["id"],
            userId: user_id,
            tabType: tab["tabType"],
            hostId: tab["hostId"],
            label: tab["label"],
            tabOrder: tab["tabOrder"],
            backendSessionId: tab["backendSessionId"],
            createdAt: now_sqlite,
            updatedAt: now_iso
          }
        end)

      if entries != [], do: Repo.insert_all(UserOpenTab, entries)
    end)

    :ok
  end

  @doc """
  Update an owned tab's mutable fields (`label`, `tabOrder`, `backendSessionId`) from the raw
  request body; only the supplied keys are changed and `updatedAt` is always bumped. Returns
  true when a row matched, false otherwise (→ 404). Mirrors `updateForUser`.
  """
  @spec update_for_user(String.t(), String.t(), map()) :: boolean()
  def update_for_user(user_id, id, params) do
    set =
      [updatedAt: iso_now()]
      |> put_if_present(params, "label", :label)
      |> put_if_present(params, "tabOrder", :tabOrder)
      |> put_if_present(params, "backendSessionId", :backendSessionId)

    {count, _} =
      Repo.update_all(
        from(t in UserOpenTab, where: t.id == ^id and t.userId == ^user_id),
        set: set
      )

    count > 0
  end

  @doc "Delete an owned tab by id. Idempotent — returns :ok whether or not a row matched."
  @spec delete_for_user(String.t(), String.t()) :: :ok
  def delete_for_user(user_id, id) do
    Repo.delete_all(from t in UserOpenTab, where: t.id == ^id and t.userId == ^user_id)
    :ok
  end

  # --- helpers --------------------------------------------------------------

  defp get_owned(user_id, id), do: Repo.get_by(UserOpenTab, id: id, userId: user_id)

  # Keep the stored value when the caller omits the key; overwrite (incl. to null) when present.
  defp backend_session_id(params, existing) do
    if Map.has_key?(params, "backendSessionId"),
      do: params["backendSessionId"],
      else: existing.backendSessionId
  end

  defp put_if_present(set, params, key, field) do
    if Map.has_key?(params, key), do: [{field, params[key]} | set], else: set
  end

  # JS `new Date().toISOString()` shape ("YYYY-MM-DDTHH:MM:SS.sssZ") so `updatedAt` matches the
  # Node repository and the TTL cutoff comparison stays a like-for-like string comparison.
  defp iso_now do
    DateTime.utc_now() |> DateTime.truncate(:millisecond) |> DateTime.to_iso8601()
  end

  # SQLite `CURRENT_TIMESTAMP` shape for `createdAt`, matching the DB default the Node insert uses.
  defp sqlite_now do
    NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second) |> NaiveDateTime.to_string()
  end
end
