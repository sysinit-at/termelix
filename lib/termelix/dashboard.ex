defmodule Termelix.Dashboard do
  @moduledoc """
  Dashboard domain: per-user service links (the Elixir port of
  `dashboard-service-link-repository.ts`). All reads and writes are scoped to the owning user;
  ownership is enforced in every query and a body `userId` is never trusted.

  The `order` column is a SQL reserved word; queries reference it via `field(l, :order)` so
  Ecto emits the quoted column name. New links append at the end (next free order).
  """
  import Ecto.Query, only: [from: 2]

  alias Termelix.Repo
  alias Termelix.Schema.DashboardServiceLink

  @doc "All of a user's service links, ordered by `order` then id (matches `listByUserId`)."
  @spec list_service_links(String.t()) :: [DashboardServiceLink.t()]
  def list_service_links(user_id) do
    Repo.all(
      from l in DashboardServiceLink,
        where: l.userId == ^user_id,
        order_by: [asc: field(l, :order), asc: l.id]
    )
  end

  @doc "A single service link owned by the user, or nil."
  @spec get_service_link(String.t(), integer()) :: DashboardServiceLink.t() | nil
  def get_service_link(user_id, id),
    do: Repo.get_by(DashboardServiceLink, id: id, userId: user_id)

  @doc """
  Create a service link for the user, appended at the next free `order`. `label` and `url`
  are stored as supplied (the controller trims + validates). Returns `{:ok, link}`.
  """
  @spec create_service_link(String.t(), String.t(), String.t()) ::
          {:ok, DashboardServiceLink.t()} | {:error, Ecto.Changeset.t()}
  def create_service_link(user_id, label, url) do
    Repo.insert(%DashboardServiceLink{
      userId: user_id,
      label: label,
      url: url,
      order: next_order(user_id),
      createdAt: DateTime.utc_now() |> DateTime.to_iso8601()
    })
  end

  @doc """
  Update an owned link with `changes` (a map of the fields to set). Returns the updated link,
  or nil when it is not found/owned.
  """
  @spec update_service_link(String.t(), integer(), map()) :: DashboardServiceLink.t() | nil
  def update_service_link(user_id, id, changes) do
    case get_service_link(user_id, id) do
      nil -> nil
      %DashboardServiceLink{} = link -> link |> Ecto.Changeset.change(changes) |> Repo.update!()
    end
  end

  @doc "Delete an owned link. Returns the deleted link, or nil when not found/owned."
  @spec delete_service_link(String.t(), integer()) :: DashboardServiceLink.t() | nil
  def delete_service_link(user_id, id) do
    case get_service_link(user_id, id) do
      nil -> nil
      %DashboardServiceLink{} = link -> Repo.delete!(link)
    end
  end

  # Next free order slot for the user: max(order) + 1, or 0 when the user has no links.
  defp next_order(user_id) do
    query =
      from l in DashboardServiceLink,
        where: l.userId == ^user_id,
        select: max(field(l, :order))

    case Repo.one(query) do
      nil -> 0
      max -> max + 1
    end
  end
end
