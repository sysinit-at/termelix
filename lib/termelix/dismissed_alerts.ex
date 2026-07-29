defmodule Termelix.DismissedAlerts do
  @moduledoc """
  Persistence of a user's dismissed announcement alerts (`dismissed_alerts`) — the Elixir
  port of `dismissed-alert-repository.ts`. Every read and write is scoped to the owning user
  (ownership is enforced in every query; a body `userId` is never trusted).

  `dismissedAt` is written in the SQLite `CURRENT_TIMESTAMP` shape, matching the DB default
  the Node insert relies on.
  """
  import Ecto.Query, only: [from: 2]

  alias Termelix.Repo
  alias Termelix.Schema.DismissedAlert

  @doc "Every dismissal row owned by the user — mirrors `listByUserId`."
  @spec list_for_user(String.t()) :: [DismissedAlert.t()]
  def list_for_user(user_id) do
    Repo.all(from d in DismissedAlert, where: d.userId == ^user_id)
  end

  @doc "Just the dismissed alert ids for the user — mirrors `listAlertIdsByUserId`."
  @spec list_alert_ids_for_user(String.t()) :: [String.t()]
  def list_alert_ids_for_user(user_id) do
    Repo.all(from d in DismissedAlert, where: d.userId == ^user_id, select: d.alertId)
  end

  @doc """
  Dismiss `alert_id` for the user. Returns `{:error, :already_dismissed}` when a dismissal
  row already exists (→ 409). The (user_id, alert_id) unique index enforces this at the
  database, so the concurrent-dismiss race can no longer produce a duplicate row.
  """
  @spec dismiss(String.t(), String.t()) :: :ok | {:error, :already_dismissed}
  def dismiss(user_id, alert_id) do
    %DismissedAlert{}
    |> DismissedAlert.changeset(%{
      userId: user_id,
      alertId: alert_id,
      dismissedAt: sqlite_now()
    })
    |> Repo.insert()
    |> case do
      {:ok, _} ->
        :ok

      {:error, changeset} ->
        if unique_violation?(changeset) do
          {:error, :already_dismissed}
        else
          # Unreachable in practice (all fields are supplied internally) — mirror the
          # previous `insert!` crash semantics for anything but the unique race.
          raise Ecto.InvalidChangesetError, changeset: changeset, action: :insert
        end
    end
  end

  @doc "Undismiss `alert_id`. Returns true when a row was removed, false otherwise (→ 404)."
  @spec undismiss(String.t(), String.t()) :: boolean()
  def undismiss(user_id, alert_id) do
    {count, _} =
      Repo.delete_all(
        from d in DismissedAlert, where: d.userId == ^user_id and d.alertId == ^alert_id
      )

    count > 0
  end

  # --- helpers --------------------------------------------------------------

  # Whether the changeset failed on the (user_id, alert_id) unique constraint.
  defp unique_violation?(changeset) do
    Enum.any?(changeset.errors, fn
      {:userId, {"has already been taken", _}} -> true
      _ -> false
    end)
  end

  # SQLite `CURRENT_TIMESTAMP` shape ("YYYY-MM-DD HH:MM:SS"), matching the DB default the
  # Node insert relies on.
  defp sqlite_now do
    NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second) |> NaiveDateTime.to_string()
  end
end
