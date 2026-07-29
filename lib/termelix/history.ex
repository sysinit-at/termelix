defmodule Termelix.History do
  @moduledoc """
  Command history (`command_history`) and recent activity (`recent_activity`) access — the
  Elixir port of `command-history-repository.ts` + `recent-activity-repository.ts` and the
  `/terminal/command_history` and `/activity/*` routes (`terminal.ts`, `dashboard.ts`).

  Every read and write is scoped to the owning user (ownership enforced in every query); a
  body `userId` is never trusted. Neither table carries secret fields, so no DEK is involved.

  Timestamp formats mirror Node: `command_history.executed_at` is written as an ISO-8601
  instant (`new Date().toISOString()`), while `recent_activity.timestamp` uses SQLite's
  `CURRENT_TIMESTAMP` shape ("YYYY-MM-DD HH:MM:SS") the Node insert relies on as a column
  default.
  """
  import Ecto.Query, only: [from: 2]

  alias Termelix.Repo
  alias Termelix.Schema.{CommandHistory, Host, RecentActivity}

  # --- command history ------------------------------------------------------

  @doc "Insert a command-history row for the user, returning the created record."
  @spec record_command(String.t(), integer(), String.t(), String.t()) :: CommandHistory.t()
  def record_command(user_id, host_id, command, executed_at \\ iso_now()) do
    Repo.insert!(%CommandHistory{
      userId: user_id,
      hostId: host_id,
      command: command,
      executedAt: executed_at
    })
  end

  @doc """
  Distinct commands run on a host by the user, most-recently-executed first
  (mirrors `listUniqueCommandsForHost`: group by command, order by MAX(executed_at) desc).
  """
  @spec list_unique_commands(String.t(), integer(), pos_integer()) :: [String.t()]
  def list_unique_commands(user_id, host_id, limit \\ 500) do
    Repo.all(
      from c in CommandHistory,
        where: c.userId == ^user_id and c.hostId == ^host_id,
        group_by: c.command,
        order_by: [desc: max(c.executedAt)],
        select: c.command,
        limit: ^limit
    )
  end

  @doc "Delete every occurrence of `command` on a host for the user. Returns the count deleted."
  @spec delete_command(String.t(), integer(), String.t()) :: non_neg_integer()
  def delete_command(user_id, host_id, command) do
    {count, _} =
      Repo.delete_all(
        from c in CommandHistory,
          where: c.userId == ^user_id and c.hostId == ^host_id and c.command == ^command
      )

    count
  end

  @doc "Clear a host's whole command history for the user. Returns the count deleted."
  @spec clear_commands(String.t(), integer()) :: non_neg_integer()
  def clear_commands(user_id, host_id) do
    {count, _} =
      Repo.delete_all(
        from c in CommandHistory,
          where: c.userId == ^user_id and c.hostId == ^host_id
      )

    count
  end

  @doc """
  The `enable_command_history` flag for a host owned by the user, or nil when the host is not
  owned (Node's per-host opt-out: only an explicit `false` suppresses saving; a missing host
  or a null flag lets the command through).
  """
  @spec command_history_flag(String.t(), integer()) :: boolean() | nil
  def command_history_flag(user_id, host_id) do
    Repo.one(
      from h in Host,
        where: h.id == ^host_id and h.userId == ^user_id,
        select: h.enableCommandHistory
    )
  end

  # --- recent activity ------------------------------------------------------

  @doc "The user's recent activity, newest first, capped at `limit` (mirrors `listByUserId`)."
  @spec list_activity(String.t(), pos_integer()) :: [RecentActivity.t()]
  def list_activity(user_id, limit) do
    Repo.all(
      from r in RecentActivity,
        where: r.userId == ^user_id,
        order_by: [desc: r.timestamp],
        limit: ^limit
    )
  end

  @doc "Insert a recent-activity row for the user, returning the created record."
  @spec record_activity(String.t(), String.t(), integer(), String.t()) :: RecentActivity.t()
  def record_activity(user_id, type, host_id, host_name) do
    Repo.insert!(%RecentActivity{
      userId: user_id,
      type: type,
      hostId: host_id,
      hostName: host_name,
      timestamp: sqlite_now()
    })
  end

  @doc """
  Keep only the user's newest `keep_count` activity rows, deleting the rest (mirrors
  `trimUserActivity`). Returns the count deleted. A no-op when the user has `keep_count`
  or fewer rows; otherwise a single set-based DELETE (no id list round-trip).
  """
  @spec trim_activity(String.t(), non_neg_integer()) :: non_neg_integer()
  def trim_activity(user_id, keep_count) do
    total = Repo.aggregate(from(r in RecentActivity, where: r.userId == ^user_id), :count)

    if total <= keep_count do
      0
    else
      {count, _} =
        Repo.delete_all(
          from r in RecentActivity,
            where: r.userId == ^user_id,
            where:
              fragment(
                "? NOT IN (SELECT id FROM recent_activity WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?)",
                r.id,
                ^user_id,
                ^keep_count
              )
        )

      count
    end
  end

  @doc "Delete all of the user's recent activity. Returns the count deleted."
  @spec clear_activity(String.t()) :: non_neg_integer()
  def clear_activity(user_id) do
    {count, _} = Repo.delete_all(from r in RecentActivity, where: r.userId == ^user_id)
    count
  end

  @doc "Whether the user owns the given host (used to gate activity logging)."
  @spec host_owned?(String.t(), integer()) :: boolean()
  def host_owned?(user_id, host_id) do
    Repo.exists?(from h in Host, where: h.id == ^host_id and h.userId == ^user_id)
  end

  # --- helpers --------------------------------------------------------------

  # `new Date().toISOString()` shape (millisecond precision, trailing Z) for executed_at.
  @doc false
  def iso_now, do: DateTime.utc_now() |> DateTime.truncate(:millisecond) |> DateTime.to_iso8601()

  # SQLite `CURRENT_TIMESTAMP` shape ("YYYY-MM-DD HH:MM:SS", UTC) for the activity timestamp.
  defp sqlite_now do
    NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second) |> NaiveDateTime.to_string()
  end
end
