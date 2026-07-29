defmodule Termelix.Audit do
  @moduledoc """
  Audit trail — the Elixir port of `utils/audit-logger.ts` plus the
  `audit-log-repository.ts` query surface.

  Writes are best-effort and must never break the caller: `record/1` (and the `log/4`
  convenience) swallow every error, exactly like `logAudit`. The exception is
  `record_strict!/1` for mutations whose audit record is *mandatory* (consent changes):
  it raises on failure so a wrapping transaction rolls the mutation back with it. Reads
  back the paginated, filterable view the admin audit page consumes, newest-first by
  `timestamp`.

  On write the table is pruned to `@prune_target` rows once it grows past `@prune_max`,
  mirroring the Node repository's `pruneIfNeeded` — except the `@retained_actions`
  (error-reporting consent decisions), which must stay reconstructible for the lifetime
  of the installation and are never pruned.
  """
  import Ecto.Query
  require Logger

  alias Termelix.Repo
  alias Termelix.Schema.AuditLog

  @prune_max 10_000
  @prune_target 9_000

  # Rows that survive pruning: consent history has record-keeping value far beyond the
  # rolling operational window the rest of the log keeps.
  @retained_actions ["error_reporting_enable", "error_reporting_disable"]

  @doc """
  Convenience audit helper: `log(user, action, resource_type, meta)`.

  `user` is a `%Termelix.Schema.User{}` (or any map with `id`/`username`); `action` and
  `resource_type` are strings; `meta` may carry `:resource_id`, `:resource_name`,
  `:details`, `:ip_address`, `:user_agent`, `:success` (default `true`) and `:error_message`.
  Never raises.
  """
  @spec log(map(), String.t(), String.t(), map()) :: :ok
  def log(user, action, resource_type, meta \\ %{}) do
    record(%{
      userId: user.id,
      username: user.username || user.id,
      action: action,
      resourceType: resource_type,
      resourceId: meta[:resource_id],
      resourceName: meta[:resource_name],
      details: meta[:details],
      ipAddress: meta[:ip_address],
      userAgent: meta[:user_agent],
      success: Map.get(meta, :success, true),
      errorMessage: meta[:error_message]
    })
  end

  @doc "Insert one audit row from a full attrs map. Never raises (audit must not break callers)."
  @spec record(map()) :: :ok
  def record(attrs) do
    record_strict!(attrs)
    :ok
  rescue
    error ->
      Logger.warning("Audit write failed: #{Exception.message(error)}")
      :ok
  end

  @doc """
  Insert one audit row, surfacing failure to the caller — for mutations whose audit record
  is mandatory (the error-reporting consent). Run it inside the mutation's transaction so
  a failed audit write rolls the mutation back rather than letting it proceed unaudited.
  Returns the inserted row.
  """
  @spec record_strict!(map()) :: AuditLog.t()
  def record_strict!(attrs) do
    row = %AuditLog{
      userId: attrs[:userId],
      username: attrs[:username],
      action: attrs[:action],
      resourceType: attrs[:resourceType],
      resourceId: attrs[:resourceId],
      resourceName: attrs[:resourceName],
      details: attrs[:details],
      ipAddress: attrs[:ipAddress],
      userAgent: attrs[:userAgent],
      success: Map.get(attrs, :success, true),
      errorMessage: attrs[:errorMessage],
      timestamp: attrs[:timestamp] || iso_now()
    }

    inserted = Repo.insert!(row)
    prune_if_needed()
    inserted
  end

  @doc """
  A page of audit rows plus the total count for the same filters.

  `input` is `%{filters: map, limit: pos_integer, offset: non_neg_integer}`. Filters accept
  `:userId`, `:action`, `:resourceType`, `:success` (boolean), `:startDate`, `:endDate`
  (inclusive `timestamp` bounds). Returns `%{logs: [%AuditLog{}], total: integer}`.
  """
  @spec list_page(%{filters: map(), limit: pos_integer(), offset: non_neg_integer()}) ::
          %{logs: [AuditLog.t()], total: non_neg_integer()}
  def list_page(%{filters: filters, limit: limit, offset: offset}) do
    base = apply_filters(from(a in AuditLog), filters)

    logs =
      base
      |> order_by_timestamp()
      |> limit(^limit)
      |> offset(^offset)
      |> Repo.all()

    %{logs: logs, total: Repo.aggregate(base, :count, :id)}
  end

  @doc "Distinct `action` values, ascending — populates the audit-page filter dropdown."
  @spec list_distinct_actions() :: [String.t()]
  def list_distinct_actions do
    Repo.all(from(a in AuditLog, distinct: true, order_by: [asc: a.action], select: a.action))
  end

  @doc """
  Delete a user's audit rows (used by full-account deletion). Returns the deleted count.
  Retained (consent) rows are **anonymized instead of deleted** — the user id is cleared,
  the row itself stays — matching the `ON DELETE SET NULL` the schema applies when the
  user row itself goes: consent history must outlive the actor.
  """
  @spec delete_by_user_id(String.t()) :: non_neg_integer()
  def delete_by_user_id(user_id) do
    Repo.update_all(
      from(a in AuditLog, where: a.userId == ^user_id and a.action in ^@retained_actions),
      set: [userId: nil]
    )

    {count, _} = Repo.delete_all(from(a in AuditLog, where: a.userId == ^user_id))
    # The counter would otherwise over-count until the next prune, which is harmless but makes
    # the prune fire early for no reason. Cheap to keep honest at a rare call site.
    forget_row_count()
    count
  end

  # --- query building --------------------------------------------------------

  defp apply_filters(query, filters) do
    Enum.reduce(filters, query, fn
      {_k, nil}, q -> q
      {_k, ""}, q -> q
      {:userId, v}, q -> from(a in q, where: a.userId == ^v)
      {:action, v}, q -> from(a in q, where: a.action == ^v)
      {:resourceType, v}, q -> from(a in q, where: a.resourceType == ^v)
      {:success, v}, q when is_boolean(v) -> from(a in q, where: a.success == ^v)
      {:startDate, v}, q -> from(a in q, where: a.timestamp >= ^v)
      {:endDate, v}, q -> from(a in q, where: a.timestamp <= ^v)
      {_k, _v}, q -> q
    end)
  end

  defp order_by_timestamp(query), do: order_by(query, [a], desc: a.timestamp)

  # --- pruning ---------------------------------------------------------------

  # An in-memory row counter, so the ordinary write does NOT run `COUNT(*)`.
  #
  # `Repo.aggregate(AuditLog, :count, :id)` is a full scan of the audit table, and it ran on
  # EVERY audited action. SQLite has a single writer and this app runs in `:immediate` mode, so
  # that scan serializes against every other write in the system — the cost of auditing an
  # action grew with how much had already been audited, which is the wrong shape for a table
  # whose entire purpose is to keep growing.
  #
  # The counter is approximate by construction (it is seeded once and can drift if rows are
  # deleted behind its back) and that is fine: it only decides WHEN to check, and the check
  # itself is exact. Drift costs a slightly early or late prune, never a wrong one.
  @counter_key {__MODULE__, :row_count}

  defp prune_if_needed do
    if bump_row_count() >= @prune_max do
      # The approximate counter decides WHEN to look; the exact count decides what to do. One
      # `COUNT(*)` per prune (every ~1000 writes) rather than one per write, and re-seeding here
      # means any drift — rows inserted or deleted behind the counter's back — self-corrects at
      # the only moment it could matter.
      count = Repo.aggregate(AuditLog, :count, :id)
      reset_row_count(count)
      prune(count)
    end

    :ok
  end

  defp prune(count) when count < @prune_max, do: :ok

  defp prune(count) do
    delete_count = count - @prune_target

    # Consent rows (@retained_actions) are never candidates for deletion.
    ids =
      Repo.all(
        from(a in AuditLog,
          where: a.action not in ^@retained_actions,
          order_by: [asc: a.timestamp],
          limit: ^delete_count,
          select: a.id
        )
      )

    {deleted, _} = Repo.delete_all(from(a in AuditLog, where: a.id in ^ids))
    reset_row_count(count - deleted)
    :ok
  end

  # Seeded from the database the first time, then kept in `:persistent_term` — one bounded slot
  # for the node's lifetime, not an entry per anything.
  defp bump_row_count do
    count = :persistent_term.get(@counter_key, nil) || Repo.aggregate(AuditLog, :count, :id)
    next = count + 1
    :persistent_term.put(@counter_key, next)
    next
  end

  defp reset_row_count(count), do: :persistent_term.put(@counter_key, max(count, 0))

  @doc false
  @spec forget_row_count() :: :ok
  def forget_row_count do
    :persistent_term.erase(@counter_key)
    :ok
  end

  defp iso_now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
