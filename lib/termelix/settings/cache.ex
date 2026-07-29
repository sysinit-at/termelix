defmodule Termelix.Settings.Cache do
  @moduledoc """
  Read-through cache backing `Termelix.Settings`: values in ETS, version counter in `:atomics`.

  ## Why the values moved out of `:persistent_term`

  `:persistent_term.put/2` and `erase/1` are not local operations. Writing a term other
  processes may reference triggers a **global scan** — every process on the node is examined
  and any holding a reference to the old term is scheduled for GC. That is the documented cost,
  and it is priced for data written a handful of times per node lifetime.

  A settings cache is not that. Every toggle in the admin UI invalidates a key, and this node is
  deliberately full of long-lived processes: a session per terminal tab, a tunnel per forward,
  a watcher per host, a pooled connection per credential set. Flipping one setting made every
  one of them a GC candidate — the kind of pause `Termelix.SystemMonitor` reports as `long_gc`
  and that nobody would connect to having changed a setting. ETS has no such coupling.

  ## Why the COUNTER did not move

  The obvious next step — put the version in the same ETS table — is wrong, and there is a test
  that says so. An ETS table dies with the process that owns it, so killing `Termelix.EtsOwner`
  would reset the version to 0, and an `install/3` still holding an old observed version would
  match again: exactly the ABA the guard exists to prevent, reopened by a supervisor restart.

  So the counter stays an `:atomics` ref pinned in `:persistent_term`. That costs one
  `:persistent_term.put/2` per NODE lifetime — the write pattern `:persistent_term` is actually
  for — while `:atomics.add/3` bumps it with no global anything. The expensive operation was
  never the counter; it was writing a value per settings key.

  ## The guard itself

  `Settings.get_value/1` reads the database on a miss and then caches what it found. An
  invalidation landing between those two steps would otherwise leave the pre-invalidation value
  cached indefinitely — the write would appear to have been lost, permanently, for readers. The
  version gates the install so that cannot happen.
  """

  @table :termelix_settings_cache
  @owner Termelix.Settings
  @counter_key {@owner, :version_counter}

  @doc "The cached value as `{:ok, value}`, or `:miss`."
  @spec get(String.t()) :: {:ok, term()} | :miss
  def get(key) do
    case :ets.lookup(@table, key) do
      [{^key, value}] -> {:ok, value}
      _ -> :miss
    end
  rescue
    # No table yet (a read during boot). A miss is always safe — the caller falls through to
    # the database.
    ArgumentError -> :miss
  end

  @doc """
  Create the values table if it does not exist. Called by `Termelix.EtsOwner`, so it outlives
  any request process that touches it; idempotent.
  """
  @spec ensure_table() :: :ok
  def ensure_table do
    case :ets.whereis(@table) do
      :undefined -> create_table()
      _tid -> :ok
    end
  end

  defp create_table do
    :ets.new(@table, [
      :named_table,
      :public,
      :set,
      read_concurrency: true,
      write_concurrency: true
    ])

    :ok
  rescue
    # Another process created it between the `whereis` and here.
    ArgumentError -> :ok
  end

  @doc """
  Create the node-lifetime version counter if it does not exist yet. Called once from
  `Termelix.Application.start/2` (single-threaded boot — no creation race); idempotent.
  """
  @spec ensure_counter() :: :ok
  def ensure_counter do
    case :persistent_term.get(@counter_key, nil) do
      nil -> :persistent_term.put(@counter_key, :atomics.new(1, signed: false))
      _ref -> :ok
    end

    ensure_table()
  end

  @doc "The current global invalidation version (bumped by every `invalidate/1`)."
  @spec version() :: non_neg_integer()
  def version, do: :atomics.get(counter(), 1)

  @doc """
  Install `value` for `key`, but only under the version the caller observed before it read the
  database. Refuses (or undoes itself) when an invalidation interleaved, so a stale read can
  never be cached past the write that invalidated it. Returns `:installed` or `:stale`.
  """
  @spec install(String.t(), non_neg_integer(), term()) :: :installed | :stale
  def install(key, observed_version, value) do
    ensure_table()

    if version() == observed_version do
      :ets.insert(@table, {key, value})

      # An invalidation may have bumped between the check and the insert; undo rather than
      # leave a value the invalidation intended to kill.
      if version() == observed_version do
        :installed
      else
        :ets.delete(@table, key)
        :stale
      end
    else
      :stale
    end
  end

  @doc """
  Invalidate `key`: atomically bump the global version, then drop the cached value.

  The atomic bump is what makes the version strictly monotonic — it can never regress to a
  value a reader observed earlier, which is what makes `install/3`'s check meaningful.
  """
  @spec invalidate(String.t()) :: :ok
  def invalidate(key) do
    :atomics.add(counter(), 1, 1)
    ensure_table()
    :ets.delete(@table, key)
    :ok
  end

  @doc false
  @spec reset() :: :ok
  def reset do
    ensure_table()
    :ets.delete_all_objects(@table)
    :ok
  end

  defp counter do
    case :persistent_term.get(@counter_key, nil) do
      nil ->
        # Pre-boot convenience only — `Application.start/2` creates the counter before anything
        # concurrent can run.
        ensure_counter()
        :persistent_term.get(@counter_key)

      ref ->
        ref
    end
  end
end
