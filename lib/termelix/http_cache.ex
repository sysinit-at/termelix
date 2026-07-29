defmodule Termelix.HttpCache do
  @moduledoc """
  A tiny single-node TTL cache for outbound-HTTP payloads (`Termelix.System`'s GitHub calls,
  `Termelix.Homepage`'s rss/favicon), backed by a named public ETS table owned for the node's
  lifetime by `Termelix.EtsOwner`.

  `fetch/3` runs `fun` on a cache miss and stores `{key, value, expires_at_ms}` under the key.
  Only `{:ok, value}` results are cached — errors and degraded responses pass through
  uncached, so a transient outage is never pinned for the whole TTL.

  Bounds that keep the footprint trivial on a self-hosted node:

    * **Entry cap** — the table holds at most `@max_entries` rows. A `put` that would push it
      over the cap first reclaims lapsed rows and, if still full, evicts the soonest-to-expire
      entry. Together with the sweep this makes the cache immune to key-space inflation from
      user-controlled inputs (e.g. an unbounded `?page=` on the releases feed).
    * **Expiry sweep** — `Termelix.EtsOwner` calls `sweep_expired/1` every 60s, so lapsed
      entries are erased rather than lingering until their key is next fetched.

  Deliberate single-node trade-offs (this is a self-hosted app, not a fleet):

    * **Stampede on expiry** — nothing serializes a refresh; N concurrent callers may all
      refetch when an entry expires. That is a handful of extra outbound requests per TTL
      window, accepted in exchange for zero coordination.
    * **Test-harness bypass** — when the Req layer is stubbed (a `:plug` in the
      `:termelix, :req_options` app env, i.e. `Req.Test`), caching is skipped entirely so
      each call reaches the stub and stubbed tests stay deterministic.
  """

  @type key :: term()

  @table :termelix_http_cache
  @max_entries 512

  @doc """
  Create the ETS table if it does not exist yet. Idempotent: the `ArgumentError`
  raised when the named table already exists means the owner (or another caller)
  beat us to it.
  """
  @spec ensure_table() :: :ok
  def ensure_table do
    try do
      :ets.new(@table, [
        :named_table,
        :public,
        :set,
        read_concurrency: true,
        write_concurrency: true
      ])

      :ok
    rescue
      ArgumentError -> :ok
    end
  end

  @doc """
  Return the cached `{:ok, value}` for `key` while it is fresh; otherwise run `fun`,
  cache an `{:ok, value}` result for `ttl_ms` milliseconds, and return it. Any
  non-`{:ok, _}` result is returned as-is and never cached.
  """
  @spec fetch(key(), non_neg_integer(), (-> {:ok, term()} | term())) :: {:ok, term()} | term()
  def fetch(key, ttl_ms, fun)
      when is_integer(ttl_ms) and ttl_ms >= 0 and is_function(fun, 0) do
    if bypass?() do
      fun.()
    else
      ensure_table()

      case get(key) do
        {:ok, value} ->
          {:ok, value}

        :miss ->
          case fun.() do
            {:ok, value} = ok ->
              put(key, value, ttl_ms)
              ok

            other ->
              other
          end
      end
    end
  end

  @doc "Drop the cached entry for `key` (a no-op when absent)."
  @spec delete(key()) :: :ok
  def delete(key) do
    ensure_table()
    :ets.delete(@table, key)
    :ok
  end

  @doc """
  Delete every entry whose TTL has lapsed as of `now_ms`, returning the number
  removed. Driven every 60s by `Termelix.EtsOwner`.
  """
  @spec sweep_expired(integer()) :: non_neg_integer()
  def sweep_expired(now_ms \\ System.monotonic_time(:millisecond)) do
    ensure_table()
    spec = [{{:_, :_, :"$1"}, [{:"=<", :"$1", now_ms}], [true]}]
    :ets.select_delete(@table, spec)
  end

  defp get(key) do
    case :ets.lookup(@table, key) do
      [{_, value, expires_at}] ->
        if System.monotonic_time(:millisecond) < expires_at, do: {:ok, value}, else: :miss

      [] ->
        :miss
    end
  end

  defp put(key, value, ttl_ms) do
    enforce_cap(key)
    expires_at = System.monotonic_time(:millisecond) + ttl_ms
    :ets.insert(@table, {key, value, expires_at})
    :ok
  end

  # Keep the table under @max_entries: a fresh key (updates don't grow the table) that
  # would push it over the cap first reclaims lapsed rows and, if that is not enough,
  # drops the soonest-to-expire entry. Best-effort — not serialized against concurrent
  # puts, which is fine for a single-node cache bound.
  defp enforce_cap(key) do
    if not :ets.member(@table, key) and :ets.info(@table, :size) >= @max_entries do
      sweep_expired()
      if :ets.info(@table, :size) >= @max_entries, do: evict_soonest()
    end

    :ok
  end

  defp evict_soonest do
    fold = fn {k, _v, exp}, {_, best} = acc -> if exp < best, do: {k, exp}, else: acc end

    case :ets.foldl(fold, {nil, :infinity}, @table) do
      {nil, _} -> :ok
      {k, _} -> :ets.delete(@table, k)
    end
  end

  # The test harness stubs outbound HTTP through `Req.Test`; caching over a stub would leak
  # one test's canned response into the next, so the cache steps aside entirely.
  defp bypass? do
    :termelix
    |> Application.get_env(:req_options, [])
    |> Keyword.get(:plug)
    |> Kernel.!=(nil)
  end

  # --- test/maintenance helpers --------------------------------------------------

  @doc false
  @spec reset() :: :ok
  def reset do
    ensure_table()
    :ets.delete_all_objects(@table)
    :ok
  end

  @doc false
  @spec size() :: non_neg_integer()
  def size do
    ensure_table()
    :ets.info(@table, :size)
  end

  @doc false
  @spec max_entries() :: pos_integer()
  def max_entries, do: @max_entries
end
