defmodule Termelix.Crypto.SettingsCacheTest do
  @moduledoc """
  Covers the read-through cache in `Termelix.Settings`: values in ETS, version counter in
  `:atomics` pinned in `:persistent_term`.

  The cache deliberately disengages inside DB transactions and on the SQL
  sandbox (which is what the test env runs on), so these tests exercise the
  sandbox contract: stale pre-seeded entries are never served, and writes
  through `put_value/2` / `delete/1` invalidate pre-seeded entries instead of
  caching possibly-phantom values.

  (Placed under test/termelix/crypto because that is the test tree this
  workstream owns; the module under test is Termelix.Settings.)
  """
  use Termelix.DataCase

  alias Termelix.Settings
  alias Termelix.Settings.Cache

  setup do
    key = "cache_test_#{System.unique_integer([:positive])}"

    on_exit(fn -> Cache.invalidate(key) end)
    {:ok, key: key}
  end

  # Reaches into the cache's storage on purpose: these tests are about what the cache holds,
  # not about what `Settings` returns.
  defp seed_cache(key, value), do: :ets.insert(:termelix_settings_cache, {key, value})

  defp cached(key) do
    case Cache.get(key) do
      {:ok, value} -> value
      :miss -> :__no_entry__
    end
  end

  test "put/get/delete round-trip", %{key: key} do
    assert Settings.get_value(key) == nil
    Settings.put_value(key, "v1")
    assert Settings.get_value(key) == "v1"
    Settings.put_value(key, "v2")
    assert Settings.get_value(key) == "v2"
    assert Settings.delete(key) == :ok
    assert Settings.get_value(key) == nil
  end

  test "a stale pre-seeded cache entry is not served inside the sandbox", %{key: key} do
    seed_cache(key, "stale")
    assert Settings.get_value(key) == nil

    Settings.put_value(key, "real")
    seed_cache(key, "stale")
    assert Settings.get_value(key) == "real"
  end

  test "put_value invalidates a pre-seeded entry rather than caching inside the sandbox",
       %{key: key} do
    seed_cache(key, "stale")
    Settings.put_value(key, "v")
    assert cached(key) == :__no_entry__
  end

  test "delete invalidates a pre-seeded entry", %{key: key} do
    Settings.put_value(key, "v")
    seed_cache(key, "stale")
    Settings.delete(key)
    assert cached(key) == :__no_entry__
    assert Settings.get_value(key) == nil
  end

  describe "version-guarded installs (Settings.Cache)" do
    test "a reader that observed the pre-invalidation version cannot install", %{key: key} do
      # The reviewer race: a reader snapshots the version, fetches the (pre-commit) value
      # from the DB, the writer commits and invalidates — and only THEN the reader tries
      # to install its stale snapshot. The guard must refuse it.
      observed = Cache.version()
      Settings.invalidate_cache(key)

      assert Cache.install(key, observed, "stale-pre-commit-value") == :stale
      assert Cache.get(key) == :miss
    end

    test "an install under the current version lands and invalidation clears it", %{key: key} do
      observed = Cache.version()
      assert Cache.install(key, observed, "fresh") == :installed
      assert Cache.get(key) == {:ok, "fresh"}

      Settings.invalidate_cache(key)
      assert Cache.get(key) == :miss
      assert Cache.version() == observed + 1
    end

    test "put_value and delete bump the version (in-flight readers cannot re-cache)", %{
      key: key
    } do
      v0 = Cache.version()
      Settings.put_value(key, "v")
      assert Cache.version() == v0 + 1

      Settings.delete(key)
      assert Cache.version() == v0 + 2

      assert Cache.install(key, v0, "stale") == :stale
      assert Cache.get(key) == :miss
    end

    test "one-shot keys leave no cache residue behind", %{key: key} do
      # The OIDC login flow mints unique settings keys per attempt; after their
      # put/get/delete lifecycle nothing keyed by them may remain in the cache. The version
      # counter is one bounded `:atomics` slot and is not keyed by anything.
      before_terms = settings_terms()

      Settings.put_value(key, "one-shot")
      Settings.get_value(key)
      Settings.delete(key)

      assert settings_terms() == before_terms
    end

    test "the version bump is atomic — concurrent invalidations never lose or regress", %{
      key: key
    } do
      # A read-modify-write bump would lose updates under contention (and a stalled
      # writer could even regress the counter — the ABA that would let a stale read
      # re-install). The atomic counter must count every bump exactly.
      v0 = Cache.version()
      tasks = 50
      bumps = 20

      1..tasks
      |> Enum.map(fn _ ->
        Task.async(fn ->
          for _ <- 1..bumps, do: Cache.invalidate(key)
        end)
      end)
      |> Task.await_many(10_000)

      assert Cache.version() == v0 + tasks * bumps
    end

    test "the version survives supervisor restarts (no process owns the counter)", %{
      key: key
    } do
      # This is the reason the counter did NOT move to ETS with the values. An ETS table dies
      # with its owner: killing EtsOwner would reset the version to 0, and an `install/3` still
      # holding an old observed version would match again — the ABA, reopened by a supervisor
      # restart. The `:atomics` ref pinned in `:persistent_term` rides it out.
      Cache.invalidate(key)
      v = Cache.version()
      assert v > 0

      owner = Process.whereis(Termelix.EtsOwner)
      ref = Process.monitor(owner)
      Process.exit(owner, :kill)
      assert_receive {:DOWN, ^ref, :process, ^owner, :killed}

      # Wait for the supervisor to bring EtsOwner back before letting other tests run.
      wait_until(fn ->
        pid = Process.whereis(Termelix.EtsOwner)
        is_pid(pid) and pid != owner
      end)

      assert Cache.version() == v
    end
  end

  defp wait_until(fun, retries \\ 200) do
    cond do
      fun.() -> :ok
      retries == 0 -> flunk("condition never became true")
      true -> Process.sleep(10) && wait_until(fun, retries - 1)
    end
  end

  # Cached VALUE keys only. The counter lives in `:persistent_term` by design (written once per
  # node lifetime) and is deliberately not counted here.
  defp settings_terms do
    :termelix_settings_cache
    |> :ets.tab2list()
    |> Enum.map(&elem(&1, 0))
    |> Enum.sort()
  end
end
