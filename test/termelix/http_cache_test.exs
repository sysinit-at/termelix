defmodule Termelix.HttpCacheTest do
  @moduledoc """
  Unit coverage for the ETS-backed TTL cache: a miss runs the fun once and serves the
  value from cache inside the TTL, a zero TTL refetches every call, errors pass through
  uncached, `delete/1` drops an entry, the `Req.Test` stub bypass skips caching, the
  periodic sweep erases lapsed entries, and the entry cap bounds the table.
  """
  use ExUnit.Case, async: false

  alias Termelix.HttpCache

  defp counter do
    {:ok, agent} = Agent.start_link(fn -> 0 end)

    fun = fn ->
      Agent.update(agent, &(&1 + 1))
      {:ok, Agent.get(agent, & &1)}
    end

    {agent, fun}
  end

  defp calls(agent), do: Agent.get(agent, & &1)

  test "a miss runs the fun once; fresh hits are served from cache" do
    {agent, fun} = counter()
    key = {:hit, make_ref()}

    assert HttpCache.fetch(key, 60_000, fun) == {:ok, 1}
    assert HttpCache.fetch(key, 60_000, fun) == {:ok, 1}
    assert calls(agent) == 1
  end

  test "a zero TTL expires immediately and refetches every call" do
    {agent, fun} = counter()
    key = {:zero_ttl, make_ref()}

    assert HttpCache.fetch(key, 0, fun) == {:ok, 1}
    assert HttpCache.fetch(key, 0, fun) == {:ok, 2}
    assert calls(agent) == 2
  end

  test "errors pass through uncached" do
    key = {:error, make_ref()}
    assert HttpCache.fetch(key, 60_000, fn -> :error end) == :error

    {agent, fun} = counter()
    assert HttpCache.fetch(key, 60_000, fun) == {:ok, 1}
    assert calls(agent) == 1
  end

  test "delete/1 drops the entry so the next fetch recomputes" do
    {_agent, fun} = counter()
    key = {:delete, make_ref()}

    assert HttpCache.fetch(key, 60_000, fun) == {:ok, 1}
    assert HttpCache.delete(key) == :ok
    assert HttpCache.fetch(key, 60_000, fun) == {:ok, 2}
    # Deleting an absent key is a no-op.
    assert HttpCache.delete({:never_seen, make_ref()}) == :ok
  end

  test "the Req.Test stub bypass skips the cache entirely" do
    Application.put_env(:termelix, :req_options, plug: {Req.Test, __MODULE__})
    on_exit(fn -> Application.delete_env(:termelix, :req_options) end)

    {agent, fun} = counter()
    key = {:bypass, make_ref()}

    assert HttpCache.fetch(key, 60_000, fun) == {:ok, 1}
    assert HttpCache.fetch(key, 60_000, fun) == {:ok, 2}
    assert calls(agent) == 2
  end

  test "sweep_expired erases lapsed entries and leaves fresh ones" do
    HttpCache.reset()

    # A zero-TTL entry is already expired the moment it is stored; a 60s one is fresh.
    assert HttpCache.fetch({:sweep_stale, make_ref()}, 0, fn -> {:ok, 1} end) == {:ok, 1}
    assert HttpCache.fetch({:sweep_fresh, make_ref()}, 60_000, fn -> {:ok, 2} end) == {:ok, 2}
    assert HttpCache.size() == 2

    # The sweep removes the lapsed entry (erased, not merely ignored) and keeps the fresh one.
    assert HttpCache.sweep_expired() == 1
    assert HttpCache.size() == 1
  end

  test "the entry cap bounds the table under key-space inflation" do
    HttpCache.reset()
    cap = HttpCache.max_entries()

    for i <- 1..(cap + 50) do
      assert HttpCache.fetch({:cap, i}, 60_000, fn -> {:ok, i} end) == {:ok, i}
    end

    assert HttpCache.size() <= cap
  end
end
