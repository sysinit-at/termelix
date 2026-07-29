defmodule Termelix.EtsOwnerTest do
  @moduledoc """
  The rate-limiter and HTTP-cache tables must be owned by the supervised
  `Termelix.EtsOwner` GenServer — not by a transient request process, whose death would
  destroy the table (and every budget / anti-replay marker in it). Also asserts they
  are `:public`, so request processes can still read and write them.
  """
  use ExUnit.Case, async: false

  @tables [:termelix_rate_limiter, :termelix_http_cache]

  test "the shared ETS tables are owned by the node-lifetime EtsOwner and are public" do
    owner = Process.whereis(Termelix.EtsOwner)
    assert is_pid(owner)

    for table <- @tables do
      assert :ets.info(table, :owner) == owner
      assert :ets.info(table, :protection) == :public
    end
  end
end
