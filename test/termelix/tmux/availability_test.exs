defmodule Termelix.Tmux.AvailabilityTest do
  @moduledoc """
  The tmux detector's contract: a verdict is probed at most once per TTL, a `false` is cached
  as hard as a `true` (or every connect to a tmux-less host re-probes), a lapsed entry
  re-probes, and a probe that FAILS is `:unknown` — never `false`, which would silently
  disable the feature for a whole TTL because a host happened to be down.

  The SSH probe itself is replaced through the `:tmux_availability_prober` app env, so nothing
  here dials anything; `verdict_from_exec/1` is exercised directly against the exec shapes
  `Termelix.SSH.Exec.run/4` actually returns.
  """
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Termelix.Tmux.Availability

  setup do
    Availability.reset()
    :ok
  end

  # A probe started by a call with `wait_ms: 0` may still be running when the test ends, so
  # every test that cares about the count waits for its probe (`@wait`) instead.
  @wait 5_000

  defp stub_prober(fun) do
    Application.put_env(:termelix, :tmux_availability_prober, fun)
    on_exit(fn -> Application.delete_env(:termelix, :tmux_availability_prober) end)
  end

  defp counting_prober(verdict) do
    {:ok, agent} = Agent.start_link(fn -> 0 end)

    stub_prober(fn _host ->
      Agent.update(agent, &(&1 + 1))
      verdict
    end)

    agent
  end

  defp probes(agent), do: Agent.get(agent, & &1)

  defp host do
    %{id: System.unique_integer([:positive]), ip: "10.0.0.9", port: 22, username: "root"}
  end

  # The `Termelix.SSH.Exec.run/4` success shape, exit 0.
  defp ok(stdout), do: %{stdout: stdout, stderr: "", exit_status: 0}

  test "a miss probes once and every later connect is served from the cache" do
    agent = counting_prober(true)
    h = host()

    assert Availability.available?(h, now_ms: 0, wait_ms: @wait) == true
    assert Availability.available?(h, now_ms: 1, wait_ms: @wait) == true
    assert Availability.available?(h, now_ms: 2, wait_ms: @wait) == true
    assert probes(agent) == 1
  end

  test "a negative verdict is cached too: a host without tmux is not re-probed per connect" do
    agent = counting_prober(false)
    h = host()

    assert Availability.available?(h, now_ms: 0, wait_ms: @wait) == false
    assert Availability.available?(h, now_ms: 1, wait_ms: @wait) == false
    assert probes(agent) == 1
  end

  test "a lapsed verdict re-probes, a fresh one does not" do
    agent = counting_prober(true)
    h = host()
    ttl = Availability.ttl_ms(true)

    assert Availability.available?(h, now_ms: 0, wait_ms: @wait) == true
    # One millisecond before expiry the row is still fresh.
    assert Availability.available?(h, now_ms: ttl - 1, wait_ms: @wait) == true
    assert probes(agent) == 1

    # At expiry it is a miss again — and the second probe answers on the same clock.
    assert Availability.available?(h, now_ms: ttl, wait_ms: @wait) == true
    assert probes(agent) == 2
  end

  test "a failed probe is :unknown, not false, and is cached only as a short cool-down" do
    agent = counting_prober(:unknown)
    h = host()

    assert Availability.available?(h, now_ms: 0, wait_ms: @wait) == :unknown
    # Cached: a host that is down must not be re-dialed by every connect.
    assert Availability.available?(h, now_ms: 1, wait_ms: @wait) == :unknown
    assert probes(agent) == 1

    # …but only briefly, so the host is re-detected as soon as it is back.
    assert Availability.available?(h, now_ms: Availability.ttl_ms(:unknown), wait_ms: @wait) ==
             :unknown

    assert probes(agent) == 2
  end

  test "the TTLs are ordered: unknown < missing < available" do
    # A wrong `false` disables the feature silently, so it must age out sooner than a `true`;
    # an `:unknown` is only a cool-down against re-dialing a dead host, so it is shortest.
    assert Availability.ttl_ms(:unknown) < Availability.ttl_ms(false)
    assert Availability.ttl_ms(false) < Availability.ttl_ms(true)
  end

  test "only one probe is in flight per host; a concurrent miss is not a second probe" do
    test_pid = self()

    stub_prober(fn _host ->
      send(test_pid, {:probing, self()})

      receive do
        :release -> true
      end
    end)

    h = host()

    # `wait_ms: 0` — the connect path never blocks; the probe fills the cache behind it.
    assert Availability.available?(h, now_ms: 0, wait_ms: 0) == :unknown
    assert_receive {:probing, probe_pid}

    # A second connect while that probe is still running takes the in-flight marker and
    # returns immediately rather than starting its own dial.
    assert Availability.available?(h, now_ms: 1, wait_ms: 0) == :unknown
    refute_receive {:probing, _}, 100

    # Once the probe finishes, its verdict is in the cache for the next connect.
    ref = Process.monitor(probe_pid)
    send(probe_pid, :release)
    assert_receive {:DOWN, ^ref, :process, ^probe_pid, _}
    assert Availability.available?(h, now_ms: 2, wait_ms: 0) == true
  end

  test "a prober that raises yields :unknown and releases the in-flight claim" do
    stub_prober(fn _host -> raise "boom" end)
    h = host()

    log =
      capture_log(fn ->
        assert Availability.available?(h, now_ms: 0, wait_ms: @wait) == :unknown
      end)

    assert log =~ "tmux availability probe crashed"

    # Past the `:unknown` cool-down but well inside the in-flight claim's lifetime: a stuck
    # claim would still be refusing to probe here.
    stub_prober(fn _host -> true end)

    assert Availability.available?(h, now_ms: Availability.ttl_ms(:unknown), wait_ms: @wait) ==
             true
  end

  test "invalidate/1 drops the verdict so the next connect re-probes" do
    agent = counting_prober(true)
    h = host()

    assert Availability.available?(h, now_ms: 0, wait_ms: @wait) == true
    assert Availability.invalidate(h) == :ok
    assert Availability.available?(h, now_ms: 1, wait_ms: @wait) == true
    assert probes(agent) == 2
  end

  test "sweep_expired/1 erases lapsed rows and leaves fresh ones" do
    counting_prober(true)

    assert Availability.available?(host(), now_ms: 0, wait_ms: @wait) == true
    assert Availability.size() == 1

    assert Availability.sweep_expired(0) == 0
    assert Availability.sweep_expired(Availability.ttl_ms(true)) == 1
    assert Availability.size() == 0
  end

  describe "verdict_from_exec/1" do
    test "a version line is the only thing that means yes" do
      assert Availability.verdict_from_exec({:ok, ok("tmux 3.4\n")}) == true
      assert Availability.verdict_from_exec({:ok, ok("tmux next-3.6")}) == true
      # A chatty rc file printing before the command must not hide the version.
      assert Availability.verdict_from_exec({:ok, ok("Welcome to the box\ntmux 3.4")}) == true
    end

    test "a shell that ran and could not find tmux is a definitive no" do
      assert Availability.verdict_from_exec(
               {:ok, %{stdout: "", stderr: "sh: tmux: not found", exit_status: 127}}
             ) == false
    end

    test "every failure is :unknown — an unreachable host is not a host without tmux" do
      for reason <- [:timeout, {:connect_failed, :etimedout}, {:connect_failed, :nxdomain}] do
        assert Availability.verdict_from_exec({:error, reason}) == :unknown
      end

      # Ran, exited 0, said nothing recognizable: ambiguous, so not evidence of absence.
      assert Availability.verdict_from_exec({:ok, ok("")}) == :unknown
      # No exit status at all (channel closed without one) is ambiguous for the same reason.
      assert Availability.verdict_from_exec({:ok, %{stdout: "", stderr: "", exit_status: nil}}) ==
               :unknown
    end
  end

  test "the cache table is owned by the node-lifetime EtsOwner and is public" do
    # Same invariant `Termelix.EtsOwnerTest` pins for the rate-limiter and HTTP-cache tables:
    # a table created lazily by a Bandit request process dies with that request. Requires
    # `Termelix.Tmux.Availability.ensure_table/0` in `EtsOwner.init/1` (ets_owner.ex:39) and
    # `sweep_expired/0` in its `:sweep` handler (ets_owner.ex:49).
    owner = Process.whereis(Termelix.EtsOwner)
    assert is_pid(owner)
    assert :ets.info(:termelix_tmux_availability, :owner) == owner
    assert :ets.info(:termelix_tmux_availability, :protection) == :public
  end
end
