defmodule Termelix.SystemMonitor do
  @moduledoc """
  Owns `:erlang.system_monitor/2` and logs the VM stalls it reports: long garbage collections,
  outsized heaps, and processes that hogged a scheduler. These are the symptoms behind "the
  terminal froze for a second" that no request-level metric can show.

  `:erlang.system_monitor/2` is a **node-global singleton**: setting it REPLACES whatever was
  registered — an `:observer` session, `:recon`, a remote shell — and returns the previous
  setting. Silently discarding that return value is how someone's debugging session quietly
  stops receiving events, so the previous setting is logged on takeover and restored in
  `terminate/2`.

  Thresholds are overridable with
  `config :termelix, system_monitor: [long_gc: …, large_heap: …, long_schedule: …]`;
  `:large_heap` is in **words** (8 bytes each on 64-bit).
  """
  use GenServer
  require Logger

  # 500 ms of GC or scheduling is already a visible stutter in an interactive terminal, and
  # 10M words (~80 MB) is far past anything a single process here allocates legitimately.
  @defaults [long_gc: 500, large_heap: 10_000_000, long_schedule: 500]

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(_opts) do
    # Without trapping, a supervisor shutdown kills this process outright, terminate/2 never
    # runs, and the previous monitor is never restored.
    Process.flag(:trap_exit, true)
    previous = :erlang.system_monitor(self(), monitor_opts())

    if previous != :undefined do
      Logger.warning(
        "Termelix.SystemMonitor replaced an existing system monitor: #{inspect(previous)} — " <>
          "it receives no further VM events until this process stops"
      )
    end

    {:ok, %{previous: previous}}
  end

  @impl true
  def handle_info({:monitor, pid_or_port, kind, info}, state) do
    culprit = "#{inspect(pid_or_port)}#{describe(pid_or_port)}"
    Logger.warning("VM #{kind}: #{culprit} #{inspect(info)}")
    :telemetry.execute([:termelix, :vm, :monitor], %{count: 1}, %{kind: kind})
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{previous: previous}) do
    :erlang.system_monitor(previous)
    :ok
  rescue
    # The previous monitor's process may be gone by now (badarg). Leaving ours registered
    # beats crashing the shutdown path over it.
    _ -> :ok
  end

  defp monitor_opts,
    do: Keyword.merge(@defaults, Application.get_env(:termelix, :system_monitor, []))

  # A bare pid says nothing at 3 a.m.; the registered name (or the initial call) names the
  # culprit. `Process.info/2` returns nil for a process that already died.
  defp describe(pid) when is_pid(pid) do
    case Process.info(pid, [:registered_name, :initial_call]) do
      [{:registered_name, name}, _] when is_atom(name) -> " (#{inspect(name)})"
      [_, {:initial_call, mfa}] -> " (#{inspect(mfa)})"
      _ -> ""
    end
  end

  defp describe(_port), do: ""
end
