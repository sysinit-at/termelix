defmodule TermelixWeb.Telemetry do
  @moduledoc """
  Metric definitions and the periodic-measurement poller.

  `metrics/0` is the catalogue every reporter consumes; the events behind the `termelix.ssh.*`,
  `termelix.terminal.*` and `termelix.tmux.*` entries are emitted by the modules named in each
  section's comment. Metadata is deliberately narrow — host/port/ids and coarse classifications
  only. A credential, a keystroke or a remote path must never reach a measurement or a tag: this
  data leaves the process, is fanned out to every attached handler, and ends up in log lines.
  """
  use Supervisor
  import Telemetry.Metrics

  # ConsoleReporter prints a line per metric per event, and the Repo metrics below fire on every
  # SQL statement — a firehose anywhere real traffic exists, and noise in `mix test` output. So
  # it defaults to dev only; other environments opt in with
  # `config :termelix, metrics_console_reporter: true`. The definitions in `metrics/0` are
  # unconditional: tests attach to the raw events, not to a reporter.
  @dev_env Mix.env() == :dev

  def start_link(arg) do
    Supervisor.start_link(__MODULE__, arg, name: __MODULE__)
  end

  @impl true
  def init(_arg) do
    # Telemetry poller will execute the given period measurements
    # every 10_000ms. Learn more here: https://telemetry-metrics.hexdocs.pm
    poller = {:telemetry_poller, measurements: periodic_measurements(), period: 10_000}

    reporters =
      if Application.get_env(:termelix, :metrics_console_reporter, @dev_env) do
        [{Telemetry.Metrics.ConsoleReporter, metrics: metrics()}]
      else
        []
      end

    Supervisor.init([poller | reporters], strategy: :one_for_one)
  end

  def metrics do
    [
      # Phoenix Metrics
      summary("phoenix.endpoint.start.system_time",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.endpoint.stop.duration",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.router_dispatch.start.system_time",
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      summary("phoenix.router_dispatch.exception.duration",
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      summary("phoenix.router_dispatch.stop.duration",
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      summary("phoenix.socket_connected.duration",
        unit: {:native, :millisecond}
      ),
      sum("phoenix.socket_drain.count"),
      summary("phoenix.channel_joined.duration",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.channel_handled_in.duration",
        tags: [:event],
        unit: {:native, :millisecond}
      ),

      # Database Metrics
      summary("termelix.repo.query.total_time",
        unit: {:native, :millisecond},
        description: "The sum of the other measurements"
      ),
      summary("termelix.repo.query.decode_time",
        unit: {:native, :millisecond},
        description: "The time spent decoding the data received from the database"
      ),
      summary("termelix.repo.query.query_time",
        unit: {:native, :millisecond},
        description: "The time spent executing the query"
      ),
      summary("termelix.repo.query.queue_time",
        unit: {:native, :millisecond},
        description: "The time spent waiting for a database connection"
      ),
      summary("termelix.repo.query.idle_time",
        unit: {:native, :millisecond},
        description:
          "The time the connection spent waiting before being checked out for the query"
      ),

      # Pooled data-plane SSH connections (Termelix.SSH.Conn). Attempts (`start`) minus
      # `stop` + `failure` is how many handshakes are still in flight.
      counter("termelix.ssh.connect.start.system_time",
        description: "Handshakes attempted"
      ),
      summary("termelix.ssh.connect.stop.duration",
        unit: {:native, :millisecond},
        description: "Handshake duration of a successful pooled SSH connect"
      ),
      counter("termelix.ssh.connect.stop.count"),
      counter("termelix.ssh.connect.failure.count",
        tags: [:class],
        description: "Failed handshakes by coarse class — never the raw :ssh reason term"
      ),
      counter("termelix.ssh.conn.checkout.count",
        tags: [:status],
        description: "Checkouts answered from a ready conn vs queued behind a live handshake"
      ),
      summary("termelix.ssh.conn.expire.idle_ms",
        description: "How long a pooled connection sat unused before closing itself"
      ),

      # Interactive shells (Termelix.SSH.Client)
      counter("termelix.ssh.shell.start.system_time",
        description: "Shell sessions started (compare against ready/failure)"
      ),
      summary("termelix.ssh.shell.ready.duration",
        unit: {:native, :millisecond},
        description: "connect + pty + shell setup, from process start to {:ssh_ready}"
      ),
      counter("termelix.ssh.shell.failure.count", tags: [:class]),
      summary("termelix.ssh.shell.window_debt.bytes",
        description: "Bytes withheld from the SSH receive window while the subscriber is behind"
      ),
      summary("termelix.ssh.shell.window_repay.bytes",
        description: "Withheld bytes handed back once the subscriber drained"
      ),
      counter("termelix.ssh.shell.stalled.count",
        description: "Subscribers declared dead for never draining (> 4 MB owed)"
      ),

      # One-shot exec (Termelix.SSH.Exec)
      summary("termelix.ssh.exec.stop.duration",
        unit: {:native, :millisecond},
        tags: [:result]
      ),
      summary("termelix.ssh.exec.stop.bytes",
        description: "stdout + stderr bytes captured by one run"
      ),
      counter("termelix.ssh.exec.stop.count", tags: [:result]),

      # Terminal sessions (Termelix.Terminal.Session)
      counter("termelix.terminal.session.attach.count", tags: [:takeover]),
      summary("termelix.terminal.session.attach.scrollback_bytes",
        description: "Scrollback replayed to a (re)attaching socket"
      ),
      counter("termelix.terminal.session.detach.count", tags: [:reason]),
      counter("termelix.terminal.session.expire.count"),
      summary("termelix.terminal.session.expire.detached_ms"),

      # tmux probes (Termelix.Tmux). "One exec per interval per host regardless of viewer
      # count" is the acceptance criterion of the overview de-duplication work, and this
      # counter is what it is measured with — hence :host_id as a tag.
      counter("termelix.tmux.exec.count", tags: [:host_id, :kind, :result]),
      summary("termelix.tmux.exec.duration", unit: {:native, :millisecond}, tags: [:kind]),

      # VM stalls reported by Termelix.SystemMonitor
      counter("termelix.vm.monitor.count", tags: [:kind]),

      # Runtime gauges from periodic_measurements/0
      last_value("termelix.runtime.stats.terminal_sessions"),
      last_value("termelix.runtime.stats.ssh_pool_conns"),
      last_value("termelix.runtime.stats.tunnels"),

      # VM Metrics
      summary("vm.memory.total", unit: {:byte, :kilobyte}),
      summary("vm.total_run_queue_lengths.total"),
      summary("vm.total_run_queue_lengths.cpu"),
      summary("vm.total_run_queue_lengths.io"),
      last_value("vm.system_counts.process_count"),
      last_value("vm.system_counts.atom_count"),
      last_value("vm.system_counts.port_count")
    ]
  end

  defp periodic_measurements do
    [
      {__MODULE__, :dispatch_runtime_stats, []}
    ]
  end

  @doc """
  Emit `[:termelix, :runtime, :stats]` — the counts that say how much work the node is holding
  open (terminal sessions, pooled SSH connections, tunnels). Called by the poller every 10 s.

  Every count is best-effort: this supervisor is the FIRST child in the application tree
  (application.ex:21), so the registries it counts may not exist yet on the first tick, and a
  missing table must not take the poller down with it.
  """
  def dispatch_runtime_stats do
    :telemetry.execute(
      [:termelix, :runtime, :stats],
      %{
        terminal_sessions: count_registry(Termelix.Terminal.Registry),
        ssh_pool_conns: count_children(Termelix.SSH.ConnSupervisor),
        tunnels: count_registry(Termelix.Tunnels.Registry)
      },
      %{}
    )
  end

  defp count_registry(name) do
    Registry.count(name)
  catch
    _, _ -> 0
  end

  defp count_children(name) do
    %{active: active} = DynamicSupervisor.count_children(name)
    active
  catch
    _, _ -> 0
  end
end
