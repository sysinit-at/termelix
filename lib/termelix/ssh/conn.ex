defmodule Termelix.SSH.Conn do
  @moduledoc """
  Owns one pooled SSH connection for `Termelix.SSH.Pool` — one process per unique
  host+credential set, registered in `Termelix.SSH.ConnRegistry` and started on demand under
  `Termelix.SSH.ConnSupervisor`.

  Callers check out the raw `:ssh` connection ref with `checkout/2` and open their own
  channels on it (native SSH multiplexing); the connection itself is shared, never the
  channels. The handshake runs in a spawned connector process (kicked off from
  `handle_continue/2`, the same non-blocking pattern as `Termelix.SSH.Client`), so a slow or
  dead host never wedges the `DynamicSupervisor`, and checkout calls made mid-handshake
  queue up as waiters that are all answered — with the real result — when the handshake
  completes.

  Lifecycle: the ssh pid is monitored; when it dies (network drop, remote close) the Conn
  stops `:normal`, so the next checkout spawns a fresh connection. A Conn that sees no
  checkout for `:ssh_conn_idle_timeout` ms (default 60 s) AND has no open channels
  (checked via `:ssh.connection_info/2`, so a long streamed download or hung exec keeps its
  conn alive) closes itself. Exits are trapped so a supervisor shutdown reaches
  `terminate/2` and closes the SSH connection politely instead of dropping it on the remote
  sshd; `child_spec/1` spells out the 5 s that gives it. Children are `restart: :temporary`:
  the pool, not the supervisor, decides when a replacement is needed — a `:permanent`
  restart would both resurrect connections nobody asked for and burn the
  DynamicSupervisor's restart intensity on routine idle expiries.

  The process is deliberately not linked to its callers: `DynamicSupervisor.start_child`
  links it to the supervisor, so a caller dying never takes the pooled connection down —
  the ssh handler closes the dead caller's channels and the connection carries on.

  Two distinct failure paths keep a dead host cheap:

    * A dial that fails leaves the Conn registered in a `:failed` cool-down
      (`:ssh_conn_failed_cooldown` ms, default 5 s) that answers checkouts with the cached
      reason in microseconds. Without it every caller — and the tmux poller retries on a
      timer, per host, forever — paid another full `@connect_timeout` into the void. When the
      window expires the Conn stops, so the next caller after it dials for real.
    * A pooled connection that turns out to be half-open (peer rebooted, NAT dropped the
      flow — the data plane sets no keepalive, so OTP notices nothing until someone tries to
      use it) is reported by its user through `invalidate/3` and drops out of the pool at
      once, with NO cool-down: that is evidence about one TCP flow, not about the host, so
      the very next checkout should dial rather than fast-fail.

  Telemetry: `[:termelix, :ssh, :connect, :start | :stop | :failure]` around the handshake,
  `[:termelix, :ssh, :conn, :checkout]` per checkout (`status: :ready | :queued | :cooldown` —
  a pool that is working shows mostly `:ready`), `[:termelix, :ssh, :conn, :invalidate]` per
  evicted half-open connection, and `[:termelix, :ssh, :conn, :expire]` on idle close.
  Metadata carries host/port only: `conn_opts` holds the password and the PEM key and must
  never be handed to a telemetry handler.
  """
  use GenServer

  alias Termelix.SSH.ConnectOpts

  @connect_timeout 15_000
  @default_idle_timeout 60_000
  # Short enough that a host coming back up is picked up within seconds, long enough to
  # collapse the burst a single page load fires (overview + panes + metrics probes).
  @default_failed_cooldown 5_000
  # How long `terminate/2` waits for the polite close before giving up on it — see `close/1`.
  @close_timeout 1_000

  # --- public API -------------------------------------------------------------

  @doc false
  def child_spec({key, _conn_opts} = arg) do
    # `:temporary` — never supervisor-restarted. Idle expiry and connect failures are
    # routine, and restarting on them would drain the DynamicSupervisor's restart
    # intensity (3/60s) until it gives up and dies; the pool spawns a fresh Conn lazily
    # on the next checkout instead.
    #
    # `shutdown: 5_000` is the worker default, spelled out because `init/1` now traps exits
    # and that turns it into the real budget `terminate/2` has to close the SSH connection
    # before the supervisor brutal-kills. The two must be changed together.
    %{
      id: {__MODULE__, key},
      start: {__MODULE__, :start_link, [arg]},
      restart: :temporary,
      shutdown: 5_000
    }
  end

  def start_link({key, conn_opts}) do
    # The registry VALUE carries the owner so `Pool.close_user_conns/1` can select on it
    # without a call into every connection — the same arrangement `Termelix.Tunnels` and
    # `Termelix.Terminal.SessionManager` use.
    value = %{owner_id: Map.get(conn_opts, :owner_id)}

    GenServer.start_link(__MODULE__, conn_opts,
      name: {:via, Registry, {Termelix.SSH.ConnRegistry, key, value}}
    )
  end

  @doc """
  Wait (bounded by `timeout`) for the connection to be ready and return `{:ok, conn}`.

  Returns `{:error, reason}` with the real `:ssh.connect` reason when the handshake
  failed (immediately, without dialing, while the failure is inside its cool-down window),
  `{:error, :timeout}` when the wait outlived `timeout`, and `{:error, :gone}` when the Conn
  died between lookup and call (the pool retries that once on a fresh process).
  """
  def checkout(pid, timeout) do
    GenServer.call(pid, :checkout, timeout)
  catch
    :exit, {:timeout, _} -> {:error, :timeout}
    :exit, _ -> {:error, :gone}
  end

  @doc """
  Report that the connection handed out by `checkout/2` is unusable — a session-channel open
  that timed out or found the connection closed, i.e. the half-open case nothing else
  detects. The Conn drops out of the pool so the next checkout dials a fresh connection.

  Asynchronous by design: the caller is mid-operation and must not block on the eviction, and
  message ordering means a checkout it issues afterwards is served after this one is handled.
  `class` must be an atom — it becomes telemetry metadata. A report naming a connection this
  Conn no longer owns (a caller that checked out before a reconnect) is ignored.
  """
  @spec invalidate(pid(), pid(), atom()) :: :ok
  def invalidate(pid, conn, class) when is_atom(class) do
    GenServer.cast(pid, {:invalidate, conn, class})
  end

  # --- server -----------------------------------------------------------------

  @impl true
  def init(conn_opts) do
    # Without trapping, a supervisor `:shutdown` kills this process outright and the
    # `terminate/2` below never runs, so every pooled connection dies unclosed on redeploy.
    # The only signal whose handling this changes is the connector's exit — see the
    # `{:EXIT, ...}` clause; the ssh connection is monitored, not linked, so its death still
    # arrives as `:DOWN`, and `gen_server` intercepts the parent's exit before `handle_info`.
    Process.flag(:trap_exit, true)

    {:ok,
     %{
       conn_opts: conn_opts,
       conn: nil,
       conn_monitor: nil,
       connector: nil,
       status: :connecting,
       failure_reason: nil,
       waiters: [],
       last_used_at: nil,
       idle_timer: nil,
       connect_started_at: nil
     }, {:continue, :connect}}
  end

  # Connect in a linked spawn rather than inline: a blocking handshake here would leave
  # checkout calls unanswered in the mailbox (and a failure would stop the server without
  # ever seeing them). The spawn owns the ssh link until it replies and exits `:normal`
  # (which the conn ignores); if the Conn is stopped mid-handshake (`:shutdown` from the
  # supervisor — the only stop possible before `:ready`), the link tears the half-open
  # connection down with the spawn.
  @impl true
  def handle_continue(:connect, %{conn_opts: opts} = state) do
    parent = self()

    :telemetry.execute(
      [:termelix, :ssh, :connect, :start],
      %{system_time: System.system_time()},
      meta(state)
    )

    connector =
      spawn_link(fn ->
        result =
          :ssh.connect(
            String.to_charlist(opts.host),
            opts.port,
            ConnectOpts.build(opts),
            @connect_timeout
          )

        send(parent, {:connect_result, self(), result})
      end)

    {:noreply, %{state | connector: connector, connect_started_at: System.monotonic_time()}}
  end

  @impl true
  def handle_call(:checkout, _from, %{status: :ready, conn: conn} = state) do
    emit_checkout(state, :ready)
    {:reply, {:ok, conn}, %{state | last_used_at: now()} |> arm_idle_timer()}
  end

  def handle_call(:checkout, from, %{status: :connecting} = state) do
    emit_checkout(state, :queued)
    {:noreply, %{state | waiters: [from | state.waiters]}}
  end

  # Inside the cool-down window after a failed dial: hand back the reason the dial produced
  # instead of spending another `@connect_timeout` on a host that was unreachable moments ago.
  def handle_call(:checkout, _from, %{status: :failed, failure_reason: reason} = state) do
    emit_checkout(state, :cooldown)
    {:reply, {:error, reason}, state}
  end

  @impl true
  def handle_cast({:invalidate, conn, class}, %{conn: conn} = state) do
    :telemetry.execute(
      [:termelix, :ssh, :conn, :invalidate],
      %{count: 1},
      Map.put(meta(state), :class, class)
    )

    # No cool-down here: a half-open flow says nothing about the host's reachability (a NAT
    # idle-drop is the common cause and the peer is usually up), so the next checkout must
    # get a real dial, not a cached failure.
    {:stop, :normal, state}
  end

  def handle_cast({:invalidate, _stale_conn, _class}, state), do: {:noreply, state}

  @impl true
  def handle_info({:connect_result, connector, result}, %{connector: connector} = state) do
    case result do
      {:ok, conn} ->
        Enum.each(state.waiters, &GenServer.reply(&1, {:ok, conn}))

        :telemetry.execute(
          [:termelix, :ssh, :connect, :stop],
          %{duration: connect_duration(state), count: 1},
          Map.put(meta(state), :queued_waiters, length(state.waiters))
        )

        {:noreply,
         %{
           state
           | conn: conn,
             conn_monitor: Process.monitor(conn),
             connector: nil,
             status: :ready,
             waiters: [],
             last_used_at: now()
         }
         |> arm_idle_timer()}

      {:error, reason} ->
        Enum.each(state.waiters, &GenServer.reply(&1, {:error, reason}))
        emit_failure(state, reason)
        cool_down(state, reason)
    end
  end

  # The connector *crashed* rather than reporting a result (a raise in `ConnectOpts.build/1`
  # or an exit out of `:ssh.connect` — an ordinary refusal arrives as `:connect_result`).
  # Before `init/1` trapped exits this signal killed the Conn outright; now it has to be
  # answered here, or the Conn would sit in `:connecting` forever with its waiters hanging
  # until each one's own call timeout fires.
  def handle_info({:EXIT, connector, reason}, %{connector: connector} = state)
      when reason != :normal do
    Enum.each(state.waiters, &GenServer.reply(&1, {:error, reason}))
    emit_failure(state, :connector_crash)
    # Deterministic (a bad key, a malformed option) far more often than not, so it earns the
    # same cool-down as a refused dial rather than being retried per caller.
    cool_down(state, reason)
  end

  def handle_info(:cooldown_over, %{status: :failed} = state), do: {:stop, :normal, state}

  def handle_info(:idle_check, state) do
    state = %{state | idle_timer: nil}

    if idle?(state) do
      :telemetry.execute(
        [:termelix, :ssh, :conn, :expire],
        %{count: 1, idle_ms: now() - state.last_used_at},
        meta(state)
      )

      {:stop, :normal, state}
    else
      {:noreply, arm_idle_timer(state)}
    end
  end

  # The monitored ssh connection died (network drop, remote close, daemon stop) — stop so
  # the next checkout spawns a fresh connection.
  def handle_info({:DOWN, ref, :process, conn, _reason}, %{conn_monitor: ref, conn: conn} = state) do
    {:stop, :normal, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{conn: conn}) when is_pid(conn), do: close(conn)

  def terminate(_reason, _state), do: :ok

  # `:ssh.close/1` is a `gen_statem` call with an `:infinity` timeout (ssh.erl:422 →
  # ssh_connection_handler.erl:149-155) that writes a disconnect message to the socket first.
  # On a half-open connection — precisely the case `invalidate/3` stops us for — that write
  # can block, and a `terminate/2` that never returns holds the Registry name: every later
  # checkout would queue on a Conn that is already dying, which is worse than the leak we are
  # avoiding. Close from a detached process and wait a bounded slice of the 5 s shutdown
  # budget for it; if the polite close never lands, `ConnectOpts`' `idle_time` reaps the
  # orphaned connection.
  defp close(conn) do
    closer =
      spawn(fn ->
        try do
          :ssh.close(conn)
        catch
          _, _ -> :ok
        end
      end)

    ref = Process.monitor(closer)

    receive do
      {:DOWN, ^ref, :process, ^closer, _reason} -> :ok
    after
      @close_timeout ->
        Process.demonitor(ref, [:flush])
        :ok
    end
  end

  # --- failure cool-down ---------------------------------------------------------

  # Stay registered and fast-fail checkouts for the window, then stop so the next caller
  # dials for real. Rollback: `config :termelix, ssh_conn_failed_cooldown: 0` restores the
  # previous behaviour (stop on the failure, every subsequent checkout dials again).
  defp cool_down(state, reason) do
    case cooldown_timeout() do
      0 ->
        {:stop, :normal, state}

      ms ->
        Process.send_after(self(), :cooldown_over, ms)

        {:noreply,
         %{state | status: :failed, failure_reason: reason, connector: nil, waiters: []}}
    end
  end

  # Read per failure (not at boot) so tests and an operator rollback take effect live.
  defp cooldown_timeout,
    do: Application.get_env(:termelix, :ssh_conn_failed_cooldown, @default_failed_cooldown)

  # --- telemetry ----------------------------------------------------------------

  # Host and port only. `conn_opts` also holds `:password`, `:private_key` and
  # `:key_password`; telemetry metadata is broadcast to every attached handler (and from
  # there into log lines), so nothing credential-shaped may enter it.
  defp meta(%{conn_opts: opts}), do: %{host: opts.host, port: opts.port}

  defp emit_checkout(state, status) do
    :telemetry.execute(
      [:termelix, :ssh, :conn, :checkout],
      %{count: 1},
      Map.put(meta(state), :status, status)
    )
  end

  defp emit_failure(state, reason) do
    :telemetry.execute(
      [:termelix, :ssh, :connect, :failure],
      %{duration: connect_duration(state), count: 1},
      Map.put(meta(state), :class, failure_class(reason))
    )
  end

  defp connect_duration(%{connect_started_at: nil}), do: 0
  defp connect_duration(%{connect_started_at: t}), do: System.monotonic_time() - t

  # A coarse class, never the raw reason: OTP reports a rejected handshake as a charlist
  # ("Unable to connect using the available authentication methods") that embeds the
  # username it tried, and metadata must stay free of anything user-supplied.
  defp failure_class(:timeout), do: :timeout
  defp failure_class({:timeout, _}), do: :timeout
  defp failure_class(:econnrefused), do: :refused
  defp failure_class(reason) when reason in [:ehostunreach, :enetunreach], do: :unreachable
  defp failure_class(:nxdomain), do: :dns
  defp failure_class(:connector_crash), do: :crash
  defp failure_class(reason) when is_binary(reason) or is_list(reason), do: :auth
  defp failure_class(_), do: :other

  # --- idle expiry --------------------------------------------------------------

  # Idle means: no checkout within the idle window AND no open channels — a long-running
  # operation (streamed download, slow exec) pins its conn via the channel it holds.
  defp idle?(%{last_used_at: nil}), do: false

  defp idle?(%{last_used_at: last, conn: conn}) do
    now() - last >= idle_timeout() and not channels_open?(conn)
  end

  defp channels_open?(nil), do: false

  defp channels_open?(conn) do
    case :ssh.connection_info(conn, [:channels]) do
      [channels: channels] when is_list(channels) -> channels != []
      _ -> false
    end
  catch
    _, _ -> false
  end

  defp arm_idle_timer(state) do
    if state.idle_timer, do: Process.cancel_timer(state.idle_timer)
    %{state | idle_timer: Process.send_after(self(), :idle_check, idle_timeout())}
  end

  # Read per check (not at compile/boot time) so tests can shrink the window.
  defp idle_timeout,
    do: Application.get_env(:termelix, :ssh_conn_idle_timeout, @default_idle_timeout)

  defp now, do: System.monotonic_time(:millisecond)
end
