defmodule Termelix.SSH.Client do
  @moduledoc """
  An interactive SSH shell session over OTP's native `:ssh`, the engine behind the terminal.

  This GenServer *owns* the SSH connection (so it receives the `{:ssh_cm, …}` channel
  messages) and relays shell output to a subscriber process as `{:ssh_data, binary}` /
  `{:ssh_closed, reason}`. It replaces the Node `ssh2`-based terminal transport; OTP `:ssh`
  provides connect/auth/pty/shell natively.

  The connect/pty/shell handshake runs in `handle_continue/2`, not `init/1`, so a slow or
  dead host never wedges the `DynamicSupervisor` that starts these clients. The subscriber
  is told the outcome as `{:ssh_ready}` or `{:ssh_failed, reason}`.

  Backpressure: SSH flow control is only replenished (`adjust_window/3`) while the
  acknowledged-delivered bytes keep the outstanding count below `@outstanding_high`; owed bytes
  accumulate otherwise and are repaid once it falls below `@outstanding_low`. A subscriber that
  never acknowledges (> 4 MB owed)
  is treated as dead and the session closes with `{:ssh_closed, :stalled}`.

  Telemetry: `[:termelix, :ssh, :shell, :start | :ready | :failure]` around the setup, plus
  `[:termelix, :ssh, :shell, :window_debt | :window_repay | :stalled]` for the backpressure
  path above — those are the only evidence a subscriber fell behind, since the window is
  repaid silently once it catches up. `:host_id` / `:session_id` are threaded through from
  `Termelix.Terminal.Session` (both nil for a standalone client). No keystroke, output byte,
  credential or remote path ever enters metadata.

  Currently supports password and private-key auth. Jump hosts / SOCKS5 are follow-ups.
  """
  use GenServer
  require Logger

  alias Termelix.SSH.ConnectOpts

  @connect_timeout 15_000
  # Bounded keystroke send: the 3-arity `:ssh_connection.send/3` is `send(..., infinity)`
  # (`ssh_connection.erl`), so a remote that stops reading its PTY (exhausted channel
  # window) would wedge this process — and while blocked it cannot process `:ssh_cm`
  # output, acks, or the conn `:DOWN`, the one process the backpressure design needs
  # responsive.
  @send_timeout 10_000

  # Subscriber backpressure thresholds (message_queue_len) and flow-control caps.
  # Bytes forwarded but not yet acknowledged as delivered. In BYTES, not messages: the
  # question backpressure answers is "how much data is in flight ahead of the client", and a
  # message count cannot answer it — one chunk may be 4 bytes or 32 KB.
  @outstanding_high 256 * 1024
  @outstanding_low 64 * 1024
  @max_pending_bytes 4 * 1024 * 1024
  @recheck_interval 250

  @type conn_opts :: %{
          required(:host) => String.t(),
          required(:port) => pos_integer(),
          required(:username) => String.t(),
          optional(:password) => String.t() | nil,
          optional(:private_key) => String.t() | nil,
          optional(:key_password) => String.t() | nil,
          optional(:cols) => pos_integer(),
          optional(:rows) => pos_integer(),
          # Telemetry correlation only — never used to connect.
          optional(:host_id) => term(),
          optional(:session_id) => String.t(),
          required(:subscriber) => pid()
        }

  # --- public API -----------------------------------------------------------

  @doc """
  Start a shell session. `{:ok, pid}` means the process started; the SSH handshake
  completes asynchronously and is reported to the subscriber as `{:ssh_ready}` or
  `{:ssh_failed, reason}`.
  """
  @spec start_link(conn_opts()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc "Send terminal input (keystrokes) to the remote shell."
  @spec send_data(pid(), iodata()) :: :ok
  def send_data(pid, data), do: GenServer.cast(pid, {:send, data})

  @doc "Resize the remote PTY."
  @spec resize(pid(), pos_integer(), pos_integer()) :: :ok
  def resize(pid, cols, rows), do: GenServer.cast(pid, {:resize, cols, rows})

  @doc "Close the session."
  @spec close(pid()) :: :ok
  def close(pid), do: GenServer.stop(pid, :normal)

  # --- server ---------------------------------------------------------------

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)

    {:ok,
     %{
       opts: opts,
       conn: nil,
       chan: nil,
       conn_monitor: nil,
       subscriber: opts.subscriber,
       pending_bytes: 0,
       outstanding_bytes: 0,
       recheck_timer: nil,
       # Kept outside `opts`, which is dropped once the handshake completes (below) so the
       # credentials in it stop living in this process' state.
       meta: %{host_id: opts[:host_id], session_id: opts[:session_id]},
       started_at: System.monotonic_time()
     }, {:continue, :connect}}
  end

  # The handshake runs here: a slow/dead host blocks only this process, never the
  # supervisor. ptty_alloc gets an explicit timeout — OTP's 3-arity default is infinity.
  @impl true
  def handle_continue(:connect, %{opts: opts} = state) do
    cols = Map.get(opts, :cols, 80)
    rows = Map.get(opts, :rows, 24)

    :telemetry.execute(
      [:termelix, :ssh, :shell, :start],
      %{system_time: System.system_time()},
      state.meta
    )

    with {:ok, conn} <- connect(opts),
         {:ok, chan} <- :ssh_connection.session_channel(conn, @connect_timeout),
         :success <-
           :ssh_connection.ptty_alloc(conn, chan, ptty_opts(cols, rows), @connect_timeout),
         :ok <- :ssh_connection.shell(conn, chan) do
      send(state.subscriber, {:ssh_ready})

      :telemetry.execute(
        [:termelix, :ssh, :shell, :ready],
        %{duration: System.monotonic_time() - state.started_at, count: 1},
        state.meta
      )

      {:noreply,
       %{state | conn: conn, chan: chan, conn_monitor: Process.monitor(conn), opts: nil}}
    else
      error ->
        reason = normalize_error(error)
        Logger.warning("SSH shell setup failed: #{inspect(error)}")
        send(state.subscriber, {:ssh_failed, reason})

        :telemetry.execute(
          [:termelix, :ssh, :shell, :failure],
          %{duration: System.monotonic_time() - state.started_at, count: 1},
          Map.put(state.meta, :class, failure_class(reason))
        )

        {:stop, :normal, state}
    end
  end

  @impl true
  def handle_cast({:send, data}, %{conn: conn, chan: chan} = state)
      when is_pid(conn) and is_integer(chan) do
    case safe_send(conn, chan, data) do
      :ok ->
        {:noreply, state}

      {:error, reason} ->
        # A dead channel, or a wedged one that could not accept input for
        # `@send_timeout` ms. Stopping beats both alternatives: a bare timeout would
        # silently drop keystrokes, and blocking again wedges the process.
        Logger.warning("SSH channel send failed: #{inspect(reason)}")

        :telemetry.execute(
          [:termelix, :ssh, :shell, :send_failed],
          %{count: 1},
          state.meta
        )

        send(state.subscriber, {:ssh_closed, :send_failed})
        {:stop, :normal, state}
    end
  end

  def handle_cast({:resize, cols, rows}, %{conn: conn, chan: chan} = state)
      when is_pid(conn) and is_integer(chan) do
    :ssh_connection.window_change(conn, chan, cols, rows, 0, 0)
    {:noreply, state}
  end

  # Delivery acknowledged: that many bytes are no longer in flight ahead of the client.
  def handle_cast({:ack, bytes}, state) do
    # Never below zero. An ack for more than is outstanding is a bug in the caller, not a
    # licence to hand the remote an unbounded receive window.
    {:noreply, %{state | outstanding_bytes: max(state.outstanding_bytes - bytes, 0)}}
  end

  # Not connected yet — drop.
  def handle_cast(_cast, state), do: {:noreply, state}

  # Shell output → subscriber. The receive window is only replenished while the
  # subscriber keeps up; owed bytes accumulate and are repaid on :recheck_window.
  @impl true
  def handle_info({:ssh_cm, conn, {:data, chan, _type, data}}, %{conn: conn, chan: chan} = state) do
    send(state.subscriber, {:ssh_data, data})
    account_window(state, byte_size(data))
  end

  def handle_info({:ssh_cm, conn, {:eof, chan}}, %{conn: conn, chan: chan} = state),
    do: {:noreply, state}

  def handle_info(
        {:ssh_cm, conn, {:exit_status, chan, _status}},
        %{conn: conn, chan: chan} = state
      ),
      do: {:noreply, state}

  def handle_info(
        {:ssh_cm, conn, {:exit_signal, chan, _, _, _}},
        %{conn: conn, chan: chan} = state
      ),
      do: {:noreply, state}

  def handle_info({:ssh_cm, conn, {closed_kind, chan}}, %{conn: conn, chan: chan} = state)
      when closed_kind in [:closed, :channel_closed] do
    send(state.subscriber, {:ssh_closed, :remote})
    {:stop, :normal, state}
  end

  # The connection handler died without closing the channel cleanly (OTP sends no
  # {closed, chan} for an internal handler crash) — clean up the zombie session.
  def handle_info({:DOWN, ref, :process, conn, _reason}, %{conn_monitor: ref, conn: conn} = state) do
    send(state.subscriber, {:ssh_closed, :conn_down})
    {:stop, :normal, state}
  end

  # Repay the SSH receive window once enough acked bytes have brought the outstanding count
  # back under the low-water mark.
  def handle_info(:recheck_window, %{conn: conn, chan: chan} = state)
      when is_pid(conn) and is_integer(chan) do
    state = %{state | recheck_timer: nil}

    case state.outstanding_bytes do
      n when n < @outstanding_low ->
        :ssh_connection.adjust_window(conn, chan, state.pending_bytes)
        emit_repay(state, n)
        {:noreply, %{state | pending_bytes: 0}}

      _ ->
        {:noreply, arm_recheck(state)}
    end
  end

  def handle_info(:recheck_window, state), do: {:noreply, %{state | recheck_timer: nil}}

  # The owning session died. Three kill paths bypass its `terminate/2` (revocation's
  # `:kill` escalation, the max-heap guard, supervisor brutal-kill), and this process
  # traps exits precisely so that message arrives here. Without this clause the
  # catch-all below swallows it, and the client survives its owner holding an open SSH
  # connection and a live remote shell — on the revocation path, a "revoked" user's
  # shell staying up on the host.
  def handle_info({:EXIT, pid, _reason}, %{subscriber: pid} = state),
    do: {:stop, :normal, state}

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{conn: conn}) when is_pid(conn) do
    :ssh.close(conn)
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  def terminate(_reason, _state), do: :ok

  @doc """
  Declare that `bytes` of forwarded output have reached the client.

  The backpressure signal, and it is a DECLARATION rather than an observation. It used to be
  `Process.info(subscriber, :message_queue_len)` on every chunk, which is wrong twice over:
  it probes another process on the hot path (a signal that briefly suspends the caller), and a
  mailbox count answers the wrong question. The subscriber's mailbox says nothing about
  whether the *socket* is draining — the session forwards onward — and it inflates whenever the
  session is merely busy with something else, so a healthy terminal throttles itself while a
  genuinely stalled one can look fine.

  An ack is causal: it exists because bytes actually got out. Nothing has to be inferred.
  """
  @spec ack(pid(), non_neg_integer()) :: :ok
  def ack(client, bytes) when is_integer(bytes) and bytes >= 0,
    do: GenServer.cast(client, {:ack, bytes})

  # `:ssh_connection.send/4` returns `:ok | {:error, term()}`; the catch covers the
  # channel or connection dying underneath the call, which OTP reports as an exit,
  # not a tuple.
  defp safe_send(conn, chan, data) do
    :ssh_connection.send(conn, chan, data, @send_timeout)
  catch
    :exit, reason -> {:error, reason}
  end

  # --- backpressure ---------------------------------------------------------

  defp account_window(state, bytes) do
    outstanding = state.outstanding_bytes + bytes
    state = %{state | outstanding_bytes: outstanding}

    case outstanding do
      n when n > @outstanding_high ->
        # Subscriber is behind: withhold the window adjustment so the remote throttles.
        pending = state.pending_bytes + bytes

        if pending > @max_pending_bytes do
          send(state.subscriber, {:ssh_closed, :stalled})

          :telemetry.execute(
            [:termelix, :ssh, :shell, :stalled],
            %{count: 1, pending_bytes: pending, outstanding_bytes: n},
            state.meta
          )

          {:stop, :normal, state}
        else
          :telemetry.execute(
            [:termelix, :ssh, :shell, :window_debt],
            %{bytes: bytes, pending_bytes: pending, outstanding_bytes: n},
            state.meta
          )

          {:noreply, arm_recheck(%{state | pending_bytes: pending})}
        end

      outstanding ->
        # Keeping up (or subscriber gone — the DOWN/EXIT path cleans that up).
        :ssh_connection.adjust_window(state.conn, state.chan, state.pending_bytes + bytes)
        emit_repay(state, outstanding)
        {:noreply, %{state | pending_bytes: 0}}
    end
  end

  # A repay is only interesting when there was debt: the steady-state path adjusts the window
  # on every chunk, and an event per chunk would drown the debt/repay signal it exists for.
  defp emit_repay(%{pending_bytes: 0}, _queue_len), do: :ok

  defp emit_repay(state, queue_len) do
    :telemetry.execute(
      [:termelix, :ssh, :shell, :window_repay],
      %{bytes: state.pending_bytes, queue_len: queue_len || 0},
      state.meta
    )
  end

  defp arm_recheck(%{recheck_timer: nil} = state) do
    %{state | recheck_timer: Process.send_after(self(), :recheck_window, @recheck_interval)}
  end

  defp arm_recheck(state), do: state

  # --- connection -----------------------------------------------------------

  defp connect(opts) do
    host = String.to_charlist(opts.host)
    port = opts.port

    # `:interactive` is the profile that adds TCP keepalive and withholds the `idle_time`
    # backstop — a shell legitimately sits idle with its channel open.
    case :ssh.connect(host, port, ConnectOpts.build(opts, :interactive), @connect_timeout) do
      {:ok, conn} -> {:ok, conn}
      {:error, reason} -> {:error, {:connect_failed, reason}}
    end
  end

  defp ptty_opts(cols, rows) do
    [{:term, ~c"xterm-256color"}, {:width, cols}, {:height, rows}]
  end

  defp normalize_error({:connect_failed, reason}), do: {:connect_failed, reason}
  defp normalize_error(:failure), do: :ptty_alloc_failed
  defp normalize_error({:error, reason}), do: reason
  defp normalize_error(other), do: other

  # A coarse class, never the raw reason: OTP reports a rejected handshake as a charlist that
  # embeds the username it tried (same rule as `Termelix.SSH.Conn`), and metadata must stay
  # free of anything user-supplied.
  defp failure_class({:connect_failed, :timeout}), do: :timeout
  defp failure_class({:connect_failed, :econnrefused}), do: :refused

  defp failure_class({:connect_failed, r}) when r in [:ehostunreach, :enetunreach],
    do: :unreachable

  defp failure_class({:connect_failed, :nxdomain}), do: :dns
  defp failure_class({:connect_failed, r}) when is_binary(r) or is_list(r), do: :auth
  defp failure_class({:connect_failed, _}), do: :connect_failed
  defp failure_class(reason) when is_atom(reason), do: reason
  defp failure_class(_), do: :other
end
