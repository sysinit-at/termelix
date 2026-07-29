defmodule Termelix.Terminal.Session do
  @moduledoc """
  A persistent terminal session, the port of the Node `TerminalSessionManager` entry.

  Sits between the WebSocket and the SSH client: the session owns a `Termelix.SSH.Client`
  (whose subscriber is this process), buffers the last 512 KB of shell output, and
  forwards output to the currently-attached WebSocket process. When the WebSocket dies the
  session *detaches* instead of closing — the SSH connection stays alive — and expires after
  `terminal_session_timeout_minutes` (default 30) unless a new socket reattaches and replays
  the buffer.

  Sessions start *unready*: the SSH handshake runs asynchronously in the client (so a slow
  host never wedges the supervisor) and callers block in `await_ready/2` until the client
  reports `{:ssh_ready}` / `{:ssh_failed, reason}`.

  ## tmux-backed shells (P4)

  This process is `restart: :temporary` with in-memory state, so it dies with the container on
  every `docker compose up -d`. When the caller asks for a tmux shell (`opts.tmux`), the first
  thing typed into the PTY once the shell is up is `tmux new-session -A -s <name>`: the shell
  the user talks to is then a *remote* tmux session, which outlives this process, the SSH
  connection and the redeploy. The BEAM session becomes a disposable attachment — and because
  the tmux session is real, a human can take the same shell over from a plain `ssh host` +
  `tmux attach` at any time, which is the point of the phase.

  Two properties this depends on:

    * the decision is the **host's**, not the client's — it is resolved once at start from
      `opts.tmux` and never from a per-message SPA field, so a client that knows nothing about
      tmux still lands in one;
    * the session name is **stable across reconnects** (`Termelix.Tmux.session_name/1` over a
      durable identity). A name derived from `opts.id` would create a new tmux session on every
      reconnect, which is exactly the failure this phase exists to remove.

  Telemetry: `[:termelix, :terminal, :session, :attach | :detach | :expire]`. The three
  together are what says whether detached sessions are being reattached or just aging out —
  ids and byte counts only, never buffered output.
  """
  use GenServer, restart: :temporary

  require Logger

  alias Termelix.SSH
  alias Termelix.Terminal.Recorder
  alias Termelix.Settings
  alias Termelix.Tmux

  @max_buffer_bytes 512 * 1024
  @trim_trigger_bytes trunc(@max_buffer_bytes * 1.25)
  @default_timeout_minutes 30
  # Attached WebSocket backpressure: past this many queued messages the socket is dead.
  @ws_queue_limit 1_000

  # --- public API -----------------------------------------------------------

  @doc """
  Start a session: spawns the SSH client, which connects asynchronously.

  `opts` carries `:id`, `:user_id`, `:host_id`, `:host_name`, `:conn_opts`, and optionally
  `:tmux` — the host's tmux-shell decision, resolved by the caller from the host row (never
  from an SPA field):

      %{
        enabled: boolean(),                    # default false → today's plain shell
        session_name: String.t() | nil,        # default: derived from user+host, see below
        start_directory: String.t() | nil      # `-c`, honoured only when tmux creates it
      }

  `:session_name` is what makes the shell durable, so it must come from something that
  survives a redeploy — the `terminal_bindings` row once P4's binding table lands. Without
  one, a name derived from `user_id` + `host_id` is used: stable by construction, at the cost
  of a second tab on the same host attaching to (and mirroring) the same tmux session, exactly
  as running `tmux attach` twice locally does.
  """
  # `hibernate_after`: a detached session idles for up to `terminal_session_timeout_minutes`
  # (30 by default) doing nothing at all. Hibernating garbage-collects and sheds the process
  # heap, which is most of what an idle session costs.
  #
  # It is 15s rather than something smaller because an *attached* session is not idle — it
  # forwards every chunk of shell output — and waking from hibernation to do that would trade
  # a real latency cost for a saving that only exists while nothing is happening.
  @hibernate_after_ms 15_000

  # 64 MiB of words on a 64-bit VM. Well above any legitimate session, well below a node.
  @max_heap_words 8 * 1024 * 1024

  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, hibernate_after: @hibernate_after_ms)

  @doc """
  Block until the SSH shell is established. Returns `{:ok, scrollback_binary}` once ready,
  `{:error, reason}` if the connect failed.
  """
  @spec await_ready(pid(), timeout()) :: {:ok, binary()} | {:error, term()}
  def await_ready(session, timeout \\ 20_000),
    do: GenServer.call(session, :await_ready, timeout)

  @doc """
  Attach a WebSocket process; returns the scrollback the client still needs.

  `from_seq` is the stream offset the client has already rendered. The session keeps a
  monotonic byte count, so it can answer with the DELTA rather than the whole buffer — a
  reattach after a brief drop then costs the few hundred bytes that arrived while the socket
  was gone, instead of re-sending and re-rendering up to 512 KB every time. That is the
  difference between a roaming phone reconnecting invisibly and one that stutters.

  Returns `{:ok, %{data:, from:, to:, reset:}}`:

    * `reset: false` — `data` continues the client's stream from `from == from_seq`.
    * `reset: true`  — the client is further behind than the buffer reaches (it was trimmed),
      so `data` is the whole buffer and the client must clear before writing it. Silently
      appending a non-contiguous chunk would corrupt the display in a way nobody could explain.

  `from_seq: nil` means a client that does not speak this, and gets the full buffer.
  """
  @spec attach(pid(), pid(), pos_integer(), pos_integer(), non_neg_integer() | nil) ::
          {:ok, map()} | {:error, term()}
  def attach(session, ws_pid, cols, rows, from_seq \\ nil),
    do: GenServer.call(session, {:attach, ws_pid, cols, rows, from_seq})

  @doc "Send terminal input to the shell."
  def input(session, data), do: GenServer.cast(session, {:input, data})

  @doc "Resize the PTY."
  def resize(session, cols, rows), do: GenServer.cast(session, {:resize, cols, rows})

  @doc "Session metadata for sessionList frames."
  @spec info(pid()) :: map()
  def info(session), do: GenServer.call(session, :info)

  @doc "Record the tmux session this terminal is attached to (nil to clear)."
  @spec set_tmux_session(pid(), String.t() | nil) :: :ok
  def set_tmux_session(session, name), do: GenServer.cast(session, {:set_tmux_session, name})

  @doc """
  Destroy the session (closes the SSH connection).

  Bounded, and it always ends with the process gone. `GenServer.stop/1` waits `:infinity` by
  default, and this process spends its life inside `:ssh` calls that can block — so an
  unbounded stop makes every caller hostage to the slowest session. That is tolerable when a
  user closes one tab and unacceptable for revocation, which walks a whole list: one wedged
  session would leave the rest of a revoked user's shells running indefinitely.
  """
  @stop_timeout_ms 5_000

  @spec stop(pid()) :: :ok
  def stop(session) do
    GenServer.stop(session, :normal, @stop_timeout_ms)
  catch
    # Already gone — the outcome we wanted.
    :exit, {:noproc, _} ->
      :ok

    # Wedged, or not a GenServer at all. The point of the call is that this pid stops.
    :exit, _ ->
      Process.exit(session, :kill)
      :ok
  end

  # --- server ---------------------------------------------------------------

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)

    # Sessions log asynchronously (stalls, SSH close) with no request_id to correlate against,
    # so tag the process itself. These keys only reach the default format once they are listed
    # in `config :logger, :console, metadata:` (config/config.exs).
    Logger.metadata(session_id: opts.id, user_id: opts.user_id, host_id: opts.host_id)

    # `:host_id` / `:session_id` ride along purely so the client's own telemetry can be
    # correlated with this session; `Termelix.SSH.Client` ignores them when connecting.
    client_opts =
      Map.merge(opts.conn_opts, %{
        subscriber: self(),
        host_id: opts.host_id,
        session_id: opts.id
      })

    # A runaway session (a `yes` into a socket that stopped draining, a pathological escape
    # stream) turns a node-wide OOM into one logged dead session. The caveat is real and worth
    # stating: the scrollback is refcounted binaries, which do NOT count toward `max_heap_size`
    # — this bounds mailbox and heap growth, not the buffer, which has its own byte cap.
    Process.flag(:max_heap_size, %{
      size: @max_heap_words,
      kill: true,
      error_logger: true,
      include_shared_binaries: false
    })

    case SSH.Client.start_link(client_opts) do
      {:ok, client} ->
        {:ok, _} =
          Registry.register(Termelix.Terminal.Registry, opts.id, %{
            user_id: opts.user_id,
            host_id: opts.host_id,
            host_name: opts.host_name,
            created_at: System.system_time(:millisecond),
            # Registration happens here, but `SSH.Client.start_link/1` above only *starts* the
            # handshake — it runs in the client's `handle_continue/2`. So a session is listed
            # for up to the connect timeout before it is usable, and one that will fail auth is
            # listed the whole time it is failing. Readers (`/open-tabs/active-sessions`) need
            # to tell those apart without a blocking call per row, so the flag lives in the
            # registry value and is flipped by `{:ssh_ready}` via `Registry.update_value/3`.
            ready: false,
            # Read by `SessionManager`'s cap and list without a call into this process — see
            # its moduledoc. Kept in step by `Registry.update_value/3` on attach and detach.
            last_detached_at: nil
          })

        {:ok,
         %{
           id: opts.id,
           user_id: opts.user_id,
           host_id: opts.host_id,
           host_name: opts.host_name,
           client: client,
           ready: false,
           waiters: [],
           buffer: [],
           buffer_bytes: 0,
           # Total bytes ever appended, and the offset of the oldest byte still buffered.
           # A monotonic COUNT, not an index into the buffer: trimming moves `buffer_start`
           # forward, and the difference is exactly "how far back can this client be and still
           # get a delta".
           seq: 0,
           buffer_start: 0,
           attached_ws: nil,
           ws_monitor: nil,
           expire_timer: nil,
           last_detached_at: nil,
           # Resolved once, here: the wrapping decision and the session name must be identical
           # for every connect of this (user, host), so nothing about them may depend on this
           # process. `tmux_session_name` stays nil until the command is actually typed.
           recorder: start_recorder(opts),
           tmux: tmux_config(opts),
           tmux_session_name: nil,
           created_at: System.system_time(:millisecond)
         }}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def handle_call(:await_ready, _from, %{ready: true} = state) do
    {:reply, {:ok, scrollback(state)}, state}
  end

  def handle_call(:await_ready, from, state) do
    {:noreply, %{state | waiters: [from | state.waiters]}}
  end

  def handle_call({:attach, ws_pid, cols, rows, from_seq}, _from, state) do
    state = cancel_expiry(state)

    takeover? = is_pid(state.attached_ws) and state.attached_ws != ws_pid

    # Takeover: tell the previously-attached socket it has been displaced before swapping.
    if takeover? and Process.alive?(state.attached_ws) do
      send(state.attached_ws, {:ssh_closed, :taken_over})
    end

    if state.ws_monitor, do: Process.demonitor(state.ws_monitor, [:flush])

    SSH.Client.resize(state.client, cols, rows)

    state = %{
      state
      | attached_ws: ws_pid,
        ws_monitor: Process.monitor(ws_pid),
        last_detached_at: nil
    }

    publish_detached_at(state.id, nil)

    replay = scrollback_since(state, from_seq)

    :telemetry.execute(
      [:termelix, :terminal, :session, :attach],
      %{
        count: 1,
        scrollback_bytes: byte_size(replay.data),
        # What the delta actually saved. The pair is the interesting measurement: a client
        # that always resets is a client whose sequence tracking is broken, and that is
        # invisible from the byte count alone.
        buffered_bytes: state.buffer_bytes
      },
      meta(state) |> Map.put(:takeover, takeover?) |> Map.put(:reset, replay.reset)
    )

    {:reply, {:ok, replay}, state}
  end

  @impl true
  def handle_call(:info, _from, state) do
    {:reply,
     %{
       id: state.id,
       hostId: state.host_id,
       hostName: state.host_name,
       createdAt: state.created_at,
       lastDetachedAt: state.last_detached_at,
       tmuxSessionName: state.tmux_session_name,
       # The stream position, so a caller can tell one moment in the output apart from another
       # without holding a copy of the output itself.
       seq: state.seq
     }, state}
  end

  @impl true
  def handle_cast({:input, data}, state) do
    SSH.Client.send_data(state.client, data)
    {:noreply, state}
  end

  def handle_cast({:resize, cols, rows}, state) do
    SSH.Client.resize(state.client, cols, rows)
    {:noreply, state}
  end

  def handle_cast({:set_tmux_session, name}, state) do
    {:noreply, %{state | tmux_session_name: name}}
  end

  # The attached socket reports what it has actually written. Forwarded straight through to the
  # SSH client, which is what decides whether to replenish the remote's window.
  @impl true
  def handle_info({:ack, bytes}, state) when is_integer(bytes) do
    ack(state, bytes)
    {:noreply, state}
  end

  # Shell output: buffer (capped) + forward to the attached socket + record.
  def handle_info({:ssh_data, data}, state) do
    # A cast, so a slow disk shows up as a lagging transcript and never as a lagging terminal.
    if is_pid(state[:recorder]), do: Recorder.record(state.recorder, data)

    # Append FIRST, so the sequence forwarded with the chunk is the offset of its last byte.
    # That is what a client stores and sends back on reattach.
    state = append_buffer(state, data)
    {:noreply, forward(state, data)}
  end

  # The SSH shell is established — wake everyone blocked in await_ready/2.
  def handle_info({:ssh_ready}, state) do
    # Wrap the shell BEFORE waking the waiters: the socket types its own post-connect input
    # (`cd <initialPath>`, `executeCommand`) as soon as `await_ready/2` returns, and that input
    # has to land inside tmux, not in the login shell tmux is about to replace.
    state = start_tmux(state)

    reply = {:ok, scrollback(state)}
    Enum.each(state.waiters, &GenServer.reply(&1, reply))
    # Publish readiness to the registry value so listings can report it without calling us.
    Registry.update_value(Termelix.Terminal.Registry, state.id, &Map.put(&1, :ready, true))
    {:noreply, %{state | ready: true, waiters: []}}
  end

  def handle_info({:ssh_failed, reason}, state) do
    Enum.each(state.waiters, &GenServer.reply(&1, {:error, reason}))
    {:stop, :normal, %{state | waiters: []}}
  end

  def handle_info({:ssh_closed, reason}, state) do
    if state.attached_ws, do: send(state.attached_ws, {:ssh_closed, reason})
    {:stop, :normal, state}
  end

  # The attached WebSocket died — detach and arm the expiry timer.
  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{ws_monitor: ref} = state) do
    {:noreply, detach_ws(state, :socket_down)}
  end

  def handle_info(:expire, %{attached_ws: nil} = state) do
    :telemetry.execute(
      [:termelix, :terminal, :session, :expire],
      %{count: 1, detached_ms: detached_ms(state)},
      meta(state)
    )

    {:stop, :normal, state}
  end

  def handle_info(:expire, state), do: {:noreply, state}

  def handle_info({:EXIT, pid, _reason}, %{client: pid} = state) do
    if state.attached_ws, do: send(state.attached_ws, {:ssh_closed, :client_exit})
    {:stop, :normal, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    # The recorder first: its trailer is what marks the transcript as cleanly closed, and it
    # cannot be written once this process is gone.
    if is_pid(state[:recorder]) and Process.alive?(state.recorder),
      do: Recorder.stop(state.recorder)

    if is_pid(state[:client]) and Process.alive?(state.client), do: SSH.Client.close(state.client)
    :ok
  catch
    _, _ -> :ok
  end

  # --- tmux wrapping --------------------------------------------------------

  # Normalize the caller's tmux decision into a fixed shape. An explicit session name is only
  # honoured when it is safe to type into a PTY; an unsafe one falls back to the derived name
  # rather than to a plain shell, because a tmux-backed shell is the product promise and the
  # derived name is always safe (`Tmux.session_name/1`).
  # Recording is opt-in per host (`enableSessionLogging`) and needs a key: a transcript is a
  # verbatim copy of everything on the operator's screen, which is a stronger secret than most
  # of the fields this app already encrypts.
  #
  # A recorder that will not start is logged and skipped, never fatal. Trading a working shell
  # for a missing transcript is a bad exchange in the moment, and the operator can fix neither
  # while they are trying to work.
  defp start_recorder(%{record: %{key: key} = record}) when is_binary(key) do
    case Recorder.start_link(record) do
      {:ok, pid} ->
        pid

      other ->
        Logger.warning("session recorder did not start: #{inspect(other)}")
        nil
    end
  end

  defp start_recorder(_opts), do: nil

  defp tmux_config(opts) do
    config = Map.get(opts, :tmux) || %{}

    if Map.get(config, :enabled, false) do
      %{
        enabled: true,
        session_name: tmux_session_name(config, opts),
        start_directory: tmux_start_directory(config, opts)
      }
    else
      %{enabled: false, session_name: nil, start_directory: nil}
    end
  end

  defp tmux_session_name(config, opts) do
    case Map.get(config, :session_name) do
      name when is_binary(name) ->
        if Tmux.safe_session_name?(name) do
          name
        else
          Logger.warning(
            "Terminal session #{opts.id}: supplied tmux session name is not a usable tmux " <>
              "target; falling back to the derived name"
          )

          derived_tmux_session_name(opts)
        end

      _ ->
        derived_tmux_session_name(opts)
    end
  end

  # user + host, not `opts.id`: the BEAM session id is new on every connect, so a name derived
  # from it would create a fresh tmux session per reconnect — the exact loss P4 removes.
  defp derived_tmux_session_name(opts),
    do: Tmux.session_name(["u", opts.user_id, "h", opts.host_id])

  defp tmux_start_directory(config, opts) do
    case Map.get(config, :start_directory) do
      dir when is_binary(dir) ->
        if Tmux.safe_start_directory?(dir) do
          dir
        else
          Logger.warning(
            "Terminal session #{opts.id}: tmux start directory contains control bytes; ignoring"
          )

          nil
        end

      _ ->
        nil
    end
  end

  # Type `tmux new-session -A -s <name>` into the PTY once the shell is up. A host without tmux
  # needs no probe: the command builder's trailing `&& exit` keeps the login shell alive when
  # tmux is missing, so the fallback is a plain shell plus one "command not found" line.
  # `tmux_session_name: nil` also makes this idempotent: the command is typed at most once per
  # SSH shell, never again on a reattach (the tmux client is still running in the same PTY).
  defp start_tmux(%{tmux: %{enabled: true, session_name: name}, tmux_session_name: nil} = state)
       when is_binary(name) do
    case Tmux.new_or_attach_command(name, start_directory: state.tmux.start_directory) do
      {:ok, command} ->
        SSH.Client.send_data(state.client, command <> "\r")
        %{state | tmux_session_name: name}

      {:error, reason} ->
        Logger.warning(
          "Terminal session #{state.id}: could not build a tmux attach command " <>
            "(#{inspect(reason)}); continuing with a plain shell"
        )

        state
    end
  end

  defp start_tmux(state), do: state

  # --- helpers --------------------------------------------------------------

  defp scrollback(state), do: IO.iodata_to_binary(Enum.reverse(state.buffer))

  # What this client still needs, given what it says it has.
  #
  # A position is only meaningful WITHIN one session's stream, and this function is the last
  # place that can notice when it is not. Two of the four cases exist for positions that do not
  # belong here: one where the bytes between are gone, and one where the position is from some
  # other stream entirely. Both answer with a full replay and `reset: true`, because the only
  # alternative — appending non-adjacent bytes, or sending nothing at all — renders a screen
  # that never existed.
  defp scrollback_since(state, nil),
    do: %{data: scrollback(state), from: state.buffer_start, to: state.seq, reset: true}

  defp scrollback_since(state, from) when is_integer(from) do
    cond do
      from > state.seq ->
        # Ahead of everything this session has ever produced, so it cannot be a position in
        # this stream — a client reattaching after a restart with an offset it earned in the
        # session that died, most likely. Treating it as "up to date" and sending nothing is
        # how that becomes a permanently blank terminal, so replay everything instead.
        %{data: scrollback(state), from: state.buffer_start, to: state.seq, reset: true}

      from == state.seq ->
        # Genuinely up to date. Common on a fast reconnect, and worth the special case: it
        # turns a reattach into zero bytes rather than a redraw.
        %{data: "", from: state.seq, to: state.seq, reset: false}

      from < state.buffer_start ->
        %{data: scrollback(state), from: state.buffer_start, to: state.seq, reset: true}

      true ->
        full = scrollback(state)
        offset = from - state.buffer_start

        %{
          data: binary_part(full, offset, byte_size(full) - offset),
          from: from,
          to: state.seq,
          reset: false
        }
    end
  end

  defp scrollback_since(state, _other), do: scrollback_since(state, nil)

  # Forward output to the attached socket; a socket that stops draining (mailbox past the
  # limit) is treated as dead and detached exactly like the DOWN path.
  # Nobody attached: the bytes are already "delivered" as far as the SSH window is concerned —
  # they are in the scrollback buffer and no socket is going to drain them. Withholding the
  # window here would throttle a detached session into a stall for no reason.
  defp forward(%{attached_ws: nil} = state, data) do
    ack(state, byte_size(data))
    state
  end

  defp forward(%{attached_ws: ws} = state, data) do
    case Process.info(ws, :message_queue_len) do
      {:message_queue_len, n} when n > @ws_queue_limit ->
        Logger.warning(
          "Terminal session #{state.id}: attached socket #{inspect(ws)} stopped draining " <>
            "(#{n} queued, limit #{@ws_queue_limit}); detaching"
        )

        # This does NOT terminate the socket. Bandit runs the WebSock handler inside a
        # ThousandIsland handler that traps exits (thousand_island/lib/thousand_island/
        # handler.ex:356), so the signal arrives as a plain {:EXIT, ...} message, which
        # TerminalSocket's catch-all handle_info/2 (terminal_socket.ex:67) discards. The browser
        # keeps showing "connected" until this session expires ~30 min later. Killing the socket
        # for real needs a protocol change (P9) — until then, the warning above is the only
        # evidence a stall happened.
        Process.exit(ws, {:shutdown, :stalled})
        detach_ws(state, :stalled)

      _ ->
        send(ws, {:ssh_data, data, state.seq})
        state
    end
  end

  # Tell the SSH client these bytes reached the client. `SSH.Client.account_window/2` withholds
  # the remote's receive window until they do — see its `ack/2`.
  defp ack(%{client: client}, bytes) when is_pid(client), do: SSH.Client.ack(client, bytes)
  defp ack(_state, _bytes), do: :ok

  # Detach the current socket and arm the expiry timer (shared by the DOWN and stall paths).
  defp publish_detached_at(id, value),
    do:
      Registry.update_value(
        Termelix.Terminal.Registry,
        id,
        &Map.put(&1, :last_detached_at, value)
      )

  defp detach_ws(state, reason) do
    if state.ws_monitor, do: Process.demonitor(state.ws_monitor, [:flush])

    timer = Process.send_after(self(), :expire, timeout_minutes() * 60_000)
    detached_at = System.system_time(:millisecond)
    publish_detached_at(state.id, detached_at)

    :telemetry.execute(
      [:termelix, :terminal, :session, :detach],
      %{count: 1, buffer_bytes: state.buffer_bytes},
      Map.put(meta(state), :reason, reason)
    )

    %{
      state
      | attached_ws: nil,
        ws_monitor: nil,
        expire_timer: timer,
        # The same instant the registry value was given, so a reader that compares the two
        # never sees them disagree.
        last_detached_at: detached_at
    }
  end

  # Ids only. The buffer holds shell output (and with it anything the user typed at a
  # password prompt), so nothing derived from it beyond a byte count is ever reported.
  defp meta(state),
    do: %{session_id: state.id, host_id: state.host_id, user_id: state.user_id}

  defp detached_ms(%{last_detached_at: nil}), do: 0
  defp detached_ms(%{last_detached_at: at}), do: System.system_time(:millisecond) - at

  # Buffer is a reversed iolist; trim only once past cap * 1.25 (hysteresis), down to the cap,
  # so steady-state output doesn't re-trim the whole buffer on every chunk.
  defp append_buffer(state, data) do
    bin = to_string(data)
    buffer = [bin | state.buffer]
    bytes = state.buffer_bytes + byte_size(bin)
    seq = state.seq + byte_size(bin)

    if bytes > @trim_trigger_bytes do
      {kept, kept_bytes} = trim_oldest(buffer, bytes)
      # Whatever was dropped came off the OLD end, so the buffer now starts that much later in
      # the stream. Derived from the byte counts rather than tracked separately, so the two can
      # never disagree.
      %{state | buffer: kept, buffer_bytes: kept_bytes, seq: seq, buffer_start: seq - kept_bytes}
    else
      %{state | buffer: buffer, buffer_bytes: bytes, seq: seq}
    end
  end

  defp trim_oldest(buffer, bytes) do
    # Drop chunks from the oldest end (tail of the reversed list) until under the cap.
    {kept_rev, final_bytes} =
      buffer
      |> Enum.reverse()
      |> Enum.reduce({[], bytes}, fn chunk, {acc, remaining} ->
        if remaining > @max_buffer_bytes do
          {acc, remaining - byte_size(chunk)}
        else
          {[chunk | acc], remaining}
        end
      end)

    {kept_rev, final_bytes}
  end

  defp cancel_expiry(%{expire_timer: nil} = state), do: state

  defp cancel_expiry(state) do
    Process.cancel_timer(state.expire_timer)
    %{state | expire_timer: nil}
  end

  defp timeout_minutes do
    case Settings.get_value("terminal_session_timeout_minutes") do
      nil -> @default_timeout_minutes
      v -> String.to_integer(v)
    end
  rescue
    _ -> @default_timeout_minutes
  end
end
