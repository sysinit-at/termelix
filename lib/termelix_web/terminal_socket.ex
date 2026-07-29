defmodule TermelixWeb.TerminalSocket do
  @moduledoc """
  WebSocket handler for the SSH terminal (`/ssh/websocket/`), speaking the original's JSON
  protocol so the existing xterm-based React terminal works unchanged.

  Client → server: `connectToHost` / `attachSession` / `resumeBinding` / `listSessions` /
  `input` / `resize` / `ping` / `disconnect`.
  Server → client: `sessionCreated` / `connected` / `sessionAttached` / `sessionExpired` /
  `sessionList` / `tmux_session_attached` / `bindingResumed` / `data` / `error` / `pong` /
  `disconnected`.

  Each socket talks to a persistent `Termelix.Terminal.Session` (which owns the SSH client and
  a 512 KB scrollback). When the socket dies the session detaches and survives until its
  expiry window lapses, so a reconnecting client can `attachSession` and replay the buffer.

  ## The session of record is the remote tmux session (P4)

  `Termelix.Terminal.Session` is `restart: :temporary` and keeps its state in memory, so
  `docker compose up -d` — the ordinary update path — destroys every BEAM session, and the
  persisted `user_open_tabs.backend_session_id` then points at nothing. The tmux session on the
  host does not care: it is still running, and a human can take it over out-of-band with
  `ssh host` + `tmux attach`. Two paths here make that reachable from the browser:

    * `connectToHost` wraps the shell in `tmux new-session -A -s <name>` when the HOST says so
      (`ssh_data.enable_tmux_shell`, a tri-state — see `Termelix.Schema.Host`) and records the
      (user, host, session) binding, so there is something to come back to;
    * `resumeBinding` starts a fresh BEAM session that attaches to that *existing* tmux session
      instead of opening a new shell. It answers with the same `sessionCreated` / `connected`
      frames `connectToHost` sends, so a client that already handles those needs no new frame
      parsing to benefit.

  ## New frames are opt-in

  `Terminal.tsx`'s `msg.type` chain is an if/else ladder ending in a SILENT fallthrough: a
  frame a shipped Electron or mobile build does not know is not an error there — it is a client
  that sits in "connecting" forever. So a client advertises what it understands,
  `data: {"supports": ["bindingResumed"]}` on any frame, and the frames listed in
  `@gated_frames` go only to clients that named them. With no `supports` a socket behaves
  exactly as it did before P4. The server's own list rides back on `sessionExpired`
  (`serverSupports`) — the frame a client gets when the session its tab remembers is gone,
  which is exactly when it needs to know whether resuming is on offer.
  """
  @behaviour WebSock

  require Logger
  # The level macros (`Logger.warning/1` and friends) are what need the require.
  alias Termelix.Crypto.UserKeyManager
  alias Termelix.Hosts
  alias Termelix.Schema.TerminalBinding
  alias Termelix.SSH.Credential
  alias Termelix.Terminal.{Bindings, Session, SessionManager}
  alias Termelix.Tmux
  alias Termelix.Tmux.Availability

  # Delay before a queued `executeCommand` is typed into the shell, giving a preceding
  # `cd` (and the shell's own prompt setup) time to land — the Node backend's 300ms.
  @execute_command_delay_ms 300

  # Server → client frames introduced after the shipped SPA was built. See the moduledoc: these
  # are pushed only to a client that named them in `supports`.
  @gated_frames ~w(bindingResumed)

  # What this build can do, reported to clients on `sessionExpired`.
  @server_supports ~w(resumeBinding bindingResumed)

  @impl true
  def init(state) do
    # `:off_heap` for the mailbox. A socket carrying a fast stream accumulates messages that
    # would otherwise be copied into (and repeatedly scanned by) the process heap; off-heap
    # keeps GC cost proportional to what the process actually holds rather than to what is
    # queued behind it. Free for a process whose mailbox is normally empty, and the difference
    # between degrading and dying for one that is behind.
    Process.flag(:message_queue_data, :off_heap)

    state =
      Map.merge(
        %{
          session: nil,
          session_id: nil,
          utf8_tail: <<>>,
          supports: MapSet.new(),
          session_monitor: nil
        },
        state
      )

    # Logger metadata lives in the process dictionary, so it tags every later log line this
    # socket emits (session/host are added once connect resolves them).
    Logger.metadata(user_id: Map.get(state, :user_id))
    {:ok, state}
  end

  @impl true
  def handle_in({text, [opcode: :text]}, state) do
    case Jason.decode(text) do
      {:ok, %{"type" => type} = msg} ->
        data = msg["data"] || %{}
        dispatch(type, data, merge_supports(state, data))

      _ ->
        {:push, error_frame("Invalid JSON"), state}
    end
  end

  def handle_in(_frame, state), do: {:ok, state}

  # Session output → client. Frames are JSON text, so every chunk must be valid UTF-8:
  # a multi-byte glyph split across SSH chunks (fzf's box-drawing UI makes these routine)
  # would otherwise crash the JSON encoder and kill the socket mid-stream. Carry the
  # incomplete tail into the next chunk and replace truly invalid bytes.
  @impl true
  # The 2-tuple is a session that predates sequence tracking (or a test harness); treat it as
  # "no sequence" rather than crashing on a shape mismatch.
  def handle_info({:ssh_data, data}, state), do: handle_info({:ssh_data, data, nil}, state)

  def handle_info({:ssh_data, data, seq}, state) do
    # Acknowledge on ENTRY, which is what makes this a causal signal rather than a guess:
    # reaching this clause proves the previous push was handed to Bandit and this process is
    # keeping up. A socket that falls behind stops acking simply by not getting here, and the
    # SSH client withholds the remote's receive window until it does — no mailbox is inspected
    # and nothing is inferred from how busy some other process looks.
    if session = state[:session], do: send(session, {:ack, byte_size(to_string(data))})

    {sendable, tail} = sanitize_utf8(state.utf8_tail <> to_string(data))
    state = %{state | utf8_tail: tail}

    case sendable do
      "" ->
        {:ok, state}

      sendable ->
        # MINUS the held tail. A split codepoint is carried into the next chunk, so the client
        # has not seen those bytes — telling it otherwise would make a reattach resume past
        # them and lose 1-3 bytes of a glyph, which renders as mojibake nobody can trace.
        {:push, frame("data", data_payload(sendable, seq, byte_size(tail))), state}
    end
  end

  # Displaced by another socket attaching to the same session. The SPA has handled
  # `sessionTakenOver` since before this server existed (`Terminal.tsx:1654`: clear, warn,
  # reconnect) and the server had never once sent it — every takeover arrived as a bare
  # `disconnected`, indistinguishable from the host going away. With P4 the reconnect lands
  # back in the same tmux session, so the displaced tab recovers instead of being told,
  # wrongly, that its connection dropped.
  def handle_info({:ssh_closed, :taken_over}, state) do
    {:push, frame("sessionTakenOver", %{sessionId: state.session_id}), forget_session(state)}
  end

  def handle_info({:ssh_closed, _reason}, state) do
    {:push, frame("disconnected", %{}), forget_session(state)}
  end

  # The session died without saying so. Until now nothing watched it: `Session` monitors the
  # socket, never the reverse, so an abnormal exit (a crash, the supervisor shutting it down,
  # the node's memory limit) left this socket holding a dead pid and the UI reading
  # "connected" — keystrokes into a `GenServer.cast` that goes nowhere, forever.
  #
  # A clean exit is the shell ending, which the client already understands as `disconnected`.
  # Anything else is a fault and says so, because "your session crashed" and "you typed exit"
  # must not look the same to whoever is reading the tab — least of all an agent.
  def handle_info({:DOWN, ref, :process, pid, reason}, %{session_monitor: ref} = state) do
    frames =
      case reason do
        r when r in [:normal, :shutdown] ->
          [frame("disconnected", %{})]

        {:shutdown, _reason} ->
          [frame("disconnected", %{})]

        reason ->
          Logger.warning("terminal session #{inspect(pid)} died: #{inspect(reason)}")

          [
            error_frame("Session ended unexpectedly: #{describe(reason)}"),
            frame("disconnected", %{})
          ]
      end

    {:push, frames, forget_session(state)}
  end

  # The queued `executeCommand` from connectToHost — type it into the shell if the
  # session is still the one it was queued for.
  def handle_info({:execute_command, session, command}, %{session: session} = state)
      when is_pid(session) do
    Session.input(session, command <> "\r")
    {:ok, state}
  end

  def handle_info({:execute_command, _stale_session, _command}, state), do: {:ok, state}

  # A session that gave up on this socket (`Session.forward/2`: mailbox past the watermark)
  # kills it — but Bandit runs the WebSock handler inside a ThousandIsland handler that traps
  # exits, so the signal arrives here as a plain message and the catch-all used to discard it.
  # The browser then showed "connected" against a socket the server had already written off,
  # until the session expired ~30 minutes later. Stopping for real is one clause.
  def handle_info({:EXIT, _pid, {:shutdown, :stalled} = reason}, state) do
    {:stop, reason, forget_session(state)}
  end

  def handle_info(_msg, state), do: {:ok, state}

  # Socket death does NOT stop the session — it detaches (the session monitors this process)
  # and survives for the expiry window so the client can reattach.
  @impl true
  def terminate(_reason, _state), do: :ok

  # --- dispatch -------------------------------------------------------------

  defp dispatch("connectToHost", data, state), do: connect_to_host(data, state)

  defp dispatch("resumeBinding", data, state), do: resume_binding(data, state)

  defp dispatch("attachSession", data, state) do
    session_id = data["sessionId"]
    cols = int(data["cols"], 80)
    rows = int(data["rows"], 24)

    case session_id && SessionManager.lookup(session_id, state.user_id) do
      pid when is_pid(pid) ->
        with {:ok, _scrollback} <- await_ready(pid),
             {:ok, buffer} <- try_attach(pid, cols, rows, last_seq(data)) do
          # Reattach is the other entry point that binds this socket to a session.
          Logger.metadata(session_id: session_id)

          frames =
            replay_frames(buffer) ++
              [
                frame("sessionAttached", %{sessionId: session_id}),
                frame("connected", %{message: "Session reattached"})
              ]

          {:push, frames, bind_session(state, pid, session_id)}
        else
          _ -> {:push, expired_frame(session_id), state}
        end

      _ ->
        {:push, expired_frame(session_id), state}
    end
  end

  defp dispatch("listSessions", _data, state) do
    sessions =
      state.user_id
      |> SessionManager.list_user_sessions()
      |> Enum.map(fn {_id, pid, _meta} -> safe_info(pid) end)
      |> Enum.reject(&is_nil/1)

    {:push, frame("sessionList", %{sessions: sessions}), state}
  end

  defp dispatch("input", data, %{session: session} = state) when is_pid(session) do
    if input = data_input(data), do: Session.input(session, input)
    {:ok, state}
  end

  # There is deliberately no "type the stored password into this shell" frame.
  #
  # Two attempts at one are in the history of this file and both were credential-reveal
  # primitives, for the same unavoidable reason: writing into the PTY is indistinguishable from
  # the user typing, so whether the secret is echoed back is decided by the REMOTE's terminal
  # settings, which this server cannot see. At an ordinary prompt the shell echoes, and the
  # plaintext lands in the client's own output stream, in the scrollback replayed to every
  # reattaching client, and in the session recording.
  #
  # The second attempt gated on the server's own detection of a password prompt. That is not a
  # defence either, because the CLIENT chooses what the remote prints: `echo -n "Password: "`
  # puts a convincing prompt at the tail of the buffer, and the fill that follows is echoed
  # straight back. Any heuristic over remote output has this hole, since the input that produces
  # that output comes from the party being defended against.
  #
  # So the feature is gone rather than guarded. `sudoPassword` is still stored (field-encrypted,
  # write-only, never returned) but nothing reads it today — see docs/BUG_REFERENCE.md for what a
  # safe replacement would have to look like.

  defp dispatch("resize", data, %{session: session} = state) when is_pid(session) do
    with c when is_integer(c) <- data["cols"], r when is_integer(r) <- data["rows"] do
      Session.resize(session, c, r)
    end

    {:ok, state}
  end

  defp dispatch("ping", _data, state), do: {:push, frame("pong", %{}), state}

  defp dispatch("disconnect", _data, %{session: session} = state) do
    # Demonitor BEFORE stopping: an intentional disconnect must not come back as a `:DOWN` that
    # pushes `disconnected` onto a socket the client has already moved on from.
    state = forget_session(state)
    stop_session(session)
    {:ok, state}
  end

  # input/resize before a connection, or unknown types: ignore.
  defp dispatch(_type, _data, state), do: {:ok, state}

  # --- connect --------------------------------------------------------------

  defp connect_to_host(data, state) do
    cols = int(data["cols"], 80)
    rows = int(data["rows"], 24)
    host_config = data["hostConfig"] || %{}

    case resolve_conn(host_config, state.user_id, cols, rows) do
      {:ok, conn_opts, host_id, host_name, host} ->
        open_session(
          state,
          conn_opts,
          host_id,
          host_name,
          fn pid, _session_id -> post_connect(pid, data, state, host) end,
          host
        )

      {:error, message} ->
        {:push, error_frame(message), state}
    end
  end

  # Create the BEAM session, wait for its shell, attach this socket, and push the frames the
  # protocol has always used for a new session. `after_attach` adds whatever the entry point
  # owes on top (tmux wrapping, the connect extras, the binding frame).
  defp open_session(state, conn_opts, host_id, host_name, after_attach, host) do
    record = recording_opts(state.user_id, host, host_id, host_name, conn_opts)

    case SessionManager.create(state.user_id, host_id, host_name, conn_opts, record: record) do
      {:ok, session_id, pid} ->
        Logger.metadata(session_id: session_id, host_id: host_id)

        # The SSH handshake runs asynchronously (it no longer blocks creation); wait
        # for it before the success frames so failures surface as the same error
        # frame connect failures produced before.
        with {:ok, _scrollback} <- await_ready(pid),
             {:ok, buffer} <- try_attach(pid, conn_opts.cols, conn_opts.rows, nil) do
          frames =
            [
              frame("sessionCreated", %{sessionId: session_id}),
              frame("connected", %{message: "Connected"})
            ] ++ replay_frames(buffer) ++ after_attach.(pid, session_id)

          {:push, frames, bind_session(state, pid, session_id)}
        else
          {:error, reason} ->
            # await_ready timing out (a slow-but-successful connect) or attach failing
            # leaves a live session that was never attached — and an un-attached session
            # is invisible to expiry eviction, so it leaks its fd + remote sshd session.
            # Stop it, off the socket process: a client still mid-handshake can't process
            # its own stop until the SSH connect returns, which must not wedge this socket.
            # `:noproc` is the exception: the session is already gone, so there is nothing to
            # stop and asking would only spawn a task to discover that.
            unless reason == :noproc, do: stop_session_async(pid)
            {:push, error_frame("Failed to connect to host: #{describe(reason)}"), state}
        end

      {:error, reason} ->
        {:push, error_frame("Failed to connect to host: #{describe(reason)}"), state}
    end
  end

  # Saved host: re-fetch by id and decrypt secrets under the user's DEK (list responses
  # strip them). Ad-hoc: use the supplied fields directly. The host row travels back with the
  # connection options because the tmux decision below is read off it, not off the request.
  defp resolve_conn(%{"id" => id}, user_id, cols, rows) when not is_nil(id) do
    case Hosts.fetch_for_connect(id, user_id) do
      {:ok, host} -> {:ok, host_conn_opts(host, cols, rows), host.id, host_label(host), host}
      {:error, :locked} -> {:error, "Encrypted data is locked"}
      {:error, :not_found} -> {:error, "Host not found"}
    end
  end

  defp resolve_conn(%{"ip" => ip, "username" => username} = hc, _user_id, cols, rows)
       when is_binary(ip) and is_binary(username) do
    conn_opts = %{
      host: ip,
      port: hc["port"] || 22,
      username: username,
      password: hc["password"],
      private_key: hc["key"],
      key_password: hc["keyPassword"],
      cols: cols,
      rows: rows
    }

    {:ok, conn_opts, hc["id"] || 0, hc["name"] || "#{username}@#{ip}", nil}
  end

  defp resolve_conn(_hc, _user_id, _cols, _rows), do: {:error, "Missing host configuration"}

  defp host_conn_opts(host, cols, rows) do
    %{
      host: host.ip,
      port: Hosts.effective_ssh_port(host),
      username: host.username,
      password: host.password,
      private_key: host.key,
      key_password: host.keyPassword,
      # Carried explicitly rather than left to a lookup: `Session.init/1` merges `host_id`
      # in, so this path was covered — but only by that indirection, and only at the cost
      # of a second read. The row is right here.
      host_key: Credential.host_key(host),
      cols: cols,
      rows: rows
    }
  end

  defp host_label(host), do: host.name || "#{host.username}@#{host.ip}"

  # TWO switches, and the instance one defaults to OFF.
  #
  # `enable_session_logging` was the obvious gate and would have been a serious mistake: the
  # column is `NOT NULL DEFAULT 1` and is set on every host in every existing install, so
  # wiring recording to it alone would silently begin writing an encrypted transcript of every
  # session on every host — a new secret-bearing artifact on the same volume as the database,
  # for an operator who never asked for one. That is the same trap the P4 migration refused
  # with `enable_tmux_monitor`, wearing a different column name.
  #
  # So the instance setting `session_recording_enabled` (default off) turns the feature on, and
  # the existing per-host flag then decides which hosts are exempt. One deliberate act to start
  # recording anything; the granularity people already have to stop it.
  #
  # `nil` — do not record — whenever anything is missing: the feature is off, the host says no,
  # there is no host row (an ad-hoc connection), or the DEK is unavailable. A recording that
  # cannot be encrypted is not a recording worth having, and silently writing one in the clear
  # is the failure this whole phase exists to avoid.
  defp recording_opts(user_id, host, host_id, host_name, conn_opts) do
    with true <- recording_enabled?(),
         %{enableSessionLogging: true} <- host,
         key when is_binary(key) <- UserKeyManager.try_get_user_dek(user_id) do
      %{
        session_id: Termelix.Id.generate(),
        user_id: user_id,
        host_id: host_id,
        host_name: host_name,
        key: key,
        cols: Map.get(conn_opts, :cols, 80),
        rows: Map.get(conn_opts, :rows, 24),
        dir: data_dir()
      }
    else
      _ -> nil
    end
  end

  defp data_dir,
    do: Application.get_env(:termelix, :data_dir) || System.get_env("DATA_DIR") || "data"

  # Off unless someone said otherwise. App env wins over the setting so the kill switch is
  # reachable when the database is not, the same arrangement `HostKeyPolicy.mode/0` uses.
  defp recording_enabled? do
    case Application.get_env(:termelix, :session_recording_enabled) do
      value when value in [true, "true"] -> true
      value when value in [false, "false"] -> false
      _ -> Termelix.Settings.get_value("session_recording_enabled") == "true"
    end
  rescue
    _error -> false
  end

  # --- resumeBinding --------------------------------------------------------

  # Attach a NEW BEAM session to an EXISTING remote tmux session. This is the redeploy path:
  # the tab's `backendSessionId` names a BEAM session that died with the old container, so
  # `attachSession` answers `sessionExpired` — and today the SPA's only fallback is
  # `connectToHost`, a brand new shell, which loses whatever the operator (or their agent) was
  # doing. The tmux session is still there; this reattaches to it.
  defp resume_binding(data, state) do
    cols = int(data["cols"], 80)
    rows = int(data["rows"], 24)

    with {:ok, host, name} <- resolve_binding(data, state.user_id),
         :ok <- ensure_session_live(host, name, state.user_id) do
      conn_opts = host_conn_opts(host, cols, rows)

      open_session(
        state,
        conn_opts,
        host.id,
        host_label(host),
        fn pid, session_id -> resume_frames(pid, state, host, name, session_id) end,
        host
      )
    else
      {:error, message} -> {:push, error_frame(message), state}
    end
  end

  # The binding is resolved SERVER-side and always through the ownership-scoped context, so a
  # client can neither name a session on someone else's host nor invent one on its own:
  #
  #   * `bindingId` — a `terminal_bindings` row of the caller's;
  #   * `hostId` + `tmuxSession` — an explicit session on one of the caller's hosts (the tmux
  #     monitor knows these names; a row is written for it on attach);
  #   * `hostId` alone — the host's most recently attached binding.
  defp resolve_binding(data, user_id) do
    with {:ok, host_id, name} <- binding_target(data, user_id),
         {:ok, host} <- Hosts.fetch_for_connect(host_id, user_id) do
      {:ok, host, name}
    else
      {:error, :locked} -> {:error, "Encrypted data is locked"}
      {:error, :not_found} -> {:error, "Host not found"}
      {:error, _message} = error -> error
    end
  end

  defp binding_target(data, user_id) do
    binding_id = int_id(data["bindingId"])
    host_id = int_id(data["hostId"] || host_config_id(data["hostConfig"]))
    requested = present_string(data["tmuxSession"])

    cond do
      binding_id != nil ->
        case find_binding(user_id, binding_id) do
          nil -> {:error, "Binding not found"}
          binding -> {:ok, binding.hostId, binding.tmuxSessionName}
        end

      host_id == nil ->
        {:error, "Missing host configuration"}

      is_binary(requested) ->
        # Screened here rather than at the point of use: this name ends up in a command typed
        # into a live PTY, where quoting is not a defence (see `Tmux.safe_session_name?/1`).
        if Tmux.safe_session_name?(requested),
          do: {:ok, host_id, requested},
          else: {:error, "Invalid tmux session name"}

      true ->
        case latest_binding(user_id, host_id) do
          nil -> {:error, "No tmux session is bound to this host"}
          binding -> {:ok, binding.hostId, binding.tmuxSessionName}
        end
    end
  end

  # A resume that finds nothing to resume must say so. `Tmux.new_or_attach_command/2` would
  # happily CREATE the session (`-A`), leaving the operator in a brand new empty shell that
  # looks like the one they lost — the one outcome this frame exists to prevent.
  defp ensure_session_live(host, name, user_id) do
    case Tmux.session_exists?(host, name) do
      {:ok, true} ->
        :ok

      {:ok, false} ->
        # The tmux session is gone, so the row pointing at it is now a permanent dead end: every
        # future resume for this host finds it, checks the host, and fails the same way. Nothing
        # else ever removed one — `Bindings.delete/2` existed with no callers at all — so the
        # table only ever grew, one row per tab per host, for the life of the install.
        #
        # Deleting it here and not on disconnect is the important part: a binding whose tmux
        # session is still running is exactly what survives a redeploy, and reaping those would
        # destroy the feature this table exists for. Only a session the HOST says is gone is
        # safe to forget.
        forget_dead_binding(user_id, host.id, name)
        {:error, "That tmux session is no longer running on the host"}

      {:error, reason} ->
        # Deliberately not deleted: an unreachable host is not a dead session, and forgetting the
        # binding because the network blinked would lose the work on the next reconnect.
        {:error, "Failed to connect to host: #{describe(reason)}"}
    end
  end

  defp forget_dead_binding(user_id, host_id, name) do
    case Bindings.get(user_id, host_id, name) do
      nil ->
        :ok

      binding ->
        Logger.info("forgetting binding #{binding.id}: tmux session #{name} is gone")
        Bindings.delete(user_id, binding)
    end
  end

  defp resume_frames(pid, state, host, name, session_id) do
    case wrap_in_tmux(pid, name, nil) do
      {:ok, used} ->
        binding = record_binding(state.user_id, host, used)

        [frame("tmux_session_attached", %{sessionName: used})] ++
          supported_frame(state, "bindingResumed", %{
            sessionId: session_id,
            hostId: host.id,
            bindingId: binding && binding.id,
            tmuxSession: used
          })

      :error ->
        [error_frame("Could not attach to the tmux session")]
    end
  end

  # `Bindings` is keyed by (user, host, name) and has no by-id reader; a user's binding list is
  # a handful of rows, so filtering it here beats asking the context for another query shape.
  defp find_binding(user_id, id),
    do: Enum.find(Bindings.list_for_user(user_id), &(&1.id == id))

  # `list_for_user/1` is ordered most-recently-attached first, so the first hit for a host is
  # the session the operator was last in on it.
  # `resumeBinding` legitimately wants "give me back my session on this host", so the most
  # recently attached binding is the right default there. It is NOT the right answer on a plain
  # connect — see binding_for/3.
  defp latest_binding(user_id, host_id),
    do: Enum.find(Bindings.list_for_user(user_id), &(&1.hostId == host_id))

  # Matched on the exact name this tab would use, NOT "the host's most recent binding": the
  # latter meant one monitor "Attach" click permanently redirected every later terminal open on
  # that host into that session.
  defp binding_for(user_id, host_id, instance_id) do
    name = derived_name(user_id, host_id, instance_id)

    Enum.find(
      Bindings.list_for_user(user_id),
      &(&1.hostId == host_id and &1.tmuxSessionName == name)
    )
  end

  # --- post-connect actions (tmux wrapping / initialPath / executeCommand) ---

  # Once the shell is up, either make a remote tmux session the shell, or run the connect
  # extras the SPA sent (`terminal/index.ts: runPostShellCommands`): an `initialPath` cd typed
  # immediately and an `executeCommand` after a short delay. Returns the extra frames to push.
  defp post_connect(pid, data, state, host) do
    case tmux_shell(host, data, state.user_id) do
      {:ok, name} -> connect_tmux_frames(pid, state.user_id, host, name, data)
      :none -> plain_shell_extras(pid, data)
    end
  end

  defp connect_tmux_frames(pid, user_id, host, name, data) do
    # tmux's own `-c` is the right way to start in a directory: it is applied when the session
    # is CREATED, so a resume never types a `cd` into a pane where an agent is already working.
    # An unsafe path is dropped rather than refused here — nothing dangerous can be typed, and
    # the session itself is still the thing the operator asked for.
    start_directory = start_directory(data)

    case wrap_in_tmux(pid, name, start_directory) do
      {:ok, used} ->
        record_binding(user_id, host, used)
        # `executeCommand` still has to run. It is the SPA's "open a terminal and run this"
        # affordance, and dropping it on the tmux path — which is now the DEFAULT path — would
        # have silently broken it for every host with tmux. `initialPath` is not re-typed: tmux
        # applied it with `-c` when the session was created, and typing a `cd` on a resume would
        # move an agent that is already working somewhere else.
        queue_execute_command(pid, data)
        [frame("tmux_session_attached", %{sessionName: used})]

      :error ->
        # tmux would not start: fall back to a plain shell rather than leaving the operator with
        # a session that ignored everything they asked for.
        plain_shell_extras(pid, data)
    end
  end

  defp instance_id(data) do
    case data["hostConfig"] do
      %{"instanceId" => id} when is_binary(id) and id != "" -> id
      _ -> nil
    end
  end

  # WHETHER the shell is wrapped in tmux is the HOST's decision. Before P4 the SPA's
  # `tmuxAttachSession` param decided it alone, which is the wrong source of truth twice over:
  # a client that knows nothing about tmux never got a durable session, and any client could
  # put any connection into tmux. The param now only says WHICH session — the tmux monitor's
  # "Attach" action — and a host that says "never wrap" (`enableTmuxShell == false`) overrides
  # even that.
  defp tmux_shell(host, data, user_id) do
    requested = present_string(data["tmuxAttachSession"])

    cond do
      match?(%{enableTmuxShell: false}, host) -> :none
      is_binary(requested) and Tmux.safe_session_name?(requested) -> {:ok, requested}
      # A name tmux cannot target is not silently "fixed" into some other session: attach to
      # nothing rather than to the wrong thing.
      is_binary(requested) -> :none
      tmux_shell?(host, user_id) -> {:ok, bound_or_derived_name(user_id, host, instance_id(data))}
      true -> :none
    end
  end

  @doc """
  Whether a terminal on `host` for `user_id` is wrapped in tmux. Public only so the rule can be
  tested directly — deciding it wrong is what strands an operator's session, and the connect
  path reaches it through five layers of `cond`.
  """
  @spec tmux_wrap?(map(), String.t()) :: boolean()
  def tmux_wrap?(host, user_id), do: tmux_shell?(host, user_id)

  defp tmux_shell?(%{enableTmuxShell: true}, _user_id), do: true

  # NULL is the tri-state's "not decided — use tmux if the host has it" (see the host schema).
  #
  # Two sources, and the ORDER is the whole point:
  #
  #   1. A binding for this (user, host). Durable, in SQLite, and *evidence*: we only ever write
  #      one after `tmux new-session` ran on that host, so tmux was there. This is what makes
  #      redeploy recovery deterministic — see `bound_before?/2`.
  #   2. Only then `Termelix.Tmux.Availability`'s cache, NOT a probe here: this runs inside the
  #      WebSocket process on the connect path, and an uncached `tmux -V` exec adds a full SSH
  #      round trip — worst case the exec budget, ~105 s — to the one latency number users feel.
  #
  # `:unknown` (probe failed, host unreachable, or nothing cached yet) does NOT wrap. A plain
  # shell works everywhere, so it is the safe answer while the truth is unknown; the cache
  # re-probes after a short TTL and the next connect wraps. The opposite choice would open a
  # "tmux: command not found" shell on a host that merely had a blip.
  defp tmux_shell?(%{enableTmuxShell: nil} = host, user_id),
    do: bound_before?(user_id, host) or Availability.available?(host) == true

  defp tmux_shell?(_host, _user_id), do: false

  # Has this user ever had a tmux session on this host?
  #
  # This exists because `Availability`'s cache is ETS, and ETS does not survive the container
  # restart that IS the redeploy. On the first connect after one the cache is cold, so
  # `available?/2` misses, starts a probe and waits `:tmux_availability_wait_ms` (1s) for an SSH
  # dial + KEX + auth + exec that rarely finishes that fast — `:unknown`, plain shell. Worse, the
  # SPA restores every tab at once: the first connect claims the single-flight probe and all the
  # others lose it and get `:unknown` immediately. So *every* restored tab came back as a plain
  # shell while its tmux session sat there on the host, and the operator's work only reappeared
  # later, unbidden, when a NEW terminal on that host found the cache warm and attached to it.
  #
  # That is the exact scenario P4 exists to fix, failing on the exact path it was built for.
  #
  # A binding row is the durable form of the same fact, and a stronger one: the cache says "tmux
  # answered a version probe", the binding says "we ran a tmux session on this host". If tmux has
  # since been removed, `tmux new-session ... && exit` prints its own error and leaves the plain
  # shell in place (the `&&` is load-bearing), so a stale `true` degrades to noise, not to a lost
  # terminal.
  defp bound_before?(user_id, %{id: host_id}),
    do: Enum.any?(Bindings.list_for_user(user_id), &(&1.hostId == host_id))

  # The name must be identical on every connect of this (user, host) or the operator gets a
  # fresh tmux session per reconnect — the exact loss P4 removes. An existing binding is that
  # durable identity; without one, the deterministic name `Termelix.Terminal.Session` derives
  # for itself (session.ex:343), so both paths agree on the name.
  defp bound_or_derived_name(user_id, %{id: host_id}, instance_id) do
    # Keyed on the TAB, not just (user, host). Two terminal tabs open on one host are two
    # shells the operator asked for; giving them one name made them the same tmux session, so
    # they mirrored each other keystroke for keystroke with no way to opt out.
    #
    # The binding is looked up for the same triple. Preferring the host's most-recently-attached
    # binding instead — which is what this did — meant one click of the monitor's "Attach"
    # permanently redirected every later plain terminal open on that host into that session.
    case binding_for(user_id, host_id, instance_id) do
      nil -> derived_name(user_id, host_id, instance_id)
      binding -> binding.tmuxSessionName
    end
  end

  # A tab id makes the name per-tab and still stable across that tab's reconnects, which is the
  # property P4 exists for. Without one (an older client, a non-SPA caller) it falls back to the
  # per-host name, matching the previous behaviour rather than inventing a random one that would
  # strand the session on every reconnect.
  defp derived_name(user_id, host_id, nil), do: Tmux.session_name(["u", user_id, "h", host_id])

  defp derived_name(user_id, host_id, instance_id),
    do: Tmux.session_name(["u", user_id, "h", host_id, "t", instance_id])

  # Make the remote tmux session the shell: `tmux new-session -A -s <name>` typed into the PTY,
  # which attaches when the session exists and creates it otherwise.
  #
  # `Termelix.Terminal.Session` types this itself when it is handed the host's tmux decision
  # (session.ex:367 `start_tmux/1`), but `SessionManager.create/4` has no argument to carry that
  # decision to it yet, so the socket does it — after checking, so it can never be typed twice
  # (a second `new-session` inside tmux nests a client in itself).
  defp wrap_in_tmux(pid, name, start_directory) do
    case session_tmux_name(pid) do
      existing when is_binary(existing) ->
        {:ok, existing}

      _no_tmux_yet ->
        case Tmux.new_or_attach_command(name, start_directory: start_directory) do
          {:ok, command} ->
            Session.input(pid, command <> "\r")
            Session.set_tmux_session(pid, name)
            {:ok, name}

          {:error, _reason} ->
            :error
        end
    end
  end

  defp session_tmux_name(pid) do
    case safe_info(pid) do
      %{tmuxSessionName: name} -> name
      _ -> nil
    end
  end

  # Persist the (user, host, session) binding so a later socket can resume it — a tmux session
  # nobody recorded is one no future BEAM can find. Saved hosts only (an ad-hoc connection has
  # no row to hang a binding off), and only for names the table accepts:
  # `TerminalBinding.session_name?/1` is stricter than what tmux itself allows, and a name it
  # rejects still gives a working shell for this connect.
  defp record_binding(user_id, host, name) do
    with %{id: host_id} when is_integer(host_id) and host_id > 0 <- host,
         true <- TerminalBinding.session_name?(name),
         {:ok, binding} <- Bindings.upsert(user_id, host_id, name) do
      binding
    else
      _ -> nil
    end
  end

  defp plain_shell_extras(pid, data) do
    # The path comes from the file manager, i.e. from remote directory names, and a POSIX
    # filename may contain any byte but `/` and NUL. Two separate layers have to be safe,
    # because this is typed into a live PTY rather than passed as an argv element:
    #
    #   * the shell parser — `Tmux.shell_escape/1` single-quotes, so `$`, backticks and `\`
    #     are inert. Escaping only `"` (the previous version) left `$(id > /tmp/pwn)`
    #     running as the SSH user.
    #   * the terminal line discipline — quoting does nothing here. `\x15` is readline's
    #     `unix-line-discard`: a directory named `\x15id #'` erases the pending `cd '/tmp`
    #     from the edit buffer, and `id #…` is what reaches the shell. `\x03` does the same
    #     via SIGINT, and a run of `\x7f` erases the prefix a character at a time.
    #
    # So escaping is necessary but not sufficient — `Tmux.safe_start_directory?/1` rejects
    # control bytes outright. Rejecting beats stripping: a path carrying a control byte is not
    # one the operator meant to open, and stripping would silently `cd` somewhere else.
    if path = start_directory(data) do
      Session.input(pid, "cd #{Tmux.shell_escape(path)}\r")
    end

    queue_execute_command(pid, data)

    []
  end

  # Shared by the plain and tmux paths — see connect_tmux_frames/5 for why the tmux path needs
  # it too.
  defp queue_execute_command(pid, data) do
    if command = present_string(data["executeCommand"]) do
      Process.send_after(self(), {:execute_command, pid, command}, @execute_command_delay_ms)
    end

    :ok
  end

  defp start_directory(data) do
    case present_string(data["initialPath"]) do
      nil -> nil
      path -> if Tmux.safe_start_directory?(path), do: path, else: nil
    end
  end

  defp present_string(v) when is_binary(v) do
    case String.trim(v) do
      "" -> nil
      trimmed -> trimmed
    end
  end

  defp present_string(_), do: nil

  # A resume may name its host either directly or inside the `hostConfig` object connectToHost
  # uses; pattern-matched rather than indexed, because `Access` raises on a non-map.
  defp host_config_id(%{"id" => id}), do: id
  defp host_config_id(_hc), do: nil

  # Host and binding ids arrive from JSON, where the SPA is not consistent about numbers vs.
  # strings; the contexts query integer columns and would raise on a binary.
  defp int_id(v) when is_integer(v) and v > 0, do: v

  defp int_id(v) when is_binary(v) do
    case Integer.parse(String.trim(v)) do
      {id, ""} when id > 0 -> id
      _ -> nil
    end
  end

  defp int_id(_v), do: nil

  # --- frames ---------------------------------------------------------------

  # A client advertises the new frame types it understands once, on any frame; the set is
  # cumulative for the life of the socket.
  # Every path that binds this socket to a session goes through here, so the monitor can never
  # be forgotten on one of them — and the previous session's monitor is always released, or a
  # socket that reconnects a few times accumulates stale refs whose `:DOWN` would tear down the
  # session it is *currently* attached to.
  defp bind_session(state, pid, session_id) do
    state = demonitor_session(state)
    %{state | session: pid, session_id: session_id, session_monitor: Process.monitor(pid)}
  end

  defp forget_session(state),
    do: %{demonitor_session(state) | session: nil, session_id: nil}

  defp demonitor_session(%{session_monitor: ref} = state) when is_reference(ref) do
    Process.demonitor(ref, [:flush])
    %{state | session_monitor: nil}
  end

  defp demonitor_session(state), do: state

  defp merge_supports(state, %{"supports" => list}) when is_list(list) do
    advertised = for type <- list, is_binary(type), into: MapSet.new(), do: type
    Map.put(state, :supports, MapSet.union(supports(state), advertised))
  end

  defp merge_supports(state, _data), do: state

  # See the moduledoc: an unknown frame type makes a shipped client hang in "connecting", so
  # a frame added after that client shipped is sent only when the client asked for it.
  defp supported_frame(state, type, payload) do
    if type in @gated_frames and not MapSet.member?(supports(state), type),
      do: [],
      else: [frame(type, payload)]
  end

  defp supports(state), do: Map.get(state, :supports) || MapSet.new()

  # `serverSupports` rides along so a client whose remembered session died in a redeploy can
  # tell "resume the tmux session" from "this server is too old to".
  defp expired_frame(session_id),
    do: frame("sessionExpired", %{sessionId: session_id, serverSupports: @server_supports})

  # --- helpers --------------------------------------------------------------

  # Split a chunk into its longest valid-UTF-8 prefix (invalid bytes replaced) and the
  # incomplete trailing codepoint, if any, to carry into the next chunk.
  @doc """
  Split a byte stream into `{sendable_utf8, held_tail}`.

  Public because it is the one function here whose failure kills a live terminal: a multi-byte
  glyph split across two SSH reads (fzf's box drawing does it on every redraw) that reaches the
  JSON encoder half-finished crashes the socket mid-stream. Properties over arbitrary bytes are
  the only way to be confident about it, and they cannot reach a private function.
  """
  @spec sanitize_utf8(binary()) :: {binary(), binary()}
  def sanitize_utf8(bin), do: sanitize_utf8(bin, [])

  defp sanitize_utf8(bin, acc) do
    case :unicode.characters_to_binary(bin, :utf8, :utf8) do
      valid when is_binary(valid) ->
        {IO.iodata_to_binary(Enum.reverse([valid | acc])), <<>>}

      {:incomplete, valid, rest} ->
        {IO.iodata_to_binary(Enum.reverse([valid | acc])), rest}

      {:error, valid, <<_bad, rest::binary>>} ->
        sanitize_utf8(rest, ["\u{FFFD}", valid | acc])
    end
  end

  # A replay is `%{data:, from:, to:, reset:}` from `Session.attach/5`. `reset` says whether the
  # client may append it (a delta continuing its stream) or must clear first (the buffer was
  # trimmed past where the client was, so the two pieces are not adjacent — appending them
  # would splice unrelated parts of the stream together).
  defp replay_frames(%{data: "", to: to, reset: false}) do
    # Nothing to send, but the client still needs to know where the stream is, or its next
    # reattach asks from a stale offset.
    [frame("data", %{data: "", seq: to, reset: false})]
  end

  defp replay_frames(%{data: data, to: to, reset: reset}) do
    # Replay must be JSON-safe too: a buffer can end mid-codepoint (trim it) or carry invalid
    # bytes from a non-UTF-8 remote (replace them).
    case sanitize_utf8(data) do
      {"", _tail} ->
        [frame("data", %{data: "", seq: to, reset: reset})]

      {sendable, tail} ->
        [frame("data", %{data: sendable, seq: to - byte_size(tail), reset: reset})]
    end
  end

  defp replay_frames(""), do: []

  defp replay_frames(buffer) when is_binary(buffer) do
    case sanitize_utf8(buffer) do
      {"", _tail} -> []
      {sendable, _tail} -> [frame("data", %{data: sendable})]
    end
  end

  # `seq` is omitted rather than sent as null when the session cannot supply one, so a client
  # storing `msg.seq` never records a null and then sends it back as its position.
  defp data_payload(sendable, nil, _held), do: %{data: sendable}
  defp data_payload(sendable, seq, held), do: %{data: sendable, seq: seq - held}

  defp last_seq(data) do
    case data["lastSeq"] do
      n when is_integer(n) and n >= 0 -> n
      _ -> nil
    end
  end

  # A session can die between lookup and the call (expiry/connect-failure race) — map the
  # exit onto the same result the session would have returned.
  # `:exit` here has two causes that must not be conflated, because they call for opposite
  # responses. `:noproc`/`:normal` mean the session is ALREADY GONE — its shell exited, or the
  # SSH connect failed and it stopped — so there is nothing to clean up and nothing to retry.
  # `:timeout` means it is alive and still handshaking, so the caller must stop the session it
  # created or leak an fd and a remote sshd session. Both used to arrive as `:noproc`, which
  # made the timeout path silently skip its own cleanup.
  defp await_ready(pid) do
    Session.await_ready(pid, await_ready_timeout())
  catch
    :exit, {:timeout, _call} -> {:error, :timeout}
    :exit, _ -> {:error, :noproc}
  end

  # Configurable so tests can exercise the readiness-timeout path without a 20s wait.
  defp await_ready_timeout, do: Application.get_env(:termelix, :await_ready_timeout_ms, 20_000)

  defp try_attach(pid, cols, rows, from_seq) do
    Session.attach(pid, self(), cols, rows, from_seq)
  catch
    :exit, {:timeout, _call} -> {:error, :timeout}
    :exit, _ -> {:error, :noproc}
  end

  defp stop_session(session) when is_pid(session) do
    Session.stop(session)
  catch
    :exit, _ -> :ok
  end

  defp stop_session(_), do: :ok

  # Stop a session without blocking the caller: a client still inside :ssh.connect can't
  # process its own stop until the connect returns (up to the connect timeout), and the
  # socket must not wait on that. stop_session/1 already tolerates a dead/mid-handshake pid.
  defp stop_session_async(pid) when is_pid(pid), do: spawn(fn -> stop_session(pid) end)
  defp stop_session_async(_), do: :ok

  defp safe_info(pid) do
    Session.info(pid)
  catch
    :exit, _ -> nil
  end

  defp data_input(data) when is_binary(data), do: data
  defp data_input(%{"data" => d}) when is_binary(d), do: d
  defp data_input(_), do: nil

  defp frame(type, payload), do: {:text, Jason.encode!(Map.put(payload, :type, type))}
  defp error_frame(message), do: frame("error", %{message: message})

  defp int(v, _default) when is_integer(v) and v > 0, do: v
  defp int(_v, default), do: default

  defp describe(:timeout), do: "timed out waiting for the shell"
  defp describe(:noproc), do: "the session ended before it was ready"
  defp describe(:session_limit), do: "too many open sessions"
  defp describe({:connect_failed, reason}) when is_list(reason), do: List.to_string(reason)
  defp describe({:connect_failed, reason}), do: inspect(reason)
  defp describe(reason), do: inspect(reason)
end
