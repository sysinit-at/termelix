defmodule TermelixWeb.TerminalSocketTest do
  @moduledoc """
  Full terminal path at the application layer: register a user, save a host that points at an
  in-VM SSH daemon, then drive `TerminalSocket` through the exact JSON protocol the frontend
  uses (`connectToHost` → `sessionCreated`/`connected`, `input` → echoed `data`,
  `ping` → `pong`), including session persistence: detach, buffered output, `attachSession`
  replay, and `listSessions`.

  We invoke the WebSock callbacks directly (Bandit's framing is library code); attaching the
  test pid means session output lands in this process exactly as it would in the socket.
  """
  use Termelix.DataCase, async: false

  alias TermelixWeb.{OriginCheck, TerminalSocket}
  alias Termelix.{Accounts, Hosts}
  alias Termelix.Terminal.{Bindings, Session, SessionManager}
  alias Termelix.Tmux.Availability

  setup do
    {:ok, _} = Application.ensure_all_started(:ssh)

    dir = Path.join(System.tmp_dir!(), "termelix_term_test_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)

    {_, 0} =
      System.cmd("ssh-keygen", [
        "-t",
        "ed25519",
        "-f",
        Path.join(dir, "ssh_host_ed25519_key"),
        "-N",
        "",
        "-q"
      ])

    shell_fun = fn _user, _peer ->
      spawn(fn ->
        write_banner()
        echo_loop()
      end)
    end

    {:ok, daemon} =
      :ssh.daemon(0,
        system_dir: String.to_charlist(dir),
        user_passwords: [{~c"tester", ~c"secret"}],
        auth_methods: ~c"password",
        shell: shell_fun
      )

    port = daemon_port(daemon)

    on_exit(fn ->
      :ssh.stop_daemon(daemon)
      File.rm_rf(dir)
    end)

    {:ok, user, _admin?} = Accounts.register_user("term-user", "password-123-abc")

    {:ok, host} =
      Hosts.create_host(user.id, %{
        name: "test-daemon",
        ip: "127.0.0.1",
        port: port,
        username: "tester",
        authType: "password",
        password: "secret",
        connectionType: "ssh"
      })

    %{user: user, host: host}
  end

  test "connectToHost → input → data flows through the socket", %{user: user, host: host} do
    {:ok, state} = TerminalSocket.init(%{user_id: user.id})

    connect =
      json(%{type: "connectToHost", data: %{cols: 80, rows: 24, hostConfig: %{id: host.id}}})

    {:push, frames, state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)
    frames_text = frames |> List.wrap() |> Enum.map(fn {:text, t} -> t end) |> Enum.join("\n")
    assert frames_text =~ ~s("type":"sessionCreated")
    assert frames_text =~ ~s("type":"connected")
    assert is_pid(state.session)
    assert is_binary(state.session_id)

    # The shell banner reaches us either replayed inside the connect frames (if it arrived
    # before attach) or as subsequent {:ssh_data, _} messages — possibly split across chunks.
    assert frames_text =~ "welcome" or collect_until(&(&1 =~ "welcome"), 5000)

    # Input is forwarded to the remote shell and echoed back.
    input = json(%{type: "input", data: "hello-term\n"})
    {:ok, ^state} = TerminalSocket.handle_in({input, [opcode: :text]}, state)
    assert collect_until(&(&1 =~ "hello-term"), 5000)

    # ping/pong.
    {:push, {:text, pong}, ^state} =
      TerminalSocket.handle_in({json(%{type: "ping"}), [opcode: :text]}, state)

    assert pong =~ ~s("type":"pong")

    # disconnect tears down the session.
    {:ok, closed} =
      TerminalSocket.handle_in({json(%{type: "disconnect"}), [opcode: :text]}, state)

    assert closed.session == nil
  end

  test "session survives socket death and replays buffered output on attach", %{
    user: user,
    host: host
  } do
    parent = self()

    # Run the first "socket" in a separate process so its death detaches the session.
    first_ws =
      spawn(fn ->
        {:ok, state} = TerminalSocket.init(%{user_id: user.id})

        connect =
          json(%{type: "connectToHost", data: %{cols: 80, rows: 24, hostConfig: %{id: host.id}}})

        {:push, _frames, state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)

        # Generate identifiable output and wait until its echo has come back — since the
        # session appends to its buffer before forwarding to us, seeing the echo proves the
        # marker is buffered. Deterministic: no sleeps.
        input = json(%{type: "input", data: "marker-123\n"})
        {:ok, _} = TerminalSocket.handle_in({input, [opcode: :text]}, state)
        collect_until(&(&1 =~ "marker-123"), 5000) || flunk("echo never arrived")

        send(parent, {:session_id, state.session_id})

        receive do
          :die -> :ok
        end
      end)

    session_id =
      receive do
        {:session_id, sid} -> sid
      after
        5000 -> flunk("no session id from first socket")
      end

    ref = Process.monitor(first_ws)
    send(first_ws, :die)
    assert_receive {:DOWN, ^ref, :process, ^first_ws, _}, 5000
    # The session's own :DOWN from monitoring first_ws is processed before our next call's
    # message, so a subsequent lookup/attach observes the detached-but-alive session.

    # Session still alive after the socket died.
    assert SessionManager.lookup(session_id, user.id)

    # A second socket attaches and gets the buffer replayed.
    {:ok, state2} = TerminalSocket.init(%{user_id: user.id})

    attach =
      json(%{type: "attachSession", data: %{sessionId: session_id, cols: 100, rows: 30}})

    {:push, frames, state2} = TerminalSocket.handle_in({attach, [opcode: :text]}, state2)
    text = frames |> List.wrap() |> Enum.map(fn {:text, t} -> t end) |> Enum.join("\n")
    assert text =~ ~s("type":"sessionAttached")
    assert text =~ "Session reattached"
    assert text =~ "marker-123"
    assert is_pid(state2.session)

    # listSessions shows it.
    {:push, {:text, list}, _} =
      TerminalSocket.handle_in({json(%{type: "listSessions"}), [opcode: :text]}, state2)

    assert list =~ ~s("type":"sessionList")
    assert list =~ session_id

    # Cleanup.
    TerminalSocket.handle_in({json(%{type: "disconnect"}), [opcode: :text]}, state2)
  end

  test "attachSession carrying lastSeq replays the delta, not the whole buffer", %{
    user: user,
    host: host
  } do
    # The seam, tested by the name the clients actually put on the wire. `lastSeq` is a key in
    # a JSON object the server is free to ignore: mistype it on either side and nothing errors,
    # the delta simply never happens and every reattach quietly costs a full scrollback again.
    parent = self()

    first_ws =
      spawn(fn ->
        {:ok, state} = TerminalSocket.init(%{user_id: user.id})

        connect =
          json(%{type: "connectToHost", data: %{cols: 80, rows: 24, hostConfig: %{id: host.id}}})

        {:push, _frames, state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)

        {:ok, _} =
          TerminalSocket.handle_in(
            {json(%{type: "input", data: "before-mark\n"}), [opcode: :text]},
            state
          )

        collect_until(&(&1 =~ "before-mark"), 5000) || flunk("first echo never arrived")

        send(parent, {:session_id, state.session_id})
        receive do: (:die -> :ok)
      end)

    session_id =
      receive do
        {:session_id, sid} -> sid
      after
        5000 -> flunk("no session id from first socket")
      end

    ref = Process.monitor(first_ws)
    send(first_ws, :die)
    assert_receive {:DOWN, ^ref, :process, ^first_ws, _}, 5000

    # Attach with no position: a full replay, and the frame tells us where the stream is now.
    {:ok, state2} = TerminalSocket.init(%{user_id: user.id})
    full = json(%{type: "attachSession", data: %{sessionId: session_id, cols: 100, rows: 30}})
    {:push, frames, state2} = TerminalSocket.handle_in({full, [opcode: :text]}, state2)

    replay = frames |> List.wrap() |> Enum.map(fn {:text, t} -> t end) |> Enum.join("\n")
    assert replay =~ "before-mark"

    mark =
      replay
      |> String.split("\n")
      |> Enum.map(&Jason.decode!/1)
      |> Enum.find_value(fn frame -> frame["type"] == "data" && frame["seq"] end)

    assert is_integer(mark), "the data frame must carry the stream position: #{replay}"

    # More output, then a reattach that declares where we got to.
    {:ok, _} =
      TerminalSocket.handle_in(
        {json(%{type: "input", data: "after-mark\n"}), [opcode: :text]},
        state2
      )

    collect_until(&(&1 =~ "after-mark"), 5000) || flunk("second echo never arrived")

    {:ok, state3} = TerminalSocket.init(%{user_id: user.id})

    delta_frame =
      json(%{
        type: "attachSession",
        data: %{sessionId: session_id, cols: 100, rows: 30, lastSeq: mark}
      })

    {:push, frames3, state3} = TerminalSocket.handle_in({delta_frame, [opcode: :text]}, state3)
    delta = frames3 |> List.wrap() |> Enum.map(fn {:text, t} -> t end) |> Enum.join("\n")

    assert delta =~ "after-mark"

    # Asserted on the RESET FLAG, which is the only race-free discriminator here.
    #
    # Two earlier versions were both wrong for the same underlying reason — a shell repaints
    # whenever it likes (this one emits reverse-index + erase and re-draws earlier lines), so
    # neither the delta's TEXT nor its SIZE is stable. `refute delta =~ "before-mark"` failed when
    # old text was repainted into a correct delta; comparing byte sizes failed when the repaint
    # made the delta larger than the replay it replaced.
    #
    # `reset` does not depend on the shell at all: the server sets it true only when it could NOT
    # produce a delta and is sending the whole buffer instead. So `reset: false` means the delta
    # path ran, which is exactly what breaks if `lastSeq` is ignored.
    frames_decoded =
      delta |> String.split("\n") |> Enum.map(&Jason.decode!/1)

    data_frame = Enum.find(frames_decoded, &(&1["type"] == "data"))

    assert data_frame["reset"] == false,
           "a delta must not be flagged as a reset (got #{inspect(data_frame)})"

    assert is_integer(data_frame["seq"]) and data_frame["seq"] > mark,
           "the delta must advance the stream position past the mark"

    TerminalSocket.handle_in({json(%{type: "disconnect"}), [opcode: :text]}, state3)
  end

  test "a resume against an UNREACHABLE host keeps the binding", %{user: user} do
    # The safety-critical direction of the binding reap. A binding is deleted only when the HOST
    # says the tmux session is gone; an unreachable host is not evidence of anything, and
    # forgetting the binding on a network blink would lose the operator's work on the next
    # reconnect — the exact failure the binding exists to prevent.
    {:ok, host} =
      Hosts.create_host(user.id, %{
        name: "unreachable",
        ip: "127.0.0.1",
        # Nothing listens here, so `Tmux.session_exists?` returns {:error, _}, not {:ok, false}.
        port: 65_012,
        username: "nobody",
        authType: "password",
        password: "x",
        connectionType: "ssh"
      })

    {:ok, binding} = Bindings.upsert(user.id, host.id, "termelix-keepme")
    assert Bindings.get(user.id, host.id, "termelix-keepme")

    {:ok, state} = TerminalSocket.init(%{user_id: user.id})

    resume =
      json(%{
        type: "resumeBinding",
        data: %{hostId: host.id, tmuxSession: "termelix-keepme", cols: 80, rows: 24}
      })

    {:push, {:text, reply}, _state} = TerminalSocket.handle_in({resume, [opcode: :text]}, state)

    assert reply =~ "Failed to connect to host"
    # Still there. This is what fails if the reap is moved outside the `{:ok, false}` branch.
    assert Bindings.get(user.id, host.id, "termelix-keepme")
    assert binding.id
  end

  test "there is no frame that types a stored password into the shell", %{user: user, host: host} do
    # A regression guard for a feature that was removed twice for being a credential-reveal
    # primitive. Writing into the PTY is indistinguishable from the user typing, so whether the
    # secret gets echoed back is decided by the REMOTE's terminal settings — which this server
    # cannot see. Gating on a server-side prompt detector did not help either: the client chooses
    # what the remote prints, so `echo -n "Password: "` manufactures a convincing prompt and the
    # fill that follows is echoed straight into the client's own output.
    #
    # An unknown frame type must be ignored, not answered.
    {:ok, _} = Hosts.update_host(user.id, host.id, %{sudoPassword: "MUST-NEVER-BE-TYPED"})

    {:ok, state} = TerminalSocket.init(%{user_id: user.id})

    connect =
      json(%{type: "connectToHost", data: %{cols: 80, rows: 24, hostConfig: %{id: host.id}}})

    {:push, _frames, state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)

    # Manufacture the prompt the old gate would have accepted, then ask for the fill.
    send(state.session, {:ssh_data, "[sudo] password for tester: "})
    collect_until(&(&1 =~ "password for tester"), 5000) || flunk("prompt never arrived")

    for frame_type <- ["fillStoredPassword", "fillSudoPassword"] do
      assert {:ok, _state} =
               TerminalSocket.handle_in(
                 {json(%{type: frame_type, data: %{field: "sudoPassword"}}), [opcode: :text]},
                 state
               ),
             "#{frame_type} must not be a handled frame"
    end

    # And nothing typed the secret at the shell.
    refute collect_until(&(&1 =~ "MUST-NEVER-BE-TYPED"), 1500)

    TerminalSocket.handle_in({json(%{type: "disconnect"}), [opcode: :text]}, state)
  end

  test "attachSession with an unknown id yields sessionExpired", %{user: user} do
    {:ok, state} = TerminalSocket.init(%{user_id: user.id})
    attach = json(%{type: "attachSession", data: %{sessionId: "nope", cols: 80, rows: 24}})
    {:push, {:text, expired}, _} = TerminalSocket.handle_in({attach, [opcode: :text]}, state)
    assert expired =~ ~s("type":"sessionExpired")
  end

  test "connectToHost to an unreachable host returns the connect-failure error frame", %{
    user: user
  } do
    {:ok, host} =
      Hosts.create_host(user.id, %{
        name: "dead-host",
        ip: "127.0.0.1",
        port: closed_port(),
        username: "tester",
        authType: "password",
        password: "secret",
        connectionType: "ssh"
      })

    {:ok, state} = TerminalSocket.init(%{user_id: user.id})

    connect =
      json(%{type: "connectToHost", data: %{cols: 80, rows: 24, hostConfig: %{id: host.id}}})

    {:push, {:text, err}, state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)
    assert err =~ ~s("type":"error")
    assert err =~ "Failed to connect to host:"
    assert state.session == nil
    assert state.session_id == nil
  end

  test "a connect whose readiness wait times out stops the orphaned session", %{
    user: user,
    host: host
  } do
    # Force the readiness wait to expire before the (real, but not instantaneous) SSH
    # handshake completes: connect_to_host then sees {:error, _} while the session is alive
    # and was never attached. An un-attached session is invisible to expiry eviction, so the
    # socket itself must stop it or it leaks its fd + remote sshd session. Without the fix the
    # handshake finishes and the session stays registered indefinitely.
    Application.put_env(:termelix, :await_ready_timeout_ms, 1)
    on_exit(fn -> Application.delete_env(:termelix, :await_ready_timeout_ms) end)

    {:ok, state} = TerminalSocket.init(%{user_id: user.id})

    connect =
      json(%{type: "connectToHost", data: %{cols: 80, rows: 24, hostConfig: %{id: host.id}}})

    {:push, {:text, err}, state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)
    assert err =~ ~s("type":"error")
    assert err =~ "Failed to connect to host:"
    assert state.session == nil
    assert state.session_id == nil

    # A session was created (valid host → SessionManager.create succeeds), so an empty session
    # list can only mean the socket tore the orphan down — the invariant the fix guarantees.
    assert eventually(fn -> SessionManager.list_user_sessions(user.id) == [] end)
  end

  test "await_ready returns the scrollback once the SSH shell is up", %{user: user, host: host} do
    {:ok, session_id, pid} =
      SessionManager.create(user.id, host.id, host.name, daemon_conn_opts(host))

    assert {:ok, _scrollback} = Session.await_ready(pid)
    assert SessionManager.lookup(session_id, user.id) == pid
    Session.stop(pid)
  end

  test "queued await_ready callers are all answered when the connect fails mid-handshake", %{
    user: user
  } do
    parent = self()

    # A peer that accepts the TCP connection but never speaks SSH: the connect hangs
    # until the socket drops, so the failure lands after the waiters have queued.
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listener)

    acceptor =
      spawn_link(fn ->
        {:ok, sock} = :gen_tcp.accept(listener)
        send(parent, :accepted)

        receive do
          :close -> :gen_tcp.close(sock)
        end
      end)

    {:ok, session_id, pid} =
      SessionManager.create(user.id, 0, "silent-host", %{
        host: "127.0.0.1",
        port: port,
        username: "tester",
        password: "secret"
      })

    assert_receive :accepted, 5000
    :gen_tcp.close(listener)

    session_ref = Process.monitor(pid)

    for _ <- 1..2 do
      spawn(fn -> send(parent, {:waiter_reply, Session.await_ready(pid)}) end)
    end

    # Both waiters are queued inside the session before the failure is triggered.
    assert eventually(fn -> waiter_count(pid) == 2 end)

    send(acceptor, :close)

    assert_receive {:waiter_reply, {:error, _}}, 5000
    assert_receive {:waiter_reply, {:error, _}}, 5000
    assert_receive {:DOWN, ^session_ref, :process, ^pid, :normal}, 5000
    # Registry drops the dead pid on its own monitor, which races the session's :DOWN we
    # observed above — poll rather than read the registry the instant the session exits.
    assert eventually(fn -> SessionManager.lookup(session_id, user.id) == nil end)
  end

  test "re-attach notifies the previously attached socket it was taken over", %{
    user: user,
    host: host
  } do
    parent = self()

    first_ws =
      spawn(fn ->
        {:ok, state} = TerminalSocket.init(%{user_id: user.id})

        connect =
          json(%{type: "connectToHost", data: %{cols: 80, rows: 24, hostConfig: %{id: host.id}}})

        {:push, _frames, state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)
        send(parent, {:session_id, state.session_id})

        receive do
          {:ssh_closed, reason} -> send(parent, {:old_ws_closed, reason})
        after
          5000 -> send(parent, {:old_ws_closed, :no_message})
        end
      end)

    session_id =
      receive do
        {:session_id, sid} -> sid
      after
        5000 -> flunk("no session id from first socket")
      end

    Process.monitor(first_ws)

    # A second socket attaches to the same (still attached) session — a takeover.
    {:ok, state2} = TerminalSocket.init(%{user_id: user.id})

    attach =
      json(%{type: "attachSession", data: %{sessionId: session_id, cols: 100, rows: 30}})

    {:push, frames, state2} = TerminalSocket.handle_in({attach, [opcode: :text]}, state2)
    text = frames |> List.wrap() |> Enum.map(fn {:text, t} -> t end) |> Enum.join("\n")
    assert text =~ ~s("type":"sessionAttached")

    # The old socket got the takeover notice it renders as "disconnected".
    assert_receive {:old_ws_closed, :taken_over}, 5000

    TerminalSocket.handle_in({json(%{type: "disconnect"}), [opcode: :text]}, state2)
  end

  test "an attached socket that stops draining is shut down and the session detaches", %{
    user: user,
    host: host
  } do
    {:ok, _session_id, session} =
      SessionManager.create(user.id, host.id, host.name, daemon_conn_opts(host))

    assert {:ok, _} = Session.await_ready(session)

    # A dead-stuck consumer: mailbox past the 1000-message limit and never reading.
    fake_ws = spawn(fn -> Process.sleep(:infinity) end)
    for _ <- 1..1001, do: send(fake_ws, :stuffed)
    {:ok, _} = Session.attach(session, fake_ws, 80, 24)

    ref = Process.monitor(fake_ws)
    Session.input(session, "trigger-output\n")

    assert_receive {:DOWN, ^ref, :process, ^fake_ws, {:shutdown, :stalled}}, 5000

    # The session survives and is detached, exactly like the socket-death path.
    assert Session.info(session).lastDetachedAt != nil
    Session.stop(session)
  end

  describe "UTF-8 safety of data frames" do
    # A multi-byte glyph split across SSH chunks must never reach the JSON encoder
    # half-finished (it would crash the socket mid-stream — the fzf/tms failure mode).
    test "a codepoint split across chunks is held back and completed" do
      state = %{session: nil, session_id: nil, utf8_tail: <<>>}

      # "┌" is e2 94 8c; deliver the first two bytes, then the last.
      {:push, {:text, frame}, state} =
        TerminalSocket.handle_info({:ssh_data, "ok" <> <<0xE2, 0x94>>}, state)

      assert Jason.decode!(frame)["data"] == "ok"
      assert state.utf8_tail == <<0xE2, 0x94>>

      {:push, {:text, frame}, state} = TerminalSocket.handle_info({:ssh_data, <<0x8C>>}, state)
      assert Jason.decode!(frame)["data"] == "┌"
      assert state.utf8_tail == <<>>
    end

    test "an incomplete tail alone pushes nothing until completed" do
      state = %{session: nil, session_id: nil, utf8_tail: <<>>}

      {:ok, state} = TerminalSocket.handle_info({:ssh_data, <<0xE2>>}, state)
      assert state.utf8_tail == <<0xE2>>
    end

    test "truly invalid bytes are replaced, not fatal" do
      state = %{session: nil, session_id: nil, utf8_tail: <<>>}

      {:push, {:text, frame}, state} =
        TerminalSocket.handle_info({:ssh_data, "a" <> <<0xFF>> <> "b"}, state)

      assert Jason.decode!(frame)["data"] == "a\u{FFFD}b"
      assert state.utf8_tail == <<>>
    end
  end

  describe "post-connect extras (initialPath / executeCommand / tmuxAttachSession)" do
    test "initialPath cds and executeCommand is typed after the delay", %{
      user: user,
      host: host
    } do
      {:ok, state} = TerminalSocket.init(%{user_id: user.id})

      connect =
        json(%{
          type: "connectToHost",
          data: %{
            cols: 80,
            rows: 24,
            hostConfig: %{id: host.id},
            initialPath: "/tmp/some dir",
            executeCommand: "echo exec-ran"
          }
        })

      {:push, _frames, state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)

      # The cd is typed immediately; the echo daemon reflects it back. Single-quoted, because
      # a double-quoted path still expands `$`, backticks and `\` in the remote shell.
      assert collect_until(&(&1 =~ ~s(cd '/tmp/some dir')), 5000)

      # The queued executeCommand arrives as a message to this (socket) process after the
      # delay; route it through handle_info exactly as the real socket would.
      assert_receive {:execute_command, pid, "echo exec-ran"}, 2000
      {:ok, _state} = TerminalSocket.handle_info({:execute_command, pid, "echo exec-ran"}, state)
      assert collect_until(&(&1 =~ "echo exec-ran"), 5000)
    end

    # A POSIX filename may hold any byte but `/` and NUL, the file manager lists whatever is
    # there, and the SPA forwards it verbatim — so both layers of this sink are attacker-shaped.
    test "initialPath neutralises shell metacharacters", %{user: user, host: host} do
      {:ok, state} = TerminalSocket.init(%{user_id: user.id})

      connect =
        json(%{
          type: "connectToHost",
          data: %{
            cols: 80,
            rows: 24,
            hostConfig: %{id: host.id},
            initialPath: ~S|/tmp/$(id > /tmp/pwn)`id`|
          }
        })

      {:push, _frames, _state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)

      # Single-quoted verbatim: the substitution is data, not syntax.
      assert collect_until(&(&1 =~ ~S|cd '/tmp/$(id > /tmp/pwn)`id`'|), 5000)
    end

    # Quoting is a shell-parser control and does nothing to the terminal line discipline.
    # `\x15` is readline's unix-line-discard: it would erase the pending `cd '/tmp` from the
    # edit buffer, leaving `id #'\'''` — with `#` starting a comment — to execute. `\x03`
    # (SIGINT) and `\x7f` (DEL) get there by other routes. Nothing may be typed at all.
    for {label, byte} <- [{"Ctrl-U", "\x15"}, {"Ctrl-C", "\x03"}, {"DEL", "\x7f"}] do
      test "initialPath containing #{label} is refused, not escaped", %{user: user, host: host} do
        {:ok, state} = TerminalSocket.init(%{user_id: user.id})

        connect =
          json(%{
            type: "connectToHost",
            data: %{
              cols: 80,
              rows: 24,
              hostConfig: %{id: host.id},
              initialPath: "/tmp#{unquote(byte)}id #'"
            }
          })

        {:push, _frames, _state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)

        # No `cd` is typed at all — not a quoted one, and above all not a bare `id`.
        refute collect_until(&(&1 =~ "cd " or &1 =~ "uid="), 1500)
      end
    end

    test "tmuxAttachSession types the attach command and reports tmux_session_attached", %{
      user: user,
      host: host
    } do
      {:ok, state} = TerminalSocket.init(%{user_id: user.id})

      connect =
        json(%{
          type: "connectToHost",
          data: %{
            cols: 80,
            rows: 24,
            hostConfig: %{id: host.id},
            tmuxAttachSession: "work"
          }
        })

      {:push, frames, state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)
      frames_text = frames |> List.wrap() |> Enum.map(fn {:text, t} -> t end) |> Enum.join("\n")

      assert frames_text =~ ~s("type":"tmux_session_attached")
      assert frames_text =~ ~s("sessionName":"work")

      # The command was typed into the PTY (the echo daemon reflects it), and the session
      # records the tmux session name for sessionList frames.
      #
      # `new-session -A` rather than `attach-session` since P4: `-A` attaches when the session
      # exists and creates it otherwise, so the monitor's "Attach" action and a first connect
      # are the same command. Asserting on the session NAME as well, because the command verb
      # alone would pass even if it targeted the wrong session.
      assert collect_until(&(&1 =~ "new-session -A" and &1 =~ "work"), 5000)
      assert Session.info(state.session).tmuxSessionName == "work"
    end

    test "a host with session logging on gets an ENCRYPTED transcript", %{user: user, host: host} do
      dir = Path.join(System.tmp_dir!(), "termelix_rec_e2e_#{System.unique_integer([:positive])}")

      # RESTORED, not deleted. `:data_dir` is shared with `Termelix.Crypto.SystemCrypto`, which
      # resolves `DATA_DIR/.env` from it — deleting the key leaves whatever ran before this
      # without the value it set, which is how a passing suite acquires an unexplained
      # intermittent failure in a module that never mentions recordings.
      previous = Application.get_env(:termelix, :data_dir)
      Application.put_env(:termelix, :data_dir, dir)
      # The instance switch. Off by default — see `recording_opts/5`.
      Application.put_env(:termelix, :session_recording_enabled, true)

      on_exit(fn ->
        restore_data_dir(previous)
        Application.delete_env(:termelix, :session_recording_enabled)
        File.rm_rf(dir)
      end)

      {:ok, host} = Hosts.update_host(user.id, host.id, %{enableSessionLogging: true})
      {:ok, state} = TerminalSocket.init(%{user_id: user.id})

      connect =
        json(%{type: "connectToHost", data: %{cols: 80, rows: 24, hostConfig: %{id: host.id}}})

      {:push, _frames, state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)

      TerminalSocket.handle_in(
        {json(%{type: "input", data: "transcript-marker-42\n"}), [opcode: :text]},
        state
      )

      assert collect_until(&(&1 =~ "transcript-marker-42"), 5000)

      # Close the session so the recorder writes its trailer.
      TerminalSocket.handle_in({json(%{type: "disconnect"}), [opcode: :text]}, state)

      files = Path.wildcard(Path.join([dir, "recordings", user.id, "*.cast"]))
      assert [path] = files

      raw = File.read!(path)

      # Encrypted at rest: what was on the operator's screen must not be readable from the
      # volume. That is the whole reason the format exists.
      refute raw =~ "transcript-marker-42"

      key = Termelix.Crypto.UserKeyManager.get_user_dek(user.id)

      assert {:ok, text} = Termelix.Crypto.StreamEnvelope.open(raw, key)
      assert text =~ "transcript-marker-42"

      # ...and it is asciicast v2, so a real player can open it.
      [header | _events] = String.split(text, "\n", trim: true)
      assert %{"version" => 2, "width" => 80} = Jason.decode!(header)
    end

    test "nothing is recorded unless the instance switch is ON", %{user: user, host: host} do
      dir = Path.join(System.tmp_dir!(), "termelix_norec_#{System.unique_integer([:positive])}")
      previous = Application.get_env(:termelix, :data_dir)
      Application.put_env(:termelix, :data_dir, dir)

      on_exit(fn ->
        restore_data_dir(previous)
        File.rm_rf(dir)
      end)

      # `enable_session_logging` is `NOT NULL DEFAULT 1`, so this host — and every host in
      # every existing install — has it set. Wiring recording to that column alone would have
      # started writing a transcript of every session on every host for an operator who never
      # asked for one.
      # Re-read: `create_host/2` returns the struct as INSERTED, and the column's `DEFAULT 1`
      # only shows up on a read — which is exactly what the connect path does.
      assert Hosts.get_for_user(host.id, user.id).enableSessionLogging == true

      {:ok, state} = TerminalSocket.init(%{user_id: user.id})

      connect =
        json(%{type: "connectToHost", data: %{cols: 80, rows: 24, hostConfig: %{id: host.id}}})

      {:push, _frames, state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)
      TerminalSocket.handle_in({json(%{type: "disconnect"}), [opcode: :text]}, state)

      # Opt-in means opt-in. A recording nobody asked for is a secret nobody knows they have.
      assert Path.wildcard(Path.join([dir, "recordings", "**", "*.cast"])) == []
    end

    test "an unsafe tmux session name is ignored, not typed into the PTY", %{
      user: user,
      host: host
    } do
      {:ok, state} = TerminalSocket.init(%{user_id: user.id})

      connect =
        json(%{
          type: "connectToHost",
          data: %{
            cols: 80,
            rows: 24,
            hostConfig: %{id: host.id},
            tmuxAttachSession: "bad\nname"
          }
        })

      {:push, frames, state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)
      frames_text = frames |> List.wrap() |> Enum.map(fn {:text, t} -> t end) |> Enum.join("\n")

      refute frames_text =~ "tmux_session_attached"
      assert Session.info(state.session).tmuxSessionName == nil
    end

    # The redeploy path, which is the whole reason P4 exists.
    #
    # `Availability` caches in ETS, and ETS dies with the container. So on the FIRST connect
    # after a redeploy the cache is always cold — the one moment the operator's tmux session is
    # sitting on the host waiting to be reattached. A cold miss starts a probe and waits 1s for
    # an SSH dial it will usually lose; `:unknown` does not wrap, so the reconnect opened a
    # PLAIN shell and walked straight past the session it was built to recover. `wait_ms: 0`
    # below is that cold miss, deterministically.
    #
    # The binding row is the durable evidence the cache cannot be: it is in SQLite, and it is
    # only ever written after a tmux session actually ran on that host.
    test "reconnect after a restart re-attaches even with a cold availability cache", %{
      user: user,
      host: host
    } do
      Application.put_env(:termelix, :tmux_availability_wait_ms, 0)
      on_exit(fn -> Application.delete_env(:termelix, :tmux_availability_wait_ms) end)
      Availability.reset()

      # What the tab left behind before the redeploy: one binding, for this tab's name.
      name = Termelix.Tmux.session_name(["u", user.id, "h", host.id, "t", "tab-7"])
      {:ok, _} = Bindings.upsert(user.id, host.id, name)

      {:ok, state} = TerminalSocket.init(%{user_id: user.id})

      connect =
        json(%{
          type: "connectToHost",
          data: %{
            cols: 80,
            rows: 24,
            hostConfig: %{id: host.id, instanceId: "tab-7"}
          }
        })

      {:push, frames, _state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)
      frames_text = frames |> List.wrap() |> Enum.map(fn {:text, t} -> t end) |> Enum.join("\n")

      # Not merely "wrapped in tmux": wrapped in THIS TAB'S session. A fresh name would be a new
      # empty shell wearing the right feature's clothes.
      assert frames_text =~ ~s("type":"tmux_session_attached")
      assert frames_text =~ name
      assert collect_until(&(&1 =~ "new-session -A" and &1 =~ name), 5000)
    end

    # The other half of the rule: evidence, not optimism. Without a binding a cold cache still
    # means "we do not know", and not knowing must not put a `tmux: command not found` between
    # the operator and their shell.
    test "a cold cache with no prior binding opens a plain shell", %{user: user, host: host} do
      Application.put_env(:termelix, :tmux_availability_wait_ms, 0)
      on_exit(fn -> Application.delete_env(:termelix, :tmux_availability_wait_ms) end)
      Availability.reset()

      {:ok, state} = TerminalSocket.init(%{user_id: user.id})

      connect =
        json(%{
          type: "connectToHost",
          data: %{
            cols: 80,
            rows: 24,
            hostConfig: %{id: host.id, instanceId: "tab-never-seen"}
          }
        })

      {:push, frames, _state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)
      frames_text = frames |> List.wrap() |> Enum.map(fn {:text, t} -> t end) |> Enum.join("\n")

      refute frames_text =~ "tmux_session_attached"
      refute collect_until(&(&1 =~ "new-session"), 1500)
    end

    # A binding is evidence about the HOST, so it also covers a tab that has never been seen
    # before — the operator opening a new terminal right after a redeploy, on a host they were
    # already using. Scoped to that host: evidence about one machine says nothing about another.
    test "a binding on the host wraps a brand-new tab, but does not leak to another host", %{
      user: user,
      host: host
    } do
      Application.put_env(:termelix, :tmux_availability_wait_ms, 0)
      on_exit(fn -> Application.delete_env(:termelix, :tmux_availability_wait_ms) end)
      Availability.reset()

      old = Termelix.Tmux.session_name(["u", user.id, "h", host.id, "t", "an-older-tab"])
      {:ok, _} = Bindings.upsert(user.id, host.id, old)

      {:ok, state} = TerminalSocket.init(%{user_id: user.id})

      connect =
        json(%{
          type: "connectToHost",
          data: %{cols: 80, rows: 24, hostConfig: %{id: host.id, instanceId: "a-new-tab"}}
        })

      {:push, frames, _state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)
      frames_text = frames |> List.wrap() |> Enum.map(fn {:text, t} -> t end) |> Enum.join("\n")

      # Its own name — the older tab's session must not be hijacked.
      fresh = Termelix.Tmux.session_name(["u", user.id, "h", host.id, "t", "a-new-tab"])
      assert frames_text =~ ~s("type":"tmux_session_attached")
      assert frames_text =~ fresh
      refute frames_text =~ old

      # A different host of the same user has no binding, so it is back to "we do not know".
      {:ok, other} =
        Hosts.create_host(user.id, %{
          ip: "127.0.0.1",
          port: 1,
          username: "tester",
          authType: "key"
        })

      refute TerminalSocket.tmux_wrap?(other, user.id)
    end
  end

  describe "OriginCheck (guards the WS upgrade)" do
    test "allows requests without an origin header (native clients)" do
      conn = Plug.Test.conn(:get, "http://www.example.com/ssh/websocket/")
      assert OriginCheck.allowed?(conn)
    end

    test "allows a same-origin header, with or without the default port" do
      conn = Plug.Test.conn(:get, "http://www.example.com/ssh/websocket/")

      for origin <- [
            "http://www.example.com",
            "http://www.example.com:80",
            "ws://www.example.com"
          ] do
        assert OriginCheck.allowed?(put_origin(conn, origin)), origin
      end
    end

    test "matches the port when it is not the scheme default" do
      conn = Plug.Test.conn(:get, "http://www.example.com:4000/ssh/websocket/")
      assert OriginCheck.allowed?(put_origin(conn, "http://www.example.com:4000"))
      refute OriginCheck.allowed?(put_origin(conn, "http://www.example.com"))
      refute OriginCheck.allowed?(put_origin(conn, "http://www.example.com:4001"))
    end

    test "matches the scheme, accepting the ws/wss equivalents" do
      conn = Plug.Test.conn(:get, "https://www.example.com/ssh/websocket/")
      assert OriginCheck.allowed?(put_origin(conn, "https://www.example.com"))
      assert OriginCheck.allowed?(put_origin(conn, "https://www.example.com:443"))
      assert OriginCheck.allowed?(put_origin(conn, "wss://www.example.com"))
      refute OriginCheck.allowed?(put_origin(conn, "http://www.example.com"))
    end

    test "denies a foreign origin unless it is explicitly configured" do
      conn = Plug.Test.conn(:get, "http://www.example.com/ssh/websocket/")
      refute OriginCheck.allowed?(put_origin(conn, "http://evil.example.com"))

      Application.put_env(:termelix, :allowed_origins, ["http://evil.example.com"])
      on_exit(fn -> Application.delete_env(:termelix, :allowed_origins) end)

      assert OriginCheck.allowed?(put_origin(conn, "http://evil.example.com"))
    end
  end

  test "connectToHost with an unknown host id returns an error frame", %{user: user} do
    {:ok, state} = TerminalSocket.init(%{user_id: user.id})
    connect = json(%{type: "connectToHost", data: %{hostConfig: %{id: 999_999}}})
    {:push, {:text, err}, _state} = TerminalSocket.handle_in({connect, [opcode: :text]}, state)
    assert err =~ ~s("type":"error")
    assert err =~ "Host not found"
  end

  # --- helpers ---

  defp restore_data_dir(nil), do: Application.delete_env(:termelix, :data_dir)
  defp restore_data_dir(value), do: Application.put_env(:termelix, :data_dir, value)

  defp json(map), do: Jason.encode!(map)

  defp daemon_conn_opts(host) do
    %{
      host: "127.0.0.1",
      port: host.port,
      username: "tester",
      password: "secret",
      cols: 80,
      rows: 24
    }
  end

  # A loopback port that is (almost certainly) closed right now.
  defp closed_port do
    {:ok, sock} = :gen_tcp.listen(0, reuseaddr: true)
    {:ok, port} = :inet.port(sock)
    :gen_tcp.close(sock)
    port
  end

  defp put_origin(conn, origin), do: Plug.Conn.put_req_header(conn, "origin", origin)

  defp waiter_count(pid) do
    if Process.alive?(pid), do: length(:sys.get_state(pid).waiters), else: -1
  end

  defp eventually(fun, timeout \\ 5000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    poll_until(fun, deadline)
  end

  defp poll_until(fun, deadline) do
    cond do
      fun.() ->
        true

      System.monotonic_time(:millisecond) >= deadline ->
        false

      true ->
        Process.sleep(20)
        poll_until(fun, deadline)
    end
  end

  # The banner races the client's disconnect: if the channel closed first its io device is gone
  # and `IO.write/1` raises `:terminated` in this unlinked process, which ExUnit charges to the
  # enclosing setup. `echo_loop/0` already tolerates that for every later write; so must this.
  defp write_banner do
    IO.write("welcome\r\n")
  rescue
    _ -> :ok
  end

  defp echo_loop do
    case IO.gets("") do
      :eof -> :ok
      {:error, _} -> :ok
      data -> echo_write(data)
    end
  rescue
    _ -> :ok
  end

  defp echo_write(data) do
    IO.write(data)
    echo_loop()
  end

  defp collect_until(pred, timeout), do: collect_until(pred, "", timeout)

  defp collect_until(pred, acc, timeout) do
    if pred.(acc) do
      true
    else
      receive do
        # The session forwards `{:ssh_data, data, seq}` (the sequence a client stores for a
        # delta reattach); `SSH.Client` still sends the 2-tuple. Accept both — these tests
        # stand in for a socket and see whichever the thing under test produces.
        {:ssh_data, d} -> collect_until(pred, acc <> to_string(d), timeout)
        {:ssh_data, d, _seq} -> collect_until(pred, acc <> to_string(d), timeout)
      after
        timeout -> false
      end
    end
  end

  defp daemon_port(daemon) do
    case :ssh.daemon_info(daemon) do
      {:ok, info} when is_list(info) -> :proplists.get_value(:port, info)
      {:ok, info} when is_map(info) -> Map.get(info, :port)
    end
  end
end
