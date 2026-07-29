defmodule Termelix.Terminal.ScrollbackDeltaTest do
  @moduledoc """
  Reattaching should cost the delta, not the buffer.

  Every reattach used to replay the whole scrollback — up to 512 KB, re-sent over the socket and
  re-rendered by the client, however briefly it had been away. On a phone whose connection
  roams that is the difference between reconnecting invisibly and stuttering, and it happens on
  every reconnect, not on unusual ones.

  The idea is Eternal Terminal's: each side declares the offset it has reached and receives only
  what came after. The subtle half is the case where the delta is NOT available — the buffer was
  trimmed past where the client was — because appending non-adjacent pieces of a stream corrupts
  the display in a way nobody can diagnose from the outside.
  """
  use Termelix.DataCase, async: false

  alias Termelix.{Accounts, Hosts}
  alias Termelix.Terminal.{Session, SessionManager}

  setup do
    {:ok, _} = Application.ensure_all_started(:ssh)
    {:ok, user, _} = Accounts.register_user("delta-#{unique()}", "password-123-abc")

    {port, daemon} = quiet_sshd()
    on_exit(fn -> :ssh.stop_daemon(daemon) end)

    {:ok, host} =
      Hosts.create_host(user.id, %{
        name: "delta",
        ip: "127.0.0.1",
        port: port,
        username: "tester",
        authType: "password",
        password: "secret",
        connectionType: "ssh"
      })

    {:ok, _id, session} =
      SessionManager.create(user.id, host.id, host.name, %{
        host: "127.0.0.1",
        port: port,
        username: "tester",
        password: "secret",
        cols: 80,
        rows: 24
      })

    {:ok, _} = Session.await_ready(session, 15_000)
    on_exit(fn -> if Process.alive?(session), do: Session.stop(session) end)

    %{session: session}
  end

  defp unique, do: System.unique_integer([:positive])

  # A daemon whose shell prints nothing on connect: these tests count bytes, and a banner would
  # make every assertion depend on its length.
  defp quiet_sshd do
    dir = Path.join(System.tmp_dir!(), "termelix_delta_#{unique()}")
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

    {:ok, daemon} =
      :ssh.daemon(0,
        system_dir: String.to_charlist(dir),
        user_passwords: [{~c"tester", ~c"secret"}],
        auth_methods: ~c"password",
        shell: fn _u, _p -> spawn(fn -> Process.sleep(:infinity) end) end
      )

    on_exit(fn -> File.rm_rf(dir) end)
    {daemon |> :ssh.daemon_info() |> elem(1) |> Keyword.fetch!(:port), daemon}
  end

  # Feed the session output as the SSH client would, and drain what it forwards to us.
  defp emit(session, data) do
    send(session, {:ssh_data, data})
    :sys.get_state(session)
    drain()
    :ok
  end

  defp drain do
    receive do
      {:ssh_data, _d, _seq} -> drain()
      {:ssh_data, _d} -> drain()
    after
      0 -> :ok
    end
  end

  defp attach(session, from_seq) do
    {:ok, replay} = Session.attach(session, self(), 80, 24, from_seq)
    drain()
    replay
  end

  test "a client that is up to date gets nothing back", %{session: session} do
    attach(session, nil)
    emit(session, "hello world")

    %{to: seq} = attach(session, nil)
    replay = attach(session, seq)

    # The whole point: a reconnect that missed nothing costs nothing. Before this, it cost the
    # entire buffer every time.
    assert replay.data == ""
    assert replay.reset == false
    assert replay.to == seq
  end

  test "a client that missed some output gets exactly that much", %{session: session} do
    attach(session, nil)
    emit(session, "AAAA")

    %{to: mark} = attach(session, nil)

    emit(session, "BBBB")
    emit(session, "CC")

    replay = attach(session, mark)

    # `contains`, not `==`: the remote PTY emits on its own (a window-change from the resize
    # inside `attach` draws an erase sequence), so an exact match here races real output. What
    # must hold is that the delta starts where the client left off and carries what it missed.
    assert replay.data =~ "BBBBCC"
    assert replay.reset == false
    assert replay.from == mark
    assert replay.to >= mark + 6
  end

  test "a client with no sequence gets the whole buffer and is told to reset", %{
    session: session
  } do
    attach(session, nil)
    emit(session, "legacy client sees everything")

    replay = attach(session, nil)

    # An older client does not send a position, so it cannot be given a delta — and must be
    # told to clear, since what it gets is the buffer rather than a continuation.
    assert replay.data =~ "legacy client sees everything"
    assert replay.reset == true
  end

  test "a client further behind than the buffer reaches is told to RESET, not appended to", %{
    session: session
  } do
    attach(session, nil)

    # Overflow the 512 KB buffer so the early bytes are trimmed away.
    emit(session, String.duplicate("x", 200_000))
    stale = 1
    emit(session, String.duplicate("y", 500_000))

    replay = attach(session, stale)

    # The bytes between `stale` and what survives are GONE. Sending the remainder as a delta
    # would splice two non-adjacent parts of the stream together — the client would render a
    # screen that never existed, and nothing downstream could tell.
    assert replay.reset == true
    assert replay.from > stale
    assert byte_size(replay.data) <= 640 * 1024
  end

  test "a sequence beyond what the session has produced replays everything", %{
    session: session
  } do
    attach(session, nil)
    emit(session, "work that predates the restart")

    replay = attach(session, 1_000_000)

    # This is the case a live browser found, and the earlier version of this test asserted the
    # bug: it called an impossible position "up to date" and returned nothing, on the reasoning
    # that sending nothing is always safe. It is not. A position past everything the session
    # produced is not a small delta, it is a position in a DIFFERENT stream — the client is
    # holding an offset it earned in the session that died with the last server restart. Answer
    # it with silence and the operator watches their terminal come back permanently blank with
    # their work apparently gone. The only honest answer is: I cannot place you, here is
    # everything.
    assert replay.data =~ "work that predates the restart"
    assert replay.reset == true
  end

  test "the delta is dramatically smaller than the buffer it replaces", %{session: session} do
    attach(session, nil)
    emit(session, String.duplicate("scrollback ", 20_000))

    %{to: mark, data: full} = attach(session, nil)
    emit(session, "just this")

    delta = attach(session, mark)

    assert byte_size(full) > 200_000
    assert delta.data =~ "just this"
    # The measurement the change exists for: three orders of magnitude, on every reconnect.
    assert byte_size(delta.data) * 1000 < byte_size(full)
  end
end
