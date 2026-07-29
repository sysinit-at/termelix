defmodule Termelix.SSH.ClientTest do
  @moduledoc """
  End-to-end proof that the terminal's SSH engine works over OTP's native `:ssh`.

  A throwaway `:ssh` daemon (password auth, echo shell) runs inside the test VM, so this
  needs no external SSH server. It exercises the exact path the terminal uses:
  connect → auth → ptty_alloc → shell → bidirectional data, plus the readiness handshake
  (`{:ssh_ready}` / `{:ssh_failed, _}`), connection-handler death cleanup, and the
  subscriber backpressure policy.
  """
  use ExUnit.Case, async: false

  alias Termelix.SSH.Client

  setup_all do
    {:ok, _} = Application.ensure_all_started(:ssh)

    dir = Path.join(System.tmp_dir!(), "termelix_ssh_test_#{System.unique_integer([:positive])}")
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

    %{port: port}
  end

  test "connects, opens a shell, and streams bidirectional data", %{port: port} do
    {:ok, client} = Client.start_link(conn_opts(port))

    # The handshake completes asynchronously and is reported to the subscriber.
    assert_receive {:ssh_ready}, 10_000

    # Shell banner arrives unsolicited.
    assert_receive {:ssh_data, banner}, 5000
    assert to_string(banner) =~ "welcome"

    # Input is echoed back by the remote shell.
    Client.send_data(client, "hello world\n")
    assert collect_until(&(&1 =~ "hello world"), 5000)

    # Resize is accepted without error.
    assert :ok = Client.resize(client, 120, 40)

    Client.close(client)
  end

  test "reports {:ssh_failed, _} to the subscriber for a wrong password and stops", %{
    port: port
  } do
    {:ok, client} = Client.start_link(conn_opts(port, "wrong-password"))
    ref = Process.monitor(client)

    assert_receive {:ssh_failed, _reason}, 10_000
    assert_receive {:DOWN, ^ref, :process, ^client, down_reason}, 5000
    assert down_reason in [:normal, :noproc]
  end

  test "cleans up the zombie session when the connection handler dies", %{port: port} do
    {:ok, client} = Client.start_link(conn_opts(port))
    assert_receive {:ssh_ready}, 10_000

    conn = :sys.get_state(client).conn
    ref = Process.monitor(client)

    # OTP sends no {closed, chan} for an internal handler crash; the monitor must catch it.
    Process.exit(conn, :kill)

    assert_receive {:ssh_closed, :conn_down}, 5000
    assert_receive {:DOWN, ^ref, :process, ^client, :normal}, 5000
  end

  test "withholds the window adjustment until delivery is ACKNOWLEDGED, then repays",
       %{port: port} do
    {:ok, client} = Client.start_link(conn_opts(port))
    assert_receive {:ssh_ready}, 10_000
    assert collect_until(&(&1 =~ "welcome"), 5000)

    %{conn: conn, chan: chan} = :sys.get_state(client)

    # A subscriber that is behind is one that has not acked — nothing about its mailbox is
    # consulted any more. The old test stuffed its own mailbox, which measured the wrong thing
    # twice: a session busy with other messages looked stalled, and a session whose SOCKET had
    # stopped draining looked fine, because the count belonged to the wrong process.
    send(client, {:ssh_cm, conn, {:data, chan, 0, :binary.copy("x", 300 * 1024)}})
    assert_receive {:ssh_data, _}, 5000

    state = :sys.get_state(client)
    assert state.outstanding_bytes >= 300 * 1024
    assert state.pending_bytes > 0, "the window must be withheld while bytes are unacknowledged"

    # Acknowledge delivery: that is the whole signal.
    Client.ack(client, 300 * 1024)

    assert eventually(fn -> :sys.get_state(client).pending_bytes == 0 end)

    # Not zero: the shell banner reached this process before the injected chunk and was never
    # acked, because a bare test process is not a session. What matters is that it is back
    # under the low-water mark — that is the condition the repay is gated on.
    assert :sys.get_state(client).outstanding_bytes < 64 * 1024

    Client.close(client)
  end

  test "an over-ack cannot hand the remote an unbounded window", %{port: port} do
    {:ok, client} = Client.start_link(conn_opts(port))
    assert_receive {:ssh_ready}, 10_000
    assert collect_until(&(&1 =~ "welcome"), 5000)

    # Acking more than is outstanding is a bug in the caller. It must clamp at zero rather than
    # go negative, which would let the next N bytes through unaccounted.
    Client.ack(client, 10_000_000)
    assert :sys.get_state(client).outstanding_bytes == 0

    Client.close(client)
  end

  test "a subscriber that never drains past 4 MB of debt is treated as stalled", %{port: port} do
    {:ok, client} = Client.start_link(conn_opts(port))
    assert_receive {:ssh_ready}, 10_000
    assert collect_until(&(&1 =~ "welcome"), 5000)

    %{conn: conn, chan: chan} = :sys.get_state(client)
    ref = Process.monitor(client)

    # Inject a channel-data message as OTP would deliver it, over the 4 MB debt cap.
    send(client, {:ssh_cm, conn, {:data, chan, 0, :binary.copy(<<0>>, 4 * 1024 * 1024 + 1)}})

    assert_receive {:ssh_closed, :stalled}, 5000
    assert_receive {:DOWN, ^ref, :process, ^client, :normal}, 5000
  end

  test "stops when its owning session exits normally, instead of leaking the connection", %{
    port: port
  } do
    # The session links to its client via start_link and is its subscriber. An owner
    # that exits WITHOUT closing the client must still take it down: the client traps
    # exits, and the catch-all used to swallow the {:EXIT, owner, _} message, leaving
    # the SSH connection and remote shell up with nobody reading them.
    test_pid = self()

    owner =
      spawn(fn ->
        {:ok, client} = Client.start_link(conn_opts(port, "secret", self()))
        send(test_pid, {:client, client})

        receive do
          {:ssh_ready} -> send(test_pid, :ready)
        end

        receive do
          :bye -> :ok
        end

        # Returns here: a :normal owner exit without SSH.Client.close/1.
      end)

    assert_receive {:client, client}, 5000
    assert_receive :ready, 10_000

    %{conn: conn} = :sys.get_state(client)
    client_ref = Process.monitor(client)
    conn_ref = Process.monitor(conn)

    send(owner, :bye)

    assert_receive {:DOWN, ^client_ref, :process, ^client, :normal}, 5000
    assert_receive {:DOWN, ^conn_ref, :process, ^conn, _reason}, 5000
  end

  test "a killed owner takes the client and connection down via exit propagation", %{port: port} do
    # Revocation escalates to Process.exit(session, :kill). The :killed signal is
    # untrappable and propagates down the link chain — this pins that a "revoked"
    # session cannot leave its connection or remote shell behind on the host.
    test_pid = self()

    owner =
      spawn(fn ->
        {:ok, client} = Client.start_link(conn_opts(port, "secret", self()))
        send(test_pid, {:client, client})

        receive do
          {:ssh_ready} -> send(test_pid, :ready)
        end

        receive do
          :never -> :ok
        end
      end)

    assert_receive {:client, client}, 5000
    assert_receive :ready, 10_000

    %{conn: conn} = :sys.get_state(client)
    client_ref = Process.monitor(client)
    conn_ref = Process.monitor(conn)

    Process.exit(owner, :kill)

    assert_receive {:DOWN, ^client_ref, :process, ^client, :killed}, 5000
    assert_receive {:DOWN, ^conn_ref, :process, ^conn, _reason}, 5000
  end

  test "a failed keystroke send surfaces a typed close instead of a silent drop", %{port: port} do
    {:ok, client} = Client.start_link(conn_opts(port))
    assert_receive {:ssh_ready}, 10_000
    assert collect_until(&(&1 =~ "welcome"), 5000)

    # Queue the cast while suspended, then kill the connection handler: on resume the
    # cast is processed first, so the send deterministically fails. The old code
    # discarded the return — the keystrokes vanished and nobody heard about it.
    :ok = :sys.suspend(client)
    :ok = Client.send_data(client, "echo never\n")
    %{conn: conn} = :sys.get_state(client)
    Process.exit(conn, :kill)
    ref = Process.monitor(client)
    :ok = :sys.resume(client)

    assert_receive {:ssh_closed, :send_failed}, 5000
    assert_receive {:DOWN, ^ref, :process, ^client, :normal}, 5000
  end

  # --- helpers ---

  defp conn_opts(port, password \\ "secret", subscriber \\ self()) do
    %{
      host: "127.0.0.1",
      port: port,
      username: "tester",
      password: password,
      cols: 100,
      rows: 30,
      subscriber: subscriber
    }
  end

  # Same hazard `echo_loop/0` documents below, on the one write that was left outside its rescue.
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
    # The ssh channel (our group leader) can terminate mid-write when the client closes.
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

  defp daemon_port(daemon) do
    case :ssh.daemon_info(daemon) do
      {:ok, info} when is_list(info) -> :proplists.get_value(:port, info)
      {:ok, info} when is_map(info) -> Map.get(info, :port)
    end
  end
end
