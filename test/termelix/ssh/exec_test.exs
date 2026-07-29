defmodule Termelix.SSH.ExecTest do
  @moduledoc "One-shot SSH exec against an in-VM OTP :ssh daemon with a direct exec handler."
  use ExUnit.Case, async: false

  alias Termelix.SSH.Exec
  alias Termelix.SSH.Pool

  setup_all do
    {:ok, _} = Application.ensure_all_started(:ssh)

    dir = Path.join(System.tmp_dir!(), "termelix_exec_test_#{System.unique_integer([:positive])}")
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

    # A direct exec handler: echoes the command, or writes to stderr / exits non-zero for
    # sentinel commands, so we can assert stdout/stderr/exit_status separately. "hang" never
    # replies, simulating a command that produces no output and never closes.
    exec_fun = fn cmd ->
      cmd = to_string(cmd)

      cond do
        cmd == "hang" -> Process.sleep(:infinity)
        cmd == "fail" -> {:error, "boom"}
        String.starts_with?(cmd, "err ") -> {:error, String.trim_leading(cmd, "err ")}
        true -> {:ok, "ran: #{cmd}\n"}
      end
    end

    {:ok, daemon} =
      :ssh.daemon(0,
        system_dir: String.to_charlist(dir),
        user_passwords: [{~c"tester", ~c"secret"}],
        auth_methods: ~c"password",
        exec: {:direct, exec_fun}
      )

    port =
      case :ssh.daemon_info(daemon) do
        {:ok, info} when is_list(info) -> :proplists.get_value(:port, info)
        {:ok, info} when is_map(info) -> Map.get(info, :port)
      end

    on_exit(fn ->
      :ssh.stop_daemon(daemon)
      File.rm_rf(dir)
    end)

    %{opts: %{host: "127.0.0.1", port: port, username: "tester", password: "secret"}}
  end

  setup do
    # `Termelix.TaskSupervisor` is part of the application supervision tree; start it here when
    # running against a tree that predates it so the supervised exec task can spawn.
    case Process.whereis(Termelix.TaskSupervisor) do
      nil -> start_supervised!({Task.Supervisor, name: Termelix.TaskSupervisor})
      _pid -> :ok
    end

    # Pooled connections must not leak between tests.
    Pool.stop_all()

    :ok
  end

  test "captures stdout of a command", %{opts: opts} do
    assert {:ok, %{stdout: out}} = Exec.run(opts, "uptime -p")
    assert out =~ "ran: uptime -p"
  end

  test "wrong password fails to connect", %{opts: opts} do
    assert {:error, {:connect_failed, _}} = Exec.run(%{opts | password: "nope"}, "whoami")
  end

  test "a hung command is a timeout, never a partial success", %{opts: opts} do
    assert {:error, :timeout} = Exec.run(opts, "hang", 100)
  end

  describe "connection pooling" do
    test "sequential runs reuse one pooled connection", %{opts: opts} do
      assert {:ok, _} = Exec.run(opts, "first")

      key = Pool.key_for(opts)
      conn_pid = Pool.lookup(key)
      assert is_pid(conn_pid)
      ssh_conn = :sys.get_state(conn_pid).conn
      assert is_pid(ssh_conn)

      assert {:ok, _} = Exec.run(opts, "second")

      # Same Conn process, same underlying :ssh connection — one handshake for both runs.
      assert Pool.lookup(key) == conn_pid
      assert :sys.get_state(conn_pid).conn == ssh_conn
    end

    test "pool keys isolate hosts and credentials", %{opts: opts} do
      key = Pool.key_for(opts)

      assert Pool.key_for(%{opts | password: "nope"}) != key
      assert Pool.key_for(%{opts | username: "other"}) != key
      assert Pool.key_for(%{opts | port: opts.port + 1}) != key
      assert Pool.key_for(%{opts | host: "localhost"}) != key
      # The PEM passphrase is part of the credential set: adding or changing key_password
      # must change the bucket, so possessing an encrypted key without its passphrase can't
      # reuse a connection already authenticated with it.
      assert Pool.key_for(Map.put(opts, :key_password, "ignored")) != key
      # Identical credentials (including passphrase) on the same host share one bucket.
      assert Pool.key_for(opts) == key
    end

    test "a failed connect does not poison the pool", %{opts: opts} do
      assert {:ok, _} = Exec.run(opts, "whoami")

      key = Pool.key_for(opts)
      conn_pid = Pool.lookup(key)

      assert {:error, {:connect_failed, _}} = Exec.run(%{opts | password: "nope"}, "whoami")

      # The good pooled connection survives and keeps serving runs.
      assert {:ok, %{stdout: out}} = Exec.run(opts, "whoami")
      assert out =~ "ran: whoami"
      assert Pool.lookup(key) == conn_pid
    end

    test "a dropped connection reconnects on the next run", %{opts: opts} do
      assert {:ok, _} = Exec.run(opts, "whoami")

      key = Pool.key_for(opts)
      conn_pid = Pool.lookup(key)
      ssh_conn = :sys.get_state(conn_pid).conn

      # Sever the underlying ssh connection; the Conn notices and stops.
      :ssh.close(ssh_conn)
      ref = Process.monitor(conn_pid)
      assert_receive {:DOWN, ^ref, :process, ^conn_pid, _reason}, 2_000

      assert {:ok, %{stdout: out}} = Exec.run(opts, "whoami")
      assert out =~ "ran: whoami"

      new_pid = Pool.lookup(key)
      assert is_pid(new_pid)
      assert :sys.get_state(new_pid).conn != ssh_conn
    end

    test "an idle pooled connection expires", %{opts: opts} do
      Application.put_env(:termelix, :ssh_conn_idle_timeout, 100)
      on_exit(fn -> Application.delete_env(:termelix, :ssh_conn_idle_timeout) end)

      assert {:ok, _} = Exec.run(opts, "whoami")

      conn_pid = Pool.lookup(Pool.key_for(opts))
      assert is_pid(conn_pid)
      ref = Process.monitor(conn_pid)

      assert_receive {:DOWN, ^ref, :process, ^conn_pid, :normal}, 2_000
    end
  end
end
