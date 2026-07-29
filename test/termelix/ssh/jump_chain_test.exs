defmodule Termelix.SSH.JumpChainTest do
  @moduledoc """
  End-to-end proof of jump-host chaining over OTP's native forward primitive
  (`:ssh.tcpip_tunnel_to_server/6`). Two in-VM `:ssh` daemons stand in for the topology:

    * **jump** — a daemon started with `tcpip_tunnel_in: true`, so a client may request the local
      (`-L`) forward `JumpChain` uses to bridge to the next hop;
    * **final** — a daemon with a `{:direct, …}` exec handler, so a full SSH session reached
      *through* the jump proves the returned `ConnRef` is a live, usable connection to the final
      host, not merely a socket that opened.

  It also drives the first hop through a tiny in-VM SOCKS5 proxy (the `Termelix.SSH.Socks5` path),
  proving the two primitives compose. Since everything is loopback, the jump host forwards to
  `127.0.0.1:<final_port>` — the same mechanism a real bastion uses to reach a private host.
  """
  use ExUnit.Case, async: false

  alias Termelix.SSH.JumpChain

  setup_all do
    {:ok, _} = Application.ensure_all_started(:ssh)

    dir = Path.join(System.tmp_dir!(), "termelix_jump_test_#{System.unique_integer([:positive])}")
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

    on_exit(fn -> File.rm_rf(dir) end)

    %{sysdir: String.to_charlist(dir)}
  end

  # Daemons are per-test, not `setup_all`, and that is load-bearing rather than tidiness.
  # `connect/3` returns only the final ConnRef and deliberately drops the intermediate hop's
  # handle *and its forward listener* (Node parity — see the module's "Lifetime" section), so a
  # test using it cannot close what it leaked. Those leaks are owned by the test process and are
  # torn down asynchronously when it exits, which raced the next test's
  # `tcpip_tunnel_to_server/6` against the same shared daemon: `connect_chain` then failed with
  # `{:connect_failed, :timeout}` in roughly half of full-suite runs while passing 5/5 alone.
  # Fresh daemons per test remove the shared mutable state instead of papering over it with a
  # longer timeout, which would have masked real connect regressions.
  setup %{sysdir: sysdir} do
    # The jump host: permits the client-requested local forward JumpChain bridges through.
    {:ok, jump_daemon} =
      :ssh.daemon(0,
        system_dir: sysdir,
        user_passwords: [{~c"jumper", ~c"jumppass"}],
        auth_methods: ~c"password",
        tcpip_tunnel_in: true
      )

    # The final host: a direct exec handler so we can run a command over the tunneled connection.
    {:ok, final_daemon} =
      :ssh.daemon(0,
        system_dir: sysdir,
        user_passwords: [{~c"finisher", ~c"finalpass"}],
        auth_methods: ~c"password",
        exec: {:direct, fn cmd -> {:ok, "final-ran: #{cmd}\n"} end}
      )

    jump_port = daemon_port(jump_daemon)
    final_port = daemon_port(final_daemon)

    on_exit(fn ->
      :ssh.stop_daemon(jump_daemon)
      :ssh.stop_daemon(final_daemon)
    end)

    jump_opts = %{host: "127.0.0.1", port: jump_port, username: "jumper", password: "jumppass"}

    final_opts = %{
      host: "127.0.0.1",
      port: final_port,
      username: "finisher",
      password: "finalpass"
    }

    %{jump_opts: jump_opts, final_opts: final_opts, jump_port: jump_port, final_port: final_port}
  end

  test "no jump hops connects straight to the target", %{final_opts: final} do
    assert {:ok, conn} = JumpChain.connect(final, [], nil)
    assert run_command(conn, "direct") =~ "final-ran: direct"
    :ssh.close(conn)
  end

  test "a 1-hop jump reaches the final host through the jump host", ctx do
    %{jump_opts: jump, final_opts: final} = ctx

    assert {:ok, conn} = JumpChain.connect(final, [jump], nil)
    assert run_command(conn, "via-jump") =~ "final-ran: via-jump"
    :ssh.close(conn)
  end

  test "connect_chain returns every hop reference for teardown", ctx do
    %{jump_opts: jump, final_opts: final} = ctx

    assert {:ok, refs} = JumpChain.connect_chain(final, [jump], nil)
    assert length(refs) == 2
    assert Enum.all?(refs, &is_pid/1)

    # The last ref is the final connection.
    assert run_command(List.last(refs), "chain") =~ "final-ran: chain"
    assert :ok = JumpChain.close_chain(refs)
  end

  test "a bad first-hop credential fails the chain", ctx do
    %{jump_opts: jump, final_opts: final} = ctx
    bad_jump = %{jump | password: "definitely-wrong"}

    assert {:error, {:connect_failed, _}} = JumpChain.connect(final, [bad_jump], nil)
  end

  test "a bad final credential fails the chain", ctx do
    %{jump_opts: jump, final_opts: final} = ctx
    bad_final = %{final | password: "definitely-wrong"}

    assert {:error, {:connect_failed, _}} = JumpChain.connect(bad_final, [jump], nil)
  end

  test "the first hop is dialed through a SOCKS5 proxy", ctx do
    %{jump_opts: jump, final_opts: final} = ctx
    proxy_port = start_socks5()
    socks5 = %{host: "127.0.0.1", port: proxy_port}

    assert {:ok, conn} = JumpChain.connect(final, [jump], socks5)
    assert run_command(conn, "via-socks-and-jump") =~ "final-ran: via-socks-and-jump"
    :ssh.close(conn)
  end

  test "socks5_from_host derives a proxy from a host row" do
    host = %{
      useSocks5: true,
      socks5Host: "proxy.example",
      socks5Port: 1080,
      socks5Username: "u",
      socks5Password: "p"
    }

    assert %{host: "proxy.example", port: 1080, username: "u", password: "p"} =
             JumpChain.socks5_from_host(host)

    assert JumpChain.socks5_from_host(%{useSocks5: false, socks5Host: "proxy.example"}) == nil
    assert JumpChain.socks5_from_host(%{useSocks5: true, socks5Host: nil}) == nil
  end

  # --- minimal no-auth SOCKS5 proxy (first-hop dialer target = the jump host) ----------------

  defp start_socks5 do
    {:ok, lsock} =
      :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}, {:ip, {127, 0, 0, 1}}])

    {:ok, {_ip, port}} = :inet.sockname(lsock)
    spawn(fn -> socks_accept_loop(lsock) end)
    on_exit(fn -> :gen_tcp.close(lsock) end)
    port
  end

  defp socks_accept_loop(lsock) do
    case :gen_tcp.accept(lsock) do
      {:ok, sock} ->
        # `spawn` does NOT move socket ownership — this loop stayed the controlling process of
        # every connection it accepted, so the server ran its whole protocol from processes that
        # did not own the socket. That is undefined for `:gen_tcp.recv/3`, and when it lost, the
        # read never returned: the SSH client had finished its TCP connect and sat waiting for a
        # version banner that was stuck in a socket nobody was successfully reading. The symptom
        # was `{:connect_failed, :timeout}` in `JumpChain` — a real hang in this fixture,
        # reported as a fault in the code under test (~25% of runs).
        worker = spawn(fn -> socks_serve(sock) end)
        :ok = :gen_tcp.controlling_process(sock, worker)
        socks_accept_loop(lsock)

      _ ->
        :ok
    end
  end

  defp socks_serve(sock) do
    with :ok <- socks_greet(sock),
         {:ok, {host, port}} <- socks_read_connect(sock),
         {:ok, up} <- :gen_tcp.connect(host, port, [:binary, {:active, false}], 5_000) do
      :gen_tcp.send(sock, <<5, 0, 0, 1, 0, 0, 0, 0, 0, 0>>)
      # One process, both sockets, active mode: neither direction can block the other and
      # neither socket is read by a process that does not own it.
      splice(sock, up)
    else
      _ -> :gen_tcp.close(sock)
    end
  end

  defp socks_greet(sock) do
    {:ok, <<5, nmethods>>} = :gen_tcp.recv(sock, 2, 5_000)
    {:ok, _methods} = recv_n(sock, nmethods)
    :gen_tcp.send(sock, <<5, 0x00>>)
    :ok
  end

  defp socks_read_connect(sock) do
    {:ok, <<5, 1, 0, atyp>>} = :gen_tcp.recv(sock, 4, 5_000)

    case atyp do
      1 ->
        {:ok, <<a, b, c, d, p::16>>} = :gen_tcp.recv(sock, 6, 5_000)
        {:ok, {{a, b, c, d}, p}}

      3 ->
        {:ok, <<len>>} = :gen_tcp.recv(sock, 1, 5_000)
        {:ok, <<domain::binary-size(^len), p::16>>} = :gen_tcp.recv(sock, len + 2, 5_000)
        {:ok, {String.to_charlist(domain), p}}
    end
  end

  defp recv_n(_sock, 0), do: {:ok, <<>>}
  defp recv_n(sock, n), do: :gen_tcp.recv(sock, n, 5_000)

  # `{:active, :once}`, re-armed after each chunk — the same flow control the real bridge uses
  # (`JumpChain.splice/2`). A fixture that buffers without bound would not fail; it would just
  # stop resembling the thing it stands in for.
  defp splice(a, b) do
    :inet.setopts(a, active: :once)
    :inet.setopts(b, active: :once)
    splice_loop(a, b)
  end

  defp splice_loop(a, b) do
    receive do
      {:tcp, ^a, data} ->
        :gen_tcp.send(b, data)
        :inet.setopts(a, active: :once)
        splice_loop(a, b)

      {:tcp, ^b, data} ->
        :gen_tcp.send(a, data)
        :inet.setopts(b, active: :once)
        splice_loop(a, b)

      {:tcp_closed, _} ->
        :gen_tcp.close(a)
        :gen_tcp.close(b)

      {:tcp_error, _, _} ->
        :gen_tcp.close(a)
        :gen_tcp.close(b)
    end
  end

  # --- ssh command helper ---------------------------------------------------

  defp daemon_port(daemon) do
    case :ssh.daemon_info(daemon) do
      {:ok, info} when is_list(info) -> :proplists.get_value(:port, info)
      {:ok, info} when is_map(info) -> Map.get(info, :port)
    end
  end

  defp run_command(conn, cmd) do
    {:ok, chan} = :ssh_connection.session_channel(conn, 15_000)
    :success = :ssh_connection.exec(conn, chan, String.to_charlist(cmd), 15_000)
    collect(conn, chan, [])
  end

  defp collect(conn, chan, acc) do
    receive do
      {:ssh_cm, ^conn, {:data, ^chan, 0, data}} ->
        :ssh_connection.adjust_window(conn, chan, byte_size(data))
        collect(conn, chan, [data | acc])

      {:ssh_cm, ^conn, {:data, ^chan, 1, _data}} ->
        collect(conn, chan, acc)

      {:ssh_cm, ^conn, {:eof, ^chan}} ->
        collect(conn, chan, acc)

      {:ssh_cm, ^conn, {:exit_status, ^chan, _}} ->
        collect(conn, chan, acc)

      {:ssh_cm, ^conn, {closed, ^chan}} when closed in [:closed, :channel_closed] ->
        acc |> Enum.reverse() |> IO.iodata_to_binary()

      {:ssh_cm, ^conn, _other} ->
        collect(conn, chan, acc)
    after
      15_000 -> acc |> Enum.reverse() |> IO.iodata_to_binary()
    end
  end
end
