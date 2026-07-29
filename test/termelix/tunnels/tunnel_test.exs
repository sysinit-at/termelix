defmodule Termelix.Tunnels.TunnelTest do
  @moduledoc """
  End-to-end proof of the SSH **local port-forward** control plane over OTP's native
  `:ssh.tcpip_tunnel_to_server/6`.

  An in-VM `:ssh` daemon started with `tcpip_tunnel_in: true` (the option that lets a client
  request `ssh -L` forwards) plays the source host, and a plain in-VM TCP echo server plays the
  forward target. A real user + host row are created through the normal API (so the host
  password is DEK-encrypted at rest and decrypted by `Hosts.get_for_user`, exactly as
  production does), then:

    * the manager lifecycle (`Termelix.Tunnels`) is exercised — connect registers a live tunnel,
      the status map reflects it, disconnect removes it, a duplicate name replaces the old one,
      and an unresolvable/failing source is surfaced correctly;
    * the **data path** is proven — bytes sent to the OS-picked local listen port round-trip
      through the SSH connection to the echo server and back;
    * the `TunnelController` HTTP surface returns the exact shapes `tunnel-api.ts` expects.

  The `Registry` + `DynamicSupervisor` are `start_supervised!`'d here (the integrator adds them
  to `application.ex`), so this suite is self-contained.
  """
  use TermelixWeb.ConnCase, async: false

  alias Termelix.Accounts
  alias Termelix.Tunnels
  alias Termelix.Tunnels.Tunnel
  alias TermelixWeb.TunnelController

  @password "correct horse battery staple"
  @host_pw "secret"

  setup_all do
    {:ok, _} = Application.ensure_all_started(:ssh)

    # The connect task runs under this supervisor (added to the app tree by the integrator);
    # start it here only if it isn't already running so the suite is self-contained.
    if Process.whereis(Termelix.TaskSupervisor) == nil do
      start_supervised!({Task.Supervisor, name: Termelix.TaskSupervisor})
    end

    dir =
      Path.join(System.tmp_dir!(), "termelix_tunnel_test_#{System.unique_integer([:positive])}")

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

    # The forward target: a TCP echo server on loopback, reachable from the daemon's network.
    {:ok, echo_lsock} =
      :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}, {:ip, {127, 0, 0, 1}}])

    {:ok, {_ip, echo_port}} = :inet.sockname(echo_lsock)
    spawn(fn -> echo_accept_loop(echo_lsock) end)

    # A blackhole TCP server: the kernel completes the handshake (so the TCP connect succeeds)
    # but nobody ever accepts or speaks, so the SSH handshake stalls until its timeout.
    {:ok, blackhole_lsock} =
      :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}, {:ip, {127, 0, 0, 1}}])

    {:ok, {_ip, blackhole_port}} = :inet.sockname(blackhole_lsock)

    # The source host: an :ssh daemon that permits client-requested local forwards.
    {:ok, daemon} =
      :ssh.daemon(0,
        system_dir: String.to_charlist(dir),
        user_passwords: [{~c"tester", to_charlist(@host_pw)}],
        auth_methods: ~c"password",
        tcpip_tunnel_in: true
      )

    port = daemon_port(daemon)

    on_exit(fn ->
      :ssh.stop_daemon(daemon)
      :gen_tcp.close(echo_lsock)
      :gen_tcp.close(blackhole_lsock)
      File.rm_rf(dir)
    end)

    %{port: port, echo_port: echo_port, blackhole_port: blackhole_port}
  end

  setup %{port: port, blackhole_port: blackhole_port} do
    # The Registry + DynamicSupervisor are started by the application supervision tree; reuse
    # them. (Started here only if running standalone without the app, which never happens.)
    {token, user} = register_and_login("alice_#{System.unique_integer([:positive])}", @password)
    host_id = create_host(token, port, @host_pw)

    # Deterministic waits: every status transition is announced on this topic.
    Phoenix.PubSub.subscribe(Termelix.PubSub, "tunnels:status")

    %{
      user: user,
      user_id: user.id,
      host_id: host_id,
      token: token,
      port: port,
      blackhole_port: blackhole_port
    }
  end

  describe "manager lifecycle (Termelix.Tunnels)" do
    test "connect registers a live tunnel, status reflects it, disconnect removes it", ctx do
      %{user_id: uid, host_id: hid, echo_port: echo} = ctx
      params = tunnel_params(hid, 0, echo)
      name = params["name"]

      assert {:ok, ^name} = Tunnels.connect(uid, params)
      assert_receive {:tunnel_status, ^name, :connected}, 15_000

      assert is_pid(Tunnels.lookup(name, uid))
      statuses = Tunnels.statuses_for_user(uid)
      assert %{connected: true, status: "connected"} = statuses[name]

      assert :ok = Tunnels.disconnect(uid, name)
      assert Tunnels.lookup(name, uid) == nil
      assert Tunnels.statuses_for_user(uid) == %{}
    end

    test "the forward carries bytes to the echo server and back", ctx do
      %{user_id: uid, host_id: hid, echo_port: echo} = ctx
      params = tunnel_params(hid, 0, echo)
      name = params["name"]

      assert {:ok, ^name} = Tunnels.connect(uid, params)
      assert_receive {:tunnel_status, ^name, :connected}, 15_000

      listen_port = Tunnel.listen_port(Tunnels.lookup(name, uid))
      assert is_integer(listen_port) and listen_port > 0

      {:ok, client} =
        :gen_tcp.connect(~c"127.0.0.1", listen_port, [:binary, {:active, false}], 5_000)

      payload = "ping-through-the-tunnel-#{System.unique_integer([:positive])}"
      :ok = :gen_tcp.send(client, payload)
      assert {:ok, echoed} = :gen_tcp.recv(client, byte_size(payload), 5_000)
      assert echoed == payload

      :gen_tcp.close(client)
      Tunnels.disconnect(uid, name)
    end

    test "reconnecting with the same name replaces the previous tunnel", ctx do
      %{user_id: uid, host_id: hid, echo_port: echo} = ctx
      params = tunnel_params(hid, 0, echo)
      name = params["name"]

      assert {:ok, ^name} = Tunnels.connect(uid, params)
      assert_receive {:tunnel_status, ^name, :connected}, 15_000
      first = Tunnels.lookup(name, uid)

      assert {:ok, ^name} = Tunnels.connect(uid, params)
      assert_receive {:tunnel_status, ^name, :connected}, 15_000
      second = Tunnels.lookup(name, uid)

      refute first == second
      refute Process.alive?(first)
      # Exactly one live tunnel remains under this name.
      assert map_size(Tunnels.statuses_for_user(uid)) == 1

      Tunnels.disconnect(uid, name)
    end

    test "an unresolvable source host reads as access denied", ctx do
      %{user_id: uid, echo_port: echo} = ctx
      params = %{tunnel_params(999_999, 0, echo) | "sourceHostId" => 999_999}
      assert {:error, :access_denied} = Tunnels.connect(uid, params)
    end

    test "a bad source password fails terminally with an auth error type", ctx do
      %{user_id: uid, token: token, echo_port: echo, port: port} = ctx
      bad_host = create_host(token, port, "definitely-not-the-password")
      params = tunnel_params(bad_host, 0, echo)
      name = params["name"]

      assert {:ok, ^name} = Tunnels.connect(uid, params)
      assert_receive {:tunnel_status, ^name, :failed}, 15_000

      status = Tunnels.status_for(uid, name)
      assert status.connected == false
      assert status.status == "failed"
      assert status.errorType == "AUTHENTICATION_FAILED"

      Tunnels.disconnect(uid, name)
    end

    test "a non-local (reverse/dynamic) mode is deferred and fails fast", ctx do
      %{user_id: uid, host_id: hid, echo_port: echo} = ctx
      params = %{tunnel_params(hid, 0, echo) | "mode" => "remote"}
      name = params["name"]

      assert {:ok, ^name} = Tunnels.connect(uid, params)
      assert_receive {:tunnel_status, ^name, :failed}, 15_000

      status = Tunnels.status_for(uid, name)
      assert status.status == "failed"
      assert status.reason =~ "not supported"

      Tunnels.disconnect(uid, name)
    end

    test "the same name can be live for two users at once, isolated per user", ctx do
      %{user_id: alice_id, host_id: alice_host, echo_port: echo, port: port} = ctx

      {bob_token, bob} =
        register_and_login("bob_#{System.unique_integer([:positive])}", @password)

      bob_host = create_host(bob_token, port, @host_pw)

      name = "shared::0::twin::0::127.0.0.1::#{echo}"
      alice_params = %{tunnel_params(alice_host, 0, echo) | "name" => name}
      bob_params = %{tunnel_params(bob_host, 0, echo) | "name" => name}

      assert {:ok, ^name} = Tunnels.connect(alice_id, alice_params)
      assert {:ok, ^name} = Tunnels.connect(bob.id, bob_params)
      assert_receive {:tunnel_status, ^name, :connected}, 15_000
      assert_receive {:tunnel_status, ^name, :connected}, 15_000

      alice_pid = Tunnels.lookup(name, alice_id)
      bob_pid = Tunnels.lookup(name, bob.id)
      assert is_pid(alice_pid) and is_pid(bob_pid)
      refute alice_pid == bob_pid

      assert %{connected: true, status: "connected"} = Tunnels.statuses_for_user(alice_id)[name]
      assert %{connected: true, status: "connected"} = Tunnels.statuses_for_user(bob.id)[name]

      # Tearing down one user's tunnel leaves the other user's untouched.
      assert :ok = Tunnels.disconnect(alice_id, name)
      assert Tunnels.lookup(name, alice_id) == nil
      assert Process.alive?(bob_pid)
      assert %{connected: true} = Tunnels.statuses_for_user(bob.id)[name]

      Tunnels.disconnect(bob.id, name)
    end

    test "status and disconnect are served immediately while the SSH connect is in flight",
         ctx do
      %{user_id: uid, token: token, echo_port: echo, blackhole_port: blackhole} = ctx
      # The blackhole accepts the TCP connect but never speaks, so :ssh.connect blocks for
      # the whole 15s handshake timeout — long enough to prove the GenServer stays responsive.
      host_id = create_host(token, blackhole, @host_pw)
      params = tunnel_params(host_id, 0, echo)
      name = params["name"]

      assert {:ok, ^name} = Tunnels.connect(uid, params)
      assert_receive {:tunnel_status, ^name, :connecting}, 15_000

      pid = Tunnels.lookup(name, uid)
      assert %{status: "connecting", connected: false} = Tunnel.status(pid)

      started = System.monotonic_time(:millisecond)
      assert :ok = Tunnels.disconnect(uid, name)
      assert System.monotonic_time(:millisecond) - started < 2_000

      assert Tunnels.lookup(name, uid) == nil
      refute Process.alive?(pid)
    end

    test "the source connection is tracked via the acknowledged handoff and closed on stop",
         ctx do
      %{user_id: uid, token: token, echo_port: echo, port: port} = ctx

      # A real connect to the source daemon: the connect task establishes the `:ssh` connection,
      # hands it to the tunnel with the acknowledged handoff, and the tunnel records it in
      # `state.conn`. An established `:ssh` connection is NOT linked to its starter and never
      # self-closes (idle_time: infinity), so if the tunnel fails to track and close it on stop it
      # leaks forever. (The narrower race — a stop landing before the handoff is acknowledged — is
      # closed structurally: the connect task monitors the owner and closes the conn itself on the
      # owner's DOWN, so no `:brutal_kill` can orphan a conn between `:ssh.connect` and the send.)
      host_id = create_host(token, port, @host_pw)
      params = tunnel_params(host_id, 0, echo)
      name = params["name"]

      assert {:ok, ^name} = Tunnels.connect(uid, params)
      assert_receive {:tunnel_status, ^name, :connected}, 15_000

      pid = Tunnels.lookup(name, uid)
      conn = :sys.get_state(pid).conn
      assert is_pid(conn) and Process.alive?(conn)

      # Stopping must close the tracked source connection, not orphan it.
      ref = Process.monitor(conn)
      assert :ok = Tunnels.disconnect(uid, name)
      assert_receive {:DOWN, ^ref, :process, ^conn, _reason}, 5_000
      refute Process.alive?(conn)
    end

    test "connect task closes its connection when the owner dies before acking the handoff",
         ctx do
      # The exact race the acknowledged handoff fixes. The connect task establishes a real `:ssh`
      # connection and offers it to the owner; if the owner dies BEFORE replying `{:conn_accepted,
      # ref}` — a `stop` landing in the window between `:ssh.connect` returning and the handoff being
      # accepted, which a `:brutal_kill` could hit — the task must close the connection itself. An
      # established `:ssh` connection is unlinked and never self-closes (idle_time: infinity), so a
      # miss here leaks it forever. We stand in for the owner: capture the offered conn, then exit
      # WITHOUT acking, and assert the task tears the connection down.
      %{port: port} = ctx
      test_pid = self()

      state = %{
        conn_opts: %{host: "127.0.0.1", port: port, username: "tester", password: @host_pw}
      }

      owner =
        spawn(fn ->
          receive do
            {:conn_established, _task_pid, _ref, conn} ->
              send(test_pid, {:handoff, conn})
              # Die before acknowledging — the "stop racing the connect" case.
              :ok
          end
        end)

      spawn(fn -> Tunnel.do_connect(state, owner) end)

      assert_receive {:handoff, conn}, 15_000
      assert is_pid(conn)

      # Pre-fix (unconditional brutal_kill / fire-and-forget send), nothing would close this conn
      # once the owner was gone. With the fix, the task observes the owner's DOWN and closes it.
      ref = Process.monitor(conn)
      assert_receive {:DOWN, ^ref, :process, ^conn, _reason}, 10_000
      refute Process.alive?(conn)
    end
  end

  # The routes are RETURNED to the integrator (router.ex is not edited here), so the controller
  # actions are exercised directly with an authenticated conn, exactly as the `Authenticate`
  # plug would leave it (`conn.assigns.current_user_id`).
  describe "TunnelController actions" do
    test "connect acks, status lists the tunnel, disconnect acks", ctx do
      %{host_id: hid, echo_port: echo, user_id: uid} = ctx
      params = tunnel_params(hid, 0, echo)
      name = params["name"]

      body = uid |> action_conn() |> TunnelController.connect(params) |> json_response(200)
      assert body == %{"message" => "Connection request received", "tunnelName" => name}
      assert_receive {:tunnel_status, ^name, :connected}, 15_000

      statuses = uid |> action_conn() |> TunnelController.status(%{}) |> json_response(200)
      assert statuses[name]["status"] == "connected"
      assert statuses[name]["connected"] == true

      by_name =
        uid
        |> action_conn()
        |> TunnelController.status_by_name(%{"tunnel_name" => name})
        |> json_response(200)

      assert by_name["name"] == name
      assert by_name["status"]["status"] == "connected"

      disc =
        uid
        |> action_conn()
        |> TunnelController.disconnect(%{"tunnelName" => name})
        |> json_response(200)

      assert disc == %{"message" => "Disconnect request received", "tunnelName" => name}
      assert Tunnels.statuses_for_user(uid) == %{}
    end

    test "connect without a name is a 400", ctx do
      %{user_id: uid} = ctx

      body =
        uid
        |> action_conn()
        |> TunnelController.connect(%{"sourceHostId" => 1})
        |> json_response(400)

      assert body == %{"error" => "Invalid tunnel configuration"}
    end

    test "connect whose config disagrees with the name is a 400", ctx do
      %{user_id: uid, host_id: hid, echo_port: echo} = ctx
      # Name says sourcePort 4242 but the config sends 5252.
      params = tunnel_params(hid, 4242, echo) |> Map.put("sourcePort", 5252)

      body = uid |> action_conn() |> TunnelController.connect(params) |> json_response(400)
      assert body == %{"error" => "Tunnel configuration does not match tunnel name"}
    end

    test "connect for a host the user does not own is a 403", ctx do
      %{user_id: uid, echo_port: echo} = ctx
      params = %{tunnel_params(999_999, 0, echo) | "sourceHostId" => 999_999}

      body = uid |> action_conn() |> TunnelController.connect(params) |> json_response(403)
      assert body == %{"error" => "Access denied to this host"}
    end

    test "disconnect without a tunnel name is a 400", ctx do
      %{user_id: uid} = ctx

      body = uid |> action_conn() |> TunnelController.disconnect(%{}) |> json_response(400)
      assert body == %{"error" => "Tunnel name required"}
    end

    test "status/:name for an unknown tunnel is a 404", ctx do
      %{user_id: uid} = ctx

      body =
        uid
        |> action_conn()
        |> TunnelController.status_by_name(%{"tunnel_name" => "nope::0::x::1::y::2"})
        |> json_response(404)

      assert body == %{"error" => "Tunnel not found"}
    end
  end

  # --- helpers --------------------------------------------------------------

  defp tunnel_params(host_id, source_port, echo_port) do
    name = "#{host_id}::0::test::#{source_port}::127.0.0.1::#{echo_port}"

    %{
      "name" => name,
      "sourceHostId" => host_id,
      "tunnelIndex" => 0,
      "mode" => "local",
      "sourcePort" => source_port,
      "endpointHost" => "127.0.0.1",
      "targetHost" => "127.0.0.1",
      "endpointPort" => echo_port,
      "maxRetries" => 1,
      "retryInterval" => 50
    }
  end

  # A conn shaped as the `Authenticate` plug leaves it for an authenticated request.
  defp action_conn(user_id) do
    build_conn() |> Plug.Conn.assign(:current_user_id, user_id)
  end

  defp register_and_login(username, password) do
    conn = build_conn()
    conn |> post("/users/create", %{username: username, password: password}) |> json_response(200)
    login = post(conn, "/users/login", %{username: username, password: password})
    %{"jwt" => %{value: token}} = login.resp_cookies
    {token, Accounts.get_user_by_username(username)}
  end

  defp create_host(token, port, password) do
    %{"id" => id} =
      build_conn()
      |> put_req_header("authorization", "Bearer #{token}")
      |> put_req_header("content-type", "application/json")
      |> post(
        "/host/db/host",
        Jason.encode!(%{
          name: "tunnel-source-#{System.unique_integer([:positive])}",
          ip: "127.0.0.1",
          port: port,
          username: "tester",
          connectionType: "ssh",
          authType: "password",
          password: password,
          enableTunnel: true
        })
      )
      |> json_response(200)

    id
  end

  defp daemon_port(daemon) do
    case :ssh.daemon_info(daemon) do
      {:ok, info} when is_list(info) -> :proplists.get_value(:port, info)
      {:ok, info} when is_map(info) -> Map.get(info, :port)
    end
  end

  # A tiny TCP echo server: accept, then echo every chunk back until the peer closes.
  defp echo_accept_loop(lsock) do
    case :gen_tcp.accept(lsock) do
      {:ok, sock} ->
        spawn(fn -> echo_handle(sock) end)
        echo_accept_loop(lsock)

      _ ->
        :ok
    end
  end

  defp echo_handle(sock) do
    case :gen_tcp.recv(sock, 0) do
      {:ok, data} ->
        :gen_tcp.send(sock, data)
        echo_handle(sock)

      _ ->
        :gen_tcp.close(sock)
    end
  end
end
