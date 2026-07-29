defmodule TermelixWeb.MetricsControllerTest do
  @moduledoc """
  Host reachability status — what powers the sidebar's online/offline indicators.

  A throwaway `:ssh` daemon runs inside the test VM; the status endpoints are checked
  against its listening port (a successful TCP connect = online). A real user + host row are
  created through the normal API, so the host is resolved by `Hosts.get_for_user` exactly as
  production does. (The former Host Metrics dashboard and its collection path were removed.)
  """
  use TermelixWeb.ConnCase, async: false

  alias Termelix.Accounts
  alias TermelixWeb.MetricsController

  @password "correct horse battery staple"

  setup_all do
    {:ok, _} = Application.ensure_all_started(:ssh)

    dir =
      Path.join(System.tmp_dir!(), "termelix_metrics_test_#{System.unique_integer([:positive])}")

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
        auth_methods: ~c"password"
      )

    port = daemon_port(daemon)

    on_exit(fn ->
      :ssh.stop_daemon(daemon)
      File.rm_rf(dir)
    end)

    %{port: port}
  end

  setup %{port: port} do
    {token, user} = register_and_login("alice", @password)
    host_id = create_host(token, port)
    %{user: user, token: token, host_id: host_id}
  end

  describe "MetricsController status endpoints" do
    test "status/2 reports the live daemon as online", ctx do
      %{user: user, host_id: id} = ctx

      resp =
        user
        |> user_conn()
        |> MetricsController.status(%{"id" => to_string(id)})
        |> json_response(200)

      assert resp["status"] == "online"
      assert is_binary(resp["lastChecked"])
    end

    test "status/2 for an unknown host is 404", %{user: user} do
      resp =
        user
        |> user_conn()
        |> MetricsController.status(%{"id" => "999999"})
        |> json_response(404)

      assert resp["error"] == "Status not available"
    end

    test "status/2 for a non-numeric id is 400", %{user: user} do
      resp =
        user
        |> user_conn()
        |> MetricsController.status(%{"id" => "not-a-number"})
        |> json_response(400)

      assert resp["error"] == "Invalid host ID"
    end

    test "status_all/2 maps the user's host to its status", ctx do
      %{user: user, host_id: id} = ctx

      resp =
        user
        |> user_conn()
        |> MetricsController.status_all(%{})
        |> json_response(200)

      assert resp[to_string(id)]["status"] == "online"
    end

    test "poller notifications acknowledge", %{user: user} do
      assert %{"success" => true} =
               user |> user_conn() |> MetricsController.poller_ack(%{}) |> json_response(200)
    end
  end

  # --- helpers ---------------------------------------------------------------

  defp user_conn(user) do
    build_conn()
    |> Plug.Conn.assign(:current_user_id, user.id)
    |> Plug.Conn.assign(:current_user, user)
  end

  defp register_and_login(username, password) do
    conn = build_conn()
    conn |> post("/users/create", %{username: username, password: password}) |> json_response(200)
    login = post(conn, "/users/login", %{username: username, password: password})
    %{"jwt" => %{value: token}} = login.resp_cookies
    {token, Accounts.get_user_by_username(username)}
  end

  defp create_host(token, port) do
    %{"id" => id} =
      build_conn()
      |> put_req_header("authorization", "Bearer #{token}")
      |> put_req_header("content-type", "application/json")
      |> post(
        "/host/db/host",
        Jason.encode!(%{
          name: "status-target",
          ip: "127.0.0.1",
          port: port,
          username: "tester",
          connectionType: "ssh",
          authType: "password",
          password: "secret"
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
end
