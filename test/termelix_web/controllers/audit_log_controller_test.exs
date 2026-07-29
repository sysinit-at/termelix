defmodule TermelixWeb.AuditLogControllerTest do
  @moduledoc """
  HTTP tests for the admin audit surface: `GET /audit-logs` (paginated + filterable) and
  `GET /audit-logs/actions`. Both are admin-gated.

  `alice` is admin (first user); `bob` is a non-admin. Requires the returned routes to be
  wired into an authenticated scope.
  """
  use TermelixWeb.ConnCase

  alias Termelix.{Accounts, Audit}

  setup do
    {alice_token, alice} = register_and_login("alice", "correct horse battery staple")
    {bob_token, _bob} = register_and_login("bob", "another good long passphrase")

    Audit.log(alice, "make_admin", "user", %{resource_id: "u1", resource_name: "victim"})
    Audit.log(alice, "delete_user", "user", %{resource_id: "u2"})
    Audit.log(alice, "revoke_session", "session", %{resource_id: "s1", ip_address: "10.0.0.1"})

    %{alice_token: alice_token, alice: alice, bob_token: bob_token}
  end

  describe "GET /audit-logs" do
    test "admin gets a paginated, camelCase page", %{alice_token: t} do
      body = authed(t) |> get("/audit-logs") |> json_response(200)

      assert body["total"] == 3
      assert body["page"] == 1
      assert body["totalPages"] == 1
      assert is_list(body["logs"])

      log = List.first(body["logs"])
      # Newest first: revoke_session was logged last.
      assert log["action"] == "revoke_session"
      assert log["resourceType"] == "session"
      assert log["resourceId"] == "s1"
      assert log["ipAddress"] == "10.0.0.1"
      assert log["success"] == true
      assert is_binary(log["timestamp"])
    end

    test "filters by action", %{alice_token: t} do
      body = authed(t) |> get("/audit-logs", %{action: "make_admin"}) |> json_response(200)

      assert body["total"] == 1
      assert List.first(body["logs"])["action"] == "make_admin"
    end

    test "paginates and reports totalPages", %{alice_token: t} do
      body = authed(t) |> get("/audit-logs", %{page: "1", limit: "2"}) |> json_response(200)

      assert length(body["logs"]) == 2
      assert body["total"] == 3
      assert body["totalPages"] == 2
    end

    test "non-admin is refused", %{bob_token: t} do
      assert %{"error" => "Not authorized"} =
               authed(t) |> get("/audit-logs") |> json_response(403)
    end
  end

  describe "GET /audit-logs/actions" do
    test "admin gets the distinct sorted actions", %{alice_token: t} do
      assert %{"actions" => actions} =
               authed(t) |> get("/audit-logs/actions") |> json_response(200)

      assert actions == ["delete_user", "make_admin", "revoke_session"]
    end

    test "non-admin is refused", %{bob_token: t} do
      assert %{"error" => "Not authorized"} =
               authed(t) |> get("/audit-logs/actions") |> json_response(403)
    end
  end

  # --- helpers ---------------------------------------------------------------

  defp register_and_login(username, password) do
    conn = Phoenix.ConnTest.build_conn()

    conn
    |> post("/users/create", %{username: username, password: password})
    |> json_response(200)

    login = conn |> post("/users/login", %{username: username, password: password})
    %{"jwt" => %{value: token}} = login.resp_cookies
    {token, Accounts.get_user_by_username(username)}
  end

  defp authed(token),
    do:
      Phoenix.ConnTest.build_conn()
      |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
end
