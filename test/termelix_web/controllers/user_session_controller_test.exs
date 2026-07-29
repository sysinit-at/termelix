defmodule TermelixWeb.UserSessionControllerTest do
  @moduledoc """
  HTTP tests for the active-session surface (`/users/sessions*`) and the per-user data
  access surface (`/users/data-status`, `/users/unlock-data`).

  `alice` is the first user (admin); `bob` is a non-admin. Requires the returned routes to be
  wired into the authenticated `/users` scope.
  """
  use TermelixWeb.ConnCase

  alias Termelix.Accounts

  @alice_pw "correct horse battery staple"
  @bob_pw "another good long passphrase"

  setup do
    {alice_token, alice} = register_and_login("alice", @alice_pw)
    {bob_token, bob} = register_and_login("bob", @bob_pw)
    %{alice_token: alice_token, alice: alice, bob_token: bob_token, bob: bob}
  end

  describe "GET /users/sessions" do
    test "admin sees every session enriched with username + current flag", %{alice_token: t} do
      %{"sessions" => sessions} = authed(t) |> get("/users/sessions") |> json_response(200)

      assert Enum.any?(sessions, &(&1["username"] == "alice"))
      assert Enum.any?(sessions, &(&1["username"] == "bob"))
      assert Enum.any?(sessions, &(&1["isCurrentSession"] == true))
      current = Enum.find(sessions, & &1["isCurrentSession"])
      assert current["username"] == "alice"
    end

    test "non-admin sees only their own sessions, without usernames", %{bob_token: t, bob: bob} do
      %{"sessions" => sessions} = authed(t) |> get("/users/sessions") |> json_response(200)

      assert Enum.all?(sessions, &(&1["userId"] == bob.id))
      assert Enum.all?(sessions, &(not Map.has_key?(&1, "username")))
      assert Enum.any?(sessions, &(&1["isCurrentSession"] == true))
    end
  end

  describe "DELETE /users/sessions/:sessionId" do
    test "user revokes one of their own sessions", %{bob_token: current, bob: bob} do
      login("bob", @bob_pw)
      other_id = other_session_id(current, bob.id)

      assert %{"success" => true, "message" => "Session revoked successfully"} =
               authed(current) |> delete("/users/sessions/#{other_id}") |> json_response(200)

      %{"sessions" => remaining} = authed(current) |> get("/users/sessions") |> json_response(200)
      refute Enum.any?(remaining, &(&1["id"] == other_id))
    end

    test "cannot revoke another user's session", %{alice_token: a, bob_token: b} do
      alice_sid = current_session_id(a)

      assert %{"error" => "Not authorized to revoke this session"} =
               authed(b) |> delete("/users/sessions/#{alice_sid}") |> json_response(403)
    end

    test "404 for an unknown session", %{bob_token: b} do
      assert %{"error" => "Session not found"} =
               authed(b) |> delete("/users/sessions/nope") |> json_response(404)
    end

    test "admin may revoke any session", %{alice_token: a, bob_token: b} do
      bob_sid = current_session_id(b)

      assert %{"success" => true} =
               authed(a) |> delete("/users/sessions/#{bob_sid}") |> json_response(200)
    end
  end

  describe "POST /users/sessions/revoke-all" do
    test "revokes all but the current session", %{bob_token: current} do
      login("bob", @bob_pw)

      assert %{"count" => 1, "message" => "1 session(s) revoked successfully"} =
               authed(current)
               |> post("/users/sessions/revoke-all", %{exceptCurrent: true})
               |> json_response(200)

      %{"sessions" => remaining} = authed(current) |> get("/users/sessions") |> json_response(200)
      assert length(remaining) == 1
    end

    test "non-admin cannot target another user", %{bob_token: b, alice: alice} do
      assert %{"error" => "Not authorized to revoke sessions for other users"} =
               authed(b)
               |> post("/users/sessions/revoke-all", %{targetUserId: alice.id})
               |> json_response(403)
    end
  end

  describe "GET /users/data-status" do
    test "reports unlocked once a DEK exists", %{bob_token: b} do
      assert %{"unlocked" => true, "message" => "Data is unlocked"} =
               authed(b) |> get("/users/data-status") |> json_response(200)
    end
  end

  describe "POST /users/unlock-data" do
    test "verifies the password and refreshes the session cookie", %{bob_token: b} do
      conn = authed(b) |> post("/users/unlock-data", %{password: @bob_pw})

      assert %{"success" => true, "message" => "Data unlocked successfully"} =
               json_response(conn, 200)

      assert %{value: token} = conn.resp_cookies["jwt"]
      assert is_binary(token)
    end

    test "401 on a wrong password", %{bob_token: b} do
      assert %{"error" => "Invalid password"} =
               authed(b) |> post("/users/unlock-data", %{password: "wrong"}) |> json_response(401)
    end

    test "400 when the password is missing", %{bob_token: b} do
      assert %{"error" => "Password is required"} =
               authed(b) |> post("/users/unlock-data", %{}) |> json_response(400)
    end
  end

  # --- helpers ---------------------------------------------------------------

  defp current_session_id(token) do
    %{"sessions" => sessions} = authed(token) |> get("/users/sessions") |> json_response(200)
    Enum.find(sessions, & &1["isCurrentSession"])["id"]
  end

  defp other_session_id(token, user_id) do
    %{"sessions" => sessions} = authed(token) |> get("/users/sessions") |> json_response(200)

    sessions
    |> Enum.filter(&(&1["userId"] == user_id and &1["isCurrentSession"] != true))
    |> List.first()
    |> Map.fetch!("id")
  end

  defp register_and_login(username, password) do
    Phoenix.ConnTest.build_conn()
    |> post("/users/create", %{username: username, password: password})
    |> json_response(200)

    {login(username, password), Accounts.get_user_by_username(username)}
  end

  defp login(username, password) do
    login =
      Phoenix.ConnTest.build_conn()
      |> post("/users/login", %{username: username, password: password})

    %{"jwt" => %{value: token}} = login.resp_cookies
    token
  end

  defp authed(token),
    do:
      Phoenix.ConnTest.build_conn()
      |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
end
