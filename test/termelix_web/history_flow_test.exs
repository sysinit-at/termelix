defmodule TermelixWeb.HistoryFlowTest do
  @moduledoc """
  HTTP coverage for the history surface: command history (`/terminal/command_history`) and
  recent activity (`/activity/*`). Exercises recording, listing, per-command delete, clearing,
  the sensitive-command / global-disabled / per-host suppression branches, activity logging +
  reset + trim, validation, and ownership isolation between users.
  """
  use TermelixWeb.ConnCase

  import Ecto.Query, only: [from: 2]

  alias Termelix.{Accounts, History, Repo, Settings}
  alias Termelix.Schema.Host

  @password "correct horse battery staple"

  # --- command history ------------------------------------------------------

  describe "command history" do
    test "save → list (unique) → delete one → clear", %{conn: _conn} do
      {token, _user} = register_and_login("alice")
      host_id = create_host(token)

      saved =
        authed(token)
        |> post_json("/terminal/command_history", %{hostId: host_id, command: "  ls -la  "})
        |> json_response(201)

      # Persisted record shape mirrors commandHistory.$inferSelect; command is trimmed.
      assert saved["command"] == "ls -la"
      assert saved["hostId"] == host_id
      assert is_integer(saved["id"]) and saved["id"] != 0
      assert is_binary(saved["executedAt"])

      # A duplicate command collapses in the unique listing; a second command adds a row.
      save(token, host_id, "ls -la")
      save(token, host_id, "pwd")

      assert ["ls -la", "pwd"] == sorted_history(token, host_id)

      # Deleting one command removes every occurrence.
      assert %{"success" => true} =
               authed(token)
               |> post_json("/terminal/command_history/delete", %{
                 hostId: host_id,
                 command: "ls -la"
               })
               |> json_response(200)

      assert ["pwd"] == history(token, host_id)

      # Clearing empties the host's history.
      assert %{"success" => true} =
               authed(token)
               |> delete("/terminal/command_history/#{host_id}")
               |> json_response(200)

      assert [] == history(token, host_id)
    end

    test "a sensitive command is echoed with id 0 but never persisted", %{conn: _conn} do
      {token, _user} = register_and_login("alice")
      host_id = create_host(token)

      echoed =
        authed(token)
        |> post_json("/terminal/command_history", %{hostId: host_id, command: "echo my secret"})
        |> json_response(201)

      assert echoed["id"] == 0
      assert echoed["command"] == "echo my secret"
      assert [] == history(token, host_id)
    end

    test "a globally disabled history echoes with id 0 without persisting", %{conn: _conn} do
      {token, _user} = register_and_login("alice")
      host_id = create_host(token)
      Settings.put_value("command_history_enabled", "false")

      echoed =
        authed(token)
        |> post_json("/terminal/command_history", %{hostId: host_id, command: "ls -la"})
        |> json_response(201)

      assert echoed["id"] == 0
      assert [] == history(token, host_id)
    end

    test "a host opted out via enable_command_history=false is not recorded", %{conn: _conn} do
      {token, _user} = register_and_login("alice")
      host_id = create_host(token)

      Repo.update_all(from(h in Host, where: h.id == ^host_id),
        set: [enableCommandHistory: false]
      )

      echoed =
        authed(token)
        |> post_json("/terminal/command_history", %{hostId: host_id, command: "ls -la"})
        |> json_response(201)

      assert echoed["id"] == 0
      assert [] == history(token, host_id)
    end

    test "a non-numeric hostId is a 400 on save and delete, not a 500", %{conn: _conn} do
      {token, _user} = register_and_login("alice")

      assert %{"error" => "Invalid request parameters"} =
               authed(token)
               |> post_json("/terminal/command_history", %{hostId: "abc", command: "ls"})
               |> json_response(400)

      assert %{"error" => "Invalid request parameters"} =
               authed(token)
               |> post_json("/terminal/command_history/delete", %{hostId: "abc", command: "ls"})
               |> json_response(400)
    end

    test "missing hostId or command is a 400 on save and delete", %{conn: _conn} do
      {token, _user} = register_and_login("alice")

      assert %{"error" => "Missing required parameters"} =
               authed(token)
               |> post_json("/terminal/command_history", %{command: "ls"})
               |> json_response(400)

      assert %{"error" => "Missing required parameters"} =
               authed(token)
               |> post_json("/terminal/command_history/delete", %{hostId: 1})
               |> json_response(400)
    end

    test "a non-numeric hostId is a 400 on list and clear", %{conn: _conn} do
      {token, _user} = register_and_login("alice")

      assert %{"error" => "Invalid request parameters"} =
               authed(token) |> get("/terminal/command_history/abc") |> json_response(400)

      assert %{"error" => "Invalid request"} =
               authed(token) |> delete("/terminal/command_history/abc") |> json_response(400)
    end

    test "command history requires authentication", %{conn: conn} do
      assert %{"error" => "Missing authentication token"} =
               conn |> get("/terminal/command_history/1") |> json_response(401)
    end

    test "a user cannot read or clear another user's command history", %{conn: _conn} do
      {alice, _} = register_and_login("alice")
      {bob, _} = register_and_login("bob")

      host_id = create_host(alice)
      save(alice, host_id, "whoami")

      # Bob's view of Alice's host is empty (rows are scoped by user).
      assert [] == history(bob, host_id)

      # Bob clearing that host id touches nothing of Alice's.
      authed(bob) |> delete("/terminal/command_history/#{host_id}") |> json_response(200)
      assert ["whoami"] == history(alice, host_id)
    end

    test "saving a command against an unowned host is a 404 and records nothing", %{
      conn: _conn
    } do
      {alice, _} = register_and_login("alice")
      {bob, bob_user} = register_and_login("bob")

      host_id = create_host(alice)

      assert %{"error" => "Host not found or access denied"} =
               authed(bob)
               |> post_json("/terminal/command_history", %{hostId: host_id, command: "whoami"})
               |> json_response(404)

      # Nothing was persisted — neither against Alice's nor Bob's account.
      assert [] == history(alice, host_id)
      assert History.list_unique_commands(bob_user.id, host_id) == []
    end

    test "saving against a nonexistent host is the same 404", %{conn: _conn} do
      {token, _} = register_and_login("alice")

      assert %{"error" => "Host not found or access denied"} =
               authed(token)
               |> post_json("/terminal/command_history", %{hostId: 999_999, command: "ls"})
               |> json_response(404)
    end
  end

  # --- recent activity ------------------------------------------------------

  describe "recent activity" do
    test "log → recent → reset", %{conn: _conn} do
      {token, _user} = register_and_login("alice")
      host_id = create_host(token)

      logged =
        authed(token)
        |> post_json("/activity/log", %{type: "terminal", hostId: host_id, hostName: "web-1"})
        |> json_response(200)

      assert logged["message"] == "Activity logged"
      assert is_integer(logged["id"])

      [item] = authed(token) |> get("/activity/recent") |> json_response(200)
      assert item["type"] == "terminal"
      assert item["hostId"] == host_id
      assert item["hostName"] == "web-1"
      assert is_binary(item["timestamp"])

      assert %{"message" => "Recent activity cleared"} =
               authed(token) |> delete("/activity/reset") |> json_response(200)

      assert [] == authed(token) |> get("/activity/recent") |> json_response(200)
    end

    test "missing fields and invalid types are 400s", %{conn: _conn} do
      {token, _user} = register_and_login("alice")

      assert %{"error" => "Missing required fields: type, hostId, hostName"} =
               authed(token)
               |> post_json("/activity/log", %{type: "terminal", hostId: 1})
               |> json_response(400)

      assert %{"error" => "Invalid activity type" <> _} =
               authed(token)
               |> post_json("/activity/log", %{type: "bogus", hostId: 1, hostName: "web-1"})
               |> json_response(400)
    end

    test "logging an unowned host is a 404", %{conn: _conn} do
      {alice, _} = register_and_login("alice")
      {bob, _} = register_and_login("bob")
      host_id = create_host(alice)

      assert %{"error" => "Host not found or access denied"} =
               authed(bob)
               |> post_json("/activity/log", %{type: "terminal", hostId: host_id, hostName: "x"})
               |> json_response(404)
    end

    test "recent respects the limit query param, defaulting to 20", %{conn: _conn} do
      {token, user} = register_and_login("alice")
      host_id = create_host(token)

      for _ <- 1..3, do: History.record_activity(user.id, "terminal", host_id, "web-1")

      assert length(authed(token) |> get("/activity/recent", %{limit: "2"}) |> json_response(200)) ==
               2

      # A zero/invalid limit falls back to the default (all three visible).
      assert length(authed(token) |> get("/activity/recent", %{limit: "0"}) |> json_response(200)) ==
               3
    end

    test "trim keeps only the newest rows", %{conn: _conn} do
      {token, user} = register_and_login("alice")
      host_id = create_host(token)

      for _ <- 1..3, do: History.record_activity(user.id, "terminal", host_id, "web-1")
      assert History.trim_activity(user.id, 1) == 2
      assert length(History.list_activity(user.id, 50)) == 1
    end

    test "trim is a no-op at or below the keep count", %{conn: _conn} do
      {token, user} = register_and_login("alice")
      host_id = create_host(token)

      for _ <- 1..3, do: History.record_activity(user.id, "terminal", host_id, "web-1")
      assert History.trim_activity(user.id, 3) == 0
      assert History.trim_activity(user.id, 100) == 0
      assert length(History.list_activity(user.id, 50)) == 3
    end

    test "a non-numeric hostId on activity log is a 404, like a nonexistent host", %{conn: _conn} do
      {token, _user} = register_and_login("alice")

      assert %{"error" => "Host not found or access denied"} =
               authed(token)
               |> post_json("/activity/log", %{type: "terminal", hostId: "abc", hostName: "x"})
               |> json_response(404)
    end

    test "recent activity is isolated per user", %{conn: _conn} do
      {alice, alice_user} = register_and_login("alice")
      {bob, _} = register_and_login("bob")
      host_id = create_host(alice)
      History.record_activity(alice_user.id, "terminal", host_id, "web-1")

      assert [] == authed(bob) |> get("/activity/recent") |> json_response(200)
    end
  end

  # --- helpers --------------------------------------------------------------

  defp save(token, host_id, command) do
    authed(token)
    |> post_json("/terminal/command_history", %{hostId: host_id, command: command})
    |> json_response(201)
  end

  defp history(token, host_id) do
    authed(token) |> get("/terminal/command_history/#{host_id}") |> json_response(200)
  end

  defp sorted_history(token, host_id), do: history(token, host_id) |> Enum.sort()

  defp create_host(token) do
    %{"id" => id} =
      authed(token)
      |> post_json("/host/db/host", %{
        name: "web-1",
        ip: "10.0.0.5",
        port: 22,
        username: "root",
        authType: "password",
        password: "s3cr3t"
      })
      |> json_response(200)

    id
  end

  defp register_and_login(username) do
    conn = build_conn()

    conn
    |> post("/users/create", %{username: username, password: @password})
    |> json_response(200)

    login = post(conn, "/users/login", %{username: username, password: @password})
    %{"jwt" => %{value: token}} = login.resp_cookies
    {token, Accounts.get_user_by_username(username)}
  end

  defp authed(token), do: build_conn() |> put_req_header("authorization", "Bearer #{token}")

  defp post_json(conn, path, payload) do
    conn
    |> put_req_header("content-type", "application/json")
    |> post(path, Jason.encode!(payload))
  end
end
