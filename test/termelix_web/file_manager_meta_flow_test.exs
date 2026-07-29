defmodule TermelixWeb.FileManagerMetaFlowTest do
  @moduledoc """
  HTTP coverage for the file-manager metadata surface
  (`/host/file_manager/{recent,pinned,shortcuts}`): add/list/remove, the recent upsert
  ("open recording") path, name resolution, newest-first ordering, the recent 20-item cap,
  the pinned/shortcut duplicate 409, validation, ownership isolation between users, and auth.
  Exercises the real endpoints end-to-end, mirroring `history_flow_test`.
  """
  use TermelixWeb.ConnCase

  import Ecto.Query, only: [from: 2]

  alias Termelix.Repo
  alias Termelix.Schema.FileManagerRecent

  @password "correct horse battery staple"

  # --- recent ---------------------------------------------------------------

  describe "recent" do
    test "add → list returns the full record shape; name defaults to the basename", %{conn: _c} do
      {token, _user} = register_and_login("alice")
      host_id = create_host(token)

      assert %{"message" => "Recent file added"} =
               post_meta(token, "/host/file_manager/recent", %{
                 hostId: host_id,
                 path: "/etc/hosts"
               })

      [rec] = list_meta(token, "/host/file_manager/recent", host_id)

      assert Enum.sort(Map.keys(rec)) == ~w(hostId id lastOpened name path userId)
      assert rec["hostId"] == host_id
      assert rec["path"] == "/etc/hosts"
      assert rec["name"] == "hosts"
      assert is_integer(rec["id"]) and rec["id"] != 0
      assert is_binary(rec["userId"])
      assert is_binary(rec["lastOpened"])
    end

    test "an explicit name wins; a trailing-slash path resolves to \"Unknown\"", %{conn: _c} do
      {token, _user} = register_and_login("alice")
      host_id = create_host(token)

      post_meta(token, "/host/file_manager/recent", %{
        hostId: host_id,
        path: "/var/log/app.log",
        name: "App Log"
      })

      post_meta(token, "/host/file_manager/recent", %{hostId: host_id, path: "/srv/"})

      names = list_meta(token, "/host/file_manager/recent", host_id) |> Enum.map(& &1["name"])
      assert "App Log" in names
      assert "Unknown" in names
    end

    test "re-opening the same path upserts (one row, bumped) rather than duplicating",
         %{conn: _c} do
      {token, _user} = register_and_login("alice")
      host_id = create_host(token)

      post_meta(token, "/host/file_manager/recent", %{hostId: host_id, path: "/a"})
      # Pin an old lastOpened so a bump is observable.
      Repo.update_all(from(r in FileManagerRecent, where: r.path == ^"/a"),
        set: [lastOpened: "2000-01-01T00:00:00.000Z"]
      )

      post_meta(token, "/host/file_manager/recent", %{hostId: host_id, path: "/a"})

      [rec] = list_meta(token, "/host/file_manager/recent", host_id)
      assert rec["path"] == "/a"
      assert rec["lastOpened"] > "2000-01-01T00:00:00.000Z"
    end

    test "listing is newest-first by lastOpened", %{conn: _c} do
      {token, _user} = register_and_login("alice")
      host_id = create_host(token)

      for path <- ["/a", "/b", "/c"],
          do: post_meta(token, "/host/file_manager/recent", %{hostId: host_id, path: path})

      # Explicit, distinct timestamps make the ordering deterministic.
      set_recent_time("/a", "2026-01-03T00:00:00.000Z")
      set_recent_time("/b", "2026-01-01T00:00:00.000Z")
      set_recent_time("/c", "2026-01-02T00:00:00.000Z")

      paths = list_meta(token, "/host/file_manager/recent", host_id) |> Enum.map(& &1["path"])
      assert paths == ["/a", "/c", "/b"]
    end

    test "listing is capped at 20 entries", %{conn: _c} do
      {token, user} = register_and_login("alice")
      host_id = create_host(token)

      rows =
        for n <- 1..25 do
          %{
            userId: user.id,
            hostId: host_id,
            name: "f#{n}",
            path: "/f#{n}",
            lastOpened: "2026-02-#{String.pad_leading("#{n}", 2, "0")}T00:00:00.000Z"
          }
        end

      Repo.insert_all(FileManagerRecent, rows)

      assert length(list_meta(token, "/host/file_manager/recent", host_id)) == 20
    end

    test "remove deletes the entry and is idempotent", %{conn: _c} do
      {token, _user} = register_and_login("alice")
      host_id = create_host(token)

      post_meta(token, "/host/file_manager/recent", %{hostId: host_id, path: "/a"})

      assert %{"message" => "Recent file removed"} =
               delete_meta(token, "/host/file_manager/recent", %{hostId: host_id, path: "/a"})

      assert [] == list_meta(token, "/host/file_manager/recent", host_id)

      # A second delete still reports success (idempotent, mirroring the Node route).
      assert %{"message" => "Recent file removed"} =
               delete_meta(token, "/host/file_manager/recent", %{hostId: host_id, path: "/a"})
    end
  end

  # --- pinned ---------------------------------------------------------------

  describe "pinned" do
    test "add → list → duplicate 409 → remove", %{conn: _c} do
      {token, _user} = register_and_login("alice")
      host_id = create_host(token)

      assert %{"message" => "File pinned"} =
               post_meta(token, "/host/file_manager/pinned", %{hostId: host_id, path: "/opt"})

      [rec] = list_meta(token, "/host/file_manager/pinned", host_id)
      assert rec["path"] == "/opt"
      assert rec["name"] == "opt"
      assert is_binary(rec["pinnedAt"])

      # Re-pinning the same (host, path) is a 409, not a duplicate row.
      assert %{"error" => "File already pinned"} =
               authed(token)
               |> post_json("/host/file_manager/pinned", %{hostId: host_id, path: "/opt"})
               |> json_response(409)

      assert length(list_meta(token, "/host/file_manager/pinned", host_id)) == 1

      assert %{"message" => "Pinned file removed"} =
               delete_meta(token, "/host/file_manager/pinned", %{hostId: host_id, path: "/opt"})

      assert [] == list_meta(token, "/host/file_manager/pinned", host_id)
    end
  end

  # --- shortcuts ------------------------------------------------------------

  describe "shortcuts" do
    test "add → list → duplicate 409 → remove", %{conn: _c} do
      {token, _user} = register_and_login("alice")
      host_id = create_host(token)

      assert %{"message" => "Shortcut added"} =
               post_meta(token, "/host/file_manager/shortcuts", %{
                 hostId: host_id,
                 path: "/home/alice",
                 name: "home"
               })

      [rec] = list_meta(token, "/host/file_manager/shortcuts", host_id)
      assert rec["path"] == "/home/alice"
      assert rec["name"] == "home"
      assert is_binary(rec["createdAt"])

      assert %{"error" => "Shortcut already exists"} =
               authed(token)
               |> post_json("/host/file_manager/shortcuts", %{
                 hostId: host_id,
                 path: "/home/alice"
               })
               |> json_response(409)

      assert length(list_meta(token, "/host/file_manager/shortcuts", host_id)) == 1

      assert %{"message" => "Shortcut removed"} =
               delete_meta(token, "/host/file_manager/shortcuts", %{
                 hostId: host_id,
                 path: "/home/alice"
               })

      assert [] == list_meta(token, "/host/file_manager/shortcuts", host_id)
    end
  end

  # --- validation -----------------------------------------------------------

  describe "validation" do
    test "GET without a usable hostId is a 400", %{conn: _c} do
      {token, _user} = register_and_login("alice")

      for surface <- ~w(recent pinned shortcuts), query <- ["", "?hostId=0", "?hostId=abc"] do
        assert %{"error" => "Host ID is required"} =
                 authed(token)
                 |> get("/host/file_manager/#{surface}#{query}")
                 |> json_response(400)
      end
    end

    test "POST/DELETE with a missing hostId or path is a 400", %{conn: _c} do
      {token, _user} = register_and_login("alice")
      host_id = create_host(token)

      for surface <- ~w(recent pinned shortcuts),
          body <- [%{path: "/a"}, %{hostId: host_id}, %{hostId: host_id, path: ""}] do
        assert %{"error" => "Invalid data"} =
                 authed(token)
                 |> post_json("/host/file_manager/#{surface}", body)
                 |> json_response(400)

        assert %{"error" => "Invalid data"} =
                 authed(token)
                 |> delete_json("/host/file_manager/#{surface}", body)
                 |> json_response(400)
      end
    end
  end

  # --- ownership ------------------------------------------------------------

  test "a user cannot see or delete another user's metadata", %{conn: _c} do
    {alice, _} = register_and_login("alice")
    {bob, _} = register_and_login("bob")
    host_id = create_host(alice)

    post_meta(alice, "/host/file_manager/recent", %{hostId: host_id, path: "/secret"})
    post_meta(alice, "/host/file_manager/pinned", %{hostId: host_id, path: "/secret"})
    post_meta(alice, "/host/file_manager/shortcuts", %{hostId: host_id, path: "/secret"})

    # Bob's view of the same host is empty — rows are scoped by user.
    assert [] == list_meta(bob, "/host/file_manager/recent", host_id)
    assert [] == list_meta(bob, "/host/file_manager/pinned", host_id)
    assert [] == list_meta(bob, "/host/file_manager/shortcuts", host_id)

    # Bob's delete reports success but leaves Alice's rows untouched.
    delete_meta(bob, "/host/file_manager/recent", %{hostId: host_id, path: "/secret"})
    delete_meta(bob, "/host/file_manager/pinned", %{hostId: host_id, path: "/secret"})
    delete_meta(bob, "/host/file_manager/shortcuts", %{hostId: host_id, path: "/secret"})

    assert [%{"path" => "/secret"}] = list_meta(alice, "/host/file_manager/recent", host_id)
    assert [%{"path" => "/secret"}] = list_meta(alice, "/host/file_manager/pinned", host_id)
    assert [%{"path" => "/secret"}] = list_meta(alice, "/host/file_manager/shortcuts", host_id)
  end

  test "the metadata endpoints require authentication", %{conn: conn} do
    assert %{"error" => "Missing authentication token"} =
             conn |> get("/host/file_manager/recent?hostId=1") |> json_response(401)
  end

  # --- helpers --------------------------------------------------------------

  defp post_meta(token, path, body) do
    authed(token) |> post_json(path, body) |> json_response(200)
  end

  defp delete_meta(token, path, body) do
    authed(token) |> delete_json(path, body) |> json_response(200)
  end

  defp list_meta(token, path, host_id) do
    authed(token) |> get("#{path}?hostId=#{host_id}") |> json_response(200)
  end

  defp set_recent_time(path, iso) do
    Repo.update_all(from(r in FileManagerRecent, where: r.path == ^path), set: [lastOpened: iso])
  end

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
    {token, Termelix.Accounts.get_user_by_username(username)}
  end

  defp authed(token), do: build_conn() |> put_req_header("authorization", "Bearer #{token}")

  defp post_json(conn, path, payload) do
    conn
    |> put_req_header("content-type", "application/json")
    |> post(path, Jason.encode!(payload))
  end

  # DELETE with a JSON body (the frontend sends `axios.delete(url, {data})`).
  defp delete_json(conn, path, payload) do
    conn
    |> put_req_header("content-type", "application/json")
    |> delete(path, Jason.encode!(payload))
  end
end
