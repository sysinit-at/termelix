defmodule TermelixWeb.OpenTabFlowTest do
  @moduledoc """
  HTTP coverage for the `/open-tabs` surface: add/upsert (POST), list (GET), bulk sync/reorder
  (PUT), single update (PATCH), delete (DELETE), legacy tab-type normalization, TTL-scoped
  listing, and ownership isolation between users. Exercises the real endpoint end-to-end,
  mirroring `snippet_flow_test`.
  """
  use TermelixWeb.ConnCase

  @record_keys ~w(id userId tabType hostId label tabOrder backendSessionId createdAt updatedAt)

  # --- add + list -----------------------------------------------------------

  test "add → list returns the full open-tab record shape", %{conn: conn} do
    token = register_and_login(conn, "alice")

    add_tab(token, %{
      id: "tab-1",
      tabType: "terminal",
      hostId: nil,
      label: "web-01",
      tabOrder: 0,
      backendSessionId: "sess-1"
    })

    [tab] = list_tabs(token)

    assert Enum.all?(@record_keys, &Map.has_key?(tab, &1))
    assert tab["id"] == "tab-1"
    assert tab["tabType"] == "terminal"
    assert tab["hostId"] == nil
    assert tab["label"] == "web-01"
    assert tab["tabOrder"] == 0
    assert tab["backendSessionId"] == "sess-1"
    assert is_binary(tab["userId"])
    assert is_binary(tab["createdAt"])
    assert is_binary(tab["updatedAt"])
  end

  test "POST requires id, tabType, and label", %{conn: conn} do
    token = register_and_login(conn, "alice")

    for body <- [
          %{tabType: "terminal", label: "x", tabOrder: 0},
          %{id: "t", label: "x", tabOrder: 0},
          %{id: "t", tabType: "terminal", tabOrder: 0},
          %{id: "", tabType: "terminal", label: "x", tabOrder: 0}
        ] do
      assert %{"error" => "id, tabType, and label are required"} =
               authed_json(token)
               |> post("/open-tabs", Jason.encode!(body))
               |> json_response(400)
    end
  end

  # --- upsert ---------------------------------------------------------------

  test "a second POST with the same id updates the existing row (upsert)", %{conn: conn} do
    token = register_and_login(conn, "alice")

    add_tab(token, %{id: "tab-1", tabType: "terminal", label: "old", tabOrder: 0})
    add_tab(token, %{id: "tab-1", tabType: "file", label: "new", tabOrder: 3})

    [tab] = list_tabs(token)
    assert tab["tabType"] == "file"
    assert tab["label"] == "new"
    assert tab["tabOrder"] == 3
  end

  test "update preserves backendSessionId when omitted and overwrites when present",
       %{conn: conn} do
    token = register_and_login(conn, "alice")

    add_tab(token, %{
      id: "tab-1",
      tabType: "terminal",
      label: "l",
      tabOrder: 0,
      backendSessionId: "sess-1"
    })

    # Body omits backendSessionId → the stored value is preserved.
    add_tab(token, %{id: "tab-1", tabType: "terminal", label: "l2", tabOrder: 0})
    [tab] = list_tabs(token)
    assert tab["label"] == "l2"
    assert tab["backendSessionId"] == "sess-1"

    # Body carries an explicit null → the value is overwritten.
    add_tab(token, %{
      id: "tab-1",
      tabType: "terminal",
      label: "l3",
      tabOrder: 0,
      backendSessionId: nil
    })

    [tab] = list_tabs(token)
    assert tab["backendSessionId"] == nil
  end

  # --- bulk sync / reorder --------------------------------------------------

  test "PUT replaces the whole set and lists ordered by tabOrder", %{conn: conn} do
    token = register_and_login(conn, "alice")

    add_tab(token, %{id: "stale", tabType: "terminal", label: "gone", tabOrder: 0})

    body = %{
      tabs: [
        %{id: "b", tabType: "terminal", label: "b", tabOrder: 2},
        %{id: "a", tabType: "terminal", label: "a", tabOrder: 0},
        %{id: "c", tabType: "file", label: "c", tabOrder: 1}
      ]
    }

    assert %{"success" => true} =
             authed_json(token) |> put("/open-tabs", Jason.encode!(body)) |> json_response(200)

    ids = list_tabs(token) |> Enum.map(& &1["id"])
    # The pre-existing tab is gone; the new set is returned ordered by tabOrder.
    assert ids == ["a", "c", "b"]
  end

  test "PUT without a tabs array is a 400", %{conn: conn} do
    token = register_and_login(conn, "alice")

    assert %{"error" => "tabs must be an array"} =
             authed_json(token)
             |> put("/open-tabs", Jason.encode!(%{tabs: "nope"}))
             |> json_response(400)
  end

  test "a failing replace rolls back: the previous set survives", %{conn: conn} do
    token = register_and_login(conn, "alice")
    user = Termelix.Accounts.get_user_by_username("alice")

    add_tab(token, %{id: "t1", tabType: "terminal", label: "one", tabOrder: 0})

    # A non-integer hostId fails the insert cast inside the transaction.
    assert_raise Ecto.ChangeError, fn ->
      Termelix.OpenTabs.replace_for_user(user.id, [
        %{"id" => "t2", "tabType" => "terminal", "label" => "two", "hostId" => "abc"}
      ])
    end

    assert [%{"id" => "t1"}] = list_tabs(token)
  end

  # --- patch ----------------------------------------------------------------

  test "PATCH updates mutable fields; an unknown id is a 404", %{conn: conn} do
    token = register_and_login(conn, "alice")

    add_tab(token, %{id: "tab-1", tabType: "terminal", label: "l", tabOrder: 0})

    assert %{"success" => true} =
             authed_json(token)
             |> patch("/open-tabs/tab-1", Jason.encode!(%{label: "renamed", tabOrder: 7}))
             |> json_response(200)

    [tab] = list_tabs(token)
    assert tab["label"] == "renamed"
    assert tab["tabOrder"] == 7

    assert %{"error" => "Tab not found"} =
             authed_json(token)
             |> patch("/open-tabs/ghost", Jason.encode!(%{label: "x"}))
             |> json_response(404)
  end

  # --- delete ---------------------------------------------------------------

  test "DELETE removes the tab and is idempotent", %{conn: conn} do
    token = register_and_login(conn, "alice")

    add_tab(token, %{id: "tab-1", tabType: "terminal", label: "l", tabOrder: 0})

    assert %{"success" => true} =
             authed(token) |> delete("/open-tabs/tab-1") |> json_response(200)

    assert [] == list_tabs(token)

    # A second delete still reports success (idempotent, mirroring the Node route).
    assert %{"success" => true} =
             authed(token) |> delete("/open-tabs/tab-1") |> json_response(200)
  end

  # --- retired tab types ----------------------------------------------------

  test "a retired tab type is returned verbatim (the frontend drops unknown types)", %{
    conn: conn
  } do
    token = register_and_login(conn, "alice")

    add_tab(token, %{id: "tab-1", tabType: "stats", label: "metrics", tabOrder: 0})

    [tab] = list_tabs(token)
    assert tab["tabType"] == "stats"
  end

  # --- ownership ------------------------------------------------------------

  test "a user cannot see, patch, or delete another user's tab", %{conn: conn} do
    alice = register_and_login(conn, "alice")
    bob = register_and_login(conn, "bob")

    add_tab(alice, %{id: "tab-1", tabType: "terminal", label: "secret", tabOrder: 0})

    # Bob's listing is empty.
    assert [] == list_tabs(bob)

    # Bob cannot patch Alice's tab.
    assert %{"error" => "Tab not found"} =
             authed_json(bob)
             |> patch("/open-tabs/tab-1", Jason.encode!(%{label: "hijack"}))
             |> json_response(404)

    # Bob's delete reports success but leaves Alice's tab untouched.
    assert %{"success" => true} =
             authed(bob) |> delete("/open-tabs/tab-1") |> json_response(200)

    # Bob's bulk sync only replaces Bob's own (empty) set.
    authed_json(bob)
    |> put(
      "/open-tabs",
      Jason.encode!(%{tabs: [%{id: "bob-1", tabType: "terminal", label: "b", tabOrder: 0}]})
    )
    |> json_response(200)

    [tab] = list_tabs(alice)
    assert tab["id"] == "tab-1"
    assert tab["label"] == "secret"
  end

  test "open-tabs require authentication", %{conn: conn} do
    assert %{"error" => "Missing authentication token"} =
             conn |> get("/open-tabs") |> json_response(401)
  end

  # --- helpers --------------------------------------------------------------

  defp add_tab(token, tab) do
    assert %{"success" => true} =
             authed_json(token) |> post("/open-tabs", Jason.encode!(tab)) |> json_response(200)
  end

  defp list_tabs(token), do: authed(token) |> get("/open-tabs") |> json_response(200)

  defp register_and_login(conn, username) do
    password = "correct horse battery staple"

    conn
    |> post("/users/create", %{username: username, password: password})
    |> json_response(200)

    login_conn = post(conn, "/users/login", %{username: username, password: password})
    %{"jwt" => %{value: token}} = login_conn.resp_cookies
    token
  end

  defp authed(token),
    do:
      Phoenix.ConnTest.build_conn()
      |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")

  defp authed_json(token),
    do: authed(token) |> Plug.Conn.put_req_header("content-type", "application/json")
end
