defmodule TermelixWeb.UserPreferenceTest do
  @moduledoc """
  HTTP surface for `/user-preferences`: register + login for a token, then exercise GET
  (defaults + reflection of saved values) and PUT (upsert, echo, validation, empty-body).
  """
  use TermelixWeb.ConnCase

  @password "correct horse battery staple"

  setup %{conn: conn} do
    conn
    |> post("/users/create", %{username: "prefuser", password: @password})
    |> json_response(200)

    login_conn = post(conn, "/users/login", %{username: "prefuser", password: @password})
    %{"jwt" => %{value: token}} = login_conn.resp_cookies

    {:ok, token: token}
  end

  test "GET returns defaults when no preferences have been saved", %{token: token} do
    prefs = authed(token) |> get("/user-preferences") |> json_response(200)

    assert prefs["reopenTabsOnLogin"] == false
    assert prefs["storageMode"] == "cloud"
    assert prefs["theme"] == nil
    assert prefs["compactHostView"] == nil
    # updatedAt is internal-only; the GET shape never exposes it.
    refute Map.has_key?(prefs, "updatedAt")
    assert Map.has_key?(prefs, "statusColorScheme")
  end

  test "PUT upserts and echoes only the supplied fields", %{token: token} do
    resp =
      authed_json(token)
      |> put(
        "/user-preferences",
        Jason.encode!(%{reopenTabsOnLogin: true, theme: "dark", fontSize: "14"})
      )
      |> json_response(200)

    assert resp["success"] == true
    assert resp["reopenTabsOnLogin"] == true
    assert resp["theme"] == "dark"
    assert resp["fontSize"] == "14"
    assert is_binary(resp["updatedAt"])
    # Fields that were not supplied are not echoed back.
    refute Map.has_key?(resp, "language")
  end

  test "GET reflects saved preferences", %{token: token} do
    authed_json(token)
    |> put(
      "/user-preferences",
      Jason.encode!(%{theme: "dark", storageMode: "local", showHostTags: true})
    )
    |> json_response(200)

    prefs = authed(token) |> get("/user-preferences") |> json_response(200)

    assert prefs["theme"] == "dark"
    assert prefs["storageMode"] == "local"
    assert prefs["showHostTags"] == true
    # Untouched fields keep their defaults.
    assert prefs["reopenTabsOnLogin"] == false
  end

  test "a second PUT updates the existing row", %{token: token} do
    authed_json(token)
    |> put("/user-preferences", Jason.encode!(%{theme: "dark"}))
    |> json_response(200)

    authed_json(token)
    |> put("/user-preferences", Jason.encode!(%{fontSize: "16"}))
    |> json_response(200)

    prefs = authed(token) |> get("/user-preferences") |> json_response(200)

    assert prefs["theme"] == "dark"
    assert prefs["fontSize"] == "16"
  end

  test "PUT with no preference fields is a 400", %{token: token} do
    assert %{"error" => "No preferences provided"} =
             authed_json(token)
             |> put("/user-preferences", Jason.encode!(%{}))
             |> json_response(400)
  end

  test "PUT rejects a non-string field", %{token: token} do
    assert %{"error" => "theme must be a string"} =
             authed_json(token)
             |> put("/user-preferences", Jason.encode!(%{theme: 123}))
             |> json_response(400)
  end

  test "PUT rejects a non-boolean reopenTabsOnLogin", %{token: token} do
    assert %{"error" => "reopenTabsOnLogin must be a boolean"} =
             authed_json(token)
             |> put("/user-preferences", Jason.encode!(%{reopenTabsOnLogin: "yes"}))
             |> json_response(400)
  end

  test "unauthenticated access is rejected", %{conn: conn} do
    assert %{"error" => "Missing authentication token"} =
             conn |> get("/user-preferences") |> json_response(401)
  end

  defp authed(token) do
    Phoenix.ConnTest.build_conn()
    |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
  end

  defp authed_json(token) do
    authed(token) |> Plug.Conn.put_req_header("content-type", "application/json")
  end
end
