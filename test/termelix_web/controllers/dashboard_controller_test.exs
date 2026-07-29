defmodule TermelixWeb.DashboardControllerTest do
  @moduledoc """
  HTTP coverage for the dashboard surface: server uptime (`GET /uptime`) and service-link
  CRUD (`/service-links`) — validation, ordering, ownership, and status codes.
  """
  use TermelixWeb.ConnCase

  alias Termelix.Accounts

  @password "correct horse battery staple"

  setup do
    {token, user} = register_and_login("alice", @password)
    %{token: token, user: user}
  end

  # --- uptime ---------------------------------------------------------------

  test "GET /uptime returns the uptime shape", %{token: token} do
    body = authed(token) |> get("/uptime") |> json_response(200)

    assert is_integer(body["uptimeMs"])
    assert is_integer(body["uptimeSeconds"])
    assert body["uptimeSeconds"] == div(body["uptimeMs"], 1000)
    assert Regex.match?(~r/^\d+d \d+h \d+m$/, body["formatted"])
  end

  # --- service links --------------------------------------------------------

  describe "service links CRUD" do
    test "create appends links with an incrementing order", %{token: token, user: user} do
      first =
        authed(token)
        |> post_json("/service-links", %{label: "Grafana", url: "https://grafana.example"})
        |> json_response(201)

      assert first["label"] == "Grafana"
      assert first["url"] == "https://grafana.example"
      assert first["order"] == 0
      assert first["userId"] == user.id

      second =
        authed(token)
        |> post_json("/service-links", %{label: "Portainer", url: "https://portainer.example"})
        |> json_response(201)

      assert second["order"] == 1
    end

    test "create trims label and url", %{token: token} do
      link =
        authed(token)
        |> post_json("/service-links", %{label: "  Padded  ", url: "  https://ex.com  "})
        |> json_response(201)

      assert link["label"] == "Padded"
      assert link["url"] == "https://ex.com"
    end

    test "create requires label and url", %{token: token} do
      assert %{"error" => "label and url are required"} =
               authed(token)
               |> post_json("/service-links", %{label: "only"})
               |> json_response(400)
    end

    test "create rejects a non-http(s) url", %{token: token} do
      assert %{"error" => "url must be a valid http or https URL"} =
               authed(token)
               |> post_json("/service-links", %{label: "x", url: "ftp://ex.com"})
               |> json_response(400)
    end

    test "list returns links ordered by order", %{token: token} do
      authed(token)
      |> post_json("/service-links", %{label: "A", url: "https://a.com"})
      |> json_response(201)

      authed(token)
      |> post_json("/service-links", %{label: "B", url: "https://b.com"})
      |> json_response(201)

      links = authed(token) |> get("/service-links") |> json_response(200)
      assert [%{"label" => "A", "order" => 0}, %{"label" => "B", "order" => 1}] = links
    end

    test "update changes label and url", %{token: token} do
      %{"id" => id} =
        authed(token)
        |> post_json("/service-links", %{label: "old", url: "https://old.com"})
        |> json_response(201)

      updated =
        authed(token)
        |> put_json("/service-links/#{id}", %{label: "new", url: "https://new.com"})
        |> json_response(200)

      assert updated["label"] == "new"
      assert updated["url"] == "https://new.com"
    end

    test "update rejects an invalid url before touching the row", %{token: token} do
      %{"id" => id} =
        authed(token)
        |> post_json("/service-links", %{label: "x", url: "https://x.com"})
        |> json_response(201)

      assert %{"error" => "url must be a valid http or https URL"} =
               authed(token)
               |> put_json("/service-links/#{id}", %{url: "javascript:alert(1)"})
               |> json_response(400)
    end

    test "update with nothing to change is a 400", %{token: token} do
      %{"id" => id} =
        authed(token)
        |> post_json("/service-links", %{label: "x", url: "https://x.com"})
        |> json_response(201)

      assert %{"error" => "Nothing to update"} =
               authed(token)
               |> put_json("/service-links/#{id}", %{label: "   "})
               |> json_response(400)
    end

    test "update 400s a non-numeric id and 404s an unknown id", %{token: token} do
      assert %{"error" => "Invalid id"} =
               authed(token)
               |> put_json("/service-links/abc", %{label: "y"})
               |> json_response(400)

      assert %{"error" => "Not found"} =
               authed(token)
               |> put_json("/service-links/999999", %{label: "y"})
               |> json_response(404)
    end

    test "delete removes an owned link, then 404s", %{token: token} do
      %{"id" => id} =
        authed(token)
        |> post_json("/service-links", %{label: "x", url: "https://x.com"})
        |> json_response(201)

      assert %{"message" => "Service link deleted"} =
               authed(token) |> delete("/service-links/#{id}") |> json_response(200)

      assert %{"error" => "Not found"} =
               authed(token) |> delete("/service-links/#{id}") |> json_response(404)
    end

    test "a user cannot update or delete another user's link", %{token: token} do
      %{"id" => id} =
        authed(token)
        |> post_json("/service-links", %{label: "x", url: "https://x.com"})
        |> json_response(201)

      {bob, _user} = register_and_login("bob", @password)

      assert %{"error" => "Not found"} =
               authed(bob)
               |> put_json("/service-links/#{id}", %{label: "y"})
               |> json_response(404)

      assert %{"error" => "Not found"} =
               authed(bob) |> delete("/service-links/#{id}") |> json_response(404)
    end
  end

  # --- auth -----------------------------------------------------------------

  test "the dashboard endpoints require authentication", %{conn: conn} do
    assert %{"error" => "Missing authentication token"} =
             conn |> get("/service-links") |> json_response(401)
  end

  # --- helpers --------------------------------------------------------------

  defp register_and_login(username, password) do
    conn = build_conn()
    conn |> post("/users/create", %{username: username, password: password}) |> json_response(200)
    login = post(conn, "/users/login", %{username: username, password: password})
    %{"jwt" => %{value: token}} = login.resp_cookies
    {token, Accounts.get_user_by_username(username)}
  end

  defp authed(token), do: build_conn() |> put_req_header("authorization", "Bearer #{token}")

  defp post_json(conn, path, payload) do
    conn
    |> put_req_header("content-type", "application/json")
    |> post(path, Jason.encode!(payload))
  end

  defp put_json(conn, path, payload) do
    conn
    |> put_req_header("content-type", "application/json")
    |> put(path, Jason.encode!(payload))
  end
end
