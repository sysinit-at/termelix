defmodule TermelixWeb.SystemFlowTest do
  @moduledoc """
  HTTP coverage for the system-bootstrap surface: the version/update check (`/version`),
  the releases feed (`/releases/rss`), the announcement-alerts surface (`/alerts` +
  dismiss/dismissed/undismiss), and the two user actions the boot flow uses
  (`/users/me/token`).

  GitHub is stubbed through `Req.Test` (wired in via the `:req_options` app env) so the
  outbound calls are deterministic and the resilience fallbacks are exercised end-to-end.
  """
  use TermelixWeb.ConnCase

  @github_stub Termelix.System

  setup do
    Application.put_env(:termelix, :req_options, plug: {Req.Test, @github_stub})
    # The update check ships disabled (no public repo yet); these tests exercise the
    # enabled path against the stub. The kill-switch default has its own test below.
    Application.put_env(:termelix, :update_check_enabled, true)

    on_exit(fn ->
      Application.delete_env(:termelix, :req_options)
      Application.delete_env(:termelix, :update_check_enabled)
    end)

    :ok
  end

  test "the update-check kill switch (default) forces local-only /version and an empty feed",
       %{conn: conn} do
    Application.delete_env(:termelix, :update_check_enabled)
    token = register_and_login(conn, "alice")
    local = Termelix.System.local_version()

    assert %{"localVersion" => ^local, "status" => "update_check_disabled"} =
             authed(token) |> get("/version") |> json_response(200)

    assert %{"items" => [], "total_count" => 0} =
             authed(token) |> get("/releases/rss") |> json_response(200)
  end

  # --- /version -------------------------------------------------------------

  test "GET /version?checkRemote=false returns the local-only shape without any fetch",
       %{conn: conn} do
    token = register_and_login(conn, "alice")
    local = Termelix.System.local_version()

    assert %{
             "localVersion" => ^local,
             "buildTime" => build_time,
             "status" => "update_check_disabled"
           } = authed(token) |> get("/version?checkRemote=false") |> json_response(200)

    assert build_time == Termelix.System.build_time()
    assert {:ok, _, 0} = DateTime.from_iso8601(build_time)
  end

  test "GET /version reports up_to_date when the remote matches the local version",
       %{conn: conn} do
    token = register_and_login(conn, "alice")
    local = Termelix.System.local_version()

    stub_release(%{
      "tag_name" => "v" <> local,
      "name" => "Release",
      "published_at" => "2026-01-01T00:00:00Z",
      "html_url" => "https://example/rel"
    })

    body = authed(token) |> get("/version") |> json_response(200)

    assert body["status"] == "up_to_date"
    assert body["localVersion"] == local
    assert body["version"] == local
    assert body["remoteVersion"] == local
    assert body["cached"] == false
    assert body["latest_release"]["tag_name"] == "v" <> local
    assert body["latest_release"]["html_url"] == "https://example/rel"
  end

  test "GET /version reports requires_update when the remote is ahead", %{conn: conn} do
    token = register_and_login(conn, "alice")
    stub_release(%{"tag_name" => "v999.0.0", "name" => "999.0.0"})

    body = authed(token) |> get("/version") |> json_response(200)
    assert body["status"] == "requires_update"
    assert body["remoteVersion"] == "999.0.0"
  end

  test "GET /version reports beta when the local build is ahead of the remote", %{conn: conn} do
    token = register_and_login(conn, "alice")
    stub_release(%{"tag_name" => "v0.0.0", "name" => "0.0.0"})

    body = authed(token) |> get("/version") |> json_response(200)
    assert body["status"] == "beta"
  end

  test "GET /version degrades to the local-only shape when the fetch fails", %{conn: conn} do
    token = register_and_login(conn, "alice")
    local = Termelix.System.local_version()
    stub_error()

    assert %{"localVersion" => ^local, "status" => "update_check_disabled"} =
             authed(token) |> get("/version") |> json_response(200)
  end

  # --- /releases/rss --------------------------------------------------------

  test "GET /releases/rss maps GitHub releases into the feed shape", %{conn: conn} do
    token = register_and_login(conn, "alice")

    stub_releases([
      %{
        "id" => 42,
        "tag_name" => "v1.2.3",
        "name" => "1.2.3",
        "body" => "release notes",
        "html_url" => "https://example/1.2.3",
        "published_at" => "2026-02-02T00:00:00Z",
        "prerelease" => false,
        "draft" => false,
        "assets" => [
          %{
            "name" => "app.zip",
            "size" => 100,
            "download_count" => 7,
            "browser_download_url" => "https://example/dl"
          }
        ]
      }
    ])

    body = authed(token) |> get("/releases/rss?per_page=100") |> json_response(200)

    assert body["total_count"] == 1
    assert body["cached"] == false
    assert body["feed"]["title"] == "Termelix Releases"
    assert body["feed"]["link"] == "https://github.com/Termelix-SSH/Termelix/releases"

    [item] = body["items"]
    assert item["id"] == 42
    assert item["title"] == "1.2.3"
    assert item["description"] == "release notes"
    assert item["link"] == "https://example/1.2.3"
    assert item["pubDate"] == "2026-02-02T00:00:00Z"
    assert item["version"] == "v1.2.3"
    assert item["isPrerelease"] == false
    assert item["isDraft"] == false
    assert [asset] = item["assets"]
    assert asset["name"] == "app.zip"
    assert asset["download_count"] == 7
    assert asset["download_url"] == "https://example/dl"
  end

  test "GET /releases/rss degrades to an empty feed when the fetch fails", %{conn: conn} do
    token = register_and_login(conn, "alice")
    stub_error()

    body = authed(token) |> get("/releases/rss?per_page=100") |> json_response(200)
    assert body["items"] == []
    assert body["total_count"] == 0
    assert body["feed"]["title"] == "Termelix Releases"
  end

  # --- /alerts --------------------------------------------------------------

  test "GET /alerts returns active alerts, dropping expired ones", %{conn: conn} do
    token = register_and_login(conn, "alice")
    stub_alerts([alert("live", future()), alert("stale", past())])

    body = authed(token) |> get("/alerts") |> json_response(200)
    assert body["total_count"] == 1
    assert body["cached"] == false
    assert [%{"id" => "live"}] = body["alerts"]
  end

  test "GET /alerts degrades to an empty list when the fetch fails", %{conn: conn} do
    token = register_and_login(conn, "alice")
    stub_error()

    assert %{"alerts" => [], "total_count" => 0, "cached" => false} =
             authed(token) |> get("/alerts") |> json_response(200)
  end

  test "a dismissed alert is excluded from /alerts", %{conn: conn} do
    token = register_and_login(conn, "alice")

    stub_alerts([alert("live", future())])
    dismiss(token, "live")

    stub_alerts([alert("live", future())])

    assert %{"alerts" => [], "total_count" => 0} =
             authed(token) |> get("/alerts") |> json_response(200)
  end

  # --- /alerts/dismiss + /alerts/dismissed ----------------------------------

  test "POST /alerts/dismiss requires an alertId, dismisses once, then 409s", %{conn: conn} do
    token = register_and_login(conn, "alice")

    assert %{"error" => "Alert ID is required"} =
             authed_json(token)
             |> post("/alerts/dismiss", Jason.encode!(%{}))
             |> json_response(400)

    assert %{"message" => "Alert dismissed successfully"} =
             authed_json(token)
             |> post("/alerts/dismiss", Jason.encode!(%{alertId: "a1"}))
             |> json_response(200)

    assert %{"error" => "Alert already dismissed"} =
             authed_json(token)
             |> post("/alerts/dismiss", Jason.encode!(%{alertId: "a1"}))
             |> json_response(409)
  end

  test "GET /alerts/dismissed returns the full dismissal record shape", %{conn: conn} do
    token = register_and_login(conn, "alice")
    dismiss(token, "a1")

    body = authed(token) |> get("/alerts/dismissed") |> json_response(200)
    assert body["total_count"] == 1
    assert [record] = body["dismissed_alerts"]
    assert record["alertId"] == "a1"
    assert is_integer(record["id"])
    assert is_binary(record["userId"])
    assert is_binary(record["dismissedAt"])
  end

  # --- DELETE /alerts/dismiss -----------------------------------------------

  test "DELETE /alerts/dismiss undismisses, 400s without an id, and 404s when absent",
       %{conn: conn} do
    token = register_and_login(conn, "alice")
    dismiss(token, "a1")

    assert %{"error" => "Alert ID is required"} =
             authed_json(token)
             |> delete("/alerts/dismiss", Jason.encode!(%{}))
             |> json_response(400)

    assert %{"message" => "Alert undismissed successfully"} =
             authed_json(token)
             |> delete("/alerts/dismiss", Jason.encode!(%{alertId: "a1"}))
             |> json_response(200)

    # Now the row is gone → a second undismiss is a 404.
    assert %{"error" => "Dismissed alert not found"} =
             authed_json(token)
             |> delete("/alerts/dismiss", Jason.encode!(%{alertId: "a1"}))
             |> json_response(404)
  end

  # --- ownership ------------------------------------------------------------

  test "one user's dismissals are invisible to another", %{conn: conn} do
    alice = register_and_login(conn, "alice")
    bob = register_and_login(conn, "bob")

    dismiss(alice, "a1")

    assert %{"dismissed_alerts" => [], "total_count" => 0} =
             authed(bob) |> get("/alerts/dismissed") |> json_response(200)

    # Bob cannot undismiss Alice's row.
    assert %{"error" => "Dismissed alert not found"} =
             authed_json(bob)
             |> delete("/alerts/dismiss", Jason.encode!(%{alertId: "a1"}))
             |> json_response(404)
  end

  # --- auth -----------------------------------------------------------------

  test "the system-bootstrap endpoints require authentication", %{conn: conn} do
    for path <- ["/version", "/releases/rss", "/alerts", "/alerts/dismissed"] do
      assert %{"error" => "Missing authentication token"} =
               conn |> get(path) |> json_response(401)
    end
  end

  # --- /users/me/token ------------------------------------------------------

  test "GET /users/me/token echoes the jwt cookie back, and is null for bearer clients",
       %{conn: conn} do
    token = register_and_login(conn, "alice")

    # Cookie client: the token is read from the request cookie and echoed back.
    assert %{"token" => ^token} =
             Phoenix.ConnTest.build_conn()
             |> Plug.Test.put_req_cookie("jwt", token)
             |> get("/users/me/token")
             |> json_response(200)

    # Bearer-only client: no cookie present → null (matches Node, which reads only the cookie).
    assert %{"token" => nil} = authed(token) |> get("/users/me/token") |> json_response(200)
  end

  # --- stub helpers ---------------------------------------------------------

  defp stub_release(release), do: Req.Test.stub(@github_stub, &Req.Test.json(&1, release))
  defp stub_releases(releases), do: Req.Test.stub(@github_stub, &Req.Test.json(&1, releases))
  defp stub_alerts(alerts), do: Req.Test.stub(@github_stub, &Req.Test.json(&1, alerts))
  defp stub_error, do: Req.Test.stub(@github_stub, &Req.Test.transport_error(&1, :econnrefused))

  defp alert(id, expires_at) do
    %{"id" => id, "title" => "t-#{id}", "message" => "m", "expiresAt" => expires_at}
  end

  defp future, do: DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.to_iso8601()
  defp past, do: DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.to_iso8601()

  # --- request helpers ------------------------------------------------------

  defp dismiss(token, alert_id) do
    assert %{"message" => "Alert dismissed successfully"} =
             authed_json(token)
             |> post("/alerts/dismiss", Jason.encode!(%{alertId: alert_id}))
             |> json_response(200)
  end

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
