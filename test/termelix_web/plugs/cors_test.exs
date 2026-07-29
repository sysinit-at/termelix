defmodule TermelixWeb.Plugs.CorsTest do
  use TermelixWeb.ConnCase, async: false

  alias TermelixWeb.Plugs.Cors

  setup do
    old = Application.get_env(:termelix, :allowed_origins)
    Application.put_env(:termelix, :allowed_origins, ["https://termelix.example.com"])

    on_exit(fn ->
      if old,
        do: Application.put_env(:termelix, :allowed_origins, old),
        else: Application.delete_env(:termelix, :allowed_origins)
    end)

    :ok
  end

  test "passes through requests without an Origin header untouched" do
    conn = Cors.call(build_conn(:get, "/users/me"), [])
    refute conn.halted
    assert get_resp_header(conn, "access-control-allow-origin") == []
  end

  test "reflects a same-origin Origin with credentials" do
    conn =
      :get
      |> build_conn("/users/me")
      |> put_req_header("origin", "http://www.example.com")
      |> Cors.call([])

    assert get_resp_header(conn, "access-control-allow-origin") == ["http://www.example.com"]
    assert get_resp_header(conn, "access-control-allow-credentials") == ["true"]
  end

  test "reflects an allowlisted Origin" do
    conn =
      :get
      |> build_conn("/users/me")
      |> put_req_header("origin", "https://termelix.example.com")
      |> Cors.call([])

    assert get_resp_header(conn, "access-control-allow-origin") == [
             "https://termelix.example.com"
           ]
  end

  test "rejects a disallowed Origin with 403 and no CORS headers" do
    conn =
      :post
      |> build_conn("/users/login")
      |> put_req_header("origin", "https://evil.example.com")
      |> Cors.call([])

    assert conn.halted
    assert conn.status == 403
    assert get_resp_header(conn, "access-control-allow-origin") == []
  end

  test "answers preflight for allowed origins" do
    conn =
      :options
      |> build_conn("/users/login")
      |> put_req_header("origin", "http://www.example.com")
      |> Cors.call([])

    assert conn.halted
    assert conn.status == 204
    assert get_resp_header(conn, "access-control-allow-methods") != []
  end

  test "rejects preflight from disallowed origins" do
    conn =
      :options
      |> build_conn("/users/login")
      |> put_req_header("origin", "https://evil.example.com")
      |> Cors.call([])

    assert conn.halted
    assert conn.status == 403
  end

  describe "preflight through the endpoint (not just the plug)" do
    # A pipeline only runs once a route MATCHES, and the router declares no `options` routes —
    # so while CORS lived only in the `:api` pipeline, every browser preflight 404'd and the
    # allowlist below was unreachable. Harmless until a cross-origin call carries a custom
    # header; `x-reauth-password` on the admin export is exactly that.
    test "an OPTIONS preflight to a path with no options route is answered, not 404'd" do
      conn =
        Phoenix.ConnTest.build_conn(:options, "/users/admin/export/someone")
        |> Plug.Conn.put_req_header("origin", "https://termelix.example.com")
        |> Plug.Conn.put_req_header("access-control-request-method", "GET")
        |> Plug.Conn.put_req_header("access-control-request-headers", "x-reauth-password")
        |> TermelixWeb.Endpoint.call([])

      assert conn.status == 204

      assert [allowed] = Plug.Conn.get_resp_header(conn, "access-control-allow-headers")
      assert allowed =~ "x-reauth-password"
    end
  end
end
