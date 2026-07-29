defmodule TermelixWeb.AuthFlowTest do
  @moduledoc """
  End-to-end vertical slice over the real endpoint: health → setup-required → register →
  login (cookie) → /users/me → host listing (empty, then one host with secrets stripped).
  """
  use TermelixWeb.ConnCase

  alias Termelix.{Accounts, Hosts, RateLimiter}

  setup do
    RateLimiter.reset_all()
    :ok
  end

  test "health endpoint is up", %{conn: conn} do
    assert %{"status" => "ok", "service" => "termelix"} =
             conn |> get("/health") |> json_response(200)
  end

  test "setup-required is true with no users", %{conn: conn} do
    assert %{"setup_required" => true} =
             conn |> get("/users/setup-required") |> json_response(200)
  end

  test "full register → login → me → host list flow", %{conn: conn} do
    # Register the first user (becomes admin).
    created =
      conn
      |> post("/users/create", %{username: "alice", password: "correct horse battery staple"})
      |> json_response(200)

    assert created["message"] == "User created"
    assert created["is_admin"] == true

    # Log in — expect success and a jwt cookie.
    login_conn =
      conn
      |> post("/users/login", %{username: "alice", password: "correct horse battery staple"})

    login = json_response(login_conn, 200)
    assert login["success"] == true
    assert login["is_admin"] == true
    assert login["username"] == "alice"
    assert %{"jwt" => %{value: token}} = login_conn.resp_cookies
    assert is_binary(token) and token != ""

    # Authenticated identity.
    me = authed(token) |> get("/users/me") |> json_response(200)
    assert me["username"] == "alice"
    assert me["is_admin"] == true
    assert me["is_oidc"] == false
    assert me["totp_enabled"] == false

    # Empty host list initially.
    assert [] == authed(token) |> get("/host/db/host") |> json_response(200)

    # Seed a host with a secret, then list it — secret stripped, presence boolean set.
    user = Accounts.get_user_by_username("alice")

    {:ok, _host} =
      Hosts.create_host(user.id, %{
        name: "web-1",
        ip: "10.0.0.5",
        port: 22,
        username: "root",
        authType: "password",
        password: "s3cr3t",
        connectionType: "ssh",
        tags: "prod,web"
      })

    [host] = authed(token) |> get("/host/db/host") |> json_response(200)
    assert host["name"] == "web-1"
    assert host["ip"] == "10.0.0.5"
    assert host["username"] == "root"
    assert host["tags"] == ["prod", "web"]
    assert host["hasPassword"] == true
    # Secret itself is never present in the list response.
    refute Map.has_key?(host, "password")
  end

  test "unauthenticated access to /users/me is rejected", %{conn: conn} do
    assert %{"error" => "Missing authentication token"} =
             conn |> get("/users/me") |> json_response(401)
  end

  test "duplicate username is a 409", %{conn: conn} do
    conn
    |> post("/users/create", %{username: "bob", password: "pw-one-two-three"})
    |> json_response(200)

    assert %{"error" => "Username already exists"} =
             conn
             |> post("/users/create", %{username: "bob", password: "another-password"})
             |> json_response(409)
  end

  test "registration rejects passwords shorter than 8 characters", %{conn: conn} do
    assert %{"error" => "Password must be at least 8 characters"} =
             conn
             |> post("/users/create", %{username: "shorty", password: "1234567"})
             |> json_response(400)

    # And nothing was persisted.
    assert Accounts.get_user_by_username("shorty") == nil
  end

  test "admin_create_user enforces the same password policy" do
    assert {:error, :password_too_short} = Accounts.admin_create_user("newbie", "short")
  end

  test "login is rate limited per IP+username after 10 failures", %{conn: conn} do
    # 10 failures inside the window are still plain 401s.
    for _ <- 1..10 do
      assert %{"error" => "Invalid username or password"} =
               conn
               |> post("/users/login", %{username: "mallory", password: "wrong-password"})
               |> json_response(401)
    end

    # The next attempt is refused before any password check, with the contract shape.
    limited =
      conn
      |> post("/users/login", %{username: "mallory", password: "wrong-password"})
      |> json_response(429)

    assert limited["error"] == "Too many login attempts. Please try again later."
    assert is_integer(limited["remainingTime"]) and limited["remainingTime"] > 0

    # A different username has its own budget.
    assert %{"error" => "Invalid username or password"} =
             conn
             |> post("/users/login", %{username: "someone-else", password: "wrong-password"})
             |> json_response(401)
  end

  test "a successful login resets the failure budget", %{conn: conn} do
    conn
    |> post("/users/create", %{username: "carol", password: "correct horse battery staple"})
    |> json_response(200)

    # Exhaust the budget down to a single attempt...
    for _ <- 1..9 do
      conn
      |> post("/users/login", %{username: "carol", password: "wrong-password"})
      |> json_response(401)
    end

    # ...then log in successfully, which must clear it...
    assert %{"success" => true} =
             conn
             |> post("/users/login", %{
               username: "carol",
               password: "correct horse battery staple"
             })
             |> json_response(200)

    # ...because otherwise one more failure would already trip the 429.
    assert %{"error" => "Invalid username or password"} =
             conn
             |> post("/users/login", %{username: "carol", password: "wrong-password"})
             |> json_response(401)
  end

  test "registration is rate limited per IP after 10 attempts", %{conn: conn} do
    for i <- 1..10 do
      assert %{"message" => "User created"} =
               conn
               |> post("/users/create", %{
                 username: "user-#{i}",
                 password: "long enough password"
               })
               |> json_response(200)
    end

    limited =
      conn
      |> post("/users/create", %{username: "user-11", password: "long enough password"})
      |> json_response(429)

    assert limited["error"] == "Too many registration attempts. Please try again later."
    assert is_integer(limited["remainingTime"]) and limited["remainingTime"] > 0
  end

  defp authed(token),
    do:
      Phoenix.ConnTest.build_conn()
      |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
end
