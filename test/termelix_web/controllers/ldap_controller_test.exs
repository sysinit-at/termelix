defmodule TermelixWeb.LdapControllerTest do
  @moduledoc """
  HTTP coverage for `POST /users/ldap/login`: the request/response shapes the `ldapLogin`
  frontend caller expects (`{success, message}` + a `jwt` cookie) and the Node error ladder
  (400/401/403/404). The `:eldap` boundary is mocked via `Termelix.LdapFakeClient` (no live
  directory in CI).

  Requires the returned route `post "/ldap/login", LdapController, :login` under the
  unauthenticated `/users` scope to be wired into the router.
  """
  use TermelixWeb.ConnCase

  import Ecto.Query

  alias Termelix.Repo

  setup do
    Application.put_env(:termelix, :ldap_client, Termelix.LdapFakeClient)
    Termelix.RateLimiter.reset_all()

    on_exit(fn ->
      Application.delete_env(:termelix, :ldap_client)
      Application.delete_env(:termelix, :ldap_fake)
    end)

    :ok
  end

  test "400 when required fields are missing", %{conn: conn} do
    body =
      conn
      |> post_json("/users/ldap/login", %{username: "alice", password: "s3cret"})
      |> json_response(400)

    assert body["error"] == "providerId, username, and password are required"
  end

  test "404 when the provider does not exist", %{conn: conn} do
    put_fake(base_fake())

    body =
      conn
      |> post_json("/users/ldap/login", %{
        providerId: 999_999,
        username: "alice",
        password: "s3cret"
      })
      |> json_response(404)

    assert body["error"] == "LDAP provider not found"
  end

  test "401 on a wrong password", %{conn: conn} do
    pid = put_provider(base_config())
    put_fake(base_fake())

    body =
      conn
      |> post_json("/users/ldap/login", %{providerId: pid, username: "alice", password: "nope"})
      |> json_response(401)

    assert body["error"] == "Invalid username or password"
  end

  test "403 when the user is not in allowedUsers", %{conn: conn} do
    pid = put_provider(Map.put(base_config(), "allowedUsers", "bob"))
    put_fake(base_fake())

    body =
      conn
      |> post_json("/users/ldap/login", %{providerId: pid, username: "alice", password: "s3cret"})
      |> json_response(403)

    assert body["error"] == "User not allowed"
  end

  test "200 provisions the user, sets the jwt cookie, and returns {success, message}", %{
    conn: conn
  } do
    pid = put_provider(base_config())
    put_fake(base_fake())

    conn =
      post_json(conn, "/users/ldap/login", %{
        providerId: pid,
        username: "alice",
        password: "s3cret"
      })

    assert json_response(conn, 200) == %{"success" => true, "message" => "Login successful"}
    assert %{"jwt" => %{value: token}} = conn.resp_cookies
    assert is_binary(token) and token != ""

    # The account now exists and is bound to this provider identity.
    assert %{id: _} =
             Repo.one(
               from(u in "users",
                 where: u.oidc_identifier == type(^"ldap:#{pid}:alice", :string),
                 select: %{id: u.id}
               )
             )
  end

  test "429 with the login contract shape after 10 failed attempts", %{conn: conn} do
    pid = put_provider(base_config())
    put_fake(base_fake())

    # 10 failures inside the window are still plain 401s.
    for _ <- 1..10 do
      assert %{"error" => "Invalid username or password"} =
               conn
               |> post_json("/users/ldap/login", %{
                 providerId: pid,
                 username: "alice",
                 password: "nope"
               })
               |> json_response(401)
    end

    # The next attempt is refused before any directory bind, with the contract shape.
    limited =
      conn
      |> post_json("/users/ldap/login", %{providerId: pid, username: "alice", password: "nope"})
      |> json_response(429)

    assert limited["error"] == "Too many login attempts. Please try again later."
    assert is_integer(limited["remainingTime"]) and limited["remainingTime"] > 0

    # A different username has its own budget.
    assert %{"error" => "Invalid username or password"} =
             conn
             |> post_json("/users/ldap/login", %{
               providerId: pid,
               username: "bob",
               password: "nope"
             })
             |> json_response(401)
  end

  test "a successful login resets the failure budget", %{conn: conn} do
    pid = put_provider(base_config())
    put_fake(base_fake())

    # Exhaust the budget down to a single attempt...
    for _ <- 1..9 do
      conn
      |> post_json("/users/ldap/login", %{providerId: pid, username: "alice", password: "nope"})
      |> json_response(401)
    end

    # ...then log in successfully, which must clear it...
    assert %{"success" => true} =
             conn
             |> post_json("/users/ldap/login", %{
               providerId: pid,
               username: "alice",
               password: "s3cret"
             })
             |> json_response(200)

    # ...so 10 fresh failures are needed before the next 429.
    for _ <- 1..10 do
      conn
      |> post_json("/users/ldap/login", %{providerId: pid, username: "alice", password: "nope"})
      |> json_response(401)
    end

    assert %{"error" => "Too many login attempts. Please try again later."} =
             conn
             |> post_json("/users/ldap/login", %{
               providerId: pid,
               username: "alice",
               password: "nope"
             })
             |> json_response(429)
  end

  # --- helpers ---------------------------------------------------------------

  defp base_config do
    %{
      "host" => "ldap.example.com",
      "port" => 389,
      "bindDN" => "cn=svc,dc=example,dc=com",
      "bindPassword" => "svc-pass",
      "userSearchBase" => "ou=people,dc=example,dc=com",
      "userSearchFilter" => "(uid={{username}})",
      "usernameAttribute" => "uid",
      "displayNameAttribute" => "cn"
    }
  end

  defp base_fake do
    %{
      user_search_base: "ou=people,dc=example,dc=com",
      bind_dn: "cn=svc,dc=example,dc=com",
      bind_password: "svc-pass",
      user_password: "s3cret",
      entries: [
        %{
          dn: "uid=alice,ou=people,dc=example,dc=com",
          attributes: %{
            "uid" => ["alice"],
            "cn" => ["Alice Liddell"],
            "mail" => ["alice@example.com"]
          }
        }
      ]
    }
  end

  defp put_fake(scenario), do: Application.put_env(:termelix, :ldap_fake, scenario)

  defp put_provider(config_map) do
    name = "corp-#{System.unique_integer([:positive])}"

    Repo.insert_all("sso_providers", [
      %{name: name, type: "ldap", enabled: 1, display_order: 0, config: Jason.encode!(config_map)}
    ])

    %{id: id} =
      Repo.one(
        from(p in "sso_providers", where: p.name == type(^name, :string), select: %{id: p.id})
      )

    id
  end

  defp post_json(conn, path, payload) do
    conn
    |> put_req_header("content-type", "application/json")
    |> post(path, Jason.encode!(payload))
  end
end
