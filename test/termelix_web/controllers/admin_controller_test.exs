defmodule TermelixWeb.AdminControllerTest do
  @moduledoc """
  HTTP tests for the admin user-management surface: `/users/list`, `/users/count`,
  `/users/make-admin`, `/users/remove-admin`, `/users/admin-create`, `/users/delete-user`.

  The first registered user (`alice`) is admin by the first-user rule; `bob`/`carol` are
  non-admins used to exercise the 403 gates and the mutations.

  Requires the returned routes to be wired into the authenticated `/users` scope.
  """
  use TermelixWeb.ConnCase

  alias Termelix.{Accounts, Audit}

  setup do
    {alice_token, alice} = register_and_login("alice", "correct horse battery staple")
    {bob_token, bob} = register_and_login("bob", "another good long passphrase")
    {carol_token, carol} = register_and_login("carol", "yet another long passphrase")

    %{
      alice_token: alice_token,
      alice: alice,
      bob_token: bob_token,
      bob: bob,
      carol_token: carol_token,
      carol: carol
    }
  end

  describe "GET /users/list" do
    test "admin sees management-only fields", %{alice_token: t} do
      %{"users" => users} = authed(t) |> get("/users/list") |> json_response(200)
      alice_row = Enum.find(users, &(&1["username"] == "alice"))

      assert alice_row["is_admin"] == true
      assert alice_row["password_hash"] == "set"
      assert Map.has_key?(alice_row, "data_unlocked")
      assert Map.has_key?(alice_row, "totp_enabled")
    end

    test "non-admin gets the list without management-only fields", %{bob_token: t} do
      %{"users" => users} = authed(t) |> get("/users/list") |> json_response(200)
      row = Enum.find(users, &(&1["username"] == "bob"))

      assert row["userId"]
      refute Map.has_key?(row, "data_unlocked")
      refute Map.has_key?(row, "totp_enabled")
    end
  end

  describe "GET /users/count" do
    test "admin gets the total", %{alice_token: t} do
      assert %{"count" => 3} = authed(t) |> get("/users/count") |> json_response(200)
    end

    test "non-admin is refused", %{bob_token: t} do
      assert %{"error" => "Admin access required"} =
               authed(t) |> get("/users/count") |> json_response(403)
    end
  end

  describe "POST /users/make-admin" do
    test "admin promotes a user and audits it", %{alice_token: t, bob: bob} do
      assert %{"message" => "User bob is now an admin"} =
               authed(t) |> post("/users/make-admin", %{userId: bob.id}) |> json_response(200)

      assert Accounts.get_user(bob.id).isAdmin == true

      %{logs: logs} = Audit.list_page(%{filters: %{action: "make_admin"}, limit: 10, offset: 0})
      assert Enum.any?(logs, &(&1.resourceId == bob.id))
    end

    test "409-style: already an admin", %{alice_token: t, alice: alice} do
      assert %{"error" => "User is already an admin"} =
               authed(t) |> post("/users/make-admin", %{userId: alice.id}) |> json_response(400)
    end

    test "400 when no identifier is supplied", %{alice_token: t} do
      assert %{"error" => "User ID or username is required"} =
               authed(t) |> post("/users/make-admin", %{}) |> json_response(400)
    end

    test "404 for an unknown user", %{alice_token: t} do
      assert %{"error" => "User not found"} =
               authed(t) |> post("/users/make-admin", %{userId: "ghost"}) |> json_response(404)
    end

    test "non-admin is refused", %{bob_token: t, carol: carol} do
      assert %{"error" => "Not authorized"} =
               authed(t) |> post("/users/make-admin", %{userId: carol.id}) |> json_response(403)
    end
  end

  describe "POST /users/remove-admin" do
    test "admin demotes another admin", %{alice_token: t, bob: bob} do
      authed(t) |> post("/users/make-admin", %{userId: bob.id}) |> json_response(200)

      assert %{"message" => "Admin status removed from bob"} =
               authed(t) |> post("/users/remove-admin", %{userId: bob.id}) |> json_response(200)

      assert Accounts.get_user(bob.id).isAdmin == false
    end

    test "cannot remove your own admin status", %{alice_token: t, alice: alice} do
      assert %{"error" => "Cannot remove your own admin status"} =
               authed(t)
               |> post("/users/remove-admin", %{userId: alice.id})
               |> json_response(400)
    end

    test "400 when the target is not an admin", %{alice_token: t, bob: bob} do
      assert %{"error" => "User is not an admin"} =
               authed(t) |> post("/users/remove-admin", %{userId: bob.id}) |> json_response(400)
    end
  end

  describe "POST /users/admin-create" do
    test "admin creates a user regardless of registration policy", %{alice_token: t} do
      body =
        authed(t)
        |> post("/users/admin-create", %{username: "dave", password: "a fresh long passphrase"})
        |> json_response(200)

      assert body["message"] == "User created"
      assert body["toast"]["message"] == "User created: dave"
      assert Accounts.get_user_by_username("dave")
    end

    test "409 on a duplicate username", %{alice_token: t} do
      assert %{"error" => "Username already exists"} =
               authed(t)
               |> post("/users/admin-create", %{username: "bob", password: "whatever long enough"})
               |> json_response(409)
    end

    test "400 when fields are missing", %{alice_token: t} do
      assert %{"error" => "Username and password are required"} =
               authed(t) |> post("/users/admin-create", %{username: "x"}) |> json_response(400)
    end

    test "non-admin is refused", %{bob_token: t} do
      assert %{"error" => "Not authorized"} =
               authed(t)
               |> post("/users/admin-create", %{username: "z", password: "long enough passphrase"})
               |> json_response(403)
    end
  end

  describe "DELETE /users/delete-user" do
    test "admin deletes a user and their data", %{alice_token: t, carol: carol} do
      assert %{"message" => "User carol deleted successfully"} =
               authed(t)
               |> delete("/users/delete-user", %{username: "carol"})
               |> json_response(200)

      refute Accounts.get_user(carol.id)
    end

    test "cannot delete your own account", %{alice_token: t} do
      assert %{"error" => "Cannot delete your own account"} =
               authed(t)
               |> delete("/users/delete-user", %{username: "alice"})
               |> json_response(400)
    end

    test "404 for an unknown username", %{alice_token: t} do
      assert %{"error" => "User not found"} =
               authed(t)
               |> delete("/users/delete-user", %{username: "ghost"})
               |> json_response(404)
    end

    test "400 when username missing", %{alice_token: t} do
      assert %{"error" => "Username is required"} =
               authed(t) |> delete("/users/delete-user", %{}) |> json_response(400)
    end

    test "non-admin is refused", %{bob_token: t} do
      assert %{"error" => "Not authorized"} =
               authed(t)
               |> delete("/users/delete-user", %{username: "carol"})
               |> json_response(403)
    end
  end

  # --- helpers ---------------------------------------------------------------

  describe "error reporting opt-in (/users/error-reporting)" do
    # The test env configures no Sentry DSN; these tests stub one so `available` is true
    # and the prompt logic can be exercised. The no-DSN behavior has its own test.
    defp with_dsn(_context) do
      Application.put_env(:sentry, :dsn, "https://public@sentry.example/1")
      on_exit(fn -> Application.delete_env(:sentry, :dsn) end)
      :ok
    end

    setup :with_dsn

    test "defaults to disabled + undecided + available, admin-readable only", %{
      alice_token: admin,
      bob_token: nonadmin
    } do
      assert %{"enabled" => false, "decided" => false, "available" => true} =
               authed(admin) |> get("/users/error-reporting") |> json_response(200)

      assert %{"error" => "Admin access required"} =
               authed(nonadmin) |> get("/users/error-reporting") |> json_response(403)
    end

    test "admin can opt in and back out; non-admin and bad bodies are rejected", %{
      alice_token: admin,
      bob_token: nonadmin
    } do
      assert %{"enabled" => true, "decided" => true} =
               authed(admin)
               |> post("/users/error-reporting", %{enabled: true})
               |> json_response(200)

      assert Termelix.ErrorReporting.enabled?()

      assert %{"enabled" => false, "decided" => true} =
               authed(admin)
               |> post("/users/error-reporting", %{enabled: false})
               |> json_response(200)

      refute Termelix.ErrorReporting.enabled?()

      assert %{"error" => "enabled must be a boolean"} =
               authed(admin)
               |> post("/users/error-reporting", %{enabled: "yes"})
               |> json_response(400)

      assert %{"error" => "Admin access required"} =
               authed(nonadmin)
               |> post("/users/error-reporting", %{enabled: true})
               |> json_response(403)
    end

    test "every consent change lands in the audit log", %{alice_token: admin} do
      authed(admin) |> post("/users/error-reporting", %{enabled: true}) |> json_response(200)
      authed(admin) |> post("/users/error-reporting", %{enabled: false}) |> json_response(200)

      %{logs: enables} =
        Audit.list_page(%{filters: %{action: "error_reporting_enable"}, limit: 10, offset: 0})

      %{logs: disables} =
        Audit.list_page(%{filters: %{action: "error_reporting_disable"}, limit: 10, offset: 0})

      assert [enable] = enables
      assert enable.username == "alice"
      assert enable.resourceType == "settings"
      assert enable.details =~ ~s("enabled":true)

      assert [disable] = disables
      assert disable.details =~ ~s("enabled":false)
      # The prior state is recorded so consent history is reconstructible.
      assert disable.details =~ ~s("previous")
    end

    test "/users/me prompts only admins, and only until a decision is made", %{
      alice_token: admin,
      bob_token: nonadmin
    } do
      assert %{"prompt_error_reporting" => true} =
               authed(admin) |> get("/users/me") |> json_response(200)

      assert %{"prompt_error_reporting" => false} =
               authed(nonadmin) |> get("/users/me") |> json_response(200)

      authed(admin) |> post("/users/error-reporting", %{enabled: false}) |> json_response(200)

      assert %{"prompt_error_reporting" => false} =
               authed(admin) |> get("/users/me") |> json_response(200)
    end

    test "without a DSN nothing is available and no admin is prompted", %{alice_token: admin} do
      Application.delete_env(:sentry, :dsn)

      assert %{"available" => false} =
               authed(admin) |> get("/users/error-reporting") |> json_response(200)

      assert %{"prompt_error_reporting" => false} =
               authed(admin) |> get("/users/me") |> json_response(200)
    end
  end

  defp register_and_login(username, password) do
    conn = Phoenix.ConnTest.build_conn()

    conn
    |> post("/users/create", %{username: username, password: password})
    |> json_response(200)

    login = conn |> post("/users/login", %{username: username, password: password})
    %{"jwt" => %{value: token}} = login.resp_cookies
    {token, Accounts.get_user_by_username(username)}
  end

  defp authed(token),
    do:
      Phoenix.ConnTest.build_conn()
      |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
end
