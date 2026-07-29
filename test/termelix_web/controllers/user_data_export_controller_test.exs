defmodule TermelixWeb.UserDataExportControllerTest do
  @moduledoc """
  HTTP tests for the user data export surface: the admin export
  (`GET /users/admin/export/:userId`, the frontend `adminExportUserData` contract) and the
  self export (`GET /users/data-export`). Requires the returned routes wired into the
  authenticated `/users` scope.

  `alice` is admin (first user); `bob` is a non-admin who owns a host with a secret.
  """
  use TermelixWeb.ConnCase

  alias Termelix.{Accounts, Repo}
  alias Termelix.Schema.User

  @password "correct horse battery staple"

  setup do
    {alice_token, alice} = register_and_login("alice", @password)
    {bob_token, bob} = register_and_login("bob", "another good long passphrase")
    create_host(bob_token, "s3cr3t")

    %{alice_token: alice_token, alice: alice, bob_token: bob_token, bob: bob}
  end

  describe "GET /users/admin/export/:userId" do
    test "admin exports another user's data with secrets decrypted, after re-auth", ctx do
      conn =
        authed(ctx.alice_token)
        |> put_req_header("x-reauth-password", @password)
        |> get("/users/admin/export/#{ctx.bob.id}")

      body = json_response(conn, 200)

      assert body["version"] == "v2.0"
      assert body["userId"] == ctx.bob.id
      assert body["username"] == "bob"
      assert [host] = body["userData"]["sshHosts"]
      assert host["password"] == "s3cr3t"
      assert body["metadata"]["encrypted"] == false

      # Served as a JSON attachment.
      assert [disposition] = Plug.Conn.get_resp_header(conn, "content-disposition")
      assert disposition =~ "termelix-user-bob-export.json"
    end

    test "non-admin is refused", ctx do
      assert %{"error" => "Admin access required"} =
               authed(ctx.bob_token)
               |> get("/users/admin/export/#{ctx.alice.id}")
               |> json_response(403)
    end

    # `isAdmin` is a standing capability: a stolen admin session should not silently yield
    # every other user's credentials in the clear. The re-auth makes the dump require the
    # admin's own password at the moment of the request.
    test "without the re-auth header it is refused, before any data is read", ctx do
      body =
        authed(ctx.alice_token)
        |> get("/users/admin/export/#{ctx.bob.id}")
        |> json_response(403)

      assert body["code"] == "REAUTH_REQUIRED"
    end

    test "a wrong re-auth password is refused", ctx do
      assert authed(ctx.alice_token)
             |> put_req_header("x-reauth-password", "not the password")
             |> get("/users/admin/export/#{ctx.bob.id}")
             |> json_response(403)
    end

    test "unknown target user is 404", ctx do
      assert %{"error" => "User not found"} =
               authed(ctx.alice_token)
               |> put_req_header("x-reauth-password", @password)
               |> get("/users/admin/export/nope")
               |> json_response(404)
    end

    test "a target without an unlocked DEK is 423 TARGET_DATA_LOCKED", ctx do
      ghost = insert_dekless_user("ghost1", "ghostuser")

      body =
        authed(ctx.alice_token)
        |> put_req_header("x-reauth-password", @password)
        |> get("/users/admin/export/#{ghost.id}")
        |> json_response(423)

      assert body["code"] == "TARGET_DATA_LOCKED"
    end
  end

  describe "GET /users/data-export" do
    # The default is now `encrypted`: a self-export is overwhelmingly a backup, and a backup
    # does not need every host password in the clear in the browser's download folder.
    test "defaults to ciphertext envelopes, not plaintext secrets", ctx do
      body = authed(ctx.bob_token) |> get("/users/data-export") |> json_response(200)

      assert body["userId"] == ctx.bob.id
      assert [host] = body["userData"]["sshHosts"]
      refute host["password"] == "s3cr3t"
      # A FieldCrypto envelope, not the secret.
      assert %{"data" => _, "iv" => _, "tag" => _} = Jason.decode!(host["password"])
    end

    test "plaintext is available on explicit opt-in", ctx do
      body =
        authed(ctx.bob_token)
        |> get("/users/data-export?format=plaintext")
        |> json_response(200)

      assert [host] = body["userData"]["sshHosts"]
      assert host["password"] == "s3cr3t"
    end

    test "requires authentication" do
      assert build_conn() |> get("/users/data-export") |> json_response(401)
    end
  end

  # --- helpers ---------------------------------------------------------------

  defp register_and_login(username, password) do
    conn = build_conn()
    conn |> post("/users/create", %{username: username, password: password}) |> json_response(200)
    login = post(conn, "/users/login", %{username: username, password: password})
    %{"jwt" => %{value: token}} = login.resp_cookies
    {token, Accounts.get_user_by_username(username)}
  end

  defp authed(token), do: build_conn() |> put_req_header("authorization", "Bearer #{token}")

  defp create_host(token, password) do
    %{"id" => id} =
      authed(token)
      |> put_req_header("content-type", "application/json")
      |> post(
        "/host/db/host",
        Jason.encode!(%{
          name: "web-1",
          ip: "10.0.0.5",
          port: 22,
          username: "root",
          authType: "password",
          password: password
        })
      )
      |> json_response(200)

    id
  end

  defp insert_dekless_user(id, username) do
    Repo.insert!(%User{
      id: id,
      username: username,
      passwordHash: "x",
      isAdmin: false,
      isOidc: false,
      totpEnabled: false,
      donationModalDismissed: false,
      registeredAt: "2026-01-01T00:00:00.000Z"
    })
  end
end
