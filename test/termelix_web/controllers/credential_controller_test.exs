defmodule TermelixWeb.CredentialControllerTest do
  @moduledoc """
  HTTP tests for the `/credentials` surface: CRUD, folders, ownership, and usage. Each test
  registers a real user (which provisions their DEK) and drives the endpoints over the endpoint
  pipeline, so secret encryption/decryption runs end-to-end.
  """
  use TermelixWeb.ConnCase

  alias Termelix.{Accounts, Hosts}

  setup do
    {token, user} = register_and_login("alice", "correct horse battery staple")
    %{token: token, user: user}
  end

  describe "create" do
    test "creates a password credential and strips the secret", %{token: token} do
      body =
        authed(token)
        |> post("/credentials", %{
          name: "prod-db",
          authType: "password",
          username: "root",
          password: "s3cr3t",
          folder: "prod",
          tags: ["db", "prod"]
        })
        |> json_response(201)

      assert body["name"] == "prod-db"
      assert body["authType"] == "password"
      assert body["username"] == "root"
      assert body["folder"] == "prod"
      assert body["tags"] == ["db", "prod"]
      assert body["usageCount"] == 0
      assert body["hasCertPublicKey"] == false
      assert is_integer(body["id"])
      # Secrets never leak in the create response.
      refute Map.has_key?(body, "password")
      refute Map.has_key?(body, "key")
      refute Map.has_key?(body, "privateKey")
    end

    test "creates a key credential", %{token: token} do
      body =
        authed(token)
        |> post("/credentials", %{name: "deploy-key", authType: "key", key: "PRIVATE-KEY-BODY"})
        |> json_response(201)

      assert body["authType"] == "key"
      refute Map.has_key?(body, "key")
      refute Map.has_key?(body, "privateKey")
    end

    test "rejects a missing name", %{token: token} do
      assert %{"error" => "Name is required"} =
               authed(token)
               |> post("/credentials", %{authType: "password", password: "x"})
               |> json_response(400)
    end

    test "rejects an invalid auth type", %{token: token} do
      assert %{"error" => ~s(Auth type must be "password" or "key")} =
               authed(token)
               |> post("/credentials", %{name: "x", authType: "totp"})
               |> json_response(400)
    end

    test "rejects password auth without a password", %{token: token} do
      assert %{"error" => "Password is required for password authentication"} =
               authed(token)
               |> post("/credentials", %{name: "x", authType: "password"})
               |> json_response(400)
    end

    test "rejects key auth without a key", %{token: token} do
      assert %{"error" => "SSH key is required for key authentication"} =
               authed(token)
               |> post("/credentials", %{name: "x", authType: "key"})
               |> json_response(400)
    end
  end

  describe "list and show" do
    test "lists a user's credentials", %{token: token} do
      create_password_credential(token, "one")
      create_password_credential(token, "two")

      names = authed(token) |> get("/credentials") |> json_response(200) |> Enum.map(& &1["name"])
      assert "one" in names and "two" in names
    end

    test "show never returns the password — only presence booleans (write-only)", %{
      token: token
    } do
      id = create_password_credential(token, "editme")

      body = authed(token) |> get("/credentials/#{id}") |> json_response(200)
      refute Map.has_key?(body, "password")
      assert body["hasPassword"] == true
      assert body["hasKey"] == false
      assert body["hasKeyPassword"] == false
    end

    test "show on a key credential reports presence without leaking any secret", %{token: token} do
      body =
        authed(token)
        |> post("/credentials", %{
          name: "k",
          authType: "key",
          key: "PRIV",
          keyPassword: "kp"
        })
        |> json_response(201)

      shown = authed(token) |> get("/credentials/#{body["id"]}") |> json_response(200)
      assert shown["hasKey"] == true
      assert shown["hasKeyPassword"] == true
      # No secret material is ever returned — not the key, key passphrase, or password.
      refute Map.has_key?(shown, "key")
      refute Map.has_key?(shown, "privateKey")
      refute Map.has_key?(shown, "keyPassword")
      refute Map.has_key?(shown, "password")
    end

    test "updating with a blank password keeps the stored secret (replace-only)", %{
      token: token
    } do
      id = create_password_credential(token, "keepme")

      # Saving the edit form with the password left blank must NOT wipe the secret.
      authed(token)
      |> put("/credentials/#{id}", %{name: "keepme2", password: ""})
      |> json_response(200)

      # Presence is unchanged; a subsequent non-blank value replaces it.
      shown = authed(token) |> get("/credentials/#{id}") |> json_response(200)
      assert shown["name"] == "keepme2"
      assert shown["hasPassword"] == true

      authed(token)
      |> put("/credentials/#{id}", %{password: "replaced"})
      |> json_response(200)

      assert authed(token)
             |> get("/credentials/#{id}")
             |> json_response(200)
             |> Map.get("hasPassword") == true
    end

    test "show returns 404 for an unknown id", %{token: token} do
      assert %{"error" => "Credential not found"} =
               authed(token) |> get("/credentials/999999") |> json_response(404)
    end
  end

  describe "update" do
    test "updates fields", %{token: token} do
      id = create_password_credential(token, "before")

      body =
        authed(token)
        |> put("/credentials/#{id}", %{name: "after", folder: "moved"})
        |> json_response(200)

      assert body["name"] == "after"
      assert body["folder"] == "moved"
    end

    test "an empty update returns the existing credential unchanged", %{token: token} do
      id = create_password_credential(token, "steady")

      body = authed(token) |> put("/credentials/#{id}", %{}) |> json_response(200)
      assert body["name"] == "steady"
    end

    test "returns 404 updating an unknown id", %{token: token} do
      assert %{"error" => "Credential not found"} =
               authed(token) |> put("/credentials/999999", %{name: "x"}) |> json_response(404)
    end
  end

  describe "delete" do
    test "deletes a credential", %{token: token} do
      id = create_password_credential(token, "gone")

      assert %{"message" => "Credential deleted successfully"} =
               authed(token) |> delete("/credentials/#{id}") |> json_response(200)

      assert authed(token) |> get("/credentials/#{id}") |> json_response(404)
    end

    test "returns 404 deleting an unknown id", %{token: token} do
      assert %{"error" => "Credential not found"} =
               authed(token) |> delete("/credentials/999999") |> json_response(404)
    end
  end

  describe "folders" do
    test "lists distinct folders and renames one", %{token: token} do
      create_password_credential(token, "a", "team-a")
      create_password_credential(token, "b", "team-b")

      folders = authed(token) |> get("/credentials/folders") |> json_response(200)
      assert folders == ["team-a", "team-b"]

      assert %{"success" => true} =
               authed(token)
               |> put("/credentials/folders/rename", %{oldName: "team-a", newName: "team-z"})
               |> json_response(200)

      renamed = authed(token) |> get("/credentials/folders") |> json_response(200)
      assert renamed == ["team-b", "team-z"]
    end

    test "rename requires both names", %{token: token} do
      assert %{"error" => "Both oldName and newName are required"} =
               authed(token)
               |> put("/credentials/folders/rename", %{oldName: "a"})
               |> json_response(400)
    end

    test "rename rejects identical names", %{token: token} do
      assert %{"error" => "Old name and new name cannot be the same"} =
               authed(token)
               |> put("/credentials/folders/rename", %{oldName: "a", newName: "a"})
               |> json_response(400)
    end
  end

  describe "ownership" do
    test "a second user cannot read the first user's credential", %{token: token} do
      id = create_password_credential(token, "mine")
      {other_token, _} = register_and_login("mallory", "another good long passphrase")

      assert authed(other_token) |> get("/credentials/#{id}") |> json_response(404)
      assert [] == authed(other_token) |> get("/credentials") |> json_response(200)
    end
  end

  describe "apply-to-host and usage" do
    test "applies a credential to a host, lists the host, and records usage", %{
      token: token,
      user: user
    } do
      id = create_password_credential(token, "shared-cred")

      {:ok, host} =
        Hosts.create_host(user.id, %{
          name: "web-1",
          ip: "10.0.0.5",
          port: 22,
          username: "root",
          authType: "password",
          password: "hostpw",
          connectionType: "ssh"
        })

      assert %{"message" => "Credential applied to host successfully"} =
               authed(token)
               |> post("/credentials/#{id}/apply-to-host/#{host.id}")
               |> json_response(200)

      hosts = authed(token) |> get("/credentials/#{id}/hosts") |> json_response(200)
      assert [%{"id" => host_id, "name" => "web-1"}] = hosts
      assert host_id == host.id

      shown = authed(token) |> get("/credentials/#{id}") |> json_response(200)
      assert shown["usageCount"] == 1
      assert is_binary(shown["lastUsed"])
    end

    test "a non-numeric host id is a 404, not a 500", %{token: token} do
      id = create_password_credential(token, "shared-cred")

      assert %{"error" => "Host not found"} =
               authed(token)
               |> post("/credentials/#{id}/apply-to-host/not-a-host")
               |> json_response(404)
    end
  end

  # --- helpers --------------------------------------------------------------

  defp register_and_login(username, password) do
    conn = Phoenix.ConnTest.build_conn()

    conn
    |> post("/users/create", %{username: username, password: password})
    |> json_response(200)

    login = conn |> post("/users/login", %{username: username, password: password})
    %{"jwt" => %{value: token}} = login.resp_cookies
    {token, Accounts.get_user_by_username(username)}
  end

  defp create_password_credential(token, name, folder \\ nil) do
    body =
      authed(token)
      |> post("/credentials", %{
        name: name,
        authType: "password",
        username: "root",
        password: "s3cr3t",
        folder: folder
      })
      |> json_response(201)

    body["id"]
  end

  defp authed(token),
    do:
      Phoenix.ConnTest.build_conn()
      |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
end
