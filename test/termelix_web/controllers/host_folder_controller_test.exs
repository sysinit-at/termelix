defmodule TermelixWeb.HostFolderControllerTest do
  @moduledoc """
  Covers the `/host/folders` surface: listing (ownership-scoped), metadata upsert
  (create + partial update), hierarchical rename fanning out across folders/hosts/credentials,
  and delete-all-hosts-in-folder (including nested descendants and ownership isolation).
  """
  use TermelixWeb.ConnCase

  alias Termelix.{Accounts, Repo}
  alias Termelix.Schema.{Host, SshCredential, SshFolder}

  @password "correct horse battery staple"

  setup do
    {token, user} = register_and_login("alice", @password)
    %{token: token, user: user}
  end

  describe "GET /host/folders" do
    test "lists only the owner's folders", %{token: token} do
      put_json(authed(token), "/host/folders/metadata", %{name: "prod", color: "#fff"})
      put_json(authed(token), "/host/folders/metadata", %{name: "stage"})

      {other_token, _bob} = register_and_login("bob", @password)
      put_json(authed(other_token), "/host/folders/metadata", %{name: "bob-only"})

      folders = authed(token) |> get("/host/folders") |> json_response(200)
      names = Enum.map(folders, & &1["name"]) |> Enum.sort()

      assert names == ["prod", "stage"]
      # Wire shape is the camelCase folder record.
      prod = Enum.find(folders, &(&1["name"] == "prod"))
      assert Map.keys(prod) |> Enum.sort() == ~w(color createdAt icon id name updatedAt userId)
      assert prod["color"] == "#fff"
    end
  end

  describe "PUT /host/folders/metadata" do
    test "creates a folder, then updates only the supplied keys", %{token: token} do
      assert %{"message" => "Folder metadata updated successfully"} =
               authed(token)
               |> put_json("/host/folders/metadata", %{name: "prod", color: "#111", icon: "star"})
               |> json_response(200)

      # Second write supplies only the color; the icon must be preserved.
      authed(token)
      |> put_json("/host/folders/metadata", %{name: "prod", color: "#222"})
      |> json_response(200)

      [folder] = authed(token) |> get("/host/folders") |> json_response(200)
      assert folder["color"] == "#222"
      assert folder["icon"] == "star"
    end

    test "rejects a missing name with 400", %{token: token} do
      assert %{"error" => "Folder name is required"} =
               authed(token)
               |> put_json("/host/folders/metadata", %{color: "#333"})
               |> json_response(400)
    end
  end

  describe "PUT /host/folders/rename" do
    test "renames the folder, its descendants, and the inline host/credential folders", ctx do
      %{token: token, user: user} = ctx

      put_json(authed(token), "/host/folders/metadata", %{name: "prod"})
      put_json(authed(token), "/host/folders/metadata", %{name: "prod / web"})

      root_host = create_host(token, "prod")
      child_host = create_host(token, "prod / web")
      cred = insert_credential(user.id, "prod")

      assert %{
               "message" => "Folder renamed successfully",
               "updatedHosts" => 2,
               "updatedCredentials" => 1
             } =
               authed(token)
               |> put_json("/host/folders/rename", %{oldName: "prod", newName: "production"})
               |> json_response(200)

      names =
        authed(token) |> get("/host/folders") |> json_response(200) |> Enum.map(& &1["name"])

      assert Enum.sort(names) == ["production", "production / web"]

      assert Repo.get(Host, root_host).folder == "production"
      assert Repo.get(Host, child_host).folder == "production / web"
      assert Repo.get(SshCredential, cred).folder == "production"
    end

    test "reports an unchanged name without touching data", %{token: token} do
      put_json(authed(token), "/host/folders/metadata", %{name: "prod"})

      assert %{"message" => "Folder name unchanged"} =
               authed(token)
               |> put_json("/host/folders/rename", %{oldName: "prod", newName: "prod"})
               |> json_response(200)

      names =
        authed(token) |> get("/host/folders") |> json_response(200) |> Enum.map(& &1["name"])

      assert names == ["prod"]
    end

    test "rejects a missing new name with 400", %{token: token} do
      assert %{"error" => "Old name and new name are required"} =
               authed(token)
               |> put_json("/host/folders/rename", %{oldName: "prod"})
               |> json_response(400)
    end

    test "cannot rename another user's folder", %{token: token} do
      put_json(authed(token), "/host/folders/metadata", %{name: "prod"})
      {other_token, _bob} = register_and_login("bob", @password)

      assert %{"updatedHosts" => 0, "updatedCredentials" => 0} =
               authed(other_token)
               |> put_json("/host/folders/rename", %{oldName: "prod", newName: "hijacked"})
               |> json_response(200)

      names =
        authed(token) |> get("/host/folders") |> json_response(200) |> Enum.map(& &1["name"])

      assert names == ["prod"]
    end
  end

  describe "DELETE /host/folders/:name/hosts" do
    test "deletes the folder's hosts (incl. descendants) and its folder records", ctx do
      %{token: token} = ctx

      put_json(authed(token), "/host/folders/metadata", %{name: "stage"})
      put_json(authed(token), "/host/folders/metadata", %{name: "stage / db"})
      put_json(authed(token), "/host/folders/metadata", %{name: "prod"})

      root_host = create_host(token, "stage")
      child_host = create_host(token, "stage / db")
      kept_host = create_host(token, "prod")

      assert %{
               "message" => "All hosts in folder deleted successfully",
               "deletedCount" => 2
             } =
               authed(token) |> delete("/host/folders/stage/hosts") |> json_response(200)

      assert Repo.get(Host, root_host) == nil
      assert Repo.get(Host, child_host) == nil
      assert Repo.get(Host, kept_host) != nil

      names =
        authed(token) |> get("/host/folders") |> json_response(200) |> Enum.map(& &1["name"])

      assert names == ["prod"]
    end

    test "leaves another user's hosts and folders intact", %{token: token, user: _user} do
      {other_token, bob} = register_and_login("bob", @password)
      put_json(authed(other_token), "/host/folders/metadata", %{name: "shared"})
      bob_host = create_host(other_token, "shared")

      put_json(authed(token), "/host/folders/metadata", %{name: "shared"})
      alice_host = create_host(token, "shared")

      assert %{"deletedCount" => 1} =
               authed(token) |> delete("/host/folders/shared/hosts") |> json_response(200)

      assert Repo.get(Host, alice_host) == nil
      assert Repo.get(Host, bob_host) != nil
      assert Repo.get_by(SshFolder, userId: bob.id, name: "shared") != nil
    end
  end

  # --- helpers ---------------------------------------------------------------

  defp create_host(token, folder) do
    %{"id" => id} =
      authed(token)
      |> post_json("/host/db/host", %{
        ip: "10.0.0.5",
        port: 22,
        username: "root",
        authType: "password",
        folder: folder
      })
      |> json_response(200)

    id
  end

  defp insert_credential(user_id, folder) do
    now = DateTime.utc_now() |> DateTime.to_iso8601()

    Repo.insert!(%SshCredential{
      userId: user_id,
      name: "cred-#{folder}",
      authType: "password",
      folder: folder,
      usageCount: 0,
      createdAt: now,
      updatedAt: now
    }).id
  end

  defp register_and_login(username, password) do
    conn = build_conn()
    conn |> post("/users/create", %{username: username, password: password}) |> json_response(200)
    login = post(conn, "/users/login", %{username: username, password: password})
    %{"jwt" => %{value: token}} = login.resp_cookies
    {token, Accounts.get_user_by_username(username)}
  end

  defp authed(token) do
    build_conn() |> put_req_header("authorization", "Bearer #{token}")
  end

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
