defmodule TermelixWeb.RbacControllerTest do
  @moduledoc """
  HTTP tests for the `/rbac` surface: roles CRUD, the permissions catalog, user-role
  assign/unassign/list, and host-sharing grants. The first registered user becomes admin
  (first-user rule), so `alice` drives the admin-gated paths and `bob`/`carol` are non-admins.
  """
  use TermelixWeb.ConnCase

  alias Termelix.{Accounts, Hosts, Repo}
  alias Termelix.Schema.{Role, HostAccess}

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

  describe "roles CRUD" do
    test "admin creates, lists, updates permissions, and deletes a role", %{alice_token: t} do
      created =
        authed(t)
        |> post("/rbac/roles", %{name: "devs", displayName: "Developers", description: "team"})
        |> json_response(201)

      assert created["success"] == true
      assert is_integer(created["roleId"])
      role_id = created["roleId"]

      roles = authed(t) |> get("/rbac/roles") |> json_response(200) |> Map.fetch!("roles")
      devs = Enum.find(roles, &(&1["id"] == role_id))
      assert devs["name"] == "devs"
      assert devs["displayName"] == "Developers"
      assert devs["isSystem"] == false
      assert devs["permissions"] == []

      assert %{"success" => true} =
               authed(t)
               |> put("/rbac/roles/#{role_id}", %{permissions: ["hosts.view", "hosts.*"]})
               |> json_response(200)

      updated =
        authed(t)
        |> get("/rbac/roles")
        |> json_response(200)
        |> Map.fetch!("roles")
        |> Enum.find(&(&1["id"] == role_id))

      assert updated["permissions"] == ["hosts.view", "hosts.*"]

      assert %{"success" => true} =
               authed(t) |> delete("/rbac/roles/#{role_id}") |> json_response(200)

      remaining = authed(t) |> get("/rbac/roles") |> json_response(200) |> Map.fetch!("roles")
      refute Enum.any?(remaining, &(&1["id"] == role_id))
    end

    test "rejects an invalid role name", %{alice_token: t} do
      assert %{"error" => msg} =
               authed(t)
               |> post("/rbac/roles", %{name: "Bad Name", displayName: "x"})
               |> json_response(400)

      assert msg =~ "lowercase letters"
    end

    test "rejects a missing display name", %{alice_token: t} do
      assert %{"error" => "Role name and display name are required"} =
               authed(t) |> post("/rbac/roles", %{name: "ok"}) |> json_response(400)
    end

    test "409 on a duplicate role name", %{alice_token: t} do
      authed(t) |> post("/rbac/roles", %{name: "dup", displayName: "Dup"}) |> json_response(201)

      assert %{"error" => "A role with this name already exists"} =
               authed(t)
               |> post("/rbac/roles", %{name: "dup", displayName: "Dup2"})
               |> json_response(409)
    end

    test "update rejects unknown permissions", %{alice_token: t} do
      id = create_role(t, "perm-role")

      body =
        authed(t)
        |> put("/rbac/roles/#{id}", %{permissions: ["hosts.view", "hosts.nope"]})
        |> json_response(400)

      assert body["error"] == "Unknown permissions"
      assert body["invalid"] == ["hosts.nope"]
    end

    test "update requires at least one field", %{alice_token: t} do
      id = create_role(t, "empty-update")

      assert %{"error" => msg} = authed(t) |> put("/rbac/roles/#{id}", %{}) |> json_response(400)
      assert msg =~ "At least one field"
    end

    test "update and delete on an unknown role return 404", %{alice_token: t} do
      assert %{"error" => "Role not found"} =
               authed(t) |> put("/rbac/roles/999999", %{displayName: "x"}) |> json_response(404)

      assert %{"error" => "Role not found"} =
               authed(t) |> delete("/rbac/roles/999999") |> json_response(404)
    end

    test "deleting a system role is forbidden", %{alice_token: t} do
      role = insert_system_role("admin")

      assert %{"error" => "Cannot delete system roles"} =
               authed(t) |> delete("/rbac/roles/#{role.id}") |> json_response(403)
    end

    test "a non-admin cannot create a role", %{bob_token: t} do
      assert %{"error" => "Admin access required"} =
               authed(t)
               |> post("/rbac/roles", %{name: "nope", displayName: "Nope"})
               |> json_response(403)
    end
  end

  describe "permissions catalog" do
    # Admin-only since P2: the catalog is the authorization model itself, and any
    # self-registered user could previously enumerate it. `bob` (non-admin) now gets 403 —
    # asserted in rbac_authz_test.exs alongside the rest of the matrix.
    test "returns the grouped catalog", %{alice_token: t} do
      catalog =
        authed(t)
        |> get("/rbac/permissions/catalog")
        |> json_response(200)
        |> Map.fetch!("catalog")

      hosts = Enum.find(catalog, &(&1["group"] == "hosts"))
      assert "hosts.share" in hosts["permissions"]
    end
  end

  describe "user roles" do
    test "admin assigns, lists, then removes a role", %{alice_token: t, bob: bob} do
      role_id = create_role(t, "ops")

      assert %{"success" => true} =
               authed(t)
               |> post("/rbac/users/#{bob.id}/roles", %{roleId: role_id})
               |> json_response(200)

      roles =
        authed(t)
        |> get("/rbac/users/#{bob.id}/roles")
        |> json_response(200)
        |> Map.fetch!("roles")

      assert [%{"roleId" => ^role_id, "roleName" => "ops", "isSystem" => false}] = roles

      assert %{"error" => "Role already assigned"} =
               authed(t)
               |> post("/rbac/users/#{bob.id}/roles", %{roleId: role_id})
               |> json_response(409)

      assert %{"success" => true} =
               authed(t)
               |> delete("/rbac/users/#{bob.id}/roles/#{role_id}")
               |> json_response(200)

      assert [] ==
               authed(t)
               |> get("/rbac/users/#{bob.id}/roles")
               |> json_response(200)
               |> Map.fetch!("roles")
    end

    test "assigning requires an integer roleId", %{alice_token: t, bob: bob} do
      assert %{"error" => "Role ID is required"} =
               authed(t)
               |> post("/rbac/users/#{bob.id}/roles", %{roleId: "5"})
               |> json_response(400)
    end

    test "assigning to an unknown user is 404", %{alice_token: t} do
      id = create_role(t, "ghost")

      assert %{"error" => "User not found"} =
               authed(t) |> post("/rbac/users/nobody/roles", %{roleId: id}) |> json_response(404)
    end

    test "assigning an unknown role is 404", %{alice_token: t, bob: bob} do
      assert %{"error" => "Role not found"} =
               authed(t)
               |> post("/rbac/users/#{bob.id}/roles", %{roleId: 999_999})
               |> json_response(404)
    end

    test "system roles cannot be assigned or removed", %{alice_token: t, bob: bob} do
      role = insert_system_role("admin")

      assert %{"error" => msg} =
               authed(t)
               |> post("/rbac/users/#{bob.id}/roles", %{roleId: role.id})
               |> json_response(403)

      assert msg =~ "cannot be manually assigned"

      assert %{"error" => remove_msg} =
               authed(t)
               |> delete("/rbac/users/#{bob.id}/roles/#{role.id}")
               |> json_response(403)

      assert remove_msg =~ "cannot be removed"
    end

    test "a non-admin cannot assign roles", %{bob_token: t, carol: carol} do
      assert %{"error" => "Admin access required"} =
               authed(t)
               |> post("/rbac/users/#{carol.id}/roles", %{roleId: 1})
               |> json_response(403)
    end

    test "a user may read own roles but not another's", %{bob_token: t, bob: bob, carol: carol} do
      assert %{"roles" => []} =
               authed(t) |> get("/rbac/users/#{bob.id}/roles") |> json_response(200)

      assert %{"error" => "Access denied"} =
               authed(t) |> get("/rbac/users/#{carol.id}/roles") |> json_response(403)
    end
  end

  describe "host sharing" do
    setup %{bob: bob} do
      {:ok, host} =
        Hosts.create_host(bob.id, %{
          name: "web-1",
          ip: "10.0.0.5",
          port: 22,
          username: "root",
          authType: "password",
          password: "hostpw",
          connectionType: "ssh"
        })

      %{host: host}
    end

    test "owner shares with a user, lists, updates, and revokes", %{
      bob_token: bt,
      carol_token: ct,
      carol: carol,
      host: host
    } do
      share =
        authed(bt)
        |> post("/rbac/host/#{host.id}/share", %{
          targets: [%{type: "user", id: carol.id}],
          permissionLevel: "connect"
        })
        |> json_response(200)

      assert share["success"] == true
      assert [%{"type" => "user", "created" => true}] = share["results"]

      access = authed(bt) |> get("/rbac/host/#{host.id}/access") |> json_response(200)
      assert access["isOwner"] == true
      assert [grant] = access["accessList"]
      assert grant["targetType"] == "user"
      assert grant["username"] == "carol"
      assert grant["permissionLevel"] == "connect"
      assert grant["grantedByUsername"] == "bob"
      access_id = grant["id"]

      shared = authed(ct) |> get("/rbac/shared-hosts") |> json_response(200)

      assert [%{"id" => shared_id, "ownerUsername" => "bob", "permissionLevel" => "connect"}] =
               shared["sharedHosts"]

      assert shared_id == host.id

      assert %{"success" => true} =
               authed(bt)
               |> patch("/rbac/host/#{host.id}/access/#{access_id}", %{permissionLevel: "view"})
               |> json_response(200)

      updated = authed(bt) |> get("/rbac/host/#{host.id}/access") |> json_response(200)
      assert [%{"permissionLevel" => "view"}] = updated["accessList"]

      assert %{"message" => "Access revoked"} =
               authed(bt)
               |> delete("/rbac/host/#{host.id}/access/#{access_id}")
               |> json_response(200)

      assert %{"accessList" => []} =
               authed(bt) |> get("/rbac/host/#{host.id}/access") |> json_response(200)
    end

    test "sharing with a duration sets an expiry", %{bob_token: bt, carol: carol, host: host} do
      share =
        authed(bt)
        |> post("/rbac/host/#{host.id}/share", %{
          targets: [%{type: "user", id: carol.id}],
          permissionLevel: "connect",
          durationHours: 2
        })
        |> json_response(200)

      assert is_binary(share["expiresAt"])
    end

    test "cannot share a host with its owner", %{bob_token: bt, bob: bob, host: host} do
      assert %{"error" => "Cannot share a host with its owner"} =
               authed(bt)
               |> post("/rbac/host/#{host.id}/share", %{targets: [%{type: "user", id: bob.id}]})
               |> json_response(400)
    end

    test "rejects an invalid permission level", %{bob_token: bt, carol: carol, host: host} do
      body =
        authed(bt)
        |> post("/rbac/host/#{host.id}/share", %{
          targets: [%{type: "user", id: carol.id}],
          permissionLevel: "root"
        })
        |> json_response(400)

      assert body["error"] == "Invalid permission level"
      assert body["validLevels"] == ["connect", "view", "edit", "manage"]
    end

    test "rejects empty targets", %{bob_token: bt, host: host} do
      assert %{"error" => msg} =
               authed(bt)
               |> post("/rbac/host/#{host.id}/share", %{targets: []})
               |> json_response(400)

      assert msg =~ "non-empty array"
    end

    test "a non-owner without manage cannot share", %{
      carol_token: ct,
      carol: carol,
      host: host
    } do
      assert %{"error" => "You may not share this host"} =
               authed(ct)
               |> post("/rbac/host/#{host.id}/share", %{targets: [%{type: "user", id: carol.id}]})
               |> json_response(403)
    end

    test "an admin can manage sharing on another user's host", %{alice_token: at, host: host} do
      assert %{"isOwner" => false, "accessList" => []} =
               authed(at) |> get("/rbac/host/#{host.id}/access") |> json_response(200)
    end

    test "admin sharing an unknown host is 404 (admin passes the manage gate)", %{
      alice_token: at
    } do
      assert %{"error" => "Host not found"} =
               authed(at)
               |> post("/rbac/host/999999/share", %{targets: [%{type: "user", id: "x"}]})
               |> json_response(404)
    end

    test "sharing with a role grants role members access", %{
      alice_token: at,
      bob_token: bt,
      carol_token: ct,
      carol: carol,
      host: host
    } do
      role_id = create_role(at, "devs")

      authed(at)
      |> post("/rbac/users/#{carol.id}/roles", %{roleId: role_id})
      |> json_response(200)

      assert %{"success" => true} =
               authed(bt)
               |> post("/rbac/host/#{host.id}/share", %{
                 targets: [%{type: "role", id: role_id}],
                 permissionLevel: "view"
               })
               |> json_response(200)

      shared = authed(ct) |> get("/rbac/shared-hosts") |> json_response(200)
      assert [%{"id" => shared_id, "permissionLevel" => "view"}] = shared["sharedHosts"]
      assert shared_id == host.id
    end

    # `list_shared_hosts/2` builds its map in a DB-side `select:`, so it is the one port
    # consumer that does not read a Host struct. Without the Elixir-side fold the recipient
    # would be handed the stored remote-desktop port (3389/5900/23).
    test "a legacy remote-desktop host is shared at its SSH port, not 3389", %{
      bob: bob,
      bob_token: bt,
      carol: carol,
      carol_token: ct
    } do
      {:ok, legacy} =
        Hosts.create_host(bob.id, %{
          name: "old-rdp",
          ip: "10.0.0.9",
          port: 3389,
          sshPort: 2222,
          username: "root",
          authType: "password",
          password: "hostpw",
          connectionType: "rdp"
        })

      assert %{"success" => true} =
               authed(bt)
               |> post("/rbac/host/#{legacy.id}/share", %{
                 targets: [%{type: "user", id: carol.id}],
                 permissionLevel: "connect"
               })
               |> json_response(200)

      shared = authed(ct) |> get("/rbac/shared-hosts") |> json_response(200)
      entry = Enum.find(shared["sharedHosts"], &(&1["id"] == legacy.id))

      assert entry["port"] == 2222
      refute Map.has_key?(entry, "connectionType")
      refute Map.has_key?(entry, "sshPort")
    end

    test "an expired grant is excluded from shared-hosts", %{
      carol_token: ct,
      carol: carol,
      bob: bob,
      host: host
    } do
      past = DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.to_iso8601()

      Repo.insert!(%HostAccess{
        hostId: host.id,
        userId: carol.id,
        grantedBy: bob.id,
        permissionLevel: "connect",
        expiresAt: past,
        createdAt: DateTime.utc_now() |> DateTime.to_iso8601(),
        accessCount: 0
      })

      assert %{"sharedHosts" => []} =
               authed(ct) |> get("/rbac/shared-hosts") |> json_response(200)
    end

    test "patch with no fields is rejected", %{bob_token: bt, carol: carol, host: host} do
      share =
        authed(bt)
        |> post("/rbac/host/#{host.id}/share", %{targets: [%{type: "user", id: carol.id}]})
        |> json_response(200)

      access_id = hd(share["results"])["accessId"]

      assert %{"error" => msg} =
               authed(bt)
               |> patch("/rbac/host/#{host.id}/access/#{access_id}", %{})
               |> json_response(400)

      assert msg =~ "At least one of"
    end

    test "patch on an unknown access grant is 404", %{bob_token: bt, host: host} do
      assert %{"error" => "Access grant not found"} =
               authed(bt)
               |> patch("/rbac/host/#{host.id}/access/999999", %{permissionLevel: "view"})
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

  defp create_role(token, name) do
    authed(token)
    |> post("/rbac/roles", %{name: name, displayName: String.capitalize(name)})
    |> json_response(201)
    |> Map.fetch!("roleId")
  end

  defp insert_system_role(name) do
    now = DateTime.utc_now() |> DateTime.to_iso8601()

    Repo.insert!(%Role{
      name: name,
      displayName: String.capitalize(name),
      isSystem: true,
      createdAt: now,
      updatedAt: now
    })
  end

  defp authed(token),
    do:
      Phoenix.ConnTest.build_conn()
      |> Plug.Conn.put_req_header("authorization", "Bearer #{token}")
end
