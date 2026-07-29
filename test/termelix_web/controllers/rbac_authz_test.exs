defmodule TermelixWeb.RbacAuthzTest do
  @moduledoc """
  The authorization matrix for every `/rbac` action, checked for three callers: an admin
  (`alice`, by the first-user rule), the non-admin owner of the shared host (`bob`), and an
  unrelated non-admin (`carol`).

  `/rbac` is a mixed scope — roles CRUD, the permissions catalog and user-role assignment are
  admin-only, while the host-sharing routes are owner-scoped — so a route moving into or out
  of the wrong bucket is a silent privilege change. This file pins both buckets down.

  `list_roles` is the deliberate exception: it stays reachable for non-admins (the share modal
  needs it) and scopes its response to the grantable roles instead.
  """
  use TermelixWeb.ConnCase

  alias Termelix.{Accounts, Hosts, Rbac, Repo}
  alias Termelix.Schema.Role

  setup do
    {alice_token, alice} = register_and_login("alice", "correct horse battery staple")
    {bob_token, bob} = register_and_login("bob", "another good long passphrase")
    {carol_token, carol} = register_and_login("carol", "yet another long passphrase")

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

    {:ok, role_id} =
      Rbac.create_role(%{
        name: "devs",
        displayName: "Developers",
        description: "the dev team",
        permissions: Jason.encode!(["hosts.view"])
      })

    system_role = insert_system_role("admin")

    %{
      alice_token: alice_token,
      alice: alice,
      bob_token: bob_token,
      bob: bob,
      carol_token: carol_token,
      carol: carol,
      host: host,
      role_id: role_id,
      system_role: system_role
    }
  end

  describe "list_roles (ungated, response-scoped)" do
    test "an admin sees every role, description and permission grant", %{
      alice_token: t,
      role_id: role_id,
      system_role: system_role
    } do
      roles = get_roles(t)

      assert Enum.any?(roles, &(&1["id"] == system_role.id))

      devs = Enum.find(roles, &(&1["id"] == role_id))
      assert devs["description"] == "the dev team"
      assert devs["permissions"] == ["hosts.view"]
    end

    test "a non-admin owner still gets the roles they may grant", %{
      bob_token: t,
      role_id: role_id
    } do
      roles = get_roles(t)

      assert [%{"id" => ^role_id, "name" => "devs", "displayName" => "Developers"}] = roles
    end

    test "a non-admin sees neither system roles nor the authorization model", %{
      bob_token: bob_t,
      carol_token: carol_t,
      role_id: role_id,
      system_role: system_role
    } do
      for t <- [bob_t, carol_t] do
        roles = get_roles(t)

        refute Enum.any?(roles, &(&1["id"] == system_role.id))

        devs = Enum.find(roles, &(&1["id"] == role_id))
        refute Map.has_key?(devs, "permissions")
        refute Map.has_key?(devs, "description")
      end
    end
  end

  describe "permissions_catalog (admin only)" do
    test "an admin gets the catalog", %{alice_token: t} do
      catalog = authed(t) |> get("/rbac/permissions/catalog") |> json_response(200)
      hosts = Enum.find(catalog["catalog"], &(&1["group"] == "hosts"))
      assert "hosts.share" in hosts["permissions"]
    end

    test "a non-admin owner is refused", %{bob_token: t} do
      assert %{"error" => "Admin access required"} =
               authed(t) |> get("/rbac/permissions/catalog") |> json_response(403)
    end

    test "an unrelated non-admin is refused", %{carol_token: t} do
      assert %{"error" => "Admin access required"} =
               authed(t) |> get("/rbac/permissions/catalog") |> json_response(403)
    end
  end

  describe "roles CRUD (admin only)" do
    test "create_role", %{alice_token: at, bob_token: bt, carol_token: ct} do
      body = %{name: "ops", displayName: "Ops"}

      for t <- [bt, ct] do
        assert %{"error" => "Admin access required"} =
                 authed(t) |> post("/rbac/roles", body) |> json_response(403)
      end

      assert %{"success" => true} = authed(at) |> post("/rbac/roles", body) |> json_response(201)
    end

    test "update_role", %{alice_token: at, bob_token: bt, carol_token: ct, role_id: role_id} do
      body = %{displayName: "Devs"}

      for t <- [bt, ct] do
        assert %{"error" => "Admin access required"} =
                 authed(t) |> put("/rbac/roles/#{role_id}", body) |> json_response(403)
      end

      assert %{"success" => true} =
               authed(at) |> put("/rbac/roles/#{role_id}", body) |> json_response(200)
    end

    test "delete_role", %{alice_token: at, bob_token: bt, carol_token: ct, role_id: role_id} do
      for t <- [bt, ct] do
        assert %{"error" => "Admin access required"} =
                 authed(t) |> delete("/rbac/roles/#{role_id}") |> json_response(403)
      end

      assert %{"success" => true} =
               authed(at) |> delete("/rbac/roles/#{role_id}") |> json_response(200)
    end
  end

  describe "user roles" do
    test "list_user_roles is self-or-admin", %{
      alice_token: at,
      bob_token: bt,
      carol_token: ct,
      bob: bob
    } do
      assert %{"roles" => []} =
               authed(at) |> get("/rbac/users/#{bob.id}/roles") |> json_response(200)

      assert %{"roles" => []} =
               authed(bt) |> get("/rbac/users/#{bob.id}/roles") |> json_response(200)

      assert %{"error" => "Access denied"} =
               authed(ct) |> get("/rbac/users/#{bob.id}/roles") |> json_response(403)
    end

    test "assign_user_role is admin only", %{
      alice_token: at,
      bob_token: bt,
      carol_token: ct,
      carol: carol,
      role_id: role_id
    } do
      body = %{roleId: role_id}

      for t <- [bt, ct] do
        assert %{"error" => "Admin access required"} =
                 authed(t) |> post("/rbac/users/#{carol.id}/roles", body) |> json_response(403)
      end

      assert %{"success" => true} =
               authed(at) |> post("/rbac/users/#{carol.id}/roles", body) |> json_response(200)
    end

    test "remove_user_role is admin only", %{
      alice_token: at,
      bob_token: bt,
      carol_token: ct,
      carol: carol,
      role_id: role_id
    } do
      path = "/rbac/users/#{carol.id}/roles/#{role_id}"

      authed(at)
      |> post("/rbac/users/#{carol.id}/roles", %{roleId: role_id})
      |> json_response(200)

      for t <- [bt, ct] do
        assert %{"error" => "Admin access required"} =
                 authed(t) |> delete(path) |> json_response(403)
      end

      assert %{"success" => true} = authed(at) |> delete(path) |> json_response(200)
    end
  end

  describe "share_host (owner-scoped)" do
    test "the owner may share", %{bob_token: t, carol: carol, host: host} do
      assert %{"success" => true} =
               authed(t)
               |> post("/rbac/host/#{host.id}/share", share_body(carol))
               |> json_response(200)
    end

    test "an admin may share someone else's host", %{alice_token: t, carol: carol, host: host} do
      assert %{"success" => true} =
               authed(t)
               |> post("/rbac/host/#{host.id}/share", share_body(carol))
               |> json_response(200)
    end

    test "an unrelated non-admin may not share", %{carol_token: t, carol: carol, host: host} do
      assert %{"error" => "You may not share this host"} =
               authed(t)
               |> post("/rbac/host/#{host.id}/share", share_body(carol))
               |> json_response(403)
    end
  end

  describe "host access grants (owner-scoped)" do
    setup %{bob: bob, carol: carol, host: host} do
      {access_id, true} =
        Rbac.upsert_host_access(%{
          hostId: host.id,
          grantedBy: bob.id,
          permissionLevel: "connect",
          expiresAt: nil,
          targetType: :user,
          targetUserId: carol.id,
          targetRoleId: nil
        })

      %{access_id: access_id}
    end

    test "host_access_list: owner and admin read it, the recipient does not", %{
      alice_token: at,
      bob_token: bt,
      carol_token: ct,
      host: host
    } do
      assert %{"isOwner" => true, "accessList" => [_grant]} =
               authed(bt) |> get("/rbac/host/#{host.id}/access") |> json_response(200)

      assert %{"isOwner" => false, "accessList" => [_]} =
               authed(at) |> get("/rbac/host/#{host.id}/access") |> json_response(200)

      assert %{"error" => "You may not manage sharing on this host"} =
               authed(ct) |> get("/rbac/host/#{host.id}/access") |> json_response(403)
    end

    test "update_host_access", %{
      alice_token: at,
      bob_token: bt,
      carol_token: ct,
      host: host,
      access_id: access_id
    } do
      path = "/rbac/host/#{host.id}/access/#{access_id}"
      body = %{permissionLevel: "view"}

      assert %{"error" => "You may not manage sharing on this host"} =
               authed(ct) |> patch(path, body) |> json_response(403)

      assert %{"success" => true} = authed(bt) |> patch(path, body) |> json_response(200)
      assert %{"success" => true} = authed(at) |> patch(path, body) |> json_response(200)
    end

    test "revoke_host_access", %{
      bob_token: bt,
      carol_token: ct,
      host: host,
      access_id: access_id
    } do
      path = "/rbac/host/#{host.id}/access/#{access_id}"

      assert %{"error" => "You may not manage sharing on this host"} =
               authed(ct) |> delete(path) |> json_response(403)

      assert %{"success" => true} = authed(bt) |> delete(path) |> json_response(200)
    end

    test "shared_hosts is scoped to the caller's own grants, with no admin bypass", %{
      alice_token: at,
      bob_token: bt,
      carol_token: ct,
      host: host
    } do
      assert %{"sharedHosts" => [%{"id" => shared_id}]} =
               authed(ct) |> get("/rbac/shared-hosts") |> json_response(200)

      assert shared_id == host.id

      assert %{"sharedHosts" => []} =
               authed(bt) |> get("/rbac/shared-hosts") |> json_response(200)

      assert %{"sharedHosts" => []} =
               authed(at) |> get("/rbac/shared-hosts") |> json_response(200)
    end
  end

  # --- helpers --------------------------------------------------------------

  defp get_roles(token),
    do: authed(token) |> get("/rbac/roles") |> json_response(200) |> Map.fetch!("roles")

  defp share_body(target),
    do: %{targets: [%{type: "user", id: target.id}], permissionLevel: "connect"}

  defp register_and_login(username, password) do
    conn = Phoenix.ConnTest.build_conn()

    conn
    |> post("/users/create", %{username: username, password: password})
    |> json_response(200)

    login = conn |> post("/users/login", %{username: username, password: password})
    %{"jwt" => %{value: token}} = login.resp_cookies
    {token, Accounts.get_user_by_username(username)}
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
