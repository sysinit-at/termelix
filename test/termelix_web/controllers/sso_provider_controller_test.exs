defmodule TermelixWeb.SsoProviderControllerTest do
  @moduledoc """
  Coverage for the `/users/sso-providers` surface: public listing, CRUD, config secret
  round-tripping, and the delete guard.

  Actions are called directly with a conn whose `current_user` is assigned, which means NO
  PLUGS RUN — so admin gating cannot be asserted here. It lives in the router's
  `:admin_access` pipeline and is covered by `test/termelix_web/admin_pipeline_test.exs`.
  """
  use TermelixWeb.ConnCase, async: false

  alias Termelix.{Accounts, Id, Repo, SsoProviders}
  alias Termelix.Crypto.SystemSecrets
  alias Termelix.Schema.User
  alias TermelixWeb.SsoProviderController

  @password "correct horse battery staple"

  setup do
    {:ok, admin, _} = Accounts.register_user("admin", @password)
    {:ok, member, _} = Accounts.register_user("member", @password)
    %{admin: admin, member: member}
  end

  # --- public listing -------------------------------------------------------

  describe "index (public)" do
    test "returns [] when nothing is enabled" do
      assert build_conn() |> SsoProviderController.index(%{}) |> json_response(200) == []
    end

    test "returns the public projection of enabled providers" do
      SsoProviders.create(%{
        name: "Corp SSO",
        type: "oidc",
        displayOrder: 3,
        config:
          SsoProviders.encrypt_provider_config(%{"client_id" => "c", "client_secret" => "s"})
      })

      assert [provider] = build_conn() |> SsoProviderController.index(%{}) |> json_response(200)
      assert provider["name"] == "Corp SSO"
      assert provider["type"] == "oidc"
      assert provider["displayOrder"] == 3
      # The public projection never leaks config.
      refute Map.has_key?(provider, "config")
    end
  end

  # --- admin listing --------------------------------------------------------

  describe "admin_index" do
    test "an admin sees the full row with a decoded config", %{admin: admin} do
      SsoProviders.create(%{
        name: "Corp",
        type: "oidc",
        config:
          SsoProviders.encrypt_provider_config(%{
            "client_id" => "c",
            "client_secret" => "topsecret"
          })
      })

      assert [row] =
               admin |> conn_for() |> SsoProviderController.admin_index(%{}) |> json_response(200)

      # Write-only secrets (CLAUDE.md): the value never comes back, only its presence.
      refute Map.has_key?(row["config"], "client_secret")
      assert row["hasClientSecret"] == true
      assert row["enabled"] == true
    end

    # The non-admin 403s that used to live in this file moved to
    # `test/termelix_web/admin_pipeline_test.exs`. Authorization is the router's
    # `:admin_access` pipeline now, and these tests call the action FUNCTION directly,
    # which runs no plugs — so asserted here they would have passed while a non-admin
    # actually performed the operation.
  end

  # --- create ---------------------------------------------------------------

  describe "create" do
    test "an admin creates an oidc provider and gets the decoded config back", %{admin: admin} do
      params = %{
        "name" => "  Corp  ",
        "type" => "oidc",
        "config" => %{
          "client_id" => "cid",
          "client_secret" => "sec",
          "issuer_url" => "https://idp",
          "authorization_url" => "https://idp/authorize",
          "token_url" => "https://idp/token"
        }
      }

      body = admin |> conn_for() |> SsoProviderController.create(params) |> json_response(201)
      assert body["name"] == "Corp"
      assert body["type"] == "oidc"
      assert body["enabled"] == true
      refute Map.has_key?(body["config"], "client_secret")
      assert body["hasClientSecret"] == true

      # Persisted config seals the secret under the instance key — no base64 wrapper — and the
      # admin read path still opens it back to the plaintext.
      stored = SsoProviders.find_by_id(body["id"])
      stored_secret = Jason.decode!(stored.config)["client_secret"]
      assert SystemSecrets.sealed?(stored_secret)
      refute String.starts_with?(stored_secret, "encoded:")
      assert SsoProviders.decrypt_provider_config(stored.config)["client_secret"] == "sec"
    end

    test "github fills endpoint defaults and only requires client id/secret", %{admin: admin} do
      params = %{
        "name" => "GitHub",
        "type" => "github",
        "config" => %{"client_id" => "gid", "client_secret" => "gsec"}
      }

      body = admin |> conn_for() |> SsoProviderController.create(params) |> json_response(201)
      assert body["config"]["authorization_url"] == "https://github.com/login/oauth/authorize"
    end

    test "rejects a missing name, invalid type, and incomplete oidc config", %{admin: admin} do
      assert %{"error" => "Provider name is required"} =
               admin
               |> conn_for()
               |> SsoProviderController.create(%{"type" => "oidc"})
               |> json_response(400)

      assert %{"error" => "Invalid provider type"} =
               admin
               |> conn_for()
               |> SsoProviderController.create(%{"name" => "x", "type" => "saml"})
               |> json_response(400)

      assert %{"error" => "Missing required OIDC fields: " <> _} =
               admin
               |> conn_for()
               |> SsoProviderController.create(%{
                 "name" => "x",
                 "type" => "oidc",
                 "config" => %{"client_id" => "c"}
               })
               |> json_response(400)

      assert %{"error" => "Client ID and Client Secret are required"} =
               admin
               |> conn_for()
               |> SsoProviderController.create(%{
                 "name" => "x",
                 "type" => "github",
                 "config" => %{"client_id" => "c"}
               })
               |> json_response(400)
    end

    # LDAP login itself is not ported (no live directory in CI); the provider-config path is,
    # so its required-field validation and bindPassword secret-wrapping are covered here.
    test "ldap validates required fields and wraps bindPassword", %{admin: admin} do
      assert %{"error" => "Missing required LDAP fields: " <> _} =
               admin
               |> conn_for()
               |> SsoProviderController.create(%{
                 "name" => "Dir",
                 "type" => "ldap",
                 "config" => %{"host" => "ldap.x"}
               })
               |> json_response(400)

      params = %{
        "name" => "Dir",
        "type" => "ldap",
        "config" => %{
          "host" => "ldap.x",
          "port" => 636,
          "bindDN" => "cn=admin",
          "bindPassword" => "dirsecret",
          "userSearchBase" => "ou=users",
          "userSearchFilter" => "(uid=%s)",
          "usernameAttribute" => "uid"
        }
      }

      body = admin |> conn_for() |> SsoProviderController.create(params) |> json_response(201)
      refute Map.has_key?(body["config"], "bindPassword")
      assert body["hasBindPassword"] == true

      stored = SsoProviders.find_by_id(body["id"])
      stored_secret = Jason.decode!(stored.config)["bindPassword"]
      assert SystemSecrets.sealed?(stored_secret)
      assert SsoProviders.decrypt_provider_config(stored.config)["bindPassword"] == "dirsecret"
    end
  end

  # --- update ---------------------------------------------------------------

  describe "update" do
    test "an admin renames, toggles, and merges config", %{admin: admin} do
      provider =
        SsoProviders.create(%{
          name: "Old",
          type: "oidc",
          config:
            SsoProviders.encrypt_provider_config(%{"client_id" => "c", "client_secret" => "old"})
        })

      params = %{
        "id" => to_string(provider.id),
        "name" => "New",
        "enabled" => false,
        "config" => %{"client_secret" => "rotated"}
      }

      body = admin |> conn_for() |> SsoProviderController.update(params) |> json_response(200)
      assert body["name"] == "New"
      assert body["enabled"] == false
      # Merge preserves the untouched client_id and rotates the secret.
      assert body["config"]["client_id"] == "c"
      refute Map.has_key?(body["config"], "client_secret")
      assert body["hasClientSecret"] == true
    end

    # The direct consequence of removing the read-back. The admin form no longer receives the
    # current secret, so an untouched field is resubmitted as "" — and a plain Map.merge would
    # overwrite the stored secret with a blank, locking the instance out of its own IdP. Blank
    # and absent must both mean "keep", the same rule credential_controller.ex applies.
    test "a blank secret keeps the stored one instead of erasing it", %{admin: admin} do
      provider =
        SsoProviders.create(%{
          name: "Keep",
          type: "oidc",
          config:
            SsoProviders.encrypt_provider_config(%{"client_id" => "c", "client_secret" => "keep"})
        })

      for submitted <- [%{"client_id" => "c2", "client_secret" => ""}, %{"client_id" => "c3"}] do
        body =
          admin
          |> conn_for()
          |> SsoProviderController.update(%{
            "id" => to_string(provider.id),
            "config" => submitted
          })
          |> json_response(200)

        assert body["hasClientSecret"] == true

        stored = SsoProviders.find_by_id(provider.id)
        assert SsoProviders.decrypt_provider_config(stored.config)["client_secret"] == "keep"
      end
    end

    test "404 for a missing provider, 400 for a bad id", %{admin: admin} do
      assert %{"error" => "SSO provider not found"} =
               admin
               |> conn_for()
               |> SsoProviderController.update(%{"id" => "9999"})
               |> json_response(404)

      assert %{"error" => "Invalid provider ID"} =
               admin
               |> conn_for()
               |> SsoProviderController.update(%{"id" => "abc"})
               |> json_response(400)
    end
  end

  # --- delete ---------------------------------------------------------------

  describe "delete" do
    test "an admin deletes a provider with no users", %{admin: admin} do
      provider = SsoProviders.create(%{name: "Temp", type: "oidc", config: "{}"})

      assert %{"message" => "SSO provider deleted"} =
               admin
               |> conn_for()
               |> SsoProviderController.delete(%{"id" => to_string(provider.id)})
               |> json_response(200)

      assert SsoProviders.find_by_id(provider.id) == nil
    end

    test "blocks deletion when users are associated", %{admin: admin} do
      provider = SsoProviders.create(%{name: "Bound", type: "oidc", config: "{}"})

      Repo.insert!(%User{
        id: Id.generate(),
        username: "sso-user",
        passwordHash: "",
        isOidc: true,
        ssoProviderId: provider.id
      })

      assert %{"error" => "Cannot delete provider: 1 user(s) are associated with it"} =
               admin
               |> conn_for()
               |> SsoProviderController.delete(%{"id" => to_string(provider.id)})
               |> json_response(409)
    end

    test "404 for a missing provider", %{admin: admin} do
      assert %{"error" => "SSO provider not found"} =
               admin
               |> conn_for()
               |> SsoProviderController.delete(%{"id" => "9999"})
               |> json_response(404)
    end
  end

  # --- helpers --------------------------------------------------------------

  defp conn_for(user) do
    build_conn()
    |> Plug.Conn.assign(:current_user, user)
    |> Plug.Conn.assign(:current_user_id, user.id)
  end
end
