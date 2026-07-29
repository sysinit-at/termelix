defmodule Termelix.OidcTest do
  @moduledoc """
  Unit coverage for the pure OIDC helpers (`user-oidc-utils.ts` port) plus the DB-backed
  provider resolution and find-or-create flow. `id_token` verification is exercised against a
  JOSE-signed token with the JWKS endpoint stubbed via `Req.Test`.
  """
  use Termelix.DataCase, async: false

  alias Termelix.{Accounts, Oidc, SsoProviders}
  alias Termelix.Crypto.UserKeyManager

  @stub __MODULE__.ReqStub

  # --- get_nested_value -----------------------------------------------------

  describe "get_nested_value/2" do
    test "reads dotted paths and returns nil for misses or blank paths" do
      obj = %{"a" => %{"b" => %{"c" => "deep"}}, "x" => "flat"}

      assert Oidc.get_nested_value(obj, "a.b.c") == "deep"
      assert Oidc.get_nested_value(obj, "x") == "flat"
      assert Oidc.get_nested_value(obj, "a.missing.c") == nil
      assert Oidc.get_nested_value(obj, "") == nil
      assert Oidc.get_nested_value(obj, nil) == nil
    end
  end

  # --- extract_oidc_groups --------------------------------------------------

  describe "extract_oidc_groups/2" do
    test "reads arrays, csv strings, and object keys from the default claims" do
      assert Oidc.extract_oidc_groups(%{"groups" => ["a", "b"]}, nil) == ["a", "b"]
      assert Oidc.extract_oidc_groups(%{"roles" => "x, y ,z"}, nil) == ["x", "y", "z"]

      assert Oidc.extract_oidc_groups(%{"group" => %{"admins" => 1, "devs" => 1}}, nil)
             |> Enum.sort() == ["admins", "devs"]

      assert Oidc.extract_oidc_groups(%{}, nil) == []
    end

    test "prefers a custom group claim when provided" do
      userinfo = %{"urn:zitadel:roles" => ["ops"], "groups" => ["ignored"]}
      assert Oidc.extract_oidc_groups(userinfo, "urn:zitadel:roles") == ["ops"]
    end
  end

  # --- oidc_user_allowed? ---------------------------------------------------

  describe "oidc_user_allowed?/3" do
    test "an empty allow-list permits everyone" do
      assert Oidc.oidc_user_allowed?("", "alice", "a@x.io")
      assert Oidc.oidc_user_allowed?(nil, "alice")
    end

    test "exact, @domain-suffix, and wildcard patterns" do
      assert Oidc.oidc_user_allowed?("alice, bob", "bob", nil)
      refute Oidc.oidc_user_allowed?("alice, bob", "carol", nil)
      assert Oidc.oidc_user_allowed?("@example.com", "x", "user@example.com")
      refute Oidc.oidc_user_allowed?("@example.com", "x", "user@other.com")
      assert Oidc.oidc_user_allowed?("*@example.com", "x", "user@example.com")
      assert Oidc.oidc_user_allowed?("*", "anyone", nil)
    end
  end

  # --- extract_identity -----------------------------------------------------

  describe "extract_identity/2" do
    test "uses identifier_path/name_path with fallbacks" do
      config = %{"identifier_path" => "sub", "name_path" => "name"}
      userinfo = %{"sub" => "abc", "name" => "Alice"}
      assert {:ok, "abc", "Alice"} = Oidc.extract_identity(config, userinfo)
    end

    test "falls back through sub/email/preferred_username" do
      config = %{"identifier_path" => "missing", "name_path" => "missing"}
      userinfo = %{"email" => "e@x.io", "given_name" => "Ann"}
      assert {:ok, "e@x.io", "Ann"} = Oidc.extract_identity(config, userinfo)
    end

    test "returns :no_identifier when nothing resolves" do
      assert {:error, :no_identifier} = Oidc.extract_identity(%{"identifier_path" => "sub"}, %{})
    end
  end

  # --- provider defaults ----------------------------------------------------

  describe "apply_provider_defaults/2" do
    test "fills google/github endpoints but keeps caller overrides" do
      google = Oidc.apply_provider_defaults(%{"client_id" => "c"}, "google")
      assert google["authorization_url"] == "https://accounts.google.com/o/oauth2/v2/auth"
      assert google["client_id"] == "c"

      github = Oidc.apply_provider_defaults(%{"scopes" => "read:user"}, "github")
      assert github["token_url"] == "https://github.com/login/oauth/access_token"
      assert github["scopes"] == "read:user"
    end

    test "leaves plain oidc configs untouched" do
      config = %{"issuer_url" => "https://idp"}
      assert Oidc.apply_provider_defaults(config, "oidc") == config
    end
  end

  # --- callback-target classification ---------------------------------------

  describe "token_callback?/1 and desktop_callback_url/1" do
    test "classifies mobile + loopback callbacks" do
      assert Oidc.token_callback?("termelix-mobile://oidc-callback")
      assert Oidc.token_callback?("http://localhost:8123/oidc-callback")
      assert Oidc.token_callback?("http://127.0.0.1:9000/oidc-callback")
      refute Oidc.token_callback?("https://app.example.com")
      refute Oidc.token_callback?("http://localhost:8123/other")
    end

    test "builds desktop loopback URLs, rejecting bad ports" do
      assert Oidc.desktop_callback_url("8123") == "http://localhost:8123/oidc-callback"
      assert Oidc.desktop_callback_url("70000") == nil
      assert Oidc.desktop_callback_url("abc") == nil
    end
  end

  # --- env config -----------------------------------------------------------

  describe "get_oidc_config_from_env/0" do
    test "returns nil when required vars are missing" do
      assert Oidc.get_oidc_config_from_env() == nil
    end

    test "builds a config when all required vars are present" do
      vars = %{
        "OIDC_CLIENT_ID" => "cid",
        "OIDC_CLIENT_SECRET" => "sec",
        "OIDC_ISSUER_URL" => "https://idp",
        "OIDC_AUTHORIZATION_URL" => "https://idp/authorize",
        "OIDC_TOKEN_URL" => "https://idp/token"
      }

      Enum.each(vars, fn {k, v} -> System.put_env(k, v) end)
      on_exit(fn -> Enum.each(Map.keys(vars), &System.delete_env/1) end)

      config = Oidc.get_oidc_config_from_env()
      assert config["client_id"] == "cid"
      assert config["scopes"] == "openid email profile"
      assert config["identifier_path"] == "sub"
    end
  end

  # --- load_provider_config -------------------------------------------------

  describe "load_provider_config/1" do
    test "resolves a provider row by id with decoded secret + defaults" do
      provider =
        SsoProviders.create(%{
          name: "Google",
          type: "google",
          config:
            SsoProviders.encrypt_provider_config(%{
              "client_id" => "gid",
              "client_secret" => "gsecret"
            })
        })

      assert {:ok, %{config: config, provider_type: "google", provider_db_id: id}} =
               Oidc.load_provider_config(provider.id)

      assert id == provider.id
      assert config["client_secret"] == "gsecret"
      # google defaults are applied at load time
      assert config["token_url"] == "https://oauth2.googleapis.com/token"
    end

    test "returns nil when nothing is configured" do
      assert Oidc.load_provider_config(nil) == nil
      assert Oidc.load_provider_config(999) == nil
    end
  end

  # --- find_or_create_user --------------------------------------------------

  describe "find_or_create_user/5" do
    test "creates the first user as admin, stores oidcIdentifier plaintext, and provisions a DEK" do
      config = %{"allowed_users" => "", "admin_group" => ""}

      assert {:ok, user} =
               Oidc.find_or_create_user(config, "idp|123", "Alice", %{"email" => "a@x.io"}, 7)

      assert user.isOidc == true
      assert user.isAdmin == true
      assert user.oidcIdentifier == "idp|123"
      assert user.ssoProviderId == 7
      # Stored plaintext → findable by exact column match (the Node findByOidcIdentifier path).
      assert Oidc.find_by_oidc_identifier("idp|123").id == user.id
      # A DEK exists for the new user.
      assert UserKeyManager.has_user_dek?(user.id)
    end

    test "a second call for the same identifier returns the existing user" do
      config = %{"allowed_users" => "", "admin_group" => ""}
      {:ok, first} = Oidc.find_or_create_user(config, "idp|1", "One", %{}, nil)
      {:ok, again} = Oidc.find_or_create_user(config, "idp|1", "One", %{}, nil)
      assert again.id == first.id
    end

    test "rejects a new non-first user not in the allow-list" do
      # Seed a first user so the next is not the first.
      {:ok, _admin, _} = Accounts.register_user("root", "correct horse battery staple")
      config = %{"allowed_users" => "alice@x.io", "admin_group" => ""}

      assert {:error, :not_allowed} =
               Oidc.find_or_create_user(config, "idp|9", "Nope", %{"email" => "bob@x.io"}, nil)
    end

    test "blocks a new non-first user when auto-provision is disabled" do
      {:ok, _admin, _} = Accounts.register_user("root", "correct horse battery staple")
      config = %{"allowed_users" => "", "admin_group" => ""}

      assert {:error, :registration_disabled} =
               Oidc.find_or_create_user(config, "idp|new", "New", %{}, nil)
    end
  end

  # --- provider-scoped identifiers (multi-provider collision guard) ----------

  describe "scoped_identifier/3 + legacy fallback" do
    test "scopes by provider id, and by issuer when there is no provider row" do
      config = %{"issuer_url" => "https://idp-a"}

      assert Oidc.scoped_identifier(42, config, "sub-1") == "oidc:42:sub-1"
      assert Oidc.scoped_identifier(nil, config, "sub-1") == "oidc:https://idp-a:sub-1"
    end

    test "the same sub from two providers resolves to two distinct accounts" do
      Termelix.Settings.put_value("oidc_auto_provision", "true")
      config = %{"allowed_users" => "", "admin_group" => ""}

      {:ok, u1} =
        Oidc.find_or_create_user(
          config,
          Oidc.scoped_identifier(1, config, "shared-sub"),
          "One",
          %{},
          1,
          legacy_identifier: "shared-sub"
        )

      {:ok, u2} =
        Oidc.find_or_create_user(
          config,
          Oidc.scoped_identifier(2, config, "shared-sub"),
          "Two",
          %{},
          2,
          legacy_identifier: "shared-sub"
        )

      refute u1.id == u2.id
      assert u1.oidcIdentifier == "oidc:1:shared-sub"
      assert u2.oidcIdentifier == "oidc:2:shared-sub"
    end

    test "a legacy unscoped row still logs in and is migrated to the scoped form" do
      config = %{"allowed_users" => "", "admin_group" => ""}

      # A row as written before identifiers were provider-scoped.
      {:ok, legacy} = Oidc.find_or_create_user(config, "ext|9", "Legacy", %{}, 5)
      assert legacy.oidcIdentifier == "ext|9"

      # The scoped lookup misses, the legacy fallback hits, and the row migrates.
      assert {:ok, migrated} =
               Oidc.find_or_create_user(
                 config,
                 Oidc.scoped_identifier(5, config, "ext|9"),
                 "Legacy",
                 %{},
                 5,
                 legacy_identifier: "ext|9"
               )

      assert migrated.id == legacy.id
      assert migrated.oidcIdentifier == "oidc:5:ext|9"

      # The next login matches the scoped form directly — no fallback involved.
      assert {:ok, again} =
               Oidc.find_or_create_user(
                 config,
                 Oidc.scoped_identifier(5, config, "ext|9"),
                 "Legacy",
                 %{},
                 5,
                 legacy_identifier: "ext|9"
               )

      assert again.id == legacy.id
    end

    test "the legacy fallback never hijacks a scoped row owned by another provider" do
      Termelix.Settings.put_value("oidc_auto_provision", "true")
      config = %{"allowed_users" => "", "admin_group" => ""}

      # Provider 1 owns the scoped row; a legacy-looking row "ext|1" belongs to someone else.
      {:ok, scoped_owner} =
        Oidc.find_or_create_user(
          config,
          Oidc.scoped_identifier(1, config, "ext|1"),
          "Scoped",
          %{},
          1,
          legacy_identifier: "ext|1"
        )

      {:ok, legacy_row} = Oidc.find_or_create_user(config, "ext|1", "Legacy", %{}, 9)

      # Provider 2 shows up with sub "ext|1": the scoped lookup misses, and the legacy
      # fallback refuses BOTH rows — provider 1's because it is already scoped, provider 9's
      # because provider 2 does not own it. Claiming the latter would be the same
      # cross-provider takeover scoping exists to prevent, just via the compatibility path.
      assert {:ok, resolved} =
               Oidc.find_or_create_user(
                 config,
                 Oidc.scoped_identifier(2, config, "ext|1"),
                 "New",
                 %{},
                 2,
                 legacy_identifier: "ext|1"
               )

      refute resolved.id == scoped_owner.id
      refute resolved.id == legacy_row.id
      assert resolved.oidcIdentifier == "oidc:2:ext|1"

      # …and provider 9's own row is untouched, still matched by its unscoped identifier.
      assert Oidc.find_by_oidc_identifier("ext|1").id == legacy_row.id
    end

    test "an owner-less legacy row is still claimable (the env-configured flow)" do
      config = %{"allowed_users" => "", "admin_group" => "", "issuer_url" => "https://idp-env"}

      # No provider row: `provider_db_id` is nil at creation, so the row carries no owner.
      {:ok, legacy} = Oidc.find_or_create_user(config, "ext|env", "Env", %{}, nil)
      assert is_nil(legacy.ssoProviderId)

      assert {:ok, migrated} =
               Oidc.find_or_create_user(
                 config,
                 Oidc.scoped_identifier(nil, config, "ext|env"),
                 "Env",
                 %{},
                 nil,
                 legacy_identifier: "ext|env"
               )

      assert migrated.id == legacy.id
    end

    test "an owner-less legacy row is NOT claimable by a configured provider" do
      Termelix.Settings.put_value("oidc_auto_provision", "true")
      config = %{"allowed_users" => "", "admin_group" => "", "issuer_url" => "https://idp-env"}

      # Written by the env-configured flow, so the row records no owning provider.
      {:ok, legacy} = Oidc.find_or_create_user(config, "ext|env", "Env", %{}, nil)
      assert is_nil(legacy.ssoProviderId)

      # An admin adds provider 3, and someone logs in through it with the same `sub`.
      # Allowing that would be the takeover the scoping exists to prevent, wearing the
      # compatibility path as a disguise.
      assert {:ok, resolved} =
               Oidc.find_or_create_user(
                 config,
                 Oidc.scoped_identifier(3, config, "ext|env"),
                 "Impostor",
                 %{},
                 3,
                 legacy_identifier: "ext|env"
               )

      refute resolved.id == legacy.id
      assert Oidc.find_by_oidc_identifier("ext|env").id == legacy.id
    end
  end

  # --- verify_oidc_token (JOSE + stubbed JWKS) ------------------------------

  describe "verify_oidc_token/4" do
    setup do
      Application.put_env(:termelix, :req_options, plug: {Req.Test, @stub})
      on_exit(fn -> Application.delete_env(:termelix, :req_options) end)

      jwk = JOSE.JWK.generate_key({:rsa, 2048})
      {_, pub_map} = JOSE.JWK.to_public_map(jwk)
      pub_map = Map.put(pub_map, "kid", "test-kid")

      # Every outbound GET returns the JWKS; discovery has no jwks_uri so the standard URL wins.
      Req.Test.stub(@stub, fn conn -> Req.Test.json(conn, %{"keys" => [pub_map]}) end)

      %{jwk: jwk}
    end

    test "accepts a well-formed token and returns its claims", %{jwk: jwk} do
      token =
        sign(jwk, %{
          "iss" => "https://idp",
          "aud" => "cid",
          "sub" => "u1",
          "nonce" => "n1",
          "exp" => future()
        })

      assert {:ok, claims} = Oidc.verify_oidc_token(token, "https://idp", "cid", nil)
      assert claims["sub"] == "u1"
      assert claims["nonce"] == "n1"
    end

    test "rejects an audience mismatch", %{jwk: jwk} do
      token =
        sign(jwk, %{"iss" => "https://idp", "aud" => "other", "sub" => "u1", "exp" => future()})

      assert {:error, :audience_mismatch} =
               Oidc.verify_oidc_token(token, "https://idp", "cid", nil)
    end

    test "rejects an expired token", %{jwk: jwk} do
      token = sign(jwk, %{"iss" => "https://idp", "aud" => "cid", "sub" => "u1", "exp" => past()})
      assert {:error, :token_expired} = Oidc.verify_oidc_token(token, "https://idp", "cid", nil)
    end
  end

  describe "outbound HTTP redirect handling" do
    setup do
      Application.put_env(:termelix, :req_options, plug: {Req.Test, @stub})
      on_exit(fn -> Application.delete_env(:termelix, :req_options) end)
      :ok
    end

    test "http GETs do not follow redirects (no unvetted second hop)" do
      {:ok, paths} = Agent.start_link(fn -> [] end)

      Req.Test.stub(@stub, fn conn ->
        Agent.update(paths, &[conn.request_path | &1])

        case conn.request_path do
          "/user" ->
            conn
            |> Plug.Conn.put_resp_header("location", "http://169.254.169.254/latest/meta-data")
            |> Plug.Conn.send_resp(302, "")

          _ ->
            Req.Test.json(conn, %{"login" => "mallory"})
        end
      end)

      assert {:error, :github_userinfo} = Oidc.fetch_github_userinfo("tok")
      assert Agent.get(paths, & &1) == ["/user"]
    end

    test "the token exchange does not re-POST the client_secret to a redirect target" do
      {:ok, paths} = Agent.start_link(fn -> [] end)

      Req.Test.stub(@stub, fn conn ->
        Agent.update(paths, &[conn.request_path | &1])

        case conn.request_path do
          "/token" ->
            conn
            |> Plug.Conn.put_resp_header("location", "http://evil.test/token")
            |> Plug.Conn.send_resp(307, "")

          _ ->
            Req.Test.json(conn, %{"access_token" => "stolen"})
        end
      end)

      config = %{
        "client_id" => "cid",
        "client_secret" => "sec",
        "token_url" => "https://idp/token"
      }

      assert {:error, {:http_status, 307}} =
               Oidc.exchange_code(config, "code-1", "https://app/callback")

      assert Agent.get(paths, & &1) == ["/token"]
    end
  end

  # --- helpers --------------------------------------------------------------

  defp sign(jwk, claims) do
    {_, token} =
      JOSE.JWS.compact(JOSE.JWT.sign(jwk, %{"alg" => "RS256", "kid" => "test-kid"}, claims))

    token
  end

  defp future, do: System.system_time(:second) + 3600
  defp past, do: System.system_time(:second) - 3600
end
