defmodule Termelix.LdapTest do
  @moduledoc """
  Unit coverage for the pure LDAP pieces (config parsing, filter escaping/parsing, attribute
  mapping, the allowed-users check) and for the full `login/3` flow driven through the injected
  `Termelix.LdapFakeClient` — a live directory is unavailable in CI, so the `:eldap` boundary is
  mocked and its integration deferred.
  """
  use Termelix.DataCase

  alias Termelix.{Accounts, Ldap, Settings}
  alias Termelix.Crypto.UserKeyManager

  # --- parse_config ----------------------------------------------------------

  describe "parse_config/1" do
    test "applies Node defaults (port 389, uid, cn) and normalises booleans" do
      config = Ldap.parse_config(%{"host" => "ldap.example.com", "useTLS" => true})

      assert config.host == "ldap.example.com"
      assert config.port == 389
      assert config.use_tls == true
      assert config.username_attribute == "uid"
      assert config.display_name_attribute == "cn"
      assert config.bind_password == ""
    end

    test "keeps explicit port/attributes and coerces a string port" do
      config =
        Ldap.parse_config(%{
          "port" => "636",
          "usernameAttribute" => "sAMAccountName",
          "displayNameAttribute" => "displayName",
          "useTLS" => false
        })

      assert config.port == 636
      assert config.username_attribute == "sAMAccountName"
      assert config.display_name_attribute == "displayName"
      assert config.use_tls == false
    end

    test "decrypts an `encoded:` bindPassword (base64)" do
      secret = "hunter2-service"
      raw = "encoded:" <> Base.encode64(secret)

      assert Ldap.parse_config(%{"bindPassword" => raw}).bind_password == secret
    end

    test "decrypts an `encrypted:` bindPassword (base64)" do
      secret = "another-secret"
      raw = "encrypted:" <> Base.encode64(secret)

      assert Ldap.parse_config(%{"bindPassword" => raw}).bind_password == secret
    end

    test "leaves a bare bindPassword untouched" do
      assert Ldap.parse_config(%{"bindPassword" => "plain"}).bind_password == "plain"
    end

    test "opens a sealed (instance-key) bindPassword" do
      sealed = Termelix.Crypto.SystemSecrets.seal("svc-sealed", "bindPassword")

      assert Ldap.parse_config(%{"bindPassword" => sealed}).bind_password == "svc-sealed"
    end

    test "a sealed bindPassword that will not open raises (mapped to :ldap_error by login/3)" do
      sealed = Termelix.Crypto.SystemSecrets.seal("svc-sealed", "bindPassword")
      tampered = String.replace(sealed, "\"recordId\":\"sso_providers\"", "\"recordId\":\"x\"")

      assert_raise RuntimeError, fn ->
        Ldap.parse_config(%{"bindPassword" => tampered})
      end
    end

    test "parses the TLS policy keys, defaulting to verification ON" do
      defaults = Ldap.parse_config(%{})
      assert defaults.insecure_skip_verify == false
      assert defaults.ca_cert == nil

      config =
        Ldap.parse_config(%{
          "insecureSkipVerify" => true,
          "caCert" => "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
        })

      assert config.insecure_skip_verify == true
      assert config.ca_cert =~ "BEGIN CERTIFICATE"
    end

    test "carries the connect timeout used for bind/search deadlines" do
      assert Ldap.parse_config(%{}).timeout == 10_000
    end
  end

  # --- escape_filter ---------------------------------------------------------

  describe "escape_filter/1" do
    test "escapes the LDAP filter metacharacters as \\HH" do
      assert Ldap.escape_filter("a*b(c)\\d") == "a\\2ab\\28c\\29\\5cd"
    end

    test "leaves ordinary text unchanged" do
      assert Ldap.escape_filter("alice") == "alice"
    end
  end

  # --- parse_filter ----------------------------------------------------------

  describe "parse_filter/1" do
    test "equality" do
      assert Ldap.parse_filter("(uid=alice)") == {:ok, {:equal, "uid", "alice"}}
    end

    test "presence" do
      assert Ldap.parse_filter("(mail=*)") == {:ok, {:present, "mail"}}
    end

    test "substrings with initial and final" do
      assert Ldap.parse_filter("(cn=a*b)") ==
               {:ok, {:substrings, "cn", [{:initial, "a"}, {:final, "b"}]}}
    end

    test "substrings with a middle segment only" do
      assert Ldap.parse_filter("(cn=*x*)") == {:ok, {:substrings, "cn", [{:any, "x"}]}}
    end

    test "conjunction" do
      assert Ldap.parse_filter("(&(objectClass=person)(uid=alice))") ==
               {:ok, {:and, [{:equal, "objectClass", "person"}, {:equal, "uid", "alice"}]}}
    end

    test "disjunction and negation" do
      assert Ldap.parse_filter("(|(uid=a)(!(uid=b)))") ==
               {:ok, {:or, [{:equal, "uid", "a"}, {:not, {:equal, "uid", "b"}}]}}
    end

    test "unescapes \\HH sequences into literal assertion bytes" do
      # `\2a` is a literal '*', not a wildcard.
      assert Ldap.parse_filter("(uid=a\\2ab)") == {:ok, {:equal, "uid", "a*b"}}
    end

    test ">= comparison" do
      assert Ldap.parse_filter("(uidNumber>=1000)") == {:ok, {:ge, "uidNumber", "1000"}}
    end

    test "rejects malformed input" do
      assert {:error, _} = Ldap.parse_filter("uid=alice")
      assert {:error, _} = Ldap.parse_filter("(uid=alice")
      assert {:error, _} = Ldap.parse_filter("(=alice)")
    end
  end

  # --- build_search_filter ---------------------------------------------------

  describe "build_search_filter/2" do
    test "substitutes {{username}} and escapes it (injection-safe)" do
      config = Ldap.parse_config(%{"userSearchFilter" => "(uid={{username}})"})

      # A '*' in the username is escaped, so it parses to a *literal* '*', never a wildcard.
      assert Ldap.build_search_filter(config, "al*ce") == {:ok, {:equal, "uid", "al*ce"}}
    end
  end

  # --- map_user_entry --------------------------------------------------------

  describe "map_user_entry/3" do
    test "extracts identifier/display-name/email, case-insensitively" do
      config = Ldap.parse_config(%{"usernameAttribute" => "uid", "displayNameAttribute" => "cn"})

      entry = %{
        dn: "uid=alice,ou=people,dc=example,dc=com",
        attributes: %{"UID" => ["alice"], "CN" => ["Alice L"], "MAIL" => ["alice@example.com"]}
      }

      assert Ldap.map_user_entry(entry, config, "login") ==
               {"alice", "Alice L", "alice@example.com"}
    end

    test "falls back to the login username and empty email when attributes are absent" do
      config = Ldap.parse_config(%{})
      entry = %{dn: "uid=bob,dc=example,dc=com", attributes: %{}}

      assert Ldap.map_user_entry(entry, config, "bob-login") ==
               {"bob-login", "bob-login", ""}
    end

    test "uses the `email` attribute when `mail` is missing" do
      config = Ldap.parse_config(%{})
      entry = %{dn: "x", attributes: %{"email" => ["e@x.io"]}}

      assert {_, _, "e@x.io"} = Ldap.map_user_entry(entry, config, "u")
    end
  end

  # --- user_allowed? ---------------------------------------------------------

  describe "user_allowed?/3" do
    test "an empty allow-list permits everyone" do
      assert Ldap.user_allowed?(nil, "alice")
      assert Ldap.user_allowed?("", "alice")
      assert Ldap.user_allowed?("   ", "alice")
    end

    test "wildcard, exact, glob, and @domain patterns" do
      assert Ldap.user_allowed?("*", "anyone")
      assert Ldap.user_allowed?("alice, bob", "bob")
      assert Ldap.user_allowed?("al*", "alice")
      assert Ldap.user_allowed?("@example.com", "who", "who@example.com")
    end

    test "matches on the email candidate too" do
      assert Ldap.user_allowed?("alice@example.com", "alice-id", "alice@example.com")
    end

    test "denies identifiers outside the list" do
      refute Ldap.user_allowed?("alice, bob", "carol")
      refute Ldap.user_allowed?("@corp.com", "x", "x@other.com")
    end
  end

  # --- normalize_provider_id -------------------------------------------------

  describe "normalize_provider_id/1" do
    test "accepts positive integers and numeric strings" do
      assert Ldap.normalize_provider_id(7) == 7
      assert Ldap.normalize_provider_id("7") == 7
    end

    test "rejects zero, negatives, blanks and junk" do
      assert Ldap.normalize_provider_id(0) == nil
      assert Ldap.normalize_provider_id(-1) == nil
      assert Ldap.normalize_provider_id("") == nil
      assert Ldap.normalize_provider_id("abc") == nil
      assert Ldap.normalize_provider_id(nil) == nil
    end
  end

  # --- login/3 (fake directory) ----------------------------------------------

  describe "login/3" do
    setup do
      Application.put_env(:termelix, :ldap_client, Termelix.LdapFakeClient)

      on_exit(fn ->
        Application.delete_env(:termelix, :ldap_client)
        Application.delete_env(:termelix, :ldap_fake)
      end)

      :ok
    end

    test "provisions the first user as admin and creates their DEK" do
      pid = put_provider(base_config())
      put_fake(base_fake())

      assert {:ok, user} = Ldap.login(pid, "alice", "s3cret")
      assert user.isAdmin == true
      assert user.isOidc == true
      assert user.username == "Alice Liddell"
      assert user.oidcIdentifier == "ldap:#{pid}:alice"
      assert user.ssoProviderId == pid
      assert user.passwordHash == ""
      assert UserKeyManager.has_user_dek?(user.id)
    end

    test "wrong password is invalid credentials (401 path)" do
      pid = put_provider(base_config())
      put_fake(base_fake())

      assert {:error, :invalid_credentials} = Ldap.login(pid, "alice", "wrong")
    end

    test "unknown user (no search hit) is invalid credentials" do
      pid = put_provider(base_config())
      put_fake(%{base_fake() | entries: []})

      assert {:error, :invalid_credentials} = Ldap.login(pid, "ghost", "s3cret")
    end

    test "a user outside allowedUsers is rejected (403 path)" do
      pid = put_provider(Map.put(base_config(), "allowedUsers", "bob"))
      put_fake(base_fake())

      assert {:error, :not_allowed} = Ldap.login(pid, "alice", "s3cret")
    end

    test "unknown/disabled/non-LDAP providers are not found" do
      put_fake(base_fake())

      assert {:error, :provider_not_found} = Ldap.login(999_999, "alice", "s3cret")

      assert {:error, :provider_not_found} =
               Ldap.login(put_provider(base_config(), enabled: 0), "alice", "s3cret")

      assert {:error, :provider_not_found} =
               Ldap.login(put_provider(base_config(), type: "oidc"), "alice", "s3cret")
    end

    test "a provider missing required keys is misconfigured (500 path)" do
      pid = put_provider(%{"host" => "ldap.example.com"})

      assert {:error, :misconfigured} = Ldap.login(pid, "alice", "s3cret")
    end

    test "second user cannot self-provision when auto-provision is off" do
      {:ok, _bob, _first} = Accounts.register_user("bob", "bob-password")
      pid = put_provider(base_config())
      put_fake(base_fake())

      assert {:error, :registration_disabled} = Ldap.login(pid, "alice", "s3cret")
    end

    test "auto-provision (setting) creates a non-admin user" do
      {:ok, _bob, _first} = Accounts.register_user("bob", "bob-password")
      Settings.put_value("oidc_auto_provision", "true")
      pid = put_provider(base_config())
      put_fake(base_fake())

      assert {:ok, user} = Ldap.login(pid, "alice", "s3cret")
      assert user.isAdmin == false
    end

    test "admin group membership provisions an admin" do
      {:ok, _bob, _first} = Accounts.register_user("bob", "bob-password")
      Settings.put_value("oidc_auto_provision", "true")

      config =
        base_config()
        |> Map.put("adminGroup", "admins")
        |> Map.put("groupSearchBase", "ou=groups,dc=example,dc=com")

      pid = put_provider(config)

      put_fake(
        Map.merge(base_fake(), %{
          group_search_base: "ou=groups,dc=example,dc=com",
          group_entries: [
            %{dn: "cn=admins,ou=groups,dc=example,dc=com", attributes: %{"cn" => ["admins"]}}
          ]
        })
      )

      assert {:ok, user} = Ldap.login(pid, "alice", "s3cret")
      assert user.isAdmin == true
    end

    test "re-login returns the same user and refreshes the display name" do
      pid = put_provider(base_config())
      put_fake(base_fake())
      assert {:ok, first} = Ldap.login(pid, "alice", "s3cret")

      renamed = put_in(base_fake(), [:entries], [entry(cn: "Alice New")])
      put_fake(renamed)
      assert {:ok, second} = Ldap.login(pid, "alice", "s3cret")

      assert second.id == first.id
      assert second.username == "Alice New"
      assert Accounts.user_count() == 1
    end

    test "a connect failure surfaces as a generic LDAP error (500 path)" do
      pid = put_provider(base_config())
      put_fake(Map.put(base_fake(), :open_error, true))

      assert {:error, :ldap_error} = Ldap.login(pid, "alice", "s3cret")
    end

    test "a search failure surfaces as a generic LDAP error" do
      pid = put_provider(base_config())
      put_fake(Map.put(base_fake(), :search_error, true))

      assert {:error, :ldap_error} = Ldap.login(pid, "alice", "s3cret")
    end
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
      entries: [entry()]
    }
  end

  defp entry(opts \\ []) do
    %{
      dn: "uid=alice,ou=people,dc=example,dc=com",
      attributes: %{
        "uid" => ["alice"],
        "cn" => [Keyword.get(opts, :cn, "Alice Liddell")],
        "mail" => ["alice@example.com"]
      }
    }
  end

  defp put_fake(scenario), do: Application.put_env(:termelix, :ldap_fake, scenario)

  defp put_provider(config_map, opts \\ []) do
    name = "corp-#{System.unique_integer([:positive])}"

    Repo.insert_all("sso_providers", [
      %{
        name: name,
        type: Keyword.get(opts, :type, "ldap"),
        enabled: Keyword.get(opts, :enabled, 1),
        display_order: 0,
        config: Jason.encode!(config_map)
      }
    ])

    %{id: id} =
      Repo.one(
        from(p in "sso_providers", where: p.name == type(^name, :string), select: %{id: p.id})
      )

    id
  end
end
