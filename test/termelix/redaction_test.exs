defmodule Termelix.RedactionTest do
  @moduledoc """
  Pins the canonical secret-key list and the scrubber Sentry calls with it.

  Sentry's own scrubber matches `"password"`/`"passwd"`/`"secret"` and nothing else, so every
  name below is a name that used to be reported verbatim. The list is spelled out here
  independently of the module under test — dropping one from `Termelix.Redaction` must fail.
  """
  use ExUnit.Case, async: true

  alias Termelix.Crypto.FieldCrypto
  alias Termelix.Redaction

  @filtered "[FILTERED]"
  @sentinel "correct-horse-battery-staple"

  # Encrypted columns (lib/termelix/crypto/field_crypto.ex:19) plus the transport and
  # deployment secrets that never reach the DB.
  @secret_names ~w(
    passwordHash clientSecret totpSecret totpBackupCodes oidcIdentifier
    password key keyPassword sudoPassword autostartPassword autostartKey
    autostartKeyPassword socks5Password privateKey publicKey sshCert
    client_secret bindPassword totp_code temp_token token ticket jwt
    authorization cookie DATABASE_KEY ENCRYPTION_KEY JWT_SECRET
  )

  # Tables of FieldCrypto's @encrypted_fields map. Kept in sync with Redaction's own copy so a
  # newly encrypted field on an existing table can't be redacted in one place and not the other.
  @encrypted_tables ~w(users ssh_data ssh_credentials opkssh_tokens termix_identity_ca
                       vault_tokens)

  describe "secret_key?/1" do
    test "matches every canonical name, in either casing convention" do
      for name <- @secret_names do
        assert Redaction.secret_key?(name), "#{name} is not recognized as a secret"
        assert Redaction.secret_key?(snake(name)), "#{snake(name)} is not recognized as a secret"
        assert Redaction.secret_key?(String.upcase(name))
        assert Redaction.secret_key?(String.to_atom(name))
      end
    end

    test "covers every encrypted field of every table" do
      for table <- @encrypted_tables, field <- FieldCrypto.encrypted_fields(table) do
        assert Redaction.secret_key?(field),
               "#{table}.#{field} is encrypted at rest but would be reported in plaintext"
      end
    end

    test "does not match names that merely contain a secret name" do
      for name <- ~w(keyboard keyType passwordless passwordHint secretary tokenizer
                     username hostname port folder tags) do
        refute Redaction.secret_key?(name), "#{name} must not be treated as a secret"
      end
    end

    test "is false for anything that is not a key" do
      refute Redaction.secret_key?(42)
      refute Redaction.secret_key?(nil)
      refute Redaction.secret_key?(%{})
      refute Redaction.secret_key?(["password"])
    end
  end

  describe "scrub_body/1" do
    test "filters every canonical name at the top level" do
      for name <- @secret_names do
        assert Redaction.scrub_body(%{name => @sentinel}) == %{name => @filtered}
        assert Redaction.scrub_body(%{snake(name) => @sentinel}) == %{snake(name) => @filtered}
      end
    end

    test "filters every canonical name nested under maps and lists" do
      for name <- @secret_names do
        payload = %{
          "hosts" => [
            %{"name" => "web-01", "credentials" => %{name => @sentinel}},
            %{"nested" => [[%{name => @sentinel}]]}
          ]
        }

        refute inspect(Redaction.scrub_body(payload), limit: :infinity) =~ @sentinel
      end
    end

    test "filters atom keys too, since structs and Ecto params carry them" do
      assert Redaction.scrub_body(%{keyPassword: @sentinel, name: "web-01"}) ==
               %{keyPassword: @filtered, name: "web-01"}
    end

    test "filters a whole subtree when the secret's value is a container" do
      assert Redaction.scrub_body(%{"key" => %{"pem" => @sentinel}}) == %{"key" => @filtered}
      assert Redaction.scrub_body(%{"token" => [@sentinel]}) == %{"token" => @filtered}
    end

    test "filters pair lists, where the key lives in the tuple" do
      pairs = [{"authorization", @sentinel}, {"accept", "application/json"}]
      scrubbed = [{"authorization", @filtered}, {"accept", "application/json"}]

      assert Redaction.scrub_body(pairs) == scrubbed
    end

    test "leaves non-secret data untouched" do
      payload = %{
        "username" => "alice",
        "port" => 22,
        "enabled" => true,
        "tags" => ["prod", "eu"],
        "folder" => nil,
        "meta" => %{"osVersion" => "27.0.0"}
      }

      assert Redaction.scrub_body(payload) == payload
    end

    test "does not raise on odd input" do
      assert Redaction.scrub_body(nil) == nil
      assert Redaction.scrub_body("a bare string") == "a bare string"
      assert Redaction.scrub_body(42) == 42
      assert Redaction.scrub_body(%{}) == %{}
      assert Redaction.scrub_body([]) == []
      assert Redaction.scrub_body(:an_atom) == :an_atom
      assert Redaction.scrub_body({:not, :a, :pair}) == {:not, :a, :pair}
    end

    test "scrubs structs as maps rather than passing them through opaquely" do
      assert %{"url" => %{host: "example.com"}} =
               Redaction.scrub_body(%{"url" => URI.parse("https://example.com/x")})
    end

    test "survives deep nesting" do
      nest = fn i, acc -> %{"level#{i}" => [acc]} end
      deep = Enum.reduce(1..200, %{"password" => @sentinel}, nest)
      scrubbed = inspect(Redaction.scrub_body(deep), limit: :infinity)

      refute scrubbed =~ @sentinel
    end
  end

  describe "wiring into Sentry" do
    test "scrubs conn params, which is what PlugContext hands the body scrubber" do
      conn = %Plug.Conn{params: %{"keyPassword" => @sentinel, "username" => "alice"}}

      assert Redaction.scrub_body(conn) == %{"keyPassword" => @filtered, "username" => "alice"}
    end

    test "reports nothing when params were never fetched" do
      conn = %Plug.Conn{params: %Plug.Conn.Unfetched{aspect: :params}}

      assert Redaction.scrub_body(conn) == %{}
    end

    test "the MFA shape used in the endpoint is one this sentry version resolves" do
      scrubber = Sentry.Scrubber.new(body_scrubber: {Redaction, :scrub_body, []})
      conn = %Plug.Conn{params: %{"sudoPassword" => @sentinel}}

      assert scrubber.body_scrubber.(conn) == %{"sudoPassword" => @filtered}
    end

    # Sentry reports request HEADERS as well as body and URL, and its default header scrubber
    # drops only authorization/authentication/cookie. `x-reauth-password` carries an
    # administrator's PLAINTEXT ACCOUNT PASSWORD on the cross-user export, so a 500 anywhere in
    # that request would have shipped it to the error backend.
    test "the x-reauth-password header is scrubbed" do
      conn = %Plug.Conn{
        req_headers: [
          {"content-type", "application/json"},
          {"x-reauth-password", @sentinel},
          {"authorization", @sentinel}
        ]
      }

      scrubbed = Redaction.scrub_headers(conn)

      assert scrubbed["x-reauth-password"] == @filtered
      assert scrubbed["authorization"] == @filtered
      assert scrubbed["content-type"] == "application/json"
      refute scrubbed |> Map.values() |> Enum.any?(&(&1 == @sentinel))
    end

    # Matching is exact on the normalized form, so a compound header name does NOT inherit
    # secrecy from a substring: `x-reauth-password` collapses to `xreauthpassword`, not
    # `password`. It only works because it is listed in full — this pins that.
    test "a compound secret header name must be listed in full, not matched by substring" do
      assert Redaction.secret_key?("x-reauth-password")
      refute Redaction.secret_key?("x-some-other-password-ish-header")
    end

    # Wiring a custom scrubber REPLACES Sentry's default rather than layering on it, so a
    # hand-maintained list can only ever LOSE coverage relative to the library. It already did:
    # `authentication` (header) and `passwd` / `secret` (params) were dropped the moment these
    # scrubbers were wired, silently. Asserting the superset against the library's own constants
    # is what makes that impossible — including after a Sentry upgrade that adds a default.
    test "covers everything Sentry's own defaults would have caught" do
      defaults = Sentry.Scrubber.default_header_keys() ++ Sentry.Scrubber.default_param_keys()

      missed = Enum.reject(defaults, &Redaction.secret_key?/1)

      assert missed == [],
             "replacing Sentry's scrubbers dropped protection for: #{inspect(missed)}"
    end

    test "header scrubbing survives the sentry MFA resolution too" do
      scrubber = Sentry.Scrubber.new(header_scrubber: {Redaction, :scrub_headers, []})
      conn = %Plug.Conn{req_headers: [{"x-reauth-password", @sentinel}]}

      assert scrubber.header_scrubber.(conn) == %{"x-reauth-password" => @filtered}
    end
  end

  # camelCase -> snake_case; the same secret is spelled both ways across the codebase.
  defp snake(name) do
    name |> String.replace(~r/([a-z0-9])([A-Z])/, "\\1_\\2") |> String.downcase()
  end
end
