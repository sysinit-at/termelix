defmodule Termelix.CredentialsTest do
  @moduledoc """
  Context-level coverage for `Termelix.Credentials`: changeset validation and the
  `decrypt: false` listing variant (secrets stay enveloped, `publicKey` — the one listed
  field that reaches the wire — is still decrypted, so the wire projection is identical).
  """
  use Termelix.DataCase, async: false

  alias Termelix.{Accounts, Credentials}

  @password "correct horse battery staple"

  setup do
    {:ok, user, _first?} = Accounts.register_user("alice", @password)
    %{user: user}
  end

  describe "create_credential/2" do
    test "changeset-invalid attrs return an error changeset and insert nothing", %{user: user} do
      assert {:error, %Ecto.Changeset{}} =
               Credentials.create_credential(user.id, %{name: nil, authType: "password"})

      assert Credentials.list_for_user(user.id) == []
    end
  end

  describe "list_for_user/2 with decrypt: false" do
    test "secrets stay enveloped, publicKey decrypts, wire projection is identical", %{
      user: user
    } do
      {:ok, _cred} =
        Credentials.create_credential(user.id, %{
          name: "deploy",
          description: "d",
          folder: nil,
          tags: "a,b",
          authType: "key",
          username: "root",
          password: nil,
          key: "PRIVATE",
          privateKey: "PRIVATE",
          publicKey: "ssh-ed25519 AAAA comment",
          keyPassword: "kp",
          keyType: nil,
          detectedKeyType: nil,
          certPublicKey: nil,
          usageCount: 0,
          lastUsed: nil
        })

      [dec] = Credentials.list_for_user(user.id)
      [raw] = Credentials.list_for_user(user.id, decrypt: false)

      # Secret fields are decrypted only in the default listing.
      assert dec.privateKey == "PRIVATE"
      assert raw.privateKey != "PRIVATE"
      assert String.starts_with?(raw.privateKey, "{")

      # publicKey reaches the list wire shape, so it is decrypted in both variants.
      assert dec.publicKey == "ssh-ed25519 AAAA comment"
      assert raw.publicKey == "ssh-ed25519 AAAA comment"

      wire_fields = [
        :id,
        :name,
        :description,
        :folder,
        :tags,
        :authType,
        :username,
        :publicKey,
        :certPublicKey,
        :keyType,
        :detectedKeyType,
        :usageCount,
        :lastUsed,
        :createdAt,
        :updatedAt
      ]

      assert Map.take(raw, wire_fields) == Map.take(dec, wire_fields)
    end
  end
end
