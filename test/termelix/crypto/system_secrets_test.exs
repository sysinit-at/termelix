defmodule Termelix.Crypto.SystemSecretsTest do
  @moduledoc """
  Round-trip coverage for instance-level secret sealing: the sealed form is a FieldCrypto
  envelope under the instance key (not base64, not reversible without the key), legacy
  `encoded:`/`encrypted:` base64 wrappers and bare values still open, and a tampered or
  wrong-context envelope raises instead of yielding a value.
  """
  use ExUnit.Case, async: true

  alias Termelix.Crypto.SystemSecrets

  test "seal/2 → open/2 round-trips, and the sealed form is not base64-reversible" do
    sealed = SystemSecrets.seal("topsecret", "client_secret")

    assert SystemSecrets.sealed?(sealed)
    # Not the legacy wrapper, and the plaintext is recoverable only with the instance key.
    refute String.starts_with?(sealed, "encoded:")
    refute String.contains?(sealed, Base.encode64("topsecret"))
    refute String.contains?(sealed, "topsecret")

    assert SystemSecrets.open(sealed, "client_secret") == "topsecret"
  end

  test "open/2 accepts the legacy encoded:/encrypted: base64 wrappers" do
    assert SystemSecrets.open("encoded:" <> Base.encode64("pw"), "bindPassword") == "pw"
    assert SystemSecrets.open("encrypted:" <> Base.encode64("pw"), "bindPassword") == "pw"
    # Unpadded base64 also decodes (the old base64_or fallback); undecodable passes through.
    assert SystemSecrets.open("encoded:" <> Base.encode64("pw", padding: false), "x") == "pw"
    assert SystemSecrets.open("encoded:not-b64!!!", "x") == "encoded:not-b64!!!"
  end

  test "open/2 returns bare values and non-binaries unchanged" do
    assert SystemSecrets.open("plain", "client_secret") == "plain"
    assert SystemSecrets.open(nil, "client_secret") == nil
    assert SystemSecrets.open(42, "client_secret") == 42
  end

  test "seal/2 of empty/nil yields \"\" (FieldCrypto's contract)" do
    assert SystemSecrets.seal("", "client_secret") == ""
    assert SystemSecrets.seal(nil, "client_secret") == ""
  end

  test "a sealed value opened under the wrong field context raises" do
    sealed = SystemSecrets.seal("topsecret", "client_secret")
    assert_raise RuntimeError, fn -> SystemSecrets.open(sealed, "bindPassword") end
  end

  test "a tampered envelope raises rather than returning a value" do
    sealed = SystemSecrets.seal("topsecret", "client_secret")
    tampered = String.replace(sealed, "\"recordId\":\"sso_providers\"", "\"recordId\":\"other\"")

    # Still structurally an envelope — but the record context no longer derives the right key.
    assert SystemSecrets.sealed?(tampered)
    assert_raise RuntimeError, fn -> SystemSecrets.open(tampered, "client_secret") end
  end
end
