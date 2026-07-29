defmodule Termelix.Crypto.CompatTest do
  @moduledoc """
  Proves the Elixir crypto core is byte-compatible with the original Node backend.

  The field envelope and wrapped DEK below were produced by Node's `crypto` using the
  exact algorithms from `field-crypto.ts` / `user-keys.ts` (see scratchpad/gen_vectors.cjs).
  Decrypting them here confirms HKDF, AES-256-GCM, hex/base64, and AAD all match.
  """
  use ExUnit.Case, async: true

  alias Termelix.Crypto.{HKDF, FieldCrypto, DekWrap}

  @master_key Base.decode16!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                case: :lower
              )

  test "HKDF-SHA256 matches RFC 5869 test case 1" do
    ikm = :binary.copy(<<0x0B>>, 22)
    salt = Base.decode16!("000102030405060708090a0b0c", case: :lower)
    info = Base.decode16!("f0f1f2f3f4f5f6f7f8f9", case: :lower)

    expected =
      Base.decode16!(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        case: :lower
      )

    assert HKDF.derive(ikm, salt, info, 42) == expected
  end

  test "HKDF matches Node with an empty salt (zero-fill behaviour)" do
    # Node hkdfSync with Buffer.alloc(0) salt == HMAC key of 32 zero bytes.
    ikm = "some-master-key-bytes"
    info = "termix:dek-wrap:v3:user-abc123"
    zero_salt = <<0::size(32)-unit(8)>>
    assert HKDF.derive(ikm, <<>>, info, 32) == HKDF.derive(ikm, zero_salt, info, 32)
  end

  test "decrypts a field envelope produced by Node" do
    envelope =
      ~s({"data":"3a80caefcc8c071179d5a4ea96c200d6eca048c2","iv":"17cd25977a95fb293b797897673262ff","tag":"907cd7fbe2ddb1a31a18fc82bf3ac4ad","salt":"96b97920f9e4f56674f8ab755cfa9596edcd0d038be292cb321368c0485c3d9e","recordId":"42"})

    assert FieldCrypto.decrypt_field(envelope, @master_key, "42", "password") ==
             "s3cr3t-password-éà"
  end

  test "field encrypt/decrypt round-trips" do
    plaintext = "hunter2 🔐 with unicode"
    envelope = FieldCrypto.encrypt_field(plaintext, @master_key, "99", "sudoPassword")
    assert FieldCrypto.decrypt_field(envelope, @master_key, "99", "sudoPassword") == plaintext
  end

  test "empty/nil field values behave like the original (return empty string)" do
    assert FieldCrypto.encrypt_field("", @master_key, "1", "password") == ""
    assert FieldCrypto.encrypt_field(nil, @master_key, "1", "password") == ""
    assert FieldCrypto.decrypt_field("", @master_key, "1", "password") == ""
    assert FieldCrypto.decrypt_field(nil, @master_key, "1", "password") == ""
  end

  test "unwraps a DEK wrapped by Node (v3)" do
    wrapped = %{
      "v" => 3,
      "alg" => "aes-256-gcm",
      "iv" => "ppl6ThmpdDJaQazI",
      "ct" => "1fatsA87YoHqEQbgtTmN6EoCRYMNpTnE7IA5ASEpei8=",
      "tag" => "rpgROdSHGtPpEvmJ+urVxQ=="
    }

    expected_dek =
      Base.decode16!("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        case: :lower
      )

    assert DekWrap.unwrap(@master_key, "user-abc123", Jason.encode!(wrapped)) == expected_dek
  end

  test "DEK wrap/unwrap round-trips and rejects tampering" do
    dek = :crypto.strong_rand_bytes(32)
    wrapped = DekWrap.wrap(@master_key, "user-xyz", dek)
    assert DekWrap.unwrap(@master_key, "user-xyz", wrapped) == dek

    # Wrong userId (AAD) must fail authentication.
    assert_raise RuntimeError, fn -> DekWrap.unwrap(@master_key, "someone-else", wrapped) end
  end
end
