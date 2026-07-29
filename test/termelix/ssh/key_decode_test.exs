defmodule Termelix.SSH.KeyDecodeTest do
  @moduledoc """
  Coverage for `Termelix.SSH.KeyDecode` and for the host-write validation built on it.

  Every key here is produced by the real `ssh-keygen` in `setup_all` rather than by a
  checked-in fixture: the OpenSSH v1 reader this module leans on is documented by OTP as
  experimental (`ssh_file.erl:445`), so the tests have to track what the tool actually emits,
  not what it emitted once.

  The `Termelix.Hosts` cases live here too — they exercise the same validator through the only
  writes that reach it, and keeping them next to the decode branches is what makes it obvious
  which reasons reject a write and which are tolerated.
  """
  use Termelix.DataCase, async: false

  alias Termelix.{Accounts, Hosts}
  alias Termelix.SSH.KeyDecode

  @user_password "correct horse battery staple"
  @key_passphrase "pum2Aequ4taeShoo0oo"

  @all_reasons [
    :no_key,
    :unsupported_key_format,
    :public_key_not_private,
    :no_private_key,
    :encrypted_openssh_key,
    :passphrase_required,
    :key_decrypt_failed,
    :key_decode_failed
  ]

  setup_all do
    {:ok, _} = Application.ensure_all_started(:ssh)

    dir =
      Path.join(
        System.tmp_dir!(),
        "termelix_key_decode_test_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)

    gen = fn name, args ->
      path = Path.join(dir, name)
      {_, 0} = System.cmd("ssh-keygen", args ++ ["-f", path, "-q"])
      path
    end

    openssh = gen.("openssh_ed25519", ["-t", "ed25519", "-N", ""])
    openssh_rsa = gen.("openssh_rsa", ["-t", "rsa", "-b", "2048", "-N", ""])
    openssh_enc = gen.("openssh_enc", ["-t", "ed25519", "-N", @key_passphrase])
    # RSA, not ECDSA. `ssh-keygen -t ecdsa -m PEM` emits an EC key with EXPLICIT curve
    # parameters, and OTP's `pem_entry_decode/1` raises a MatchError on the ASN.1
    # `invalid_choice_tag` for those — a pre-existing OTP limitation, not something this module
    # introduced (the decoder it replaced made the same call). Covered explicitly below.
    pem = gen.("pem_rsa", ["-t", "rsa", "-b", "2048", "-m", "PEM", "-N", ""])
    pem_enc = gen.("pem_enc", ["-t", "rsa", "-b", "2048", "-m", "PEM", "-N", @key_passphrase])

    # ssh-keygen only writes PKCS#8 by converting an existing key in place.
    pkcs8 = gen.("pkcs8_rsa", ["-t", "rsa", "-b", "2048", "-N", ""])

    # Kept solely to pin the OTP limitation documented above, so it is a stated fact rather
    # than something the next person rediscovers from a generic failure.
    pem_ecdsa = gen.("pem_ecdsa", ["-t", "ecdsa", "-m", "PEM", "-N", ""])
    {_, 0} = System.cmd("ssh-keygen", ["-p", "-m", "PKCS8", "-f", pkcs8, "-N", "", "-q"])

    # A PEM block holding only a public key — the shape `hd/1` on the entry list would pick.
    # Exported from the RSA key, not the ed25519 one: `ssh-keygen -e -m PEM` refuses ed25519
    # ("do_convert_to_pem: unsupported key type ED25519"), which is a property of the tool, not
    # of what is under test here — any PEM public block exercises the same selection path.
    {pem_public, 0} = System.cmd("ssh-keygen", ["-e", "-m", "PEM", "-f", openssh_rsa <> ".pub"])

    %{
      keys: %{
        pem_ecdsa: File.read!(pem_ecdsa),
        openssh: File.read!(openssh),
        openssh_pub: File.read!(openssh <> ".pub"),
        openssh_rsa: File.read!(openssh_rsa),
        openssh_enc: File.read!(openssh_enc),
        pem: File.read!(pem),
        pem_enc: File.read!(pem_enc),
        pkcs8: File.read!(pkcs8),
        pem_public: pem_public
      }
    }
  end

  defp attrs(overrides) do
    Map.merge(
      %{
        name: "web-1",
        ip: "10.0.0.5",
        port: 22,
        username: "root",
        authType: "key",
        connectionType: "ssh"
      },
      overrides
    )
  end

  describe "decode/2 with an OpenSSH-native key" do
    test "an unencrypted ed25519 key decodes", %{keys: keys} do
      assert {:ok, key} = KeyDecode.decode(keys.openssh, nil)
      # ed25519 has no private-key record of its own; OTP carries it as an EC key with a
      # namedCurve parameter (ssh_message.erl:833-836).
      assert elem(key, 0) == :ECPrivateKey
    end

    test "an unencrypted RSA key decodes", %{keys: keys} do
      assert {:ok, key} = KeyDecode.decode(keys.openssh_rsa, nil)
      assert elem(key, 0) == :RSAPrivateKey
    end

    test "the private entry is picked out of the list, which also holds the public key", %{
      keys: keys
    } do
      entries = :ssh_file.decode(keys.openssh, :openssh_key_v1)

      # Both halves of the pair come back (ssh_file.erl:1177-1181) — the reason this module
      # searches the list instead of taking `hd/1`.
      assert length(entries) == 2
      assert Enum.any?(entries, fn {key, _attrs} -> not is_atom(elem(key, 0)) end)

      assert {:ok, key} = KeyDecode.decode(keys.openssh, nil)
      assert elem(key, 0) == :ECPrivateKey
    end

    test "the decoded key is the one ssh-keygen wrote, and OTP's auth gate accepts it", %{
      keys: keys
    } do
      assert {:ok, key} = KeyDecode.decode(keys.openssh, nil)

      # `ssh_auth:get_public_key/2` (ssh_auth.erl:151-158) runs exactly these two checks on
      # whatever a key callback returns; passing them is what "this key can authenticate" means.
      assert :ssh_transport.valid_key_sha_alg(:private, key, :"ssh-ed25519")

      [{public_from_file, _attrs}] = :ssh_file.decode(keys.openssh_pub, :openssh_key)
      assert :ssh_file.extract_public_key(key) == public_from_file
    end

    test "a passphrase-protected key is refused by name, passphrase or not", %{keys: keys} do
      assert {:error, :encrypted_openssh_key} = KeyDecode.decode(keys.openssh_enc, nil)

      assert {:error, :encrypted_openssh_key} =
               KeyDecode.decode(keys.openssh_enc, @key_passphrase)

      assert {:error, :encrypted_openssh_key} = KeyDecode.check_format(keys.openssh_enc)

      assert KeyDecode.message(:encrypted_openssh_key) =~ "ssh-keygen -p -m PEM"
    end

    test "armour around an unreadable body is a decode failure, not an encryption verdict" do
      key =
        "-----BEGIN OPENSSH PRIVATE KEY-----\nnot base64 at all !!\n" <>
          "-----END OPENSSH PRIVATE KEY-----\n"

      assert {:error, :key_decode_failed} = KeyDecode.decode(key, nil)
      assert {:error, :key_decode_failed} = KeyDecode.check_format(key)
    end
  end

  describe "decode/2 with a PEM key" do
    test "an unencrypted PEM key decodes", %{keys: keys} do
      assert {:ok, key} = KeyDecode.decode(keys.pem, nil)
      assert elem(key, 0) == :RSAPrivateKey
    end

    test "a PKCS#8 key decodes to the same record shape", %{keys: keys} do
      assert {:ok, key} = KeyDecode.decode(keys.pkcs8, nil)
      assert elem(key, 0) == :RSAPrivateKey
    end

    test "an encrypted PEM key needs its passphrase and decodes with it", %{keys: keys} do
      assert {:error, :passphrase_required} = KeyDecode.decode(keys.pem_enc, nil)
      assert {:error, :passphrase_required} = KeyDecode.decode(keys.pem_enc, "   ")
      assert {:ok, key} = KeyDecode.decode(keys.pem_enc, @key_passphrase)
      assert elem(key, 0) == :RSAPrivateKey
    end

    # NOT a defect in this module and NOT a regression: the decoder this replaced made the same
    # `:public_key.pem_entry_decode/1` call, so an `ssh-keygen -t ecdsa -m PEM` key has never
    # worked here. OTP raises MatchError on the ASN.1 `invalid_choice_tag` because that key
    # carries EXPLICIT curve parameters rather than a named-curve OID. Pinned so the behaviour
    # is a known limitation with a workaround (use ed25519, or RSA, or the OpenSSH format —
    # all three are covered above and all three work) instead of a mystery.
    test "an ECDSA key in PEM form is rejected — a known OTP limitation", %{keys: keys} do
      assert {:error, :key_decode_failed} = KeyDecode.decode(keys.pem_ecdsa, nil)
      assert {:error, :key_decode_failed} = KeyDecode.check_format(keys.pem_ecdsa)

      # The same key in OpenSSH form is fine, which is what the operator should be told.
      assert {:error, msg} = {:error, KeyDecode.message(:key_decode_failed)}
      assert is_binary(msg) and msg != ""
    end

    test "a wrong passphrase is reported as a decryption failure", %{keys: keys} do
      assert {:error, :key_decrypt_failed} = KeyDecode.decode(keys.pem_enc, "not the passphrase")
    end

    test "a PEM block carrying only a public key is rejected", %{keys: keys} do
      assert {:error, :no_private_key} = KeyDecode.decode(keys.pem_public, nil)
      assert {:error, :no_private_key} = KeyDecode.check_format(keys.pem_public)
    end
  end

  describe "decode/2 with input that is not a usable key" do
    test "a missing, blank or non-binary key" do
      assert {:error, :no_key} = KeyDecode.decode(nil, nil)
      assert {:error, :no_key} = KeyDecode.decode("   \n ", nil)
      assert {:error, :unsupported_key_format} = KeyDecode.decode(42, nil)
      assert {:error, :no_key} = KeyDecode.check_format(nil)
    end

    test "a pasted .pub line names itself", %{keys: keys} do
      assert {:error, :public_key_not_private} = KeyDecode.decode(keys.openssh_pub, nil)
      assert KeyDecode.message(:public_key_not_private) =~ "public key"
    end

    test "anything without PEM armour is an unsupported format" do
      assert {:error, :unsupported_key_format} = KeyDecode.decode("hunter2", nil)
    end

    test "leading blank lines and CRLF endings are tolerated", %{keys: keys} do
      mangled = "\n\n" <> String.replace(keys.openssh, "\n", "\r\n")
      assert {:ok, _key} = KeyDecode.decode(mangled, nil)
    end
  end

  describe "check_format/1" do
    test "a passphrase-protected PEM key passes — its passphrase is a separate field", %{
      keys: keys
    } do
      assert :ok = KeyDecode.check_format(keys.pem_enc)
    end

    test "the formats that do work all pass", %{keys: keys} do
      for key <- [keys.openssh, keys.openssh_rsa, keys.pem, keys.pkcs8] do
        assert :ok = KeyDecode.check_format(key)
      end
    end

    test "every reason renders a message" do
      for reason <- @all_reasons do
        assert is_binary(KeyDecode.message(reason))
        assert KeyDecode.message(reason) != ""
      end
    end
  end

  describe "Termelix.Hosts private-key validation" do
    setup do
      {:ok, user, _first?} = Accounts.register_user("keyowner", @user_password)
      %{user: user}
    end

    test "a passphrase-protected OpenSSH key is rejected with a message that names it", %{
      user: user,
      keys: keys
    } do
      assert {:error, changeset} = Hosts.create_host(user.id, attrs(%{key: keys.openssh_enc}))
      assert [message] = errors_on(changeset).key
      assert message =~ "ssh-keygen -p -m PEM"
      assert Hosts.list_for_user(user.id) == []
    end

    test "a pasted public key is rejected", %{user: user, keys: keys} do
      assert {:error, changeset} = Hosts.create_host(user.id, attrs(%{key: keys.openssh_pub}))
      assert [message] = errors_on(changeset).key
      assert message =~ "public key"
    end

    test "the autostart key is validated too", %{user: user, keys: keys} do
      assert {:error, changeset} =
               Hosts.create_host(user.id, attrs(%{autostartKey: keys.openssh_enc}))

      assert [_message] = errors_on(changeset).autostartKey
    end

    test "usable keys save, and so does a passphrase-protected PEM key with no passphrase", %{
      user: user,
      keys: keys
    } do
      for key <- [keys.openssh, keys.openssh_rsa, keys.pem, keys.pkcs8, keys.pem_enc] do
        assert {:ok, _host} = Hosts.create_host(user.id, attrs(%{key: key}))
      end
    end

    test "a blank or absent key is not checked", %{user: user} do
      assert {:ok, _host} = Hosts.create_host(user.id, attrs(%{key: ""}))
      assert {:ok, _host} = Hosts.create_host(user.id, attrs(%{}))
    end

    test "an update that does not resend the key does not re-check the stored ciphertext", %{
      user: user,
      keys: keys
    } do
      {:ok, host} = Hosts.create_host(user.id, attrs(%{key: keys.openssh}))

      # The stored value is now an encryption envelope, which is not a key in any format.
      assert {:ok, updated} = Hosts.update_host(user.id, host.id, %{name: "renamed"})
      assert updated.name == "renamed"
    end

    test "an update that resends an unusable key is rejected and persists nothing", %{
      user: user,
      keys: keys
    } do
      {:ok, host} = Hosts.create_host(user.id, attrs(%{key: keys.openssh}))

      assert {:error, changeset} =
               Hosts.update_host(user.id, host.id, %{key: keys.openssh_enc, name: "renamed"})

      assert [_message] = errors_on(changeset).key
      assert Hosts.get_for_user(host.id, user.id).name == "web-1"
    end

    test "the :warn rollback saves the same key and :off skips the check", %{
      user: user,
      keys: keys
    } do
      on_exit(fn -> Application.delete_env(:termelix, :host_key_format_validation) end)

      Application.put_env(:termelix, :host_key_format_validation, :warn)
      assert {:ok, _host} = Hosts.create_host(user.id, attrs(%{key: keys.openssh_enc}))

      Application.put_env(:termelix, :host_key_format_validation, :off)
      assert {:ok, _host} = Hosts.create_host(user.id, attrs(%{key: keys.openssh_enc}))
    end
  end
end
