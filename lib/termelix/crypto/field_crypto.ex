defmodule Termelix.Crypto.FieldCrypto do
  @moduledoc """
  Per-field encryption, byte-compatible with the original Termix `field-crypto.ts`.

  Each secret field is encrypted with AES-256-GCM under a field-specific key
  `HKDF-SHA256(masterKey, salt, "<recordId>:<fieldName>")`, where `salt` is a fresh
  random 32 bytes and `masterKey` is the owning user's DEK. The stored value is a JSON
  string `{"data","iv","tag","salt","recordId"}` with hex-encoded byte fields.
  """
  alias Termelix.Crypto.HKDF

  @key_length 32
  @iv_length 16
  @salt_length 32

  # Mirrors ENCRYPTED_FIELDS in field-crypto.ts: table -> set of field names that
  # are stored encrypted. Field names are the *schema.ts* camelCase keys, which the
  # Ecto schemas reuse as struct field atoms.
  @encrypted_fields %{
    "users" => ~w(passwordHash clientSecret totpSecret totpBackupCodes oidcIdentifier),
    "ssh_data" => ~w(password key keyPassword sudoPassword autostartPassword autostartKey
         autostartKeyPassword socks5Password),
    "ssh_credentials" => ~w(password privateKey keyPassword key publicKey),
    "opkssh_tokens" => ~w(sshCert privateKey),
    "termix_identity_ca" => ~w(privateKey),
    "vault_tokens" => ~w(sshCert privateKey)
  }

  @doc "Whether `field` of `table` is stored encrypted."
  @spec should_encrypt_field?(String.t(), String.t() | atom()) :: boolean()
  def should_encrypt_field?(table, field) do
    case Map.fetch(@encrypted_fields, table) do
      {:ok, fields} -> to_string(field) in fields
      :error -> false
    end
  end

  @doc "Encrypted field names for a table (as strings)."
  @spec encrypted_fields(String.t()) :: [String.t()]
  def encrypted_fields(table), do: Map.get(@encrypted_fields, table, [])

  @doc """
  Encrypt `plaintext` into the JSON envelope. Empty/nil plaintext yields `""`,
  matching the original's `if (!plaintext) return ""`.
  """
  @spec encrypt_field(binary() | nil, binary(), any(), String.t() | atom()) :: String.t()
  def encrypt_field(plaintext, _master_key, _record_id, _field_name)
      when plaintext in [nil, ""],
      do: ""

  def encrypt_field(plaintext, master_key, record_id, field_name) do
    salt = :crypto.strong_rand_bytes(@salt_length)
    context = "#{record_id}:#{field_name}"
    field_key = HKDF.derive(master_key, salt, context, @key_length)
    iv = :crypto.strong_rand_bytes(@iv_length)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, field_key, iv, to_string(plaintext), <<>>, true)

    Jason.encode!(%{
      "data" => hex(ciphertext),
      "iv" => hex(iv),
      "tag" => hex(tag),
      "salt" => hex(salt),
      "recordId" => to_string(record_id)
    })
  end

  @doc """
  Decrypt a JSON envelope produced by `encrypt_field/4` (or the original backend).
  Empty/nil input yields `""`. Raises on tampering or a missing recordId context.
  """
  @spec decrypt_field(binary() | nil, binary(), any(), String.t() | atom()) :: String.t()
  def decrypt_field(encrypted_value, _master_key, _record_id, _field_name)
      when encrypted_value in [nil, ""],
      do: ""

  def decrypt_field(encrypted_value, master_key, _record_id, field_name) do
    enc = Jason.decode!(encrypted_value)

    record_id =
      case enc["recordId"] do
        nil ->
          raise "Encrypted field missing recordId context - data corruption or legacy format not supported"

        rid ->
          rid
      end

    context = "#{record_id}:#{field_name}"
    field_key = HKDF.derive(master_key, unhex(enc["salt"]), context, @key_length)

    :crypto.crypto_one_time_aead(
      :aes_256_gcm,
      field_key,
      unhex(enc["iv"]),
      unhex(enc["data"]),
      <<>>,
      unhex(enc["tag"]),
      false
    )
    |> case do
      :error -> raise "Field decryption failed (auth tag mismatch)"
      plaintext -> plaintext
    end
  end

  @doc """
  Whether `value` is one of our envelopes rather than legacy plaintext — cheaply, without a
  key.

  Decryption is deliberately *graceful*: `DataCrypto.safe_decrypt/4` hands back anything it
  cannot open, which is what lets pre-encryption rows keep working. The cost is that a caller
  holding a failed decryption cannot tell it apart from a value that was never encrypted, and
  one caller must: the SSH path, which would otherwise hand a JSON envelope to a real sshd as
  a password. `Termelix.Hosts.fetch_for_connect/2` asks this so it can refuse instead.

  Structural, not just "looks like JSON": all four hex fields must be present, because a host
  whose password is genuinely the string `{}` must not be mistaken for a locked secret.
  """
  @spec envelope?(term()) :: boolean()
  def envelope?(value) when is_binary(value) and byte_size(value) > 1 do
    case Jason.decode(value) do
      {:ok, %{"data" => d, "iv" => i, "tag" => t, "salt" => s}} ->
        Enum.all?([d, i, t, s], &is_binary/1)

      _ ->
        false
    end
  end

  def envelope?(_value), do: false

  defp hex(bin), do: Base.encode16(bin, case: :lower)
  defp unhex(str), do: Base.decode16!(str, case: :mixed)
end
