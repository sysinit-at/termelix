defmodule Termelix.Crypto.SystemSecrets do
  @moduledoc """
  Instance-level secret sealing, for values that have no owning user DEK.

  Per-user credentials are sealed under that user's DEK (`Termelix.Crypto.FieldCrypto` with
  the DEK as master key). Instance-wide rows have no user context — the provider configs in
  `sso_providers.config` hold an OIDC `client_secret` / LDAP `bindPassword` used by the whole
  deployment, and previously stored them as plain base64, reversible by anyone holding the
  database file. They are now sealed with the same FieldCrypto envelope (AES-256-GCM under
  HKDF-SHA256) but keyed with the instance master key — `SystemCrypto.encryption_key/0`, the
  `ENCRYPTION_KEY` root secret from `<DATA_DIR>/.env` — and a fixed `sso_providers` record
  context that binds each ciphertext to its config field.

  Readers stay backward compatible: `open/2` accepts the sealed envelope AND the legacy
  `encoded:` / `encrypted:` base64 wrappers, and returns bare values unchanged. Writers only
  ever produce the sealed form (`seal/2`); legacy values are upgraded the next time the
  config is written.
  """

  alias Termelix.Crypto.{FieldCrypto, SystemCrypto}

  @record_id "sso_providers"

  @doc """
  Seal `plaintext` for the provider-config `field` (`"client_secret"` / `"bindPassword"`),
  returning the FieldCrypto JSON envelope. Empty/nil plaintext yields `""`, exactly as
  `FieldCrypto.encrypt_field/4`.
  """
  @spec seal(binary() | nil, String.t()) :: String.t()
  def seal(plaintext, field) do
    FieldCrypto.encrypt_field(plaintext, SystemCrypto.encryption_key(), @record_id, field)
  end

  @doc "Whether `value` is a sealed envelope (cheap, keyless, structural check)."
  @spec sealed?(term()) :: boolean()
  def sealed?(value), do: FieldCrypto.envelope?(value)

  @doc """
  Open a stored provider-config secret for `field`:

    * a sealed envelope → the plaintext (raises on tamper or wrong instance key, as
      `FieldCrypto.decrypt_field/4` does);
    * a legacy `encoded:` / `encrypted:` base64 wrapper → the decoded value (an undecodable
      wrapper comes back unchanged, the historical `base64_or` behaviour);
    * anything else (bare plaintext, non-binary) → unchanged.
  """
  @spec open(term(), String.t()) :: term()
  def open("encoded:" <> b64 = original, _field), do: base64_or(b64, original)
  def open("encrypted:" <> b64 = original, _field), do: base64_or(b64, original)

  def open(value, field) when is_binary(value) do
    if sealed?(value) do
      FieldCrypto.decrypt_field(value, SystemCrypto.encryption_key(), @record_id, field)
    else
      value
    end
  end

  def open(value, _field), do: value

  defp base64_or(b64, original) do
    case Base.decode64(b64) do
      {:ok, bin} ->
        bin

      :error ->
        case Base.decode64(b64, padding: false) do
          {:ok, bin} -> bin
          :error -> original
        end
    end
  end
end
