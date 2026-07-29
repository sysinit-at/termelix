defmodule Termelix.Crypto.DataCrypto do
  @moduledoc """
  Record-level encryption glue, mirroring `data-crypto.ts`.

  Ecto schemas use the original schema.ts camelCase field names as struct keys (with a
  snake_case `source:` column), so the same field-name set that drives `FieldCrypto`'s
  encrypted-field map applies directly here. Decryption is *lazy/graceful*: a field that
  is not a valid encryption envelope (e.g. legacy plaintext) is returned unchanged, as
  the original `LazyFieldEncryption.safeGetFieldValue` does.
  """
  require Logger
  alias Termelix.Crypto.{FieldCrypto, UserKeyManager}

  @doc "Decrypt every encrypted field of `record` (a struct/map) for the given table + DEK."
  @spec decrypt_record(String.t(), map(), binary()) :: map()
  def decrypt_record(table, record, dek) when is_map(record) do
    record_id = to_string(fetch(record, :id))

    Enum.reduce(FieldCrypto.encrypted_fields(table), record, fn field_str, acc ->
      case field_atom(field_str) do
        nil ->
          acc

        field ->
          case fetch(acc, field) do
            value when is_binary(value) and value != "" ->
              put(acc, field, safe_decrypt(value, dek, record_id, field_str))

            _ ->
              acc
          end
      end
    end)
  end

  @doc "Decrypt a list of records."
  @spec decrypt_records(String.t(), [map()], binary()) :: [map()]
  def decrypt_records(table, records, dek) when is_list(records),
    do: Enum.map(records, &decrypt_record(table, &1, dek))

  @doc "Encrypt every encrypted field of `attrs` (a map) for the given table + DEK."
  @spec encrypt_record(String.t(), map(), any(), binary()) :: map()
  def encrypt_record(table, attrs, record_id, dek) when is_map(attrs) do
    rid = to_string(record_id)

    Enum.reduce(FieldCrypto.encrypted_fields(table), attrs, fn field_str, acc ->
      case field_atom(field_str) do
        nil ->
          acc

        field ->
          case fetch(acc, field) do
            value when is_binary(value) and value != "" ->
              put(acc, field, FieldCrypto.encrypt_field(value, dek, rid, field_str))

            _ ->
              acc
          end
      end
    end)
  end

  # Field names come from FieldCrypto's static @encrypted_fields list, so no
  # attacker-controlled atoms are created. A configured name that has no schema
  # field anywhere (atom never loaded, e.g. "sshCert" today) simply has nothing
  # to convert and is skipped — same outcome as the previous Map.get miss.
  defp field_atom(field_str) do
    String.to_existing_atom(field_str)
  rescue
    ArgumentError -> nil
  end

  @doc "Fetch and decrypt a single user's record via their DEK (raises if DEK unavailable)."
  @spec decrypt_record_for_user(String.t(), map(), String.t()) :: map()
  def decrypt_record_for_user(table, record, user_id) do
    decrypt_record(table, record, UserKeyManager.get_user_dek(user_id))
  end

  defp safe_decrypt(value, dek, record_id, field_str) do
    if String.starts_with?(value, "{") do
      try do
        FieldCrypto.decrypt_field(value, dek, record_id, field_str)
      rescue
        error ->
          Logger.warning("Field decrypt failed for #{field_str}: #{Exception.message(error)}")
          value
      end
    else
      # Not an envelope — treat as legacy plaintext and return unchanged.
      value
    end
  end

  defp fetch(map, key) when is_map(map), do: Map.get(map, key)
  defp put(map, key, value) when is_map(map), do: Map.put(map, key, value)
end
