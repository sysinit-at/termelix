defmodule Termelix.Crypto.DekWrap do
  @moduledoc """
  Pure DEK wrap/unwrap (v3), byte-compatible with `user-keys.ts`.

  A 32-byte DEK is sealed with AES-256-GCM under
  `HKDF-SHA256(masterKey, salt=∅, info="termix:dek-wrap:v3:<userId>")`, with the userId as
  additional authenticated data. Serialized as a map with base64 byte fields.
  """
  alias Termelix.Crypto.HKDF

  @dek_length 32
  @wrap_version 3
  @wrap_algorithm "aes-256-gcm"
  @wrap_info_prefix "termix:dek-wrap:v3:"

  @doc "Seal `dek` for `user_id`, returning the JSON-serializable wrap map."
  @spec wrap(binary(), String.t(), binary()) :: map()
  def wrap(master_key, user_id, dek) do
    wrap_key = derive_wrap_key(master_key, user_id)
    iv = :crypto.strong_rand_bytes(12)
    {ct, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, wrap_key, iv, dek, user_id, true)

    %{
      "v" => @wrap_version,
      "alg" => @wrap_algorithm,
      "iv" => Base.encode64(iv),
      "ct" => Base.encode64(ct),
      "tag" => Base.encode64(tag),
      "createdAt" => DateTime.utc_now() |> DateTime.to_iso8601()
    }
  end

  @doc "Unseal a wrap produced by `wrap/3` (from a raw JSON string). Raises on tampering."
  @spec unwrap(binary(), String.t(), String.t()) :: binary()
  def unwrap(master_key, user_id, raw) when is_binary(raw) do
    unwrap(master_key, user_id, Jason.decode!(raw))
  end

  @spec unwrap(binary(), String.t(), map()) :: binary()
  def unwrap(master_key, user_id, %{} = wrapped) do
    if wrapped["v"] != @wrap_version or wrapped["alg"] != @wrap_algorithm do
      raise "Unsupported key wrap (v=#{wrapped["v"]}, alg=#{wrapped["alg"]}) for user #{user_id}"
    end

    wrap_key = derive_wrap_key(master_key, user_id)

    case :crypto.crypto_one_time_aead(
           :aes_256_gcm,
           wrap_key,
           Base.decode64!(wrapped["iv"]),
           Base.decode64!(wrapped["ct"]),
           user_id,
           Base.decode64!(wrapped["tag"]),
           false
         ) do
      :error -> raise "DEK unwrap failed (auth tag mismatch) for user #{user_id}"
      dek -> dek
    end
  end

  defp derive_wrap_key(master_key, user_id) do
    HKDF.derive(master_key, <<>>, "#{@wrap_info_prefix}#{user_id}", @dek_length)
  end
end
