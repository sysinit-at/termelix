defmodule Termelix.Crypto.HKDF do
  @moduledoc """
  HKDF-SHA256 (RFC 5869), byte-compatible with Node's `crypto.hkdfSync("sha256", …)`.

  Node treats a zero-length salt as `HashLen` (32) zero bytes, matching RFC 5869's
  "if not provided, set to a string of HashLen zeros". We replicate that so keys
  derived here are identical to keys the original Termelix backend derived.
  """
  @hash_len 32

  @doc "Derive `length` bytes of key material from `ikm` using `salt` and `info`."
  @spec derive(binary(), binary(), binary(), pos_integer()) :: binary()
  def derive(ikm, salt, info, length) do
    salt = if byte_size(salt) == 0, do: <<0::size(@hash_len)-unit(8)>>, else: salt
    prk = :crypto.mac(:hmac, :sha256, salt, ikm)
    expand(prk, info, length)
  end

  defp expand(prk, info, length) do
    blocks = div(length + @hash_len - 1, @hash_len)

    {okm, _last} =
      Enum.reduce(1..blocks, {<<>>, <<>>}, fn i, {acc, prev} ->
        t = :crypto.mac(:hmac, :sha256, prk, <<prev::binary, info::binary, i::8>>)
        {acc <> t, t}
      end)

    binary_part(okm, 0, length)
  end
end
