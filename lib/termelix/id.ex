defmodule Termelix.Id do
  @moduledoc """
  URL-safe random identifiers, matching the *shape* of the original's `nanoid()` ids
  (21 chars, URL-safe alphabet). Termelix treats user/session ids as opaque strings, so an
  independent generator is fine — existing ids from an imported database remain valid as
  plain TEXT keys.
  """
  # 64-symbol URL-safe alphabet (A-Za-z0-9_-), so 6 bits per character with no bias.
  # A tuple: `elem/2` is O(1), unlike `Enum.at/2` on a charlist.
  @alphabet ~c"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
            |> List.to_tuple()
  @default_size 21

  @doc "Generate a URL-safe id of `size` characters (default 21)."
  @spec generate(pos_integer()) :: String.t()
  def generate(size \\ @default_size) do
    alphabet = @alphabet

    :crypto.strong_rand_bytes(size)
    |> :binary.bin_to_list()
    |> Enum.map(fn byte -> elem(alphabet, Bitwise.band(byte, 63)) end)
    |> List.to_string()
  end
end
