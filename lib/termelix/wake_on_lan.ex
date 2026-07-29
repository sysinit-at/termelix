defmodule Termelix.WakeOnLan do
  @moduledoc """
  Builds and sends Wake-on-LAN magic packets. Port of `src/backend/utils/wake-on-lan.ts`.

  A magic packet is six `0xFF` bytes followed by the target MAC repeated sixteen times
  (102 bytes total), sent as a UDP broadcast to port 9. There is no reply, so a successful
  send only means the datagram left this host.
  """

  @mac_regex ~r/^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/
  @default_broadcast "255.255.255.255"
  @wol_port 9

  @doc "True when `mac` is six colon- or dash-separated hex octets."
  @spec valid_mac?(term()) :: boolean()
  def valid_mac?(mac) when is_binary(mac), do: Regex.match?(@mac_regex, mac)
  def valid_mac?(_), do: false

  @doc "The 102-byte magic packet for `mac`. Raises on a malformed MAC."
  @spec magic_packet(String.t()) :: binary()
  def magic_packet(mac) do
    bytes =
      mac
      |> String.replace(["-", ":"], "")
      |> String.upcase()
      |> Base.decode16!()

    :binary.copy(<<0xFF>>, 6) <> :binary.copy(bytes, 16)
  end

  @doc """
  Broadcast a magic packet for `mac`. `broadcast` defaults to `255.255.255.255`; a blank or
  nil value falls back to the default.

  Returns `:ok`, `{:error, :invalid_mac}` for a malformed MAC, `{:error, :invalid_broadcast}`
  for an unresolvable broadcast address, or `{:error, reason}` from `:gen_udp`.
  """
  @spec send(String.t(), String.t() | nil) :: :ok | {:error, term()}
  def send(mac, broadcast \\ nil) do
    target = normalize_broadcast(broadcast)

    with true <- valid_mac?(mac) || {:error, :invalid_mac},
         {:ok, address} <- parse_address(target) do
      broadcast_packet(magic_packet(mac), address)
    else
      {:error, _} = error -> error
    end
  end

  defp normalize_broadcast(value) when is_binary(value) do
    case String.trim(value) do
      "" -> @default_broadcast
      trimmed -> trimmed
    end
  end

  defp normalize_broadcast(_), do: @default_broadcast

  defp parse_address(target) do
    case :inet.parse_address(String.to_charlist(target)) do
      {:ok, address} -> {:ok, address}
      {:error, _} -> {:error, :invalid_broadcast}
    end
  end

  defp broadcast_packet(packet, address) do
    case :gen_udp.open(0, [:binary, broadcast: true]) do
      {:ok, socket} ->
        try do
          :gen_udp.send(socket, address, @wol_port, packet)
        after
          :gen_udp.close(socket)
        end

      {:error, _} = error ->
        error
    end
  end
end
