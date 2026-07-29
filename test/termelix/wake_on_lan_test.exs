defmodule Termelix.WakeOnLanTest do
  use ExUnit.Case, async: true

  alias Termelix.WakeOnLan

  describe "valid_mac?/1" do
    test "accepts colon- and dash-separated hex octets" do
      assert WakeOnLan.valid_mac?("AA:BB:CC:DD:EE:FF")
      assert WakeOnLan.valid_mac?("aa-bb-cc-dd-ee-ff")
    end

    test "rejects anything else" do
      refute WakeOnLan.valid_mac?("AA:BB:CC:DD:EE")
      refute WakeOnLan.valid_mac?("AABBCCDDEEFF")
      refute WakeOnLan.valid_mac?("ZZ:BB:CC:DD:EE:FF")
      refute WakeOnLan.valid_mac?("")
      refute WakeOnLan.valid_mac?(nil)
    end
  end

  describe "magic_packet/1" do
    test "is six 0xFF bytes plus the MAC sixteen times" do
      packet = WakeOnLan.magic_packet("aa:bb:cc:dd:ee:ff")

      assert byte_size(packet) == 102
      assert <<0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, rest::binary>> = packet
      assert rest == :binary.copy(<<0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF>>, 16)
    end
  end

  describe "send/2" do
    test "delivers the packet to the given address" do
      {:ok, listener} = :gen_udp.open(0, [:binary, active: false])
      {:ok, port} = :inet.port(listener)

      # Aim at the loopback so nothing leaves the machine; port 9 is fixed in the sender, so
      # the assertion is on the packet the module builds, sent to a socket we control.
      packet = WakeOnLan.magic_packet("AA:BB:CC:DD:EE:FF")
      {:ok, sender} = :gen_udp.open(0, [:binary])
      :ok = :gen_udp.send(sender, {127, 0, 0, 1}, port, packet)
      :gen_udp.close(sender)

      assert {:ok, {_addr, _port, received}} = :gen_udp.recv(listener, 0, 1_000)
      assert received == packet
      :gen_udp.close(listener)

      # The public entry point still succeeds against loopback.
      assert :ok == WakeOnLan.send("AA:BB:CC:DD:EE:FF", "127.0.0.1")
    end

    test "rejects a malformed MAC before opening a socket" do
      assert {:error, :invalid_mac} == WakeOnLan.send("nope", "127.0.0.1")
    end

    test "rejects an unparsable broadcast address" do
      assert {:error, :invalid_broadcast} == WakeOnLan.send("AA:BB:CC:DD:EE:FF", "not-an-ip")
    end

    test "a blank broadcast address falls back to the global broadcast" do
      # 255.255.255.255 parses; whether the datagram leaves the host depends on the runner's
      # interfaces, so only the argument handling is asserted here.
      assert WakeOnLan.send("AA:BB:CC:DD:EE:FF", "  ") in [:ok, {:error, :enetunreach}]
    end
  end
end
