defmodule Termelix.Crypto.StreamEnvelopeTest do
  @moduledoc """
  The format exists so a transcript can be written a chunk at a time and still be tamper-
  evident as a whole. These tests are mostly about the second half: every edit an attacker (or
  a corrupt disk) can make to a file of independently-encrypted records must be detected.

  A per-record MAC alone gives an attacker a cut-and-paste primitive — reorder, duplicate,
  drop, splice from another file — because a record that authenticates only itself says nothing
  about where it belongs. That is why the counter is in the AAD, and why there is a trailer.
  """
  use ExUnit.Case, async: true

  alias Termelix.Crypto.StreamEnvelope, as: Env

  @key :crypto.strong_rand_bytes(32)

  defp write(chunks, key \\ @key) do
    {header, writer} = Env.init(key)

    {records, writer} =
      Enum.reduce(chunks, {[], writer}, fn chunk, {acc, w} ->
        {record, w} = Env.seal(w, chunk)
        {[record | acc], w}
      end)

    {IO.iodata_to_binary([header | Enum.reverse(records)]), writer}
  end

  defp sealed(chunks, key \\ @key) do
    {bytes, writer} = write(chunks, key)
    bytes <> Env.finish(writer)
  end

  describe "round trip" do
    test "chunks come back as one stream, in order" do
      assert {:ok, "onetwothree"} = Env.open(sealed(["one", "two", "three"]), @key)
    end

    test "an empty stream is valid" do
      assert {:ok, ""} = Env.open(sealed([]), @key)
    end

    test "binary chunks, including empty ones and NULs" do
      chunks = [<<0, 1, 2>>, "", :binary.copy(<<0xFF>>, 100_000), <<0>>]
      assert {:ok, joined} = Env.open(sealed(chunks), @key)
      assert joined == IO.iodata_to_binary(chunks)
    end

    test "the ciphertext does not contain the plaintext" do
      secret = "hunter2-and-a-very-distinctive-string"
      assert {:ok, ^secret} = Env.open(sealed([secret]), @key)
      refute sealed([secret]) =~ secret
    end
  end

  describe "the wrong key" do
    test "cannot open it, and fails on the FIRST record rather than returning garbage" do
      assert {:error, :bad_record} = Env.open(sealed(["secret"]), :crypto.strong_rand_bytes(32))
    end
  end

  describe "tamper detection" do
    test "flipping a byte anywhere in a record is caught" do
      bytes = sealed(["alpha", "bravo", "charlie"])

      for position <- [30, 60, byte_size(bytes) - 40] do
        <<head::binary-size(position), byte, tail::binary>> = bytes
        corrupted = head <> <<Bitwise.bxor(byte, 0x01)>> <> tail
        assert match?({:error, _}, Env.open(corrupted, @key)), "byte #{position} not detected"
      end
    end

    test "REORDERING two records is caught — the counter is in the AAD" do
      {header, writer} = Env.init(@key)
      {a, writer} = Env.seal(writer, "first")
      {b, writer} = Env.seal(writer, "second")

      swapped = header <> b <> a <> Env.finish(writer)

      # Without the counter in the AAD each record would verify happily in either position, and
      # an attacker could rewrite the story a transcript tells without breaking a single MAC.
      assert {:error, :bad_record} = Env.open(swapped, @key)
    end

    test "DUPLICATING a record is caught" do
      {header, writer} = Env.init(@key)
      {a, writer} = Env.seal(writer, "once")
      assert {:error, :bad_record} = Env.open(header <> a <> a <> Env.finish(writer), @key)
    end

    test "SPLICING a record from another stream is caught" do
      {header, writer} = Env.init(@key)
      {a, writer} = Env.seal(writer, "mine")
      {_other_header, other_writer} = Env.init(@key)
      {foreign, _} = Env.seal(other_writer, "theirs")

      # Same key material, different stream: the per-stream salt makes the content keys differ.
      assert {:error, :bad_record} = Env.open(header <> a <> foreign <> Env.finish(writer), @key)
    end

    test "TRUNCATING whole records from the end is caught by the trailer" do
      {header, writer} = Env.init(@key)
      {a, writer} = Env.seal(writer, "kept")
      {_b, writer} = Env.seal(writer, "removed")
      trailer = Env.finish(writer)

      # Every remaining record is individually valid — this is the one edit a per-record MAC
      # cannot see, and the only reason the trailer exists.
      assert {:error, :record_count_mismatch} = Env.open(header <> a <> trailer, @key)
    end

    test "a forged trailer is caught" do
      bytes = sealed(["a", "b"])
      forged = binary_part(bytes, 0, byte_size(bytes) - 16) <> :crypto.strong_rand_bytes(16)
      assert {:error, :bad_trailer} = Env.open(forged, @key)
    end
  end

  describe "an interrupted write" do
    test "reads back what survived, and SAYS it is unterminated" do
      {bytes, _writer} = write(["kept-one", "kept-two"])

      # A session killed mid-write leaves no trailer. The bytes are still worth reading, and a
      # caller that cannot tell "complete" from "as much as survived" will show one as the other
      # — so this is a distinct return, not a plain {:ok, _}.
      assert {:ok, "kept-onekept-two", :unterminated} = Env.open(bytes, @key)
    end

    test "a half-written final record is dropped, and everything before it survives" do
      {bytes, _writer} = write(["complete", "partial"])
      chopped = binary_part(bytes, 0, byte_size(bytes) - 10)
      assert {:ok, "complete", :unterminated} = Env.open(chopped, @key)
    end
  end

  describe "framing" do
    test "a file that is not ours is refused by name" do
      assert {:error, :not_an_envelope} = Env.open("just some bytes", @key)
      assert {:error, :not_an_envelope} = Env.open("", @key)
    end

    test "a future version is refused rather than misread" do
      <<_magic::binary-size(8), _version, rest::binary>> = sealed(["x"])
      assert {:error, :unsupported_version} = Env.open(Env.magic() <> <<99>> <> rest, @key)
    end
  end

  describe "key separation" do
    test "two streams from the SAME key material use different content keys" do
      # The per-stream salt is what makes deterministic counter IVs safe: without it, record 0
      # of every recording would share an IV under one key, which is the classic GCM failure.
      one = sealed(["same text"])
      two = sealed(["same text"])

      body = fn bytes -> binary_part(bytes, 25, 9) end
      refute body.(one) == body.(two)
    end
  end
end
