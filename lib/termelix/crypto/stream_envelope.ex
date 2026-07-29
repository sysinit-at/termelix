defmodule Termelix.Crypto.StreamEnvelope do
  @moduledoc """
  Append-only authenticated encryption for things that arrive a piece at a time.

  `Termelix.Crypto.FieldCrypto` is a single-shot seal that produces one JSON object with
  hex-encoded fields. It is right for a password and wrong for a transcript: sealing an
  eight-hour session with it means holding the whole thing in memory until the session ends —
  precisely the unbounded-memory failure the backpressure work exists to prevent — and hex
  doubles a stream that is already the largest artifact this app writes.

  So this is a different format, specified rather than improvised.

  ## Wire format

      header  := MAGIC(8) ‖ VERSION(1) ‖ SALT(16)
      record  := LENGTH(4, big-endian) ‖ CIPHERTEXT(LENGTH) ‖ TAG(16)
      trailer := LENGTH(4) = 0xFFFFFFFF ‖ COUNT(8) ‖ TAG(16)

  Raw bytes throughout. One AES-256-GCM record per chunk, each with its own IV derived from the
  record counter, and **the counter in the AAD**. That last part is the whole point: a record
  authenticates its own position, so a truncated file, a reordered pair of records, or a record
  spliced in from another file all fail to open. Encrypting each chunk independently without
  binding it to a position gives an attacker a free cut-and-paste primitive over the transcript.

  The trailer seals the final record count, so truncation of whole records at the END — the one
  edit that leaves every remaining record individually valid — is detectable too. A file with
  no trailer is reported as `:unterminated`, not as corrupt: a session killed mid-write leaves
  exactly that, and it is still worth reading.

  ## Keys

  One content key per stream, derived by HKDF from the caller's key material and a random
  per-stream salt. The salt lives in the header, so the same DEK across a thousand recordings
  never reuses a content key. IVs are deterministic in the counter rather than random: with a
  per-stream key, a counter cannot repeat, and deterministic IVs remove the birthday bound that
  makes random 96-bit IVs uncomfortable past a few billion records.
  """

  @magic "TMXSTRM1"
  @version 1
  @salt_bytes 16
  @key_bytes 32
  @tag_bytes 16
  @trailer_marker 0xFFFFFFFF

  @type writer :: %{key: binary(), counter: non_neg_integer()}
  @type header :: %{salt: binary(), version: pos_integer()}

  @doc """
  Begin a stream. Returns `{header_bytes, writer}` — write the header first, then records.
  """
  @spec init(binary()) :: {binary(), writer()}
  def init(key_material) when is_binary(key_material) do
    salt = :crypto.strong_rand_bytes(@salt_bytes)
    {@magic <> <<@version>> <> salt, %{key: derive(key_material, salt), counter: 0}}
  end

  @doc """
  Seal one chunk. Returns `{record_bytes, writer}`.

  The record number is in the AAD, so this record cannot be moved, duplicated, or dropped
  without the next `open/2` noticing.
  """
  @spec seal(writer(), binary()) :: {binary(), writer()}
  def seal(%{key: key, counter: counter} = writer, plaintext) when is_binary(plaintext) do
    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        key,
        iv(key, counter),
        plaintext,
        aad(counter),
        true
      )

    record = <<byte_size(ciphertext)::32>> <> ciphertext <> tag
    {record, %{writer | counter: counter + 1}}
  end

  @doc """
  Close a stream: a trailer sealing the number of records written.

  Without it, dropping whole records from the end of the file leaves every remaining record
  individually valid — the one truncation a per-record MAC cannot see.
  """
  @spec finish(writer()) :: binary()
  def finish(%{key: key, counter: counter}) do
    {_ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        key,
        iv(key, @trailer_marker),
        <<>>,
        trailer_aad(counter),
        true
      )

    <<@trailer_marker::32, counter::64>> <> tag
  end

  @doc """
  Open a whole stream.

    * `{:ok, plaintext}` — every record verified and the trailer agreed on the count.
    * `{:ok, plaintext, :unterminated}` — every record verified, no trailer. A session killed
      mid-write leaves exactly this, and the bytes are still worth reading.
    * `{:error, reason}` — a record failed to authenticate, the count disagreed, or the file is
      not one of ours.

  A partial read is deliberately not offered as a plain `{:ok, _}`: a caller that cannot tell
  "complete" from "as much as survived" will show one as the other.
  """
  @spec open(binary(), binary()) ::
          {:ok, binary()} | {:ok, binary(), :unterminated} | {:error, atom()}
  def open(@magic <> <<version, salt::binary-size(@salt_bytes), rest::binary>>, key_material)
      when version == @version do
    read_records(rest, derive(key_material, salt), 0, [])
  end

  def open(@magic <> <<_version, _rest::binary>>, _key_material),
    do: {:error, :unsupported_version}

  def open(_bytes, _key_material), do: {:error, :not_an_envelope}

  defp read_records(<<>>, _key, _counter, acc),
    do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary(), :unterminated}

  defp read_records(
         <<@trailer_marker::32, count::64, tag::binary-size(@tag_bytes), _ignored::binary>>,
         key,
         counter,
         acc
       ) do
    # The trailer must agree with what was actually read. A file whose trailer claims more
    # records than are present has been truncated; one that claims fewer has been extended.
    case :crypto.crypto_one_time_aead(
           :aes_256_gcm,
           key,
           iv(key, @trailer_marker),
           <<>>,
           trailer_aad(count),
           tag,
           false
         ) do
      :error -> {:error, :bad_trailer}
      _ when count != counter -> {:error, :record_count_mismatch}
      _ -> {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary()}
    end
  end

  defp read_records(<<length::32, body::binary>>, key, counter, acc)
       when byte_size(body) >= length + @tag_bytes do
    <<ciphertext::binary-size(^length), tag::binary-size(@tag_bytes), rest::binary>> = body

    case :crypto.crypto_one_time_aead(
           :aes_256_gcm,
           key,
           iv(key, counter),
           ciphertext,
           aad(counter),
           tag,
           false
         ) do
      :error -> {:error, :bad_record}
      plaintext -> read_records(rest, key, counter + 1, [plaintext | acc])
    end
  end

  # A trailing fragment: the process died between writing a length and writing the body. Every
  # COMPLETE record before it is still good, which is the point of a record format.
  defp read_records(_partial, _key, _counter, acc),
    do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary(), :unterminated}

  @doc "The magic bytes a file must start with to be one of ours."
  @spec magic() :: binary()
  def magic, do: @magic

  # --- derivation -------------------------------------------------------------

  defp derive(key_material, salt) do
    # One content key per stream. The same DEK across a thousand recordings never reuses a key,
    # which is what makes deterministic counter IVs safe.
    Termelix.Crypto.HKDF.derive(key_material, salt, "termelix:stream:v1", @key_bytes)
  end

  # 96 bits: 32 of per-stream nonce (derived from the key, so it differs per stream) plus the
  # 64-bit counter. Deterministic on purpose: with a per-stream key the counter cannot repeat, and
  # this removes the birthday bound that makes random 96-bit IVs uncomfortable at scale.
  defp iv(key, counter) do
    <<nonce::binary-size(4), _::binary>> = :crypto.hash(:sha256, key)
    nonce <> <<counter::64>>
  end

  defp aad(counter), do: <<"rec", counter::64>>
  defp trailer_aad(count), do: <<"end", count::64>>
end
