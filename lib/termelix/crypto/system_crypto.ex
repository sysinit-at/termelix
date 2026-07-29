defmodule Termelix.Crypto.SystemCrypto do
  @moduledoc """
  Root key material for the instance, mirroring the original `system-crypto.ts`.

  Two secrets live in `<DATA_DIR>/.env` (env vars override the file). Each is loaded
  on boot, or generated and persisted if absent:

    * `JWT_SECRET`     — 32-byte hex string; the HS256 signing secret. Used as the
                         *string itself* (not decoded), exactly as the Node backend.
    * `ENCRYPTION_KEY` — 32-byte hex, decoded to 32 raw bytes; the master key that wraps
                         every per-user DEK (`Termelix.Crypto.DekWrap`).

  **The database file itself is not encrypted.** Only the columns listed in
  `Termelix.Crypto.FieldCrypto`'s `@encrypted_fields` (field_crypto.ex:19) are sealed,
  under the user's DEK. Everything else in the SQLite file — hostnames, usernames,
  session recordings, audit rows — is plaintext on disk.

  Older installs also have `DATABASE_KEY` and `INTERNAL_AUTH_TOKEN` lines in their
  `.env`. Neither was ever read by this port: `DATABASE_KEY` named a whole-file
  encryption that does not exist, `INTERNAL_AUTH_TOKEN` belonged to the retired Node
  services. They are no longer generated. Existing `.env` files are left untouched —
  the stale lines are inert, and rewriting a file full of root secrets to drop a
  comment-level wart is the riskier move.
  """
  use GenServer
  require Logger

  @min_hex_len 64

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  # Key material never changes after boot, so `init/1` publishes the whole state
  # map to `:persistent_term` under this key and the accessors below read it back
  # with zero message passing (the GenServer is only the one-time loader/persister).
  @keys_term {__MODULE__, :keys}

  @doc "The HS256 JWT signing secret (the hex string itself, as the original uses it)."
  @spec jwt_secret() :: String.t()
  def jwt_secret, do: get_key(:jwt_secret)

  @doc "32-byte master key used to wrap/unwrap per-user DEKs."
  @spec encryption_key() :: binary()
  def encryption_key, do: get_key(:encryption_key)

  # Zero-cost read; falls back to the GenServer if called before init published
  # the state (e.g. unusual boot ordering in tests).
  defp get_key(key) do
    case :persistent_term.get(@keys_term, nil) do
      %{^key => value} -> value
      _ -> GenServer.call(__MODULE__, {:get, key})
    end
  end

  @impl true
  def init(_opts) do
    dir = data_dir()
    File.mkdir_p!(dir)
    env_path = Path.join(dir, ".env")
    env = read_env_file(env_path)

    state = %{
      jwt_secret: resolve_hex_string("JWT_SECRET", env, &gen_hex/0),
      encryption_key: resolve_binary("ENCRYPTION_KEY", env, &gen_hex/0)
    }

    # The .env file holds root secrets; make sure it is not world-readable even if
    # it was left behind by an older version or a permissive umask.
    if File.exists?(env_path), do: chmod_private(env_path)

    :persistent_term.put(@keys_term, state)

    Logger.info("SystemCrypto initialized (data_dir=#{dir})")
    {:ok, state}
  end

  @impl true
  def handle_call({:get, key}, _from, state), do: {:reply, Map.fetch!(state, key), state}

  # --- resolution helpers ---------------------------------------------------

  # For JWT_SECRET the value is used verbatim as a string (the Node backend signs with
  # the hex text, not the decoded bytes — decoding here would invalidate live sessions).
  defp resolve_hex_string(name, env, gen) do
    case lookup(name, env) do
      val when is_binary(val) and byte_size(val) >= @min_hex_len ->
        val

      _ ->
        val = gen.()
        persist(name, val)
        val
    end
  end

  # For ENCRYPTION_KEY the hex value is decoded to 32 raw bytes.
  defp resolve_binary(name, env, gen) do
    case lookup(name, env) do
      val when is_binary(val) and byte_size(val) >= @min_hex_len ->
        Base.decode16!(val, case: :mixed)

      _ ->
        val = gen.()
        persist(name, val)
        Base.decode16!(val, case: :mixed)
    end
  end

  defp lookup(name, env), do: System.get_env(name) || Map.get(env, name)

  defp gen_hex, do: :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)

  # --- .env file I/O --------------------------------------------------------

  defp read_env_file(path) do
    case File.read(path) do
      {:ok, contents} ->
        contents
        |> String.split("\n", trim: true)
        |> Enum.reject(&String.starts_with?(String.trim(&1), "#"))
        |> Enum.reduce(%{}, fn line, acc ->
          case String.split(line, "=", parts: 2) do
            [k, v] -> Map.put(acc, String.trim(k), String.trim(v))
            _ -> acc
          end
        end)

      {:error, _} ->
        %{}
    end
  end

  defp persist(name, value) do
    path = Path.join(data_dir(), ".env")
    File.mkdir_p!(data_dir())

    contents =
      case File.read(path) do
        {:ok, c} -> c
        {:error, _} -> "# Termelix Auto-generated Configuration\n\n"
      end

    updated =
      if Regex.match?(~r/^#{name}=.*$/m, contents) do
        Regex.replace(~r/^#{name}=.*$/m, contents, "#{name}=#{value}")
      else
        contents <> "#{name}=#{value}\n"
      end

    # Lock the file to 0600 BEFORE the secret is written into it: a freshly
    # created file lands at the umask default (typically 0644) and would be
    # briefly world-readable — with key material inside — between the write and a
    # trailing chmod. Touching + chmod first means only an empty file ever exists
    # world-readable; the secret is written after the mode is tightened.
    ensure_private_file(path)
    File.write!(path, updated)
    System.put_env(name, value)
    Logger.info("SystemCrypto generated and persisted #{name}")
  end

  # Create the file (if absent) and tighten it to 0600 before any secret is
  # written into it. `File.touch!` creates an empty file at the umask default,
  # so the world-readable window only ever covers empty content.
  defp ensure_private_file(path) do
    File.touch!(path)
    chmod_private(path)
  end

  # Best-effort 0600 on the secrets file; a failure (odd filesystem, ACLs) must
  # not take down boot or secret generation.
  defp chmod_private(path) do
    case File.chmod(path, 0o600) do
      :ok -> :ok
      {:error, reason} -> Logger.warning("Could not chmod 0600 #{path}: #{inspect(reason)}")
    end
  end

  defp data_dir do
    Application.get_env(:termelix, :data_dir) || System.get_env("DATA_DIR") || "./db/data"
  end
end
