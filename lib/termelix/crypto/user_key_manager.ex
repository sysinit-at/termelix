defmodule Termelix.Crypto.UserKeyUnavailableError do
  @moduledoc """
  Raised when a user's DEK cannot be produced: `:missing`, `:pending_migration`, or
  `:locked` (the stored wrap will not open under this instance's ENCRYPTION_KEY).
  """
  defexception [:user_id, :reason, :message]

  @impl true
  def exception(opts) do
    user_id = Keyword.fetch!(opts, :user_id)
    reason = Keyword.get(opts, :reason, :missing)

    message =
      case reason do
        :pending_migration ->
          "User #{user_id} data stays locked until their next login migrates their encryption key"

        :locked ->
          "User #{user_id}'s data encryption key could not be unsealed " <>
            "(wrong ENCRYPTION_KEY for this database, or a corrupt wrap)"

        _ ->
          "User #{user_id} has no data encryption key"
      end

    %__MODULE__{user_id: user_id, reason: reason, message: message}
  end
end

defmodule Termelix.Crypto.UserKeyManager do
  @moduledoc """
  Per-user Data Encryption Keys (DEKs), byte-compatible with `user-keys.ts` (wrap v3).

  Each user has a 32-byte DEK, stored wrapped in the `settings` table under
  `user_dek_v3_<userId>`. The wrap key is `HKDF-SHA256(ENCRYPTION_KEY, salt=∅,
  info="termix:dek-wrap:v3:<userId>")` and the DEK is sealed with AES-256-GCM using the
  userId as additional authenticated data. Because the wrap depends only on the instance
  ENCRYPTION_KEY (not the user's password), the server can unseal any user's DEK on
  demand — which is how background/terminal operations decrypt host secrets.

  Unsealed DEKs are cached in a `:protected` named ETS table (entries carry a monotonic
  expiry timestamp, same 15-minute TTL as before), so `get_user_dek/1` reads hit the
  cache directly in the caller process instead of serializing through the GenServer.
  The GenServer owns the table and performs every write: unwrap/create on a cache miss,
  and `invalidate/1`.

  A wrap that will not open (a database restored without its matching `ENCRYPTION_KEY`,
  a corrupt settings row) is reported as `:locked` rather than raised out of the server,
  so one bad row locks one user's data instead of crash-looping the application.
  """
  use GenServer

  require Logger

  alias Termelix.Crypto.{DekWrap, SystemCrypto, UserKeyUnavailableError}
  alias Termelix.Settings

  @dek_length 32
  # Overridable so the TTL-expiry path is testable at all. The cache table is `:protected`, so a
  # test can no longer seed an already-expired entry from outside — and waiting out 15 minutes is
  # not a test. Production never sets this.
  @default_cache_ttl_ms 15 * 60 * 1000
  @legacy_prefixes ~w(user_encrypted_dek_ user_kek_salt_)
  @table __MODULE__

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "Return the user's DEK, unsealing and caching it. Raises if unavailable."
  @spec get_user_dek(String.t()) :: binary()
  def get_user_dek(user_id) do
    case cached_dek(user_id) do
      {:ok, dek} ->
        dek

      :miss ->
        case GenServer.call(__MODULE__, {:get_dek, user_id}) do
          {:__key_error__, uid, reason} ->
            raise UserKeyUnavailableError, user_id: uid, reason: reason

          dek when is_binary(dek) ->
            dek
        end
    end
  end

  @doc "Like get_user_dek/1 but returns nil instead of raising when unavailable."
  @spec try_get_user_dek(String.t()) :: binary() | nil
  def try_get_user_dek(user_id) do
    get_user_dek(user_id)
  rescue
    UserKeyUnavailableError -> nil
  end

  @doc "Whether the user already has a (wrapped) DEK."
  @spec has_user_dek?(String.t()) :: boolean()
  def has_user_dek?(user_id), do: GenServer.call(__MODULE__, {:has_dek, user_id})

  @doc "Create and persist a fresh DEK for a new user. Raises if one already exists."
  @spec create_user_dek(String.t()) :: binary()
  def create_user_dek(user_id) do
    case GenServer.call(__MODULE__, {:create_dek, user_id}) do
      {:__key_error__, uid, :already_exists} ->
        raise "User #{uid} already has a data encryption key"

      {:__key_error__, uid, :persist_failed} ->
        raise "Could not persist a data encryption key for user #{uid}"

      dek when is_binary(dek) ->
        dek
    end
  end

  @doc "Drop the cached DEK for a user (does not delete the wrapped copy)."
  @spec invalidate(String.t()) :: :ok
  def invalidate(user_id) do
    # The table is :protected, so the delete has to run in the owner process.
    GenServer.call(__MODULE__, {:invalidate, user_id})
  catch
    # Manager not running (boot ordering, shutdown); there is no cache to drop.
    :exit, _ -> :ok
  end

  # --- server ---------------------------------------------------------------

  @impl true
  def init(_opts) do
    # :protected is owner-writes / all-processes-read. That closes DEK *poisoning* — no
    # other process can swap a cached DEK for one it controls — but NOT disclosure:
    # `:ets.tab2list/1` still dumps every cached DEK from any process. Closing the read
    # would take `:private` plus a GenServer round-trip on every `get_user_dek/1`,
    # reintroducing exactly the serialization this cache exists to avoid.
    :ets.new(@table, [:named_table, :protected, :set, read_concurrency: true])
    # No master key in state: GenServer state is dumped into OTP crash reports (and
    # shipped to Sentry). It is read from :persistent_term at point of use instead.
    {:ok, %{}}
  end

  @impl true
  def handle_call({:invalidate, user_id}, _from, state) do
    :ets.delete(@table, user_id)
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:get_dek, user_id}, _from, state) do
    # Re-check the table: another caller may have populated it while this call
    # was queued.
    case cached_dek(user_id) do
      {:ok, dek} ->
        {:reply, dek, state}

      :miss ->
        case Settings.get_value(dek_settings_key(user_id)) do
          nil ->
            reason = if has_legacy_wrap?(user_id), do: :pending_migration, else: :missing
            {:reply, {:__key_error__, user_id, reason}, state}

          raw ->
            case unwrap_dek(user_id, raw) do
              {:ok, dek} ->
                cache_dek(user_id, dek)
                {:reply, dek, state}

              :error ->
                {:reply, {:__key_error__, user_id, :locked}, state}
            end
        end
    end
  end

  @impl true
  def handle_call({:has_dek, user_id}, _from, state) do
    result =
      :ets.member(@table, user_id) or
        Settings.get_value(dek_settings_key(user_id)) != nil

    {:reply, result, state}
  end

  @impl true
  def handle_call({:create_dek, user_id}, _from, state) do
    if Settings.get_value(dek_settings_key(user_id)) != nil do
      {:reply, {:__key_error__, user_id, :already_exists}, state}
    else
      dek = :crypto.strong_rand_bytes(@dek_length)
      wrapped = DekWrap.wrap(master_key(), user_id, dek)

      case persist_dek(user_id, wrapped) do
        :ok ->
          cache_dek(user_id, dek)
          {:reply, dek, state}

        {:error, error} ->
          Logger.error("Failed to persist DEK for user #{user_id}: #{inspect(error)}")
          {:reply, {:__key_error__, user_id, :persist_failed}, state}
      end
    end
  end

  # The master key lives in :persistent_term (SystemCrypto publishes it at boot) and is
  # read here, at point of use, so it is never part of this GenServer's state — state is
  # what an OTP crash report prints and what Sentry attaches as `genserver_state`.
  defp master_key, do: SystemCrypto.encryption_key()

  # A wrap that will not open is a data condition, not a bug: a database restored without
  # its matching ENCRYPTION_KEY, or one corrupt settings row. Letting DekWrap raise here
  # would fail every login AND take the application down (three restarts in five seconds
  # exceeds the supervisor's default intensity). Report it as :locked instead — callers
  # already handle a missing DEK by degrading to "data locked" (e.g. hosts.ex:37).
  defp unwrap_dek(user_id, raw) do
    {:ok, DekWrap.unwrap(master_key(), user_id, raw)}
  rescue
    # Covers the whole path: Jason.DecodeError, Base.decode64! ArgumentError, and
    # DekWrap's own version/auth-tag raises. Message text carries no key material.
    error ->
      Logger.error("DEK unwrap failed for user #{user_id}: #{Exception.message(error)}")
      :error
  end

  # A failed insert must not crash the manager (a crash would drop the ETS
  # table and every cached DEK with it).
  defp persist_dek(user_id, wrapped) do
    Settings.put_value(dek_settings_key(user_id), Jason.encode!(wrapped))
    :ok
  rescue
    error -> {:error, error}
  end

  defp cached_dek(user_id) do
    now = System.monotonic_time(:millisecond)

    case :ets.lookup(@table, user_id) do
      [{^user_id, dek, expires_at}] when expires_at > now -> {:ok, dek}
      _ -> :miss
    end
  rescue
    # Table not created yet (boot ordering); treat as a miss.
    ArgumentError -> :miss
  end

  defp cache_dek(user_id, dek) do
    expires_at = System.monotonic_time(:millisecond) + cache_ttl_ms()
    :ets.insert(@table, {user_id, dek, expires_at})
  end

  defp cache_ttl_ms,
    do: Application.get_env(:termelix, :user_dek_cache_ttl_ms, @default_cache_ttl_ms)

  defp dek_settings_key(user_id), do: "user_dek_v3_#{user_id}"

  defp has_legacy_wrap?(user_id) do
    Enum.any?(@legacy_prefixes, fn prefix ->
      Settings.get_value("#{prefix}#{user_id}") != nil
    end)
  end
end
