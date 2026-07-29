defmodule Termelix.ApiKeys.Usage do
  @moduledoc """
  Buffers `api_keys.last_used_at` and flushes it periodically.

  SQLite has a single writer, and this app runs in `:immediate` transaction mode: an `UPDATE`
  per authenticated request serializes against every other write in the system. An agent
  polling in a loop would write to the database as fast as it reads — to maintain a field whose
  only job is answering "is this key still being used", which nobody needs to second-level
  precision.

  So the timestamp is recorded in ETS and written once per interval, per key, no matter how
  many requests arrived. The cost of a crash is the last interval's worth of timestamps, which
  is a strictly better trade than a write per request forever.
  """
  use GenServer

  require Logger

  import Ecto.Query, only: [from: 2]

  alias Termelix.Repo
  alias Termelix.Schema.ApiKey

  @table :termelix_api_key_usage
  @flush_interval_ms 30_000

  @doc false
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "Note that `key_id` was used just now. Constant time, no database access."
  @spec touch(String.t()) :: :ok
  def touch(key_id) do
    ensure_table()
    :ets.insert(@table, {key_id, DateTime.utc_now() |> DateTime.to_iso8601()})
    :ok
  rescue
    _error -> :ok
  end

  @doc """
  Write every buffered timestamp and clear the buffer, returning how many rows were updated.

  Public so a test does not have to wait out the interval, and so a shutdown can flush.
  """
  @spec flush() :: non_neg_integer()
  def flush do
    ensure_table()

    # Take the whole buffer in one pass and clear it BEFORE writing: a request landing during
    # the flush then records a newer timestamp that the next flush picks up, rather than being
    # silently overwritten by the one already in flight.
    pending = :ets.tab2list(@table)
    :ets.delete_all_objects(@table)

    Enum.each(pending, fn {key_id, at} ->
      Repo.update_all(from(k in ApiKey, where: k.id == ^key_id), set: [lastUsedAt: at])
    end)

    length(pending)
  rescue
    error ->
      Logger.warning("api key usage flush failed: #{Exception.message(error)}")
      0
  end

  @doc false
  @spec ensure_table() :: :ok
  def ensure_table do
    case :ets.whereis(@table) do
      :undefined ->
        :ets.new(@table, [:named_table, :public, :set, write_concurrency: true])
        :ok

      _tid ->
        :ok
    end
  rescue
    ArgumentError -> :ok
  end

  @impl true
  def init(_opts) do
    ensure_table()
    Process.flag(:trap_exit, true)
    {:ok, schedule()}
  end

  @impl true
  def handle_info(:flush, _state) do
    flush()
    {:noreply, schedule()}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, _state) do
    # A clean shutdown is the one time the buffer can be written for free. A redeploy is the
    # ordinary case, and losing "last used" across every redeploy would make the field useless
    # precisely on the instances that restart most.
    flush()
    :ok
  end

  defp schedule, do: %{timer: Process.send_after(self(), :flush, @flush_interval_ms)}
end
