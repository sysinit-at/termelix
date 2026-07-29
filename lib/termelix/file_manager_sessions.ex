defmodule Termelix.FileManagerSessions do
  @moduledoc """
  Virtual file-manager "SSH sessions" backing the `/ssh/file_manager/ssh/connect|status|
  keepalive|disconnect` lifecycle the SPA drives before it starts browsing.

  The Node backend held one live ssh2 client per `sessionId` and these routes managed it.
  This port's SFTP operations open short-lived pooled connections per request
  (`Termelix.SSH.Sftp`), so there is no long-lived OS resource to manage — but the SPA still
  requires the lifecycle to succeed (its FileManager refuses to browse until `connect`
  reports success, then polls `status` and `keepalive`). A session row here is therefore a
  *claim check*: "this user proved at connect time that the host is reachable".

  Rows live in the `:termelix_file_manager_sessions` ETS table (`:named_table, :public`,
  owned for the node's lifetime by `Termelix.EtsOwner`): `{session_id, user_id, last_active_ms,
  expires_at_ms}`. `Termelix.EtsOwner` sweeps lapsed rows every 60s; `touch/1` (keepalive)
  renews the idle window. The idle TTL mirrors the Node cleanup scheduler's 30 minutes.
  Ownership is enforced on every lookup so one user can never read or drop another user's
  session (Node's `verifySessionOwnership`).
  """

  @table :termelix_file_manager_sessions
  @idle_ttl_ms 30 * 60_000

  @doc "Create the ETS table if it does not exist yet (idempotent, see `Termelix.EtsOwner`)."
  @spec ensure_table() :: :ok
  def ensure_table do
    try do
      :ets.new(@table, [:named_table, :public, :set])
      :ok
    rescue
      ArgumentError -> :ok
    end
  end

  @doc "Register (or refresh) `session_id` as connected for `user_id`."
  @spec register(String.t(), String.t()) :: :ok
  def register(session_id, user_id) do
    ensure_table()
    now_ms = now()
    :ets.insert(@table, {session_id, user_id, now_ms, now_ms + @idle_ttl_ms})
    :ok
  end

  @doc """
  Look up a live session: `{:ok, user_id, last_active_ms}` while unexpired, else `:error`.
  A lapsed row is deleted and treated as absent.
  """
  @spec lookup(String.t() | nil) :: {:ok, String.t(), integer()} | :error
  def lookup(session_id) when is_binary(session_id) do
    ensure_table()
    now_ms = now()

    case :ets.lookup(@table, session_id) do
      [{_, user_id, last_active, expires_at}] when expires_at > now_ms ->
        {:ok, user_id, last_active}

      [{_, _, _, _}] ->
        :ets.delete(@table, session_id)
        :error

      [] ->
        :error
    end
  end

  def lookup(_), do: :error

  @doc "Renew the idle window (keepalive). Returns the new last-active ms, or `:error` if absent."
  @spec touch(String.t()) :: {:ok, integer()} | :error
  def touch(session_id) do
    case lookup(session_id) do
      {:ok, user_id, _} ->
        now_ms = now()
        :ets.insert(@table, {session_id, user_id, now_ms, now_ms + @idle_ttl_ms})
        {:ok, now_ms}

      :error ->
        :error
    end
  end

  @doc "Drop a session (disconnect). Succeeds whether or not it existed."
  @spec remove(String.t() | nil) :: :ok
  def remove(session_id) when is_binary(session_id) do
    ensure_table()
    :ets.delete(@table, session_id)
    :ok
  end

  def remove(_), do: :ok

  @doc "Delete expired rows (called by `Termelix.EtsOwner`'s sweep timer)."
  @spec sweep_expired() :: non_neg_integer()
  def sweep_expired do
    ensure_table()
    now_ms = now()

    :ets.select_delete(@table, [
      {{:_, :_, :_, :"$1"}, [{:"=<", :"$1", now_ms}], [true]}
    ])
  end

  # Wall-clock ms: `last_active` is echoed to the SPA (Node used `Date.now()`).
  defp now, do: System.system_time(:millisecond)
end
