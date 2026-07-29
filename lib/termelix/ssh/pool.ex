defmodule Termelix.SSH.Pool do
  @moduledoc """
  Connection pool for data-plane SSH (`Termelix.SSH.Exec`, `Termelix.SSH.Sftp`): one
  `Termelix.SSH.Conn` GenServer per unique host+credential set, registered in
  `Termelix.SSH.ConnRegistry` and started on demand under `Termelix.SSH.ConnSupervisor`
  (both in the application supervision tree).

  Channels are still opened per operation on the checked-out connection — native SSH
  multiplexing — so back-to-back operations skip the TCP + key-exchange + auth handshake
  without sharing any channel state. A server-side `MaxSessions` cap (or a stale conn on
  its way down) surfaces as a channel-open failure; callers degrade to `fresh_conn/1` for
  that one operation instead of failing.
  """

  alias Termelix.SSH.{Conn, ConnectOpts}

  @registry Termelix.SSH.ConnRegistry
  @supervisor Termelix.SSH.ConnSupervisor
  @connect_timeout 15_000
  # Bounded wait for a Conn still mid-handshake (the connect itself is capped at
  # @connect_timeout, and every queued waiter is answered the moment it completes).
  @ready_timeout 20_000

  @type conn_opts :: ConnectOpts.conn_opts()

  @doc """
  Check out the pooled connection for `conn_opts`, starting the owning `Termelix.SSH.Conn`
  on first use and waiting (bounded by `timeout`) for the handshake. Returns `{:ok, conn}`
  or `{:error, reason}`, mirroring `:ssh.connect/4` so callers wrap failures exactly as
  they did for dedicated connections.
  """
  @spec checkout(conn_opts(), timeout()) :: {:ok, pid()} | {:error, term()}
  def checkout(conn_opts, timeout \\ @ready_timeout) do
    do_checkout(key_for(conn_opts), conn_opts, timeout, _retried? = false)
  end

  defp do_checkout(key, conn_opts, timeout, retried?) do
    with {:ok, pid} <- ensure_started(key, conn_opts) do
      case Conn.checkout(pid, timeout) do
        {:ok, conn} ->
          {:ok, conn}

        # The registered Conn died between lookup and checkout — start over once.
        {:error, :gone} when not retried? ->
          do_checkout(key, conn_opts, timeout, true)

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc """
  Open a dedicated, unpooled connection — owned by and linked to the caller, which must
  close it (`:ssh.close/1`). This is the graceful-degradation path when a pooled
  connection refuses a channel (`MaxSessions` pressure, stale conn).
  """
  @spec fresh_conn(conn_opts()) :: {:ok, pid()} | {:error, term()}
  def fresh_conn(conn_opts) do
    :ssh.connect(
      String.to_charlist(conn_opts.host),
      conn_opts.port,
      ConnectOpts.build(conn_opts),
      @connect_timeout
    )
  end

  @doc """
  The Registry key for `conn_opts`: identical credentials on the same host share one
  connection; different credentials or hosts never do. "Credentials" includes the PEM
  passphrase (`:key_password`) — two configs with the same encrypted `:private_key` but a
  different passphrase are NOT the same identity (possessing the encrypted key without its
  passphrase must not check out a connection authenticated with it), so they never share a
  bucket.

  `:owner_id` is part of the key too, which costs one extra handshake in the rare case where
  two accounts hold the same credentials for the same host, and buys two things worth more
  than that. A live pooled connection is a *capability* — already authenticated, ready to open
  a channel — so it should not silently span accounts. And revocation has to be able to find
  one: without an owner in the key, `Termelix.Revocation` could stop a user's sessions and
  tunnels and still leave an authenticated connection to their host open in the pool, usable
  for as long as it stays warm.
  """
  @spec key_for(conn_opts()) :: binary()
  def key_for(opts) do
    :crypto.hash(
      :sha256,
      :erlang.term_to_binary(
        {opts.host, opts.port, opts.username, opts[:password], opts[:private_key],
         opts[:key_password], opts[:owner_id]}
      )
    )
  end

  @doc """
  Stop every pooled connection owned by `user_id`, returning how many were stopped.

  The pool's half of revocation. A `Conn` is an authenticated SSH connection held open for
  reuse — 60s past its last checkout, and indefinitely while a channel is open (a streamed
  download, a slow exec) — so without this a revoked user's connection to their host outlived
  the revocation by exactly as long as it stayed busy.
  """
  @spec close_user_conns(String.t()) :: non_neg_integer()
  def close_user_conns(user_id) do
    pids =
      Registry.select(@registry, [
        {{:_, :"$1", :"$2"}, [{:==, {:map_get, :owner_id, :"$2"}, user_id}], [:"$1"]}
      ])

    Enum.each(pids, &DynamicSupervisor.terminate_child(@supervisor, &1))
    length(pids)
  end

  @doc "The pid of the pooled `Termelix.SSH.Conn` registered under `key`, if one is running."
  @spec lookup(binary()) :: pid() | nil
  def lookup(key) do
    case Registry.lookup(@registry, key) do
      [{pid, _}] -> pid
      [] -> nil
    end
  end

  @doc "Stop every pooled connection (test cleanup)."
  @spec stop_all() :: :ok
  def stop_all do
    @supervisor
    |> DynamicSupervisor.which_children()
    |> Enum.each(fn {_, pid, _, _} -> DynamicSupervisor.terminate_child(@supervisor, pid) end)

    :ok
  end

  defp ensure_started(key, conn_opts) do
    case lookup(key) do
      nil -> start_conn(key, conn_opts)
      pid -> if Process.alive?(pid), do: {:ok, pid}, else: start_conn(key, conn_opts)
    end
  end

  # How long to wait out a stale Registry entry (a just-dead Conn whose name the Registry
  # hasn't reclaimed yet) before giving up on starting a replacement.
  @stale_entry_retries 10

  defp start_conn(key, conn_opts, stale_retries \\ @stale_entry_retries)

  defp start_conn(key, conn_opts, stale_retries) do
    case DynamicSupervisor.start_child(@supervisor, {Conn, {key, conn_opts}}) do
      {:ok, pid} ->
        {:ok, pid}

      # Checkout race for the same key: another caller won the start.
      {:error, {:already_started, pid}} ->
        cond do
          Process.alive?(pid) ->
            {:ok, pid}

          stale_retries > 0 ->
            # Stale Registry entry for a just-dead Conn; the Registry drops it as soon as
            # it processes its own DOWN, which takes microseconds — wait it out (bounded).
            Process.sleep(5)
            start_conn(key, conn_opts, stale_retries - 1)

          true ->
            # Give up waiting out the stale entry: hand the dead pid back so the caller's
            # checkout fails fast with `:gone` and retries the whole lookup once more.
            {:ok, pid}
        end

      # `ConnSupervisor` has a `max_children` cap (application.ex). Before that cap existed
      # this branch was unreachable, so a bare `case` on the two clauses above was total —
      # adding the cap turned a memory bound into a `CaseClauseError` raised in whatever
      # process asked for a connection. `Sftp` calls this in the request process (a 500),
      # `Exec` inside a supervised task (a crash report per probe). Degrade to a typed error
      # instead: every caller of `checkout/2` already handles `{:error, reason}`.
      {:error, :max_children} ->
        {:error, :pool_exhausted}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
