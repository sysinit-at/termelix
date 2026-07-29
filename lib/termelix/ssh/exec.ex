defmodule Termelix.SSH.Exec do
  @moduledoc """
  One-shot command execution over OTP `:ssh` — the engine behind host metrics, the tmux
  probes, and any "run a command and capture its output" path.

  Each run still gets its own session channel in a dedicated task under
  `Termelix.TaskSupervisor` (so the task owns the `{:ssh_cm, …}` channel messages in
  isolation, and a crash inside it cannot take the calling HTTP request down with it), but
  the connection is checked out of `Termelix.SSH.Pool` instead of dialed per run — the task
  closes only its channel; the shared connection survives for the next run. A pooled
  connection that refuses a channel is degraded from in one of two ways (`degrade/5`): a
  server that is out of sessions gets a dedicated fresh connection for this run, a connection
  that turns out to be half-open is evicted from the pool and the run takes one more turn
  through it. Password and PEM-key auth are supported (same `conn_opts` shape as
  `Termelix.SSH.Client`).

  Output is capped: a run accumulates its stdout+stderr in one process on a box that also
  holds the SQLite DB and every live session, so a command that dumps a log file is a
  node-wide memory event, not a slow request. Past `:max_output_bytes` the run gives up with
  `{:error, {:output_too_large, max}}` instead of allocating the whole result.

  Telemetry: one `[:termelix, :ssh, :exec, :stop]` per `run/4` — duration, bytes captured,
  and a coarse `:result`. Emitted caller-side so the timeout and task-crash paths are counted
  too. The command is never in metadata (callers interpolate remote paths and, in the docker
  console, user input into it); host and port are, credentials are not.
  """
  alias Termelix.SSH.Conn
  alias Termelix.SSH.Pool

  # One connect budget for the whole module: the wait a checkout gets for a pooled handshake,
  # and the ceiling on any single dial. Passed explicitly to `Pool.checkout/2` so the pool's
  # own default and the caller-side budget below cannot drift apart — that drift is what made
  # a caller queued behind someone else's handshake get brutal-killed at 15 s and reported as
  # a timeout against its own command. 20 s rather than the 15 s of a dial (pool.ex:19,
  # conn.ex:54): a queued waiter has to outlast the whole handshake it is waiting on.
  @connect_budget 20_000
  @channel_timeout 15_000
  @default_exec_timeout 30_000
  # Slack on top of the worst-case connect + channel-open + collect budget.
  @budget_slack 5_000

  # Cap on the stdout+stderr one run may accumulate. 16 MiB is roughly two orders of
  # magnitude above what the callers actually produce, so it cannot break one: the tmux
  # probes are a `ps -eo` snapshot (~60 B per process, well under 1 MB even at 10k
  # processes) plus tmux listings, and the widest of them — the pane search, capped at
  # 100 panes × 50 matches (tmux.ex:93-95) — only reaches megabytes if every single match
  # is a multi-KB wrapped line. It still bounds a run's peak heap at ~2× the cap, briefly,
  # while `finalize/1` flattens the chunk list.
  @default_max_output_bytes 16 * 1024 * 1024

  @type conn_opts :: %{
          required(:host) => String.t(),
          required(:port) => pos_integer(),
          required(:username) => String.t(),
          optional(:password) => String.t() | nil,
          optional(:private_key) => String.t() | nil,
          optional(:key_password) => String.t() | nil
        }

  @type result :: %{stdout: binary(), stderr: binary(), exit_status: integer() | nil}

  @doc """
  Run `command` on the host and capture output. Returns `{:ok, %{stdout, stderr,
  exit_status}}` or `{:error, reason}` — `{:error, :timeout}` when the command goes silent
  for `timeout` ms or the whole attempt outlives the overall budget, and
  `{:error, {:output_too_large, max}}` when it produced more than `max` bytes of stdout and
  stderr combined.

  Options:

    * `:max_output_bytes` — output budget for this call. Defaults to the
      `:ssh_exec_max_output_bytes` app env, itself defaulting to 16 MiB; `:infinity` turns
      the cap off (the rollback for a caller the cap turns out to break).
  """
  @spec run(conn_opts(), String.t(), timeout(), keyword()) :: {:ok, result()} | {:error, term()}
  def run(conn_opts, command, timeout \\ @default_exec_timeout, opts \\ []) do
    started_at = System.monotonic_time()
    budget = %{timeout: timeout, max_output_bytes: max_output_bytes(opts)}

    task =
      Task.Supervisor.async_nolink(Termelix.TaskSupervisor, fn ->
        exec(conn_opts, command, budget)
      end)

    result =
      case Task.yield(task, overall_budget(timeout)) do
        {:ok, result} ->
          result

        nil ->
          Task.shutdown(task, :brutal_kill)
          {:error, :timeout}

        {:exit, reason} ->
          {:error, reason}
      end

    emit_run(conn_opts, started_at, result)
    result
  end

  defp max_output_bytes(opts) do
    Keyword.get_lazy(opts, :max_output_bytes, fn ->
      Application.get_env(:termelix, :ssh_exec_max_output_bytes, @default_max_output_bytes)
    end)
  end

  defp emit_run(conn_opts, started_at, result) do
    {bytes, outcome} =
      case result do
        {:ok, %{stdout: out, stderr: err, exit_status: status}} ->
          {byte_size(out) + byte_size(err), %{result: :ok, exit_status: status, class: nil}}

        {:error, reason} ->
          {0, %{result: :error, exit_status: nil, class: error_class(reason)}}
      end

    :telemetry.execute(
      [:termelix, :ssh, :exec, :stop],
      %{duration: System.monotonic_time() - started_at, count: 1, bytes: bytes},
      Map.merge(outcome, %{host: conn_opts.host, port: conn_opts.port})
    )
  end

  # Coarse classes only. A task-exit reason carries the crashed task's whole stacktrace and a
  # `{:connect_failed, reason}` carries OTP's auth message; neither belongs in metadata.
  defp error_class(:timeout), do: :timeout
  defp error_class(:exec_failed), do: :exec_failed
  defp error_class({:connect_failed, _}), do: :connect_failed
  defp error_class({:output_too_large, _}), do: :output_too_large
  defp error_class(_), do: :other

  # The caller-side backstop must cover the task's own worst case, or a slow connect gets
  # brutal-killed and reported as an exec timeout against the command. Stage by stage that
  # worst case is: obtain a connection (queue behind a live handshake, or dial) + open a
  # session channel, twice — `exec/3` allows exactly one degrade attempt, either through the
  # pool (after evicting a half-open conn) or on a dedicated connection. The collect timeout
  # is an *idle* timeout, so a command that dribbles output forever is bounded by
  # `:max_output_bytes`, not by this.
  defp overall_budget(:infinity), do: :infinity

  defp overall_budget(timeout),
    do: 2 * (@connect_budget + @channel_timeout) + timeout + @budget_slack

  defp exec(conn_opts, command, budget) do
    case exec_pooled(conn_opts, command, budget) do
      {:degrade, conn, reason} -> degrade(conn_opts, command, budget, conn, reason)
      result -> result
    end
  end

  # One attempt against the pool. `{:degrade, conn, reason}` means the checked-out connection
  # would not give us a session channel — see `degrade/5` for which of the two reasons that is.
  defp exec_pooled(conn_opts, command, budget) do
    case Pool.checkout(conn_opts, @connect_budget) do
      {:ok, conn} ->
        case session_channel(conn) do
          {:ok, chan} -> run_on_channel(conn, chan, command, budget)
          {:error, reason} -> {:degrade, conn, reason}
        end

      {:error, reason} ->
        {:error, {:connect_failed, reason}}
    end
  end

  # A pooled connection that refuses a channel is one of two very different things.
  #
  # Half-open (peer rebooted, NAT dropped the flow): OTP notices nothing until someone tries
  # to use it — the data plane sets no keepalive (`ConnectOpts`) — and nothing evicted it, so
  # with the tmux poller keeping the Conn from ever going idle EVERY probe paid
  # `@channel_timeout` of dead time. Evict it, then take one more turn through the pool
  # rather than `fresh_conn/1`: the replacement is pooled for the next run, and if the host
  # really is gone the failed dial lands in the Conn's cool-down, so the run after this one
  # fails in microseconds instead of dialing again.
  #
  # Server-side refusal (`MaxSessions` pressure): the connection is healthy and only this
  # operation needs somewhere else to run — the pre-pool behavior, a dedicated connection.
  defp degrade(conn_opts, command, budget, conn, reason) do
    if dead_conn?(reason) and evict_half_open?() do
      evict(conn_opts, conn, reason)

      case exec_pooled(conn_opts, command, budget) do
        # A second refusal does not earn a third connection: `overall_budget/1` allows two.
        {:degrade, _conn, retry_reason} -> {:error, {:connect_failed, retry_reason}}
        result -> result
      end
    else
      exec_on_fresh_conn(conn_opts, command, budget)
    end
  end

  defp dead_conn?(reason), do: reason in [:timeout, :closed, :conn_down]

  # Rollback: `config :termelix, ssh_exec_evict_half_open: false` puts every channel refusal
  # back on the single old path (a dedicated connection, the suspect conn stays pooled).
  defp evict_half_open?, do: Application.get_env(:termelix, :ssh_exec_evict_half_open, true)

  defp evict(conn_opts, conn, class) do
    case conn_opts |> Pool.key_for() |> Pool.lookup() do
      nil -> :ok
      pid -> Conn.invalidate(pid, conn, class)
    end
  end

  # Degrade to a dedicated connection for this run — the pre-pool behavior for every run.
  defp exec_on_fresh_conn(conn_opts, command, budget) do
    case Pool.fresh_conn(conn_opts) do
      {:ok, conn} ->
        try do
          case session_channel(conn) do
            {:ok, chan} -> run_on_channel(conn, chan, command, budget)
            {:error, reason} -> {:error, {:connect_failed, reason}}
          end
        after
          safe_close(conn)
        end

      {:error, reason} ->
        {:error, {:connect_failed, reason}}
    end
  end

  # Three shapes have to be normalized here. `{:error, :timeout | :closed}` is the ordinary
  # failure; a gen call to a vanished pid raises instead (`:conn_down`); and a server-side
  # refusal comes back as a bare `{:open_error, reason, desc, lang}` (ssh_connection.erl:373-381
  # passes the handler's reply through verbatim rather than wrapping it), which the previous
  # two-clause `case` did not match at all, so `MaxSessions` pressure raised a CaseClauseError
  # inside the task instead of taking the degrade path that exists for exactly that case.
  defp session_channel(conn) do
    case :ssh_connection.session_channel(conn, @channel_timeout) do
      {:ok, chan} -> {:ok, chan}
      {:error, reason} -> {:error, reason}
      other -> {:error, other}
    end
  catch
    :exit, _ -> {:error, :conn_down}
  end

  defp run_on_channel(conn, chan, command, budget) do
    case :ssh_connection.exec(conn, chan, String.to_charlist(command), budget.timeout) do
      :success ->
        acc = %{stdout: [], stderr: [], exit_status: nil, bytes: 0}
        result = collect(conn, chan, budget, acc)
        safe_close_channel(conn, chan)
        finish(result)

      :failure ->
        safe_close_channel(conn, chan)
        {:error, :exec_failed}

      {:error, reason} ->
        safe_close_channel(conn, chan)
        {:error, {:connect_failed, reason}}
    end
  end

  defp finish(:timeout), do: {:error, :timeout}
  defp finish({:too_large, max}), do: {:error, {:output_too_large, max}}

  defp finish(acc) do
    {:ok,
     %{stdout: finalize(acc.stdout), stderr: finalize(acc.stderr), exit_status: acc.exit_status}}
  end

  defp collect(conn, chan, budget, acc) do
    receive do
      {:ssh_cm, ^conn, {:data, ^chan, 0, data}} ->
        capture(conn, chan, budget, acc, :stdout, data)

      {:ssh_cm, ^conn, {:data, ^chan, 1, data}} ->
        capture(conn, chan, budget, acc, :stderr, data)

      {:ssh_cm, ^conn, {:exit_status, ^chan, status}} ->
        collect(conn, chan, budget, %{acc | exit_status: status})

      {:ssh_cm, ^conn, {:eof, ^chan}} ->
        collect(conn, chan, budget, acc)

      {:ssh_cm, ^conn, {closed, ^chan}} when closed in [:closed, :channel_closed] ->
        acc

      {:ssh_cm, ^conn, _other} ->
        collect(conn, chan, budget, acc)
    after
      # No channel traffic for `timeout` ms: the command is hung. Distinct from a clean
      # close — partial output is never reported as success.
      budget.timeout -> :timeout
    end
  end

  # Stop at the budget instead of accumulating whatever the remote decides to send, and stop
  # granting it window credit while we do: `run_on_channel/4` closes the channel next, so the
  # unread bytes still in flight are the peer's window, not our heap. Truncating and reporting
  # success is deliberately not an option — a caller parsing half a `ps` table would draw
  # wrong conclusions from it, the same reason a hung command is never a partial success.
  defp capture(conn, chan, budget, acc, stream, data) do
    bytes = acc.bytes + byte_size(data)

    if over_budget?(bytes, budget.max_output_bytes) do
      {:too_large, budget.max_output_bytes}
    else
      :ssh_connection.adjust_window(conn, chan, byte_size(data))
      collect(conn, chan, budget, Map.update!(%{acc | bytes: bytes}, stream, &[data | &1]))
    end
  end

  defp over_budget?(_bytes, :infinity), do: false
  defp over_budget?(bytes, max), do: bytes > max

  defp finalize(chunks), do: chunks |> Enum.reverse() |> IO.iodata_to_binary()

  # Only the channel is closed — the connection belongs to the pool.
  defp safe_close_channel(conn, chan) do
    :ssh_connection.close(conn, chan)
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  defp safe_close(conn) do
    :ssh.close(conn)
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end
end
