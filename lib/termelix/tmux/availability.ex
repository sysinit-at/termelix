defmodule Termelix.Tmux.Availability do
  @moduledoc """
  Does this host have tmux? — answered from a cache, so the tri-state `enableTmuxShell`
  (nil = detect) never pays for a detection round trip on the connect path.

  The one latency number a user feels when opening a terminal is keystroke-to-first-prompt.
  Running `tmux -V` over SSH before every attach would add a whole exec (worst case a fresh
  dial) to it, so the probe is decoupled from the answer: `available?/2` reads a cached
  verdict, and only a *miss* starts a probe — one, in a supervised task, with a bounded wait
  (see "Bounding the connect path" below).

  ## Verdicts

    * `true` — `tmux -V` printed a version;
    * `false` — the remote shell ran and could not find tmux (non-zero exit, typically 127);
    * `:unknown` — we do not know: nothing cached yet and the probe did not answer inside the
      wait, or the probe failed (unreachable host, auth failure, timeout).

  `:unknown` is deliberately NOT `false`. A host that was merely down would otherwise be
  recorded as "no tmux" and the feature would stay silently disabled for a whole TTL. The
  caller decides what `:unknown` means for it (today: fall back to a plain shell) and gets a
  definitive answer on the next connect, because the probe keeps running and fills the cache.

  ## Cache

  A named public ETS table (`:termelix_tmux_availability`) created and swept by
  `Termelix.EtsOwner` — the same arrangement the rate-limiter and HTTP-cache tables use
  (`ets_owner.ex:36-39` creates, `:46-49` sweeps), so the table outlives the request process
  that first touched it. Rows are `{key, verdict, expires_at_ms}`, keyed by the SSH endpoint
  (`{host_id, ip, port, username}`): edit a host's address and the old verdict is simply not
  looked up again.

  Three TTLs, longest to shortest, because the three verdicts age differently:

    * `true` — 30 min. tmux does not get uninstalled during a session.
    * `false` — 5 min. A `false` disables the feature silently, so re-detect soon after an
      admin installs tmux; a probe every 5 min is nothing next to a probe per connect, which
      is exactly what the negative cache exists to prevent.
    * `:unknown` — 1 min. A cool-down: a host that is down must not be re-dialed by every
      connect either.

  ## Bounding the connect path

  Three separate bounds, because `Termelix.SSH.Exec` alone is not one — its caller-side
  backstop is `2 * (connect + channel) + timeout` (`exec.ex:140-143`), i.e. over a minute on a
  host that is dead but not yet in its `Conn` cool-down:

    1. The probe never runs in the caller. It runs in a `Termelix.TaskSupervisor` task that
       writes the cache itself, so it may outlive the connect that started it.
    2. The caller waits at most `:wait_ms` (default 1s, `:tmux_availability_wait_ms` app env,
       `0` to never wait) for that task, via an explicit monitor that is flushed on timeout —
       nothing stray ever lands in the caller's mailbox, and the task is never killed.
    3. Only one probe per host is in flight: the claim is an atomic ETS CAS (same shape as
       `Termelix.RateLimiter.cas_totp_step/2`), and a caller that loses it gets `:unknown`
       immediately rather than queueing behind someone else's dial.

  So the worst case this adds to a connect is `:wait_ms`, and only on a cache miss.
  """

  require Logger

  alias Termelix.Hosts
  alias Termelix.SSH.Exec
  alias Termelix.Tmux

  @table :termelix_tmux_availability

  @available_ttl_ms 30 * 60 * 1000
  @missing_ttl_ms 5 * 60 * 1000
  @unknown_ttl_ms 60 * 1000

  # Lifetime cap on an in-flight claim. Only reached when the probing task is killed without
  # writing its row (it overwrites the claim on every other path, crash included), so it just
  # has to outlast the task: `Exec.run/4`'s own worst case is
  # `2 * (20_000 + 15_000) + timeout + 5_000` (exec.ex:140-143) = 85s for our timeout.
  @probing_ttl_ms 90 * 1000

  # The probe is a version string, not a data transfer: a host that cannot answer in 10s is
  # not going to give us a useful shell either.
  @exec_timeout_ms 10_000

  @default_wait_ms 1_000

  @type verdict :: boolean() | :unknown

  @doc """
  Create the ETS table if it does not exist yet. Called by `Termelix.EtsOwner.init/1`; kept
  idempotent so a caller that runs before the owner still works.

  Unlike its peers this checks `:ets.whereis/1` first instead of raising and rescuing on every
  call — the check runs on the connect path, and an exception per terminal open buys nothing.
  """
  @spec ensure_table() :: :ok
  def ensure_table do
    case :ets.whereis(@table) do
      :undefined -> create_table()
      _tid -> :ok
    end
  end

  defp create_table do
    :ets.new(@table, [
      :named_table,
      :public,
      :set,
      read_concurrency: true,
      write_concurrency: true
    ])

    :ok
  rescue
    # Another process created it between the `whereis` and here.
    ArgumentError -> :ok
  end

  @doc """
  Whether `host` can host a tmux shell: `true`, `false` or `:unknown` (never an exception —
  this sits on the connect path).

  `host` must be DEK-decrypted (`Termelix.Hosts.get_for_user(id, user_id, decrypt: true)`), the
  same shape `Termelix.Tmux` execs with; the probe reuses `Termelix.Tmux.conn_opts/1` so it
  inherits the host-key pin rather than hand-rolling a second connection map.

  Options:

    * `:wait_ms` — how long the caller may wait for a probe started by this call. Defaults to
      the `:tmux_availability_wait_ms` app env, itself 1s. `0` returns `:unknown` immediately
      and lets the probe fill the cache for the next connect.
    * `:now_ms` — monotonic-clock override, so tests can advance time instead of sleeping
      (the trailing-`now_ms` convention of `Termelix.RateLimiter`).
  """
  @spec available?(map(), keyword()) :: verdict()
  def available?(host, opts \\ []) do
    ensure_table()
    now_ms = Keyword.get_lazy(opts, :now_ms, &now/0)
    key = cache_key(host)

    case lookup(key, now_ms) do
      # Someone else's probe is in flight. Waiting on it would mean queueing this connect
      # behind their dial; the cache will be warm for the next one.
      {:ok, :probing} -> :unknown
      {:ok, verdict} -> verdict
      :miss -> miss(key, host, now_ms, wait_ms(opts))
    end
  end

  @doc """
  Forget the cached verdict for `host` — for when something learns more than the probe did
  (a host edit, or an attach that failed because tmux was gone). The next `available?/2`
  re-probes.
  """
  @spec invalidate(map()) :: :ok
  def invalidate(host) do
    ensure_table()
    :ets.delete(@table, cache_key(host))
    :ok
  end

  @doc """
  Delete every row whose TTL has lapsed as of `now_ms`, returning the number removed. Driven
  every 60s by `Termelix.EtsOwner` — lapsed verdicts are erased rather than left to be
  ignored on a read that may never come (a host can be deleted while its verdict sits here).
  """
  @spec sweep_expired(integer()) :: non_neg_integer()
  def sweep_expired(now_ms \\ now()) do
    ensure_table()
    spec = [{{:_, :_, :"$1"}, [{:"=<", :"$1", now_ms}], [true]}]
    :ets.select_delete(@table, spec)
  end

  # --- probing ----------------------------------------------------------------

  defp miss(key, host, now_ms, wait_ms) do
    case claim(key, now_ms) do
      :won -> key |> spawn_probe(host, now_ms) |> await(wait_ms, key, now_ms)
      :lost -> :unknown
    end
  end

  # Single-flight: win the key outright when no row exists, or take over one whose TTL has
  # lapsed. `select_replace/2` applies its guard per object atomically, so exactly one of
  # several racing callers can flip a lapsed row — the CAS shape of
  # `Termelix.RateLimiter.cas_totp_step/2` (rate_limiter.ex:156-180).
  defp claim(key, now_ms) do
    until = now_ms + @probing_ttl_ms

    cond do
      :ets.insert_new(@table, {key, :probing, until}) ->
        :won

      :ets.select_replace(@table, claim_spec(key, now_ms, until)) == 1 ->
        :won

      true ->
        :lost
    end
  end

  defp claim_spec(key, now_ms, until) do
    [{{key, :_, :"$1"}, [{:"=<", :"$1", now_ms}], [{{{:const, key}, :probing, until}}]}]
  end

  # The task owns the write, so the verdict is cached whether or not anyone is still waiting
  # for it — that is what makes the next connect definitive after a `:wait_ms` timeout.
  # `now_ms` travels in so the row's expiry is on the caller's clock, which tests drive.
  defp spawn_probe(key, host, now_ms) do
    {:ok, pid} =
      Task.Supervisor.start_child(Termelix.TaskSupervisor, fn ->
        started_at = System.monotonic_time()
        verdict = run_prober(host)
        :ets.insert(@table, {key, verdict, now_ms + ttl_ms(verdict)})
        emit(host, started_at, verdict)
      end)

    pid
  end

  # A prober that raises is a bug in us, not a verdict about the host: report `:unknown` (and
  # cache it briefly) rather than letting the task die with the claim still standing, which
  # would freeze every connect on `:unknown` until `@probing_ttl_ms` lapsed.
  defp run_prober(host) do
    normalize(prober().(host))
  rescue
    e ->
      Logger.warning(
        "tmux availability probe crashed for host #{inspect(host_id(host))}: " <>
          Exception.message(e)
      )

      :unknown
  end

  # The prober is a swappable seam; anything it returns that is not a verdict is `:unknown`,
  # so the stored value always has a TTL and the task can never die holding the claim.
  defp normalize(true), do: true
  defp normalize(false), do: false
  defp normalize(_other), do: :unknown

  defp await(_pid, wait_ms, _key, _now_ms) when wait_ms <= 0, do: :unknown

  defp await(pid, wait_ms, key, now_ms) do
    ref = Process.monitor(pid)

    receive do
      {:DOWN, ^ref, :process, ^pid, _reason} ->
        case lookup(key, now_ms) do
          {:ok, :probing} -> :unknown
          {:ok, verdict} -> verdict
          :miss -> :unknown
        end
    after
      wait_ms ->
        # Leave the probe running — it still fills the cache for the next connect — but flush
        # the monitor: this runs inside the terminal socket process and a stray `:DOWN` there
        # would be an unexpected message on a long-lived connection.
        Process.demonitor(ref, [:flush])
        :unknown
    end
  end

  @doc false
  @spec ssh_probe(map()) :: verdict()
  def ssh_probe(host) do
    # `Tmux.tmux_command/1` wraps this in the PATH-prefixing `/bin/sh -c` shim, so a tmux that
    # only lives in /opt/homebrew/bin is not reported as absent (tmux.ex:580-589). Nothing
    # user-supplied is interpolated — the whole script is a constant, escaped by the shim.
    host
    |> Tmux.conn_opts()
    |> Exec.run(Tmux.tmux_command("-V"), @exec_timeout_ms)
    |> verdict_from_exec()
  end

  @doc """
  Interpret one `tmux -V` exec result. Public for the test that pins the rule this module
  exists for: only a shell that ran and could not find tmux is `false`; every failure —
  connect, auth, timeout, an exit status we never got — is `:unknown`.
  """
  @spec verdict_from_exec({:ok, map()} | {:error, term()}) :: verdict()
  def verdict_from_exec({:ok, result}) do
    out = result |> Map.get(:stdout, "") |> String.trim()
    status = Map.get(result, :exit_status)

    cond do
      # "tmux 3.4" / "tmux next-3.6", scanned per line so a chatty rc file cannot hide it.
      version_line?(out) -> true
      is_integer(status) and status != 0 -> false
      # Ran, exited 0, said nothing recognizable. Not evidence of absence.
      true -> :unknown
    end
  end

  def verdict_from_exec({:error, _reason}), do: :unknown

  defp version_line?(out) do
    out
    |> String.split("\n")
    |> Enum.any?(&String.starts_with?(String.trim(&1), "tmux "))
  end

  # Swappable so tests can drive verdicts without an SSH server (the `:ldap_client` seam of
  # `Termelix.Ldap`, narrowed to one function).
  defp prober do
    case Application.get_env(:termelix, :tmux_availability_prober) do
      fun when is_function(fun, 1) -> fun
      _ -> &ssh_probe/1
    end
  end

  defp emit(host, started_at, verdict) do
    :telemetry.execute(
      [:termelix, :tmux, :availability],
      %{count: 1, duration: System.monotonic_time() - started_at},
      %{host_id: host_id(host), result: verdict}
    )
  end

  # --- cache primitives -------------------------------------------------------

  defp lookup(key, now_ms) do
    case :ets.lookup(@table, key) do
      [{_key, verdict, expires_at}] when now_ms < expires_at -> {:ok, verdict}
      _ -> :miss
    end
  end

  # The SSH endpoint, not just the row id: repointing a host at another machine must not
  # inherit the old machine's verdict, and `effective_ssh_port/1` is the port the probe (and
  # every connect) actually dials.
  defp cache_key(host) do
    {host_id(host), Map.get(host, :ip), Hosts.effective_ssh_port(host), Map.get(host, :username)}
  end

  defp host_id(host), do: Map.get(host, :id)

  defp wait_ms(opts) do
    Keyword.get_lazy(opts, :wait_ms, fn ->
      Application.get_env(:termelix, :tmux_availability_wait_ms, @default_wait_ms)
    end)
  end

  defp now, do: System.monotonic_time(:millisecond)

  @doc false
  @spec ttl_ms(verdict()) :: pos_integer()
  def ttl_ms(true), do: @available_ttl_ms
  def ttl_ms(false), do: @missing_ttl_ms
  def ttl_ms(:unknown), do: @unknown_ttl_ms

  @doc false
  @spec reset() :: :ok
  def reset do
    ensure_table()
    :ets.delete_all_objects(@table)
    :ok
  end

  @doc false
  @spec size() :: non_neg_integer()
  def size do
    ensure_table()
    :ets.info(@table, :size)
  end
end
