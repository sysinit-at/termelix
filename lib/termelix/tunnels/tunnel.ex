defmodule Termelix.Tunnels.Tunnel do
  @moduledoc """
  A single, long-lived SSH **local** port forward (the `ssh -L` direction), the port of one
  entry in the Node tunnel manager's `activeTunnelRuntimes` map. Modeled after
  `Termelix.Terminal.Session`: a per-resource GenServer, registered in `Termelix.Tunnels.Registry`
  and supervised by `Termelix.Tunnels.TunnelSupervisor`.

  The process owns the source `:ssh` connection and asks OTP's native tunneling API,
  `:ssh.tcpip_tunnel_to_server/6`, to listen on `bind_host:source_port` locally and forward
  every accepted connection through the SSH connection to `connect_to_host:connect_to_port`
  (resolved from the server's network). This mirrors the Node `establishDirectTunnel` "local"
  branch, but the listener + per-socket `direct-tcpip` plumbing lives inside OTP `:ssh` instead
  of a hand-rolled `net.createServer` + `forwardOut` loop.

  Lifecycle / status (`connecting` → `connected`, or `waiting` → retry, or `failed`) is tracked
  in the Registry value so the control plane can read it without a round-trip, and every change
  is announced on the `"tunnels:status"` PubSub topic for the SSE stream. The connection is
  monitored; a drop auto-reconnects with bounded exponential backoff up to `max_retries`.
  Authentication failures are terminal (no retry), matching the Node classifier.

  The Registry key is `{user_id, name}` — the raw user-chosen name is only unique per user,
  so two users may run same-named tunnels without colliding.

  The blocking `:ssh.connect` (up to 15s) runs in a `Task.Supervisor.async_nolink` task under
  `Termelix.TaskSupervisor`, so `status/1` and `stop/1` are served immediately while a connect
  is in flight (`POST /ssh/tunnel/disconnect` never waits out the connect timeout). An
  established `:ssh` connection is started under OTP's `sshc_sup`, NOT linked to the task that
  created it, with `idle_time: infinity` — so it never self-closes and killing the task does not
  tear it down. Ownership is therefore transferred with an *acknowledged* handoff: the task
  monitors the owner, and the instant `:ssh.connect` returns it sends
  `{:conn_established, task_pid, ref, conn}` and waits. The owner records the pid and replies
  `{:conn_accepted, ref}`, after which `terminate/2` owns the close. If the owner dies before
  acknowledging (a `stop` racing the connect), the task sees the owner's `:DOWN` and closes the
  conn itself. This is why `terminate/2` does NOT brutal-kill an unacknowledged connect task:
  doing so could land in the window between `:ssh.connect` returning and the handoff send,
  orphaning the connection forever — instead the still-living task's owner-monitor guarantees
  cleanup. The task result (`{ref, ...}`) or its `DOWN` then drives the same retry/backoff logic
  an inline connect used to.

  Reverse (`ssh -R`, `tcpip_tunnel_from_server`) and dynamic/SOCKS forwarding are DEFERRED — a
  non-`local` mode connects to an immediate `failed` status with a clear reason and does not
  retry.
  """
  use GenServer, restart: :temporary
  require Logger

  alias Termelix.SSH.ConnectOpts

  @registry Termelix.Tunnels.Registry
  @topic "tunnels:status"

  @connect_timeout 15_000
  @tunnel_timeout 15_000
  @max_backoff 30_000
  # How long the connect task waits for the owner to accept the connection handoff before
  # closing the conn and giving up. The owner acks in microseconds on the happy path; this is
  # only a safety net so the task can never hang holding an un-owned connection.
  @handoff_timeout 15_000

  @type config :: %{
          required(:name) => String.t(),
          required(:user_id) => String.t(),
          required(:host_id) => integer() | String.t() | nil,
          required(:mode) => :local | :remote | :dynamic,
          required(:bind_host) => String.t(),
          required(:source_port) => non_neg_integer(),
          required(:connect_to_host) => String.t(),
          required(:connect_to_port) => non_neg_integer(),
          required(:max_retries) => non_neg_integer(),
          required(:retry_interval) => pos_integer(),
          required(:conn_opts) => map()
        }

  # --- public API -----------------------------------------------------------

  @doc "Start a tunnel process. Connect happens asynchronously (status is broadcast)."
  @spec start_link(config()) :: GenServer.on_start()
  def start_link(config), do: GenServer.start_link(__MODULE__, config)

  @doc "The rendered `TunnelStatus` map for this tunnel."
  @spec status(pid()) :: map()
  def status(pid), do: GenServer.call(pid, :status)

  @doc "The actual local port being listened on (0 in config resolves to an OS-picked port)."
  @spec listen_port(pid()) :: non_neg_integer() | nil
  def listen_port(pid), do: GenServer.call(pid, :listen_port)

  @doc "Stop the tunnel (closes the SSH connection and its listener)."
  @spec stop(pid()) :: :ok
  @stop_timeout_ms 5_000

  def stop(pid) do
    GenServer.stop(pid, :normal, @stop_timeout_ms)
  catch
    :exit, {:noproc, _} ->
      :ok

    # Wedged inside `:ssh`. Unbounded here would make revocation hostage to the slowest
    # tunnel: one stuck forward would leave every LATER tunnel of a revoked user still up.
    :exit, _ ->
      Process.exit(pid, :kill)
      :ok
  end

  # --- server ---------------------------------------------------------------

  @impl true
  def init(config) do
    Process.flag(:trap_exit, true)

    state =
      config
      |> Map.merge(%{
        status: :connecting,
        conn: nil,
        monitor: nil,
        listen_port: nil,
        connect_task: nil,
        retry_count: 0,
        retry_exhausted: false,
        reason: nil,
        error_type: nil,
        next_retry_in: nil,
        retry_timer: nil
      })

    case Registry.register(@registry, key(state), meta(state)) do
      {:ok, _} ->
        broadcast(state)
        send(self(), :connect)
        {:ok, state}

      {:error, _} ->
        {:stop, :name_taken}
    end
  end

  @impl true
  def handle_call(:status, _from, state), do: {:reply, render(state), state}
  def handle_call(:listen_port, _from, state), do: {:reply, state.listen_port, state}

  # Reverse/dynamic forwarding is not ported — fail fast, terminal (no retry).
  @impl true
  def handle_info(:connect, %{mode: mode} = state) when mode != :local do
    reason = "Reverse (remote) and dynamic (SOCKS) forwarding are not supported yet (deferred)"
    {:noreply, transition(state, :failed, reason: reason, error_type: "CONNECTION_FAILED")}
  end

  def handle_info(:connect, %{connect_task: %Task{}} = state) do
    # A connect is already in flight (cannot happen via the retry flow); ignore the duplicate.
    {:noreply, %{state | retry_timer: nil}}
  end

  def handle_info(:connect, state) do
    # The connect blocks for up to @connect_timeout (+ @tunnel_timeout for the forward
    # setup); run it out-of-process so status/stop calls are served immediately. The task
    # reports its established connection back to us (see `do_connect/2`).
    parent = self()

    task =
      Task.Supervisor.async_nolink(Termelix.TaskSupervisor, fn -> do_connect(state, parent) end)

    {:noreply, %{state | retry_timer: nil, connect_task: task}}
  end

  # The connect task finished: continue setup exactly as an inline connect would have.
  def handle_info({ref, result}, %{connect_task: %{ref: ref}} = state)
      when is_reference(ref) do
    Process.demonitor(ref, [:flush])
    state = %{state | connect_task: nil}

    case result do
      {:ok, conn, listen_port} ->
        monitor = if is_pid(conn), do: Process.monitor(conn), else: nil

        state = %{
          state
          | conn: conn,
            monitor: monitor,
            listen_port: listen_port,
            retry_count: 0,
            retry_exhausted: false,
            reason: nil,
            error_type: nil,
            next_retry_in: nil
        }

        {:noreply, transition(state, :connected)}

      {:error, err} ->
        # `do_connect/2` already closed the connection on this path; drop the now-stale pid.
        {reason, type} = classify(err)
        Logger.warning("Tunnel '#{state.name}' connect failed: #{reason}")
        {:noreply, handle_failure(%{state | conn: nil}, reason, type)}
    end
  end

  # The connect task established its SSH connection and is offering ownership before the (slower)
  # forward setup. Record the pid and acknowledge, so the task knows the owner — not it — is now
  # responsible for closing the conn. The offer must match the in-flight task; a mismatch is not
  # reachable under the single-task protocol, but close defensively rather than orphan it.
  def handle_info(
        {:conn_established, task_pid, handoff_ref, conn},
        %{connect_task: %{pid: task_pid}} = state
      )
      when is_pid(conn) do
    send(task_pid, {:conn_accepted, handoff_ref})
    {:noreply, %{state | conn: conn}}
  end

  def handle_info({:conn_established, _task_pid, _handoff_ref, conn}, state) when is_pid(conn) do
    safe_close(conn)
    {:noreply, state}
  end

  # The connect task crashed without delivering a result — a connect failure like any other. If
  # it had already reported an established connection, that connection outlives the (unlinked)
  # task, so close it here rather than orphan it.
  def handle_info({:DOWN, ref, :process, _pid, reason}, %{connect_task: %{ref: ref}} = state) do
    if is_pid(state.conn), do: safe_close(state.conn)
    state = %{state | connect_task: nil, conn: nil}
    {message, type} = classify({:connect_failed, reason})
    Logger.warning("Tunnel '#{state.name}' connect task crashed: #{message}")
    {:noreply, handle_failure(state, message, type)}
  end

  # The source SSH connection dropped — tear down and reconnect (unless it is terminal).
  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{monitor: ref} = state) do
    state = %{state | conn: nil, monitor: nil, listen_port: nil}
    {:noreply, handle_failure(state, "Tunnel connection lost", "NETWORK_ERROR")}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    # Close the source connection iff the handoff was acknowledged — then it lives in
    # `state.conn` and we own it. We deliberately do NOT kill an in-flight, *unacknowledged*
    # connect task: it monitors us, so if `:ssh.connect` completes after we're gone it observes
    # our `:DOWN` and closes its own conn. Brutal-killing it instead could land in the window
    # between `:ssh.connect` returning and the handoff send, orphaning the connection forever
    # (unlinked, `idle_time: infinity`).
    if is_map(state) and is_pid(state[:conn]), do: safe_close(state.conn)

    # Unregister synchronously (Registry's own DOWN cleanup is async) so a same-name reconnect
    # and any status read immediately after `stop/1` see the entry already gone.
    if is_map(state) and is_binary(state[:name]) do
      Registry.unregister(@registry, key(state))
    end

    :ok
  catch
    _, _ -> :ok
  end

  # --- connect / forward ----------------------------------------------------

  # Runs in the connect task. Establishes the connection, then hands ownership to the tunnel
  # process with an *acknowledged* handoff before the (slower) forward setup. The owner is
  # monitored so that if the tunnel is stopped before it accepts the handoff — the window a
  # `:brutal_kill` used to orphan the conn in — this task closes the conn itself instead of
  # leaking it.
  #
  # Exposed (`@doc false`) rather than private so the leak-race regression test can drive it with
  # a stand-in owner that dies before acknowledging; it is not part of the public API.
  @doc false
  def do_connect(state, parent) do
    parent_ref = Process.monitor(parent)

    case ssh_connect(state.conn_opts) do
      {:ok, conn} ->
        handoff_ref = make_ref()
        send(parent, {:conn_established, self(), handoff_ref, conn})

        receive do
          {:conn_accepted, ^handoff_ref} ->
            Process.demonitor(parent_ref, [:flush])
            forward_after_handoff(conn, state)

          {:DOWN, ^parent_ref, :process, _pid, _reason} ->
            # Owner gone before accepting ownership — this task is the only party holding the
            # conn, so close it here rather than orphan it.
            safe_close(conn)
            exit(:normal)
        after
          @handoff_timeout ->
            # Owner neither accepted nor died within the window (not reachable in practice);
            # don't leak the conn.
            Process.demonitor(parent_ref, [:flush])
            safe_close(conn)
            exit(:normal)
        end

      {:error, reason} ->
        Process.demonitor(parent_ref, [:flush])
        {:error, {:connect_failed, reason}}
    end
  end

  defp forward_after_handoff(conn, state) do
    case open_forward(conn, state) do
      {:ok, listen_port} ->
        {:ok, conn, listen_port}

      {:error, reason} ->
        safe_close(conn)
        {:error, {:tunnel_failed, reason}}
    end
  end

  # `ssh -L`: listen on bind_host:source_port, forward each connection through the server to
  # connect_to_host:connect_to_port. Returns the actually-bound local port.
  defp open_forward(conn, state) do
    :ssh.tcpip_tunnel_to_server(
      conn,
      String.to_charlist(state.bind_host),
      state.source_port,
      String.to_charlist(state.connect_to_host),
      state.connect_to_port,
      @tunnel_timeout
    )
  end

  defp ssh_connect(opts) do
    host = String.to_charlist(opts.host)

    # The `:tunnel` profile deliberately carries no `idle_time`: this connection sits with zero
    # channels open whenever no TCP client is using the forward, so the data-plane backstop
    # would reap a perfectly healthy tunnel.
    case :ssh.connect(host, opts.port, ConnectOpts.build(opts, :tunnel), @connect_timeout) do
      {:ok, conn} -> {:ok, conn}
      {:error, reason} -> {:error, reason}
    end
  end

  # --- retry / backoff ------------------------------------------------------

  defp handle_failure(state, reason, type) do
    cond do
      # An SSH-layer auth failure will never fix itself on retry (Node parity).
      type == "AUTHENTICATION_FAILED" ->
        transition(%{state | next_retry_in: nil}, :failed, reason: reason, error_type: type)

      state.retry_count + 1 > state.max_retries ->
        transition(
          %{
            state
            | retry_count: state.retry_count + 1,
              retry_exhausted: true,
              next_retry_in: nil
          },
          :failed,
          reason: "Max retries exhausted: #{reason}",
          error_type: type
        )

      true ->
        retry_count = state.retry_count + 1
        delay = backoff(state.retry_interval, retry_count)
        timer = Process.send_after(self(), :connect, delay)

        transition(
          %{
            state
            | retry_count: retry_count,
              next_retry_in: div(delay, 1000),
              retry_timer: timer
          },
          :waiting,
          reason: reason,
          error_type: type
        )
    end
  end

  # Deterministic bounded exponential backoff: base, 2·base, 4·base … capped at @max_backoff.
  defp backoff(base, attempt) do
    min(base * Integer.pow(2, attempt - 1), @max_backoff)
  end

  # --- status bookkeeping ---------------------------------------------------

  # Update in-process status, mirror it into the Registry value (so the control plane reads it
  # without messaging us), and announce the change for the SSE stream.
  defp transition(state, status, extra \\ []) do
    state = state |> Map.put(:status, status) |> Map.merge(Map.new(extra))
    Registry.update_value(@registry, key(state), fn _ -> meta(state) end)
    broadcast(state)
    state
  end

  # The Registry key: tunnel names are only unique per user.
  defp key(state), do: {state.user_id, state.name}

  defp broadcast(state) do
    Phoenix.PubSub.broadcast(Termelix.PubSub, @topic, {:tunnel_status, state.name, state.status})
  end

  defp meta(state) do
    %{user_id: state.user_id, host_id: state.host_id, status: render(state)}
  end

  # The `TunnelStatus` wire shape the React frontend consumes (`types/index.ts`): lowercase
  # `status` string + `connected`, with the optional fields present only when meaningful.
  defp render(state) do
    %{connected: state.status == :connected, status: Atom.to_string(state.status)}
    |> maybe(:retryCount, state.retry_count > 0 && state.retry_count)
    |> maybe(:maxRetries, state.status == :waiting && state.max_retries)
    |> maybe(:nextRetryIn, state.status == :waiting && state.next_retry_in)
    |> maybe(:reason, state.reason)
    |> maybe(:errorType, state.error_type)
    |> maybe(:retryExhausted, state.retry_exhausted && true)
  end

  defp maybe(map, _key, value) when value in [nil, false], do: map
  defp maybe(map, key, value), do: Map.put(map, key, value)

  # --- error classification (port of `classifyTunnelError`) ------------------

  # OTP `:ssh` surfaces bad auth as a message about "Unable to connect using the available
  # authentication methods"; treat that (and permission denied) as a terminal auth failure.
  defp classify({:connect_failed, reason}), do: {format(reason), classify_type(reason)}

  defp classify({:tunnel_failed, reason}),
    do: {"Port forwarding failed: #{format(reason)}", "CONNECTION_FAILED"}

  defp classify_type(reason) do
    msg = reason |> format() |> String.downcase()

    cond do
      contains_any?(msg, [
        "authentication",
        "permission denied",
        "incorrect password",
        "unable to connect using"
      ]) ->
        "AUTHENTICATION_FAILED"

      contains_any?(msg, ["timeout", "timed out", "etimedout"]) ->
        "TIMEOUT"

      contains_any?(msg, ["already in use", "port forwarding failed", "eaddrinuse"]) ->
        "CONNECTION_FAILED"

      contains_any?(msg, ["closed", "reset", "refused", "broken pipe", "econnrefused"]) ->
        "NETWORK_ERROR"

      true ->
        "UNKNOWN"
    end
  end

  defp contains_any?(haystack, needles), do: Enum.any?(needles, &String.contains?(haystack, &1))

  defp format(reason) when is_binary(reason), do: reason
  defp format(reason) when is_atom(reason), do: to_string(reason)
  defp format(reason), do: inspect(reason)

  # --- small helpers --------------------------------------------------------

  defp safe_close(conn) do
    :ssh.close(conn)
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end
end
