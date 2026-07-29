defmodule Termelix.Tmux.Watcher do
  @moduledoc """
  One process per watched host, polling its tmux state so nobody else has to.

  ## Why this exists

  The monitor polls from the *browser*: every open tab issues its own SSH exec on its own timer,
  so two tabs on one host meant two connections doing identical work, and closing the tab meant
  the fleet stopped being observed at all. That is the wrong place for the loop. An agent that
  dispatches a command and walks away needs the state to keep being collected after every human
  has closed every tab — otherwise "tell me when it finishes" cannot be built at all.

  So the server owns the loop, one watcher per host regardless of how many viewers there are,
  and viewers subscribe to `Phoenix.PubSub` instead of driving SSH.

  ## Started by interest, stopped by its absence

  A watcher is not started for every host that exists — that would open an SSH connection to
  every machine the operator has ever saved, forever, whether or not anyone cares. It is started
  on demand (`ensure_started/2`) and stops itself after `@idle_shutdown_ms` with no subscribers
  and no agent waiting on it. Interest is refreshed by `touch/2`.

  ## The adaptive interval

  Polling a host every 2 s forever is rude to the host and expensive for us; polling every 30 s
  makes `awaiting_input` arrive too late to be useful. So the interval follows what the host is
  actually doing:

    * something changed on the last tick, or a pane is `:awaiting_input` -> **2 s**
    * something changed within the last minute -> **5 s**
    * quiet -> **30 s**
    * failing -> exponential backoff to 5 min, because a host that is down does not become
      reachable faster by being asked more often.

  ## Skip-and-log, not crash-and-restart

  Two conditions make a host permanently unwatchable rather than temporarily unreachable: the
  owner's DEK cannot be unwrapped (so the credentials are ciphertext — see
  `Termelix.Hosts.fetch_for_connect/2`), and the host is gone. Both would otherwise raise on
  every tick and burn the supervisor's restart intensity until it gave up on siblings too. The
  watcher publishes the reason and stops cleanly — a diagnosis the operator can see, instead of
  a crash loop they have to read logs to understand.
  """

  use GenServer, restart: :transient

  require Logger

  alias Termelix.Hosts
  alias Termelix.Tmux
  alias Termelix.Tmux.Activity

  @registry Termelix.Tmux.WatcherRegistry
  @supervisor Termelix.Tmux.WatcherSupervisor

  @active_interval_ms 2_000
  @recent_interval_ms 5_000
  @idle_interval_ms 30_000
  @max_backoff_ms 300_000

  # How long a change counts as "recent" for the middle interval.
  @recent_window_ms 60_000

  # No subscriber and no waiter for this long and the watcher stops. Long enough to survive a
  # page reload, short enough that a closed tab does not leave an SSH poll running for an hour.
  @idle_shutdown_ms 120_000

  @type key :: {String.t(), integer()}

  # --- api --------------------------------------------------------------------

  @doc """
  Start a watcher for `host_id` owned by `user_id`, or return the running one. Idempotent, and
  safe to call on every subscribe.
  """
  @spec ensure_started(String.t(), integer()) :: {:ok, pid()} | {:error, term()}
  def ensure_started(user_id, host_id) do
    case whereis(user_id, host_id) do
      nil ->
        case DynamicSupervisor.start_child(@supervisor, {__MODULE__, {user_id, host_id}}) do
          {:ok, pid} -> {:ok, pid}
          {:error, {:already_started, pid}} -> {:ok, pid}
          {:error, reason} -> {:error, reason}
        end

      pid ->
        {:ok, pid}
    end
  end

  @doc "The running watcher for this (user, host), or nil."
  @spec whereis(String.t(), integer()) :: pid() | nil
  def whereis(user_id, host_id) do
    case Registry.lookup(@registry, {user_id, host_id}) do
      [{pid, _}] -> pid
      _ -> nil
    end
  end

  @doc """
  Observe now instead of at the next scheduled tick.

  For a caller that has just CHANGED something and needs to know what happened — `wait/4`
  after a `dispatch`. Without it the caller either accepts a snapshot taken before its own
  action (which is how a `wait` returns the result of the previous command) or blocks for up to
  a full idle interval to find out about something that already happened.

  A cast, and idempotent in effect: the worst case is one extra observation.
  """
  @spec poll_now(String.t(), integer()) :: :ok
  def poll_now(user_id, host_id) do
    case whereis(user_id, host_id) do
      nil -> :ok
      pid -> GenServer.cast(pid, :poll_now)
    end
  end

  @doc """
  Record interest, keeping the watcher alive. Cheap enough to call on every poll or SSE tick.
  """
  @spec touch(String.t(), integer()) :: :ok
  def touch(user_id, host_id) do
    case whereis(user_id, host_id) do
      nil -> :ok
      pid -> GenServer.cast(pid, :touch)
    end
  end

  @doc """
  The last observation, without touching SSH. `{:ok, snapshot}` where `snapshot` carries an
  `age_ms` so a caller can decide whether it is fresh enough, or `:miss` before the first tick.

  `age_ms` is not decoration. A cached value with no age is indistinguishable from a live one,
  and a caller that cannot tell will eventually show a five-minute-old screen as current.
  """
  @spec snapshot(String.t(), integer()) :: {:ok, map()} | :miss
  def snapshot(user_id, host_id) do
    case whereis(user_id, host_id) do
      nil -> :miss
      pid -> GenServer.call(pid, :snapshot, 5_000)
    end
  catch
    :exit, _ -> :miss
  end

  @doc "PubSub topic for one host's updates: `{:tmux_state, host_id, snapshot}`."
  @spec topic(String.t(), integer()) :: String.t()
  def topic(user_id, host_id), do: "tmux:#{user_id}:#{host_id}"

  @doc "PubSub topic for every host of one user — what the control channel subscribes to."
  @spec user_topic(String.t()) :: String.t()
  def user_topic(user_id), do: "tmux:#{user_id}"

  @doc """
  Stop every watcher belonging to `user_id`, returning how many were stopped.

  Revocation's fourth surface, and the one most likely to be forgotten because a watcher is
  not something a user opened — it is something the server started on their behalf. It holds
  their credentials and dials their host on a timer, and it does NOT expire while any pane is
  `awaiting_input` (by design: a pane waiting for an answer is exactly what must not be
  dropped). So a revoked user's watcher would have gone on polling their machine, with their
  key, indefinitely.
  """
  @spec stop_user_watchers(String.t()) :: non_neg_integer()
  def stop_user_watchers(user_id) do
    pids =
      Registry.select(@registry, [
        {{:_, :"$1", :"$2"}, [{:==, {:map_get, :user_id, :"$2"}, user_id}], [:"$1"]}
      ])

    Enum.each(pids, fn pid ->
      try do
        GenServer.stop(pid, :normal, 5_000)
      catch
        :exit, {:noproc, _} -> :ok
        :exit, _ -> Process.exit(pid, :kill)
      end
    end)

    length(pids)
  end

  @doc "Stop the watcher for this (user, host). Idempotent."
  @spec stop(String.t(), integer()) :: :ok
  def stop(user_id, host_id) do
    case whereis(user_id, host_id) do
      nil -> :ok
      pid -> GenServer.stop(pid, :normal, 5_000)
    end
  catch
    :exit, _ -> :ok
  end

  @doc false
  def start_link({user_id, host_id}) do
    GenServer.start_link(__MODULE__, {user_id, host_id},
      name: {:via, Registry, {@registry, {user_id, host_id}, %{user_id: user_id}}}
    )
  end

  # --- server -----------------------------------------------------------------

  @impl true
  def init({user_id, host_id}) do
    # Nothing blocking here: `init/1` runs inside the supervisor, and an SSH dial in it would
    # serialize every other watcher's startup behind this host's connect timeout.
    {:ok,
     %{
       user_id: user_id,
       host_id: host_id,
       snapshot: nil,
       states: %{},
       # Last tick's screen per pane — the second sample `Activity.classify/1`'s
       # `hash_stable?` needs, and the only piece of the observation that cannot come from a
       # single poll.
       tails: %{},
       last_change_at: nil,
       last_touched_at: now(),
       failures: 0,
       timer: nil
     }, {:continue, :first_tick}}
  end

  @impl true
  def handle_continue(:first_tick, state), do: {:noreply, tick(state)}

  @impl true
  def handle_call(:snapshot, _from, state) do
    reply =
      case state.snapshot do
        nil -> :miss
        snapshot -> {:ok, Map.put(snapshot, :age_ms, now() - snapshot.observed_at)}
      end

    {:reply, reply, %{state | last_touched_at: now()}}
  end

  @impl true
  def handle_cast(:touch, state), do: {:noreply, %{state | last_touched_at: now()}}

  def handle_cast(:poll_now, state) do
    if state.timer, do: Process.cancel_timer(state.timer)
    {:noreply, tick(%{state | timer: nil, last_touched_at: now()})}
  end

  @impl true
  def handle_info(:tick, state) do
    if idle_too_long?(state) do
      Logger.debug("tmux watcher for host #{state.host_id} stopping: no interest")
      {:stop, :normal, state}
    else
      {:noreply, tick(state)}
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    if state.timer, do: Process.cancel_timer(state.timer)
    :ok
  end

  # --- the loop ---------------------------------------------------------------

  defp tick(state) do
    case Hosts.fetch_for_connect(state.host_id, state.user_id) do
      {:ok, host} ->
        state |> observe(host) |> schedule()

      # Permanently unwatchable, both of them. Publishing the reason and stopping beats raising
      # every tick against the supervisor's restart intensity — and beats silence, which is what
      # an operator gets today when a watcher dies for a reason nobody surfaced.
      {:error, reason} ->
        publish(state, %{
          available: false,
          unwatchable: reason,
          sessions: [],
          observed_at: now()
        })

        Logger.info("tmux watcher for host #{state.host_id} stopping: #{reason}")
        Process.exit(self(), :normal)
        state
    end
  end

  defp observe(state, host) do
    case Tmux.overview(host, state.user_id) do
      {:ok, overview} ->
        snapshot =
          overview
          |> classify_panes(state.tails)
          |> Map.put(:host_id, state.host_id)
          |> Map.put(:observed_at, now())

        state
        |> Map.put(:failures, 0)
        |> record(snapshot)

      {:error, reason} ->
        Logger.debug("tmux watcher for host #{state.host_id}: #{inspect(reason)}")
        %{state | failures: state.failures + 1}
    end
  end

  # Attach an activity verdict to every pane. The overview already carries the pane's command
  # and its CPU sample; `Activity` turns those into the question a caller actually has.
  defp classify_panes(%{sessions: sessions} = overview, previous_tails) when is_list(sessions) do
    %{overview | sessions: Enum.map(sessions, &classify_session(&1, previous_tails))}
  end

  defp classify_session(session, previous_tails) do
    windows = Enum.map(Map.get(session, :windows, []), &classify_window(&1, previous_tails))
    %{session | windows: windows}
  end

  defp classify_window(window, previous_tails) do
    panes = Enum.map(Map.get(window, :panes, []), &classify_pane(&1, previous_tails))
    %{window | panes: panes}
  end

  # The key names here are the ones `Termelix.Tmux.enrich_pane/3` actually produces. Getting
  # them wrong does not fail loudly — `Map.get/2` returns nil and `Activity.classify/1` is
  # total by design — it just silently degrades every verdict to "no evidence", which is the
  # worst possible failure for a classifier and is invisible from the outside.
  defp classify_pane(pane, previous_tails) do
    tail = Map.get(pane, :screenTail)

    verdict =
      Activity.classify(%{
        argv: Map.get(pane, :topCommand) || Map.get(pane, :command),
        # `:cpuPercent`, not `:cpu`.
        cpu_delta: Map.get(pane, :cpuPercent),
        screen_tail: tail,
        # The second sample `Activity` asks for: whether the screen is the same as it was last
        # tick. That is what separates "blocked on I/O" from "about to print something", and it
        # is only knowable across two observations — which is why the watcher computes it and
        # the classifier does not.
        hash_stable?: stable?(previous_tails, Map.get(pane, :id), tail)
      })

    pane
    |> Map.put(:activity, verdict.state)
    |> Map.put(:activityEvidence, verdict.evidence)
  end

  defp stable?(_previous, nil, _tail), do: nil
  defp stable?(_previous, _pane_id, nil), do: nil

  defp stable?(previous, pane_id, tail) do
    case Map.fetch(previous, pane_id) do
      {:ok, ^tail} -> true
      {:ok, _different} -> false
      # Never seen before: not evidence of stability, and saying "true" would report a pane as
      # settled the first time it is ever observed.
      :error -> nil
    end
  end

  # Publish only when something actually changed. A watcher that broadcasts an identical
  # snapshot every 2 s makes every subscriber re-render for nothing, and buries the transitions
  # that matter in the ones that do not.
  defp record(state, snapshot) do
    # Cross-sample promotion BEFORE anything else reads the states, and the snapshot is
    # rewritten to match — `Orchestrator.wait/4` reads the pane's `:activity` out of the
    # snapshot, so a promotion that only touched the states map would be invisible to it.
    promoted = promote_finished(state.states, pane_states(snapshot))
    snapshot = apply_states(snapshot, promoted)
    states = promoted
    changed? = states != state.states

    transitions = transitions(state.states, states)

    if changed? or state.snapshot == nil do
      publish(state, snapshot)
      Enum.each(transitions, &publish_transition(state, &1))
    end

    %{
      state
      | snapshot: snapshot,
        states: states,
        tails: pane_tails(snapshot),
        last_change_at: if(changed?, do: now(), else: state.last_change_at)
    }
  end

  # Keyed on `:id` — the field `Termelix.Tmux.parse_panes/1` writes. It was `:paneId`, which
  # only exists on the METRICS map, so every pane hashed to the same `nil` key: N panes
  # collapsed into one entry, the last one won, and a pane arriving at `awaiting_input` was
  # silently dropped whenever any other pane sorted after it. The watcher looked like it was
  # working — it published snapshots on every change — while emitting transitions for a pane
  # that does not exist.
  defp pane_states(snapshot), do: pane_map(snapshot, :activity)

  @doc """
  Promote `:idle` to `:finished` for a pane that was `:running` or `:working` on the previous
  observation.

  `Activity.classify/1` is pure and sees ONE sample, so a pane sitting at a shell prompt is
  `:idle` whether the operator has been reading email for an hour or a build just exited a
  second ago. Those are the same picture and different events — and the second one is the whole
  answer to "tell me when it finishes".

  Without this, `:finished` was **unreachable**: the watcher never supplies a
  `last_exit_status`, which is the only other route to it, so `wait(until: [:finished])` — part
  of the DEFAULT — ran to its timeout on every command that completed normally. Worse than a
  wrong answer: `notable?(:running, :idle)` is false, so nothing was published either, and a
  human watching the monitor saw the pane go quiet with no event at all.

  Only from `:running`/`:working`. Promoting from `:awaiting_input` would report a prompt
  someone answered as a completed command, and promoting from `nil` would fire on the first
  observation of every idle pane on the host.
  """
  @spec promote_finished(%{optional(String.t()) => atom()}, %{optional(String.t()) => atom()}) ::
          %{optional(String.t()) => atom()}
  def promote_finished(previous, current) do
    Map.new(current, fn {pane_id, state} ->
      case {Map.get(previous, pane_id), state} do
        {was, :idle} when was in [:running, :working] -> {pane_id, :finished}
        _ -> {pane_id, state}
      end
    end)
  end

  # Rewrite each pane's `:activity` from the promoted map, so the snapshot a subscriber (and
  # `wait`) reads agrees with the transition that was published about it.
  defp apply_states(%{sessions: sessions} = snapshot, states) when is_list(sessions) do
    %{
      snapshot
      | sessions:
          Enum.map(sessions, fn session ->
            %{
              session
              | windows:
                  Enum.map(Map.get(session, :windows, []), fn window ->
                    %{
                      window
                      | panes:
                          Enum.map(Map.get(window, :panes, []), fn pane ->
                            case Map.fetch(states, Map.get(pane, :id)) do
                              {:ok, activity} -> Map.put(pane, :activity, activity)
                              :error -> pane
                            end
                          end)
                    }
                  end)
            }
          end)
    }
  end

  defp apply_states(snapshot, _states), do: snapshot

  defp pane_tails(snapshot), do: pane_map(snapshot, :screenTail)

  defp pane_map(snapshot, field) do
    for session <- Map.get(snapshot, :sessions, []),
        window <- Map.get(session, :windows, []),
        pane <- Map.get(window, :panes, []),
        id = Map.get(pane, :id),
        is_binary(id),
        into: %{} do
      {id, Map.get(pane, field)}
    end
  end

  # Only the transitions worth telling a human about — `Activity.notable?/2` decides, so the
  # rule lives with the classification rather than being reinvented per consumer.
  defp transitions(previous, current) do
    # `from` is computed in the BODY, not as a comprehension clause. Written as
    # `from = Map.get(previous, pane_id),` it is a FILTER, whose truthiness is the assigned
    # value — so a pane seen for the first time (`from == nil`) was silently dropped. That is
    # precisely the case that matters most: a pane already sitting at a prompt when the watcher
    # starts, which is what happens on every restart and every newly watched host.
    # `Activity.notable?(nil, :awaiting_input)` is true for exactly this reason.
    current
    |> Enum.map(fn {pane_id, to} -> {pane_id, Map.get(previous, pane_id), to} end)
    |> Enum.filter(fn {_pane_id, from, to} -> Activity.notable?(from, to) end)
    |> Enum.map(fn {pane_id, from, to} -> %{pane_id: pane_id, from: from, to: to} end)
  end

  defp publish(state, snapshot) do
    message = {:tmux_state, state.host_id, snapshot}
    Phoenix.PubSub.broadcast(Termelix.PubSub, topic(state.user_id, state.host_id), message)
    Phoenix.PubSub.broadcast(Termelix.PubSub, user_topic(state.user_id), message)
  end

  defp publish_transition(state, transition) do
    message = {:tmux_transition, state.host_id, transition}
    Phoenix.PubSub.broadcast(Termelix.PubSub, topic(state.user_id, state.host_id), message)
    Phoenix.PubSub.broadcast(Termelix.PubSub, user_topic(state.user_id), message)

    :telemetry.execute([:termelix, :tmux, :transition], %{count: 1}, %{
      host_id: state.host_id,
      user_id: state.user_id,
      from: transition.from,
      to: transition.to
    })
  end

  # --- scheduling -------------------------------------------------------------

  defp schedule(state) do
    if state.timer, do: Process.cancel_timer(state.timer)
    %{state | timer: Process.send_after(self(), :tick, interval_ms(state))}
  end

  @doc false
  @spec interval_ms(map()) :: pos_integer()
  def interval_ms(%{failures: failures}) when failures > 0 do
    # A host that is down does not become reachable faster by being asked more often.
    min(@idle_interval_ms * Bitwise.bsl(1, min(failures, 8)), @max_backoff_ms)
  end

  def interval_ms(state) do
    cond do
      awaiting_input?(state) -> @active_interval_ms
      changed_within?(state, @active_interval_ms * 2) -> @active_interval_ms
      changed_within?(state, @recent_window_ms) -> @recent_interval_ms
      true -> @idle_interval_ms
    end
  end

  # A pane waiting for an answer is polled fast: the whole value of the verdict is that somebody
  # finds out quickly, and the answer arriving turns it back into ordinary work.
  defp awaiting_input?(%{states: states}),
    do: Enum.any?(states, fn {_pane, activity} -> activity == :awaiting_input end)

  defp changed_within?(%{last_change_at: nil}, _window), do: false
  defp changed_within?(%{last_change_at: at}, window), do: now() - at <= window

  defp idle_too_long?(state) do
    now() - state.last_touched_at > @idle_shutdown_ms and
      not Enum.any?(state.states, fn {_pane, activity} -> activity == :awaiting_input end)
  end

  defp now, do: System.monotonic_time(:millisecond)
end
