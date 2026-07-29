defmodule Termelix.Tmux.Orchestrator do
  @moduledoc """
  The verbs an agent uses to work a pane it is not attached to: `send_keys`, `dispatch`,
  `capture`, `wait`.

  Everything up to here made the fleet *observable*. These make it *actionable* without a PTY,
  which is what lets an agent drive a session a human can walk up to and take over — the
  constraint the whole design is built around. A pane driven through these verbs is an ordinary
  tmux pane: `ssh host && tmux attach` still works, mid-command, with no handoff protocol.

  ## Why `send-keys` and not an exec

  An exec would run the command in a *new* shell with no relationship to what the operator (or
  the agent) has open. The point is the opposite: put the keystrokes into THE pane, so the
  history, the working directory, the environment, the running REPL and the scrollback are all
  the ones a human would see. That is what makes taking over possible.

  ## Copy mode

  A pane in copy mode routes keys to the copy-mode command table, not to the shell. So
  `send-keys "make test" Enter` into a pane someone scrolled up in does not run anything — it
  performs whatever those letters mean as copy-mode commands, which for `q` is "quit", for `:`
  is "prompt", and for the rest is mostly nothing. Silent, and it looks like the command was
  lost.

  Every write therefore cancels copy mode first — but conditionally, using tmux's OWN
  `if-shell -F '\#{pane_in_mode}'`, evaluated server-side inside the same invocation. An
  unconditional `send-keys -X cancel` is NOT harmless: on a pane that is not in a mode tmux
  answers `not in a mode` and exits non-zero, which fails the whole chained command and takes
  the keystrokes with it. (Found by running it against a real tmux, not by reading the manual —
  the docs describe the cancel as a no-op, and in effect it is; the exit status is not.)

  Doing the check with a separate round trip would be the obvious alternative and is worse: two
  execs with a window in between during which the pane can enter copy mode.

  ## Literal keys

  `send-keys` interprets its arguments as KEY NAMES: a command containing the word `Enter`, or
  `C-c`, or `Space` would be sent as those keys rather than as text. `-l` makes it literal, and
  the Enter is sent as its own separate `send-keys` — which is also what makes
  `dispatch/3`'s "type the command, then run it" two distinguishable steps rather than one
  ambiguous string.
  """

  alias Termelix.Tmux
  alias Termelix.Tmux.{Activity, Watcher}

  @capture_default_lines 200

  # A pane id (`%12`) or a session/window/pane target. Anything else is refused before it can
  # reach a shell.
  @pane_id_re ~r/^%\d+$/

  @type target :: String.t()

  @doc """
  Type `text` into `pane` without pressing Enter.

  For answering a prompt, correcting a line, or sending a control key — the "quick reply" case,
  where the agent (or a human) is responding to something the pane is asking.

  `keys` may be `:enter`, `:ctrl_c`, `:escape` or `{:literal, text}`. A literal string is sent
  with `-l`, so no part of it is interpreted as a key name.
  """
  @spec send_keys(map(), target(), [key()]) :: :ok | {:error, term()}
  def send_keys(host, pane, keys) when is_list(keys) do
    with :ok <- validate_pane(pane),
         {:ok, args} <- key_args(keys) do
      esc = Tmux.shell_escape(pane)

      # Cancel copy mode (only if the pane is in one), then the keys, in ONE invocation so
      # nothing can interleave between them.
      script =
        [cancel_copy_mode(pane) | Enum.map(args, &"send-keys -t #{esc} #{&1}")]
        |> Enum.join(" \\; ")

      run(host, script)
    end
  end

  @type key :: :enter | :ctrl_c | :escape | {:literal, String.t()}

  # tmux's own conditional, evaluated by the server against this pane. `-F` takes a format
  # string rather than running a shell, so this costs nothing and cannot fail the chain the way
  # an unconditional cancel does.
  # The nested command is tmux's own argument, so it carries a SECOND layer of quoting. The
  # pane is used bare inside it: `validate_pane/1` has already established it matches `%\d+`,
  # and wrapping it in single quotes there would close tmux's quoted string and reopen it —
  # which happens to concatenate back to the same thing today, and would stop doing so the
  # moment anything else appeared in the id.
  defp cancel_copy_mode(pane),
    do:
      ~s(if-shell -t #{Tmux.shell_escape(pane)} -F '\#{pane_in_mode}' ) <>
        ~s('send-keys -t #{pane} -X cancel')

  @doc """
  Type `command` into `pane` and press Enter — the "run this over there" verb.

  Returns `{:ok, %{pane: pane, dispatched_at: ...}}`. It does NOT wait: that is `wait/4`'s job,
  and keeping them separate is what lets an agent dispatch to five hosts and then wait on all
  five, rather than serialising on the slowest.

  The command is sent literally, so a command containing `Enter`, `C-c` or `Space` is text and
  not keys.
  """
  @spec dispatch(map(), target(), String.t()) :: {:ok, map()} | {:error, term()}
  def dispatch(host, pane, command) when is_binary(command) do
    cond do
      String.trim(command) == "" ->
        {:error, :empty_command}

      # A command is a line to be typed. Embedded newlines would run everything after the first
      # one as separate commands, which is never what a caller asking for ONE command meant —
      # and is how a "run this" verb becomes an arbitrary-script verb.
      String.contains?(command, ["\n", "\r"]) ->
        {:error, :multiline_command}

      true ->
        case send_keys(host, pane, [{:literal, command}, :enter]) do
          :ok -> {:ok, %{pane: pane, command: command, dispatchedAt: now_ms()}}
          {:error, _reason} = error -> error
        end
    end
  end

  @doc """
  Create-or-attach a named session on `host` and return the pane to work in.

  The verb the stated use case starts with — *"open or attach to a claude code session in the
  foobar app dir on host ava"* — and the one the other verbs are useless without: they all take
  a pane id, and an agent that cannot make a pane has nowhere to begin.

  Idempotent by construction (`new-session -A -d`), which is the whole point: an agent that
  reconnects, or a second agent asked to do the same thing, must land in the SAME session
  rather than pile up a new one per attempt. `-d` because nothing here attaches a client — the
  session exists on the host, and a human attaches to it whenever they like.

  `start_directory` is applied with tmux's own `-c` at creation, so an existing session is
  never moved: an agent already working in a directory must not be `cd`-ed out from under it by
  a caller that merely asked for the session again.

  Returns `{:ok, %{session: name, pane: pane_id, created: boolean}}`. `created` distinguishes
  "I made this" from "this was already here", which is exactly what a caller needs to decide
  whether to dispatch a fresh command or read what is already on screen.
  """
  @spec ensure_session(map(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def ensure_session(host, session, opts \\ []) do
    start_directory = Keyword.get(opts, :start_directory)

    with :ok <- validate_session(session),
         :ok <- validate_directory(start_directory) do
      if session_exists?(host, session) do
        {:ok, Map.put(first_pane(host, session), :created, false)}
      else
        create_session(host, session, start_directory)
      end
    end
  end

  # `new-session -d`, deliberately NOT `new-session -A -d`.
  #
  # `-A` means "attach if it already exists", and that is what it does — it tries to open a
  # terminal even with `-d`, and this runs over an exec with no TTY, so the second call for a
  # session that already existed failed with `open terminal failed: not a terminal`. Found by
  # calling `open` twice against a real host; the first call created and succeeded, and only
  # the idempotent repeat — the whole reason the verb exists — broke.
  #
  # The existence check was already here, so the branch costs nothing and says what it means.
  # (`Tmux.new_or_attach_command/2` keeps `-A`, correctly: that string is typed into a live
  # PTY, where attaching is exactly the point.)
  defp create_session(host, session, start_directory) do
    args =
      ["new-session -d -s #{Tmux.shell_escape(session)}"] ++
        if(start_directory, do: ["-c #{Tmux.shell_escape(start_directory)}"], else: [])

    case Tmux.exec(host, Tmux.tmux_command(Enum.join(args, " ")), :ensure_session) do
      {:ok, _out} -> {:ok, Map.put(first_pane(host, session), :created, true)}
      {:error, _reason} = error -> error
    end
  end

  defp session_exists?(host, session) do
    case Tmux.session_exists?(host, session) do
      {:ok, exists?} -> exists?
      _ -> false
    end
  end

  # The pane a caller should work in: the session's first. Asked for separately rather than
  # parsed out of `new-session`'s output, because `-A` prints nothing when it attaches.
  defp first_pane(host, session) do
    target = Tmux.shell_escape("=" <> session)

    case Tmux.exec(
           host,
           Tmux.tmux_command("list-panes -t #{target} -F '\#{pane_id}'"),
           :ensure_session
         ) do
      {:ok, out} ->
        pane = out |> String.split("\n") |> Enum.map(&String.trim/1) |> Enum.find(&(&1 != ""))
        %{session: session, pane: pane}

      {:error, _reason} ->
        %{session: session, pane: nil}
    end
  end

  # A session name reaches a command typed into a PTY and is also a tmux TARGET, where `.` and
  # `:` select a pane or window of some other session. `Tmux.safe_session_name?/1` is the one
  # rule for both.
  defp validate_session(session) when is_binary(session) do
    if Tmux.safe_session_name?(session), do: :ok, else: {:error, :invalid_session}
  end

  defp validate_session(_session), do: {:error, :invalid_session}

  defp validate_directory(nil), do: :ok

  defp validate_directory(dir) do
    if Tmux.safe_start_directory?(dir), do: :ok, else: {:error, :invalid_directory}
  end

  @doc """
  The last `lines` of `pane`'s screen, plus the activity verdict for it.

  The verdict travels with the text because a caller reading a pane almost always wants to know
  whether it is still going — and computing it here means one round trip rather than a capture
  followed by an overview.
  """
  @spec capture(map(), target(), keyword()) :: {:ok, map()} | {:error, term()}
  def capture(host, pane, opts \\ []) do
    lines = opts |> Keyword.get(:lines, @capture_default_lines) |> clamp_lines()

    with :ok <- validate_pane(pane) do
      esc = Tmux.shell_escape(pane)

      case Tmux.exec(
             host,
             Tmux.tmux_command("capture-pane -p -J -t #{esc} -S -#{lines}"),
             :capture
           ) do
        {:ok, text} ->
          {:ok, %{pane: pane, lines: lines, text: text, activity: classify(text)}}

        {:error, _reason} = error ->
          error
      end
    end
  end

  @doc """
  Block until `pane` reaches one of `until_states`, or `timeout_ms` elapses.

  **This is the verb the whole architecture was built to support.** Without it an agent must
  poll, and a polling agent either burns tokens on a loop or picks an interval that is wrong in
  both directions. With it, "run the migration on ava and tell me if it asks anything" is one
  call that costs nothing while it waits.

  It is implemented over the watcher's PubSub — NOT by polling here. That matters twice: the
  SSH cost is one watcher per host no matter how many waiters there are, and the wait is woken
  by the same event that would have notified a human, so the two can never disagree about when
  something happened.

  Returns `{:ok, %{state: ..., pane: ...}}`, or `{:error, :timeout}` with the last state seen.
  A wait that ends in `:awaiting_input` is a success, not a failure: being asked a question IS
  the outcome, and treating it as an error would push callers into retry loops around a pane
  that is waiting for them.
  """
  @spec wait(String.t(), integer(), target(), keyword()) ::
          {:ok, map()} | {:error, :timeout, map()} | {:error, term()}
  def wait(user_id, host_id, pane, opts \\ []) do
    until = opts |> Keyword.get(:until, default_until()) |> List.wrap()
    timeout_ms = Keyword.get(opts, :timeout_ms, 300_000)

    with :ok <- validate_pane(pane),
         :ok <- validate_states(until),
         {:ok, _pid} <- Watcher.ensure_started(user_id, host_id) do
      topic = Watcher.topic(user_id, host_id)
      Phoenix.PubSub.subscribe(Termelix.PubSub, topic)

      # The instant this wait begins. Nothing observed BEFORE it may satisfy it — see
      # `fresh_enough?/2`.
      started_at = now_ms()

      # Ask for an observation now rather than at the next scheduled tick, so a wait that
      # follows a dispatch does not sit through a whole idle interval to learn about it.
      Watcher.poll_now(user_id, host_id)

      try do
        await(user_id, host_id, pane, until, timeout_ms, started_at)
      after
        Phoenix.PubSub.unsubscribe(Termelix.PubSub, topic)
      end
    end
  end

  @doc """
  What `wait/4` waits for when the caller does not say: the two outcomes that mean "stop
  waiting and look".

  `:crashed` is deliberately NOT here, and that is a limitation worth naming rather than
  papering over. It requires the command's exit status, and a tmux pane does not expose the
  exit status of a command its shell has already reaped — there is no such tmux format to read.
  `Activity.classify/1` still returns `:crashed` for a caller that HAS an exit status (shell
  integration, a wrapper), so the verdict is not fictional; the watcher simply cannot produce
  it. Leaving it in the default would advertise an outcome that can never arrive, which is
  worse than not offering it: a caller would reasonably read "no crash reported" as "it did not
  crash".
  """
  @spec default_until() :: [atom()]
  def default_until, do: [:awaiting_input, :finished]

  # --- waiting ----------------------------------------------------------------

  defp await(user_id, host_id, pane, until, timeout_ms, started_at) do
    # A snapshot the watcher took BEFORE this call cannot answer it. That is not pedantry: the
    # cached snapshot is exactly what a `dispatch` immediately followed by a `wait` races
    # against, and trusting it made `wait(until: [:finished])` return in 0 ms — reporting the
    # END of the previous command as the end of the one just sent. Proven against a real host:
    # a `sleep 12` "finished" instantly.
    #
    # A snapshot taken after `started_at` is still allowed to satisfy the wait immediately;
    # what is refused is evidence older than the question.
    last_state =
      case Watcher.snapshot(user_id, host_id) do
        {:ok, snapshot} ->
          state = pane_state(snapshot, pane)

          if fresh_enough?(snapshot, started_at) and state in until do
            throw({:done, %{pane: pane, state: state, waited_ms: 0, immediate: true}})
          end

          state

        :miss ->
          nil
      end

    receive_loop(pane, until, started_at + timeout_ms, started_at, last_state)
  catch
    {:done, result} -> {:ok, result}
  end

  # `observed_at` and `started_at` are both `System.monotonic_time(:millisecond)` from this VM,
  # so they are directly comparable.
  defp fresh_enough?(snapshot, started_at) do
    case Map.get(snapshot, :observed_at) do
      observed_at when is_integer(observed_at) -> observed_at >= started_at
      _ -> false
    end
  end

  defp receive_loop(pane, until, deadline, started_at, last_state) do
    remaining = deadline - now_ms()

    if remaining <= 0 do
      {:error, :timeout, %{pane: pane, state: last_state}}
    else
      receive do
        {:tmux_state, _host_id, snapshot} ->
          # Published snapshots are by construction newer than `started_at` — but a watcher
          # that was mid-tick when the subscription landed can deliver one that is not.
          if not fresh_enough?(snapshot, started_at) do
            receive_loop(pane, until, deadline, started_at, last_state)
          else
            handle_snapshot(snapshot, pane, until, deadline, started_at, last_state)
          end

        {:tmux_transition, _host_id, _transition} ->
          # The snapshot that accompanies it carries the full picture; this is a duplicate.
          receive_loop(pane, until, deadline, started_at, last_state)
      after
        remaining -> {:error, :timeout, %{pane: pane, state: last_state}}
      end
    end
  end

  defp handle_snapshot(snapshot, pane, until, deadline, started_at, _last_state) do
    case pane_state(snapshot, pane) do
      nil ->
        # The pane is gone. That is an outcome, not a hang: a pane that closed cannot reach any
        # state, and a caller waiting for one needs to be told rather than left until the
        # timeout.
        {:ok, %{pane: pane, state: :gone, waited_ms: now_ms() - started_at}}

      state ->
        if state in until do
          {:ok, %{pane: pane, state: state, waited_ms: now_ms() - started_at}}
        else
          receive_loop(pane, until, deadline, started_at, state)
        end
    end
  end

  defp pane_state(snapshot, pane) do
    Enum.find_value(Map.get(snapshot, :sessions, []), fn session ->
      Enum.find_value(Map.get(session, :windows, []), fn window ->
        Enum.find_value(Map.get(window, :panes, []), fn p ->
          if Map.get(p, :id) == pane, do: Map.get(p, :activity)
        end)
      end)
    end)
  end

  # --- key encoding -----------------------------------------------------------

  defp key_args(keys) do
    Enum.reduce_while(keys, {:ok, []}, fn key, {:ok, acc} ->
      case key_arg(key) do
        {:ok, arg} -> {:cont, {:ok, acc ++ [arg]}}
        :error -> {:halt, {:error, {:unsupported_key, key}}}
      end
    end)
  end

  defp key_arg(:enter), do: {:ok, "Enter"}
  defp key_arg(:ctrl_c), do: {:ok, "C-c"}
  defp key_arg(:escape), do: {:ok, "Escape"}

  # `-l` (literal), so nothing inside is read as a key name. Control bytes are refused rather
  # than escaped: these end up in a real terminal's input, where a C0 byte edits the line the
  # shell will run — the same argument as `safe_initial_path?/1` in the terminal socket.
  defp key_arg({:literal, text}) when is_binary(text) do
    if Regex.match?(~r/[\x00-\x08\x0a-\x1f\x7f]/, text),
      do: :error,
      else: {:ok, "-l #{Tmux.shell_escape(text)}"}
  end

  defp key_arg(_other), do: :error

  # --- validation -------------------------------------------------------------

  # Only a tmux pane id. Session/window names would have to be screened for tmux's own target
  # syntax (`.` and `:` select a pane or window of some OTHER session — see
  # `Tmux.safe_session_name?/1`), and a verb that writes keystrokes into a terminal is the
  # wrong place to be clever about targeting.
  defp validate_pane(pane) when is_binary(pane) do
    if Regex.match?(@pane_id_re, pane), do: :ok, else: {:error, :invalid_pane}
  end

  defp validate_pane(_pane), do: {:error, :invalid_pane}

  defp validate_states(states) do
    known = Activity.states() ++ [:gone]

    case Enum.reject(states, &(&1 in known)) do
      [] -> :ok
      unknown -> {:error, {:unknown_states, unknown}}
    end
  end

  defp clamp_lines(lines) when is_integer(lines) and lines > 0, do: min(lines, 2_000)
  defp clamp_lines(_lines), do: @capture_default_lines

  defp classify(text),
    do: Activity.classify(%{screen_tail: text, shell?: false, argv: nil}).state

  defp run(host, script) do
    case Tmux.exec(host, Tmux.tmux_command(script), :orchestrate) do
      {:ok, _out} -> :ok
      {:error, _reason} = error -> error
    end
  end

  defp now_ms, do: System.monotonic_time(:millisecond)
end
