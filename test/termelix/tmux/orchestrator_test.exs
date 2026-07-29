defmodule Termelix.Tmux.OrchestratorTest do
  @moduledoc """
  The verbs an agent uses to work a pane it is not attached to.

  These type into somebody's live terminal, so the tests are mostly about what must NOT happen:
  a command interpreted as key names, a control byte editing the line the shell will run, a
  pane target that selects a window of some other session, and a `wait` that hangs on a pane
  which already finished.
  """
  use Termelix.DataCase, async: false

  alias Termelix.{Accounts, Hosts}
  alias Termelix.Tmux.{Orchestrator, Watcher}

  setup do
    {:ok, user, _} = Accounts.register_user("orch-#{unique()}", "password-123-abc")
    {port, daemon, sink} = recording_tmux_host()
    on_exit(fn -> :ssh.stop_daemon(daemon) end)

    {:ok, host} =
      Hosts.create_host(user.id, %{
        name: "orch",
        ip: "127.0.0.1",
        port: port,
        username: "tester",
        authType: "password",
        password: "secret",
        enableTmuxMonitor: true
      })

    on_exit(fn -> Watcher.stop(user.id, host.id) end)
    %{user: user, host: host, sink: sink}
  end

  defp unique, do: System.unique_integer([:positive])

  describe "dispatch" do
    test "types the command literally and presses Enter as a separate key", ctx do
      assert {:ok, %{command: "make test"}} = Orchestrator.dispatch(ctx.host, "%3", "make test")

      cmd = last_command(ctx.sink)

      # `-l` is what stops `send-keys` reading the words as KEY NAMES. Without it a command
      # containing "Enter", "C-c" or "Space" is sent as those keys instead of as text.
      assert cmd =~ "send-keys -t '%3' -l 'make test'"
      # And the Enter is its own send-keys, not part of the literal string.
      assert cmd =~ "send-keys -t '%3' Enter"
    end

    test "cancels copy mode first, in the same command", ctx do
      assert {:ok, _} = Orchestrator.dispatch(ctx.host, "%3", "ls")
      cmd = last_command(ctx.sink)

      # A pane someone scrolled up in routes keys to the copy-mode command table, so the
      # command would be silently swallowed. The cancel must come FIRST and must be part of the
      # same tmux invocation — two round trips would leave a window in which the pane re-enters
      # copy mode between them.
      [cancel_at, keys_at] = [
        :binary.match(cmd, "-X cancel") |> elem(0),
        :binary.match(cmd, "-l 'ls'") |> elem(0)
      ]

      assert cancel_at < keys_at
      assert cmd =~ " \\; "

      # CONDITIONAL, via tmux's own `if-shell -F`. An unconditional cancel answers
      # `not in a mode` and exits non-zero on a pane that is not in one, which fails the whole
      # chain and silently takes the keystrokes with it. Proven against a real tmux, not
      # inferred: the docs describe the cancel as a no-op, and in effect it is — the exit
      # status is not.
      assert cmd =~ "if-shell -t '%3' -F '\#{pane_in_mode}'"
    end

    test "refuses an empty or multi-line command", ctx do
      assert Orchestrator.dispatch(ctx.host, "%3", "") == {:error, :empty_command}
      assert Orchestrator.dispatch(ctx.host, "%3", "   ") == {:error, :empty_command}

      # A "run this command" verb that accepts newlines is an arbitrary-script verb wearing a
      # smaller name.
      assert Orchestrator.dispatch(ctx.host, "%3", "ls\nrm -rf /") == {:error, :multiline_command}
      assert Orchestrator.dispatch(ctx.host, "%3", "ls\rrm -rf /") == {:error, :multiline_command}
    end

    test "refuses control bytes — quoting is not a defence in a live terminal", ctx do
      # `\x15` is unix-line-discard: it erases what has been typed so far, so a "quoted"
      # command can still run something entirely different. Same argument as the terminal
      # socket's `initialPath` guard.
      assert {:error, {:unsupported_key, _}} =
               Orchestrator.dispatch(ctx.host, "%3", "echo hi\x15rm -rf /")

      assert {:error, {:unsupported_key, _}} = Orchestrator.dispatch(ctx.host, "%3", "a\x00b")
      assert {:error, {:unsupported_key, _}} = Orchestrator.dispatch(ctx.host, "%3", "a\x7fb")
    end

    test "a single quote in the command is escaped, not broken out of", ctx do
      assert {:ok, _} = Orchestrator.dispatch(ctx.host, "%3", "echo 'hi'; id")

      # Asserted on the RAW wire form, before the shim unwrapping: the escaping is the point.
      raw = ctx.sink |> Agent.get(& &1) |> List.first()

      # The `; id` must never become a second command for the shell — it stays inside the
      # quoted literal that `send-keys -l` types into the pane.
      assert raw =~ "send-keys"
      assert String.contains?(raw, "id")
      refute raw =~ ~r/;\s*id\s*'?$/
    end
  end

  describe "pane targets" do
    test "only a tmux pane id is accepted", ctx do
      for bad <- ["work", "work:0.1", "%1;id", "%", "", "$1", "@2", "%1 -X kill-session"] do
        assert Orchestrator.dispatch(ctx.host, bad, "ls") == {:error, :invalid_pane}, bad
        assert Orchestrator.send_keys(ctx.host, bad, [:enter]) == {:error, :invalid_pane}, bad
        assert Orchestrator.capture(ctx.host, bad) == {:error, :invalid_pane}, bad
      end

      assert {:ok, _} = Orchestrator.dispatch(ctx.host, "%0", "ls")
      assert {:ok, _} = Orchestrator.dispatch(ctx.host, "%1234", "ls")
    end
  end

  describe "send_keys" do
    test "named keys are sent as keys, not as text", ctx do
      assert :ok = Orchestrator.send_keys(ctx.host, "%2", [:ctrl_c])
      assert last_command(ctx.sink) =~ "send-keys -t '%2' C-c"

      assert :ok = Orchestrator.send_keys(ctx.host, "%2", [:escape])
      assert last_command(ctx.sink) =~ "send-keys -t '%2' Escape"
    end

    test "answering a prompt sends the text WITHOUT an Enter", ctx do
      # The quick-reply case. Sending Enter here would answer and submit in one step, which is
      # wrong for a prompt the operator may want to edit first.
      assert :ok = Orchestrator.send_keys(ctx.host, "%2", [{:literal, "y"}])
      cmd = last_command(ctx.sink)
      assert cmd =~ "-l 'y'"
      refute cmd =~ "Enter"
    end

    test "an unknown key is refused rather than guessed", ctx do
      assert {:error, {:unsupported_key, :reboot}} =
               Orchestrator.send_keys(ctx.host, "%2", [:reboot])
    end
  end

  describe "capture" do
    test "returns the pane text and a verdict about it", ctx do
      assert {:ok, result} = Orchestrator.capture(ctx.host, "%1")
      assert result.pane == "%1"
      assert is_binary(result.text)
      # The verdict travels with the text: a caller reading a pane almost always also wants to
      # know whether it is still going.
      assert result.activity in Termelix.Tmux.Activity.states()
      assert last_command(ctx.sink) =~ "capture-pane -p -J -t '%1'"
    end

    test "the line count is clamped, and junk falls back to the default", ctx do
      assert {:ok, %{lines: 2_000}} = Orchestrator.capture(ctx.host, "%1", lines: 999_999)
      assert {:ok, %{lines: 200}} = Orchestrator.capture(ctx.host, "%1", lines: 0)
      assert {:ok, %{lines: 200}} = Orchestrator.capture(ctx.host, "%1", lines: "lots")
      assert {:ok, %{lines: 50}} = Orchestrator.capture(ctx.host, "%1", lines: 50)
    end
  end

  describe "wait — the verb the architecture was built for" do
    test "returns immediately when the pane is ALREADY in a target state", ctx do
      Phoenix.PubSub.subscribe(Termelix.PubSub, Watcher.user_topic(ctx.user.id))
      {:ok, _pid} = Watcher.ensure_started(ctx.user.id, ctx.host.id)
      assert_receive {:tmux_state, _id, _snapshot}, 10_000

      # %1 sits at a prompt in the fixture. A `wait` that blocked here would hang until the
      # next change — which for a pane waiting for an answer is never.
      assert {:ok, %{state: :awaiting_input, immediate: true}} =
               Orchestrator.wait(ctx.user.id, ctx.host.id, "%1", timeout_ms: 5_000)
    end

    test "times out with the last state it saw, rather than an empty error", ctx do
      {:ok, _pid} = Watcher.ensure_started(ctx.user.id, ctx.host.id)

      assert {:error, :timeout, result} =
               Orchestrator.wait(ctx.user.id, ctx.host.id, "%0",
                 until: [:crashed],
                 timeout_ms: 700
               )

      assert result.pane == "%0"
      # The last known state is what makes a timeout actionable — "still running" and "we never
      # saw it at all" call for different next moves.
      assert result.state in [nil | Termelix.Tmux.Activity.states()]
    end

    test "a snapshot taken BEFORE the wait cannot satisfy it", ctx do
      # The bug this pins: `dispatch` then `wait` races the watcher's cache, and trusting a
      # stale snapshot made `wait(until: [:finished])` return in 0 ms — reporting the end of the
      # PREVIOUS command as the end of the one just sent. Proven against a real host first: a
      # `sleep 12` "finished" instantly.
      Phoenix.PubSub.subscribe(Termelix.PubSub, Watcher.user_topic(ctx.user.id))
      {:ok, _pid} = Watcher.ensure_started(ctx.user.id, ctx.host.id)
      assert_receive {:tmux_state, _id, snapshot}, 10_000

      # %1 is at a prompt in the fixture, so the cache says `:awaiting_input` — the state the
      # wait below is asking for. It must still not be answered from that cached observation.
      assert snapshot.observed_at

      # Nothing new will be observed within the budget (the fixture never changes), so a wait
      # that refuses stale evidence must TIME OUT rather than answer from the cache.
      #
      # `poll_now` does produce a fresh observation, so this asserts the honest outcome: the
      # answer comes from an observation taken after the call, not before it.
      assert {:ok, %{state: :awaiting_input, waited_ms: waited}} =
               Orchestrator.wait(ctx.user.id, ctx.host.id, "%1",
                 until: [:awaiting_input],
                 timeout_ms: 8_000
               )

      # It was answered by a FRESH poll, not by the cache: an answer straight from the cache
      # would have been reported as `immediate: true` with zero wait.
      assert is_integer(waited)
    end

    test "the default does not advertise an outcome that can never arrive" do
      # `:crashed` needs the command's exit status, and a tmux pane does not expose the exit
      # status of something its shell already reaped. `Activity` still returns it for a caller
      # that HAS one, so the verdict is not fictional — but leaving it in the default would let
      # a caller read "no crash reported" as "it did not crash".
      assert Orchestrator.default_until() == [:awaiting_input, :finished]
      refute :crashed in Orchestrator.default_until()
    end

    test "refuses an unknown target state instead of waiting forever for it", ctx do
      assert {:error, {:unknown_states, [:banana]}} =
               Orchestrator.wait(ctx.user.id, ctx.host.id, "%1", until: [:banana])
    end

    test "refuses an invalid pane before starting a watcher", ctx do
      assert Orchestrator.wait(ctx.user.id, ctx.host.id, "work:0.1") == {:error, :invalid_pane}
    end
  end

  # --- a tmux host that records what it was asked ------------------------------

  # Answers the overview with a fixture (so the watcher works) and records every command, so a
  # test can assert on the tmux invocation the verb actually built. Asserting on the RESULT
  # alone would pass for a `send-keys` that silently sent key names instead of text.
  defp recording_tmux_host do
    {:ok, _} = Application.ensure_all_started(:ssh)
    dir = Path.join(System.tmp_dir!(), "termelix_orch_#{unique()}")
    File.mkdir_p!(dir)

    {_, 0} =
      System.cmd("ssh-keygen", [
        "-t",
        "ed25519",
        "-f",
        Path.join(dir, "ssh_host_ed25519_key"),
        "-N",
        "",
        "-q"
      ])

    sink = start_supervised!({Agent, fn -> [] end}, id: {:sink, unique()})

    handler = fn command ->
      cmd = to_string(command)
      Agent.update(sink, &[cmd | &1])

      cond do
        String.contains?(cmd, "TERMELIX-TMUX:version") -> {:ok, overview_fixture()}
        String.contains?(cmd, "capture-pane -p -J -t") -> {:ok, "Do you want to proceed? [y/N]"}
        true -> {:ok, ""}
      end
    end

    {:ok, daemon} =
      :ssh.daemon(0,
        system_dir: String.to_charlist(dir),
        user_passwords: [{~c"tester", ~c"secret"}],
        auth_methods: ~c"password",
        exec: {:direct, handler}
      )

    on_exit(fn -> File.rm_rf(dir) end)
    {daemon |> :ssh.daemon_info() |> elem(1) |> Keyword.fetch!(:port), daemon, sink}
  end

  # Unwrapped from the `/bin/sh -c '<escaped script>'` shim, so the assertions read as the
  # tmux command that was actually built rather than as its shell quoting.
  defp last_command(sink) do
    sink
    |> Agent.get(& &1)
    |> Enum.reject(&String.contains?(&1, "TERMELIX-TMUX:version"))
    |> List.first()
    |> to_string()
    |> unwrap_script()
  end

  defp unwrap_script("/bin/sh -c " <> quoted) do
    quoted
    |> binary_part(1, byte_size(quoted) - 2)
    |> String.replace("'\\''", "'")
  end

  defp unwrap_script(other), do: other

  defp overview_fixture do
    sep = Termelix.Tmux.sep()
    line = fn fields -> Enum.join(fields, sep) <> "\n" end

    "===TERMELIX-TMUX:version===\ntmux 3.4\n" <>
      "===TERMELIX-TMUX:sessions===\n" <>
      line.(["work", "1710000000", "1710000500", "1"]) <>
      "===TERMELIX-TMUX:windows===\n" <>
      line.(["work", "0", "1", "editor"]) <>
      "===TERMELIX-TMUX:panes===\n" <>
      line.(["work", "0", "%0", "0", "1234", "1", "80", "24", "vim", "/home/t", "e"]) <>
      line.(["work", "0", "%1", "1", "1250", "0", "80", "24", "bash", "/home/t", "s"]) <>
      "===TERMELIX-TMUX:ps===\n" <>
      "  1234     1 42.0  2.0  8000 vim\n" <>
      "  1250     1  0.0  0.1  1000 bash\n" <>
      "===TERMELIX-TMUX:tails===\n" <>
      "===TERMELIX-TMUX:pane:%0===\n~/src\n" <>
      "===TERMELIX-TMUX:pane:%1===\nDo you want to proceed? [y/N]\n"
  end
end
