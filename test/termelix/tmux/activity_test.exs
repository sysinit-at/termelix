defmodule Termelix.Tmux.ActivityTest do
  @moduledoc """
  The classifier is a pile of judgement calls about someone's terminal, so this file is where
  those calls are argued. Two failure modes matter and they are not symmetric:

    * A **missed** `:awaiting_input` means an agent waits for something that will never come.
      Annoying, recoverable, and visible.
    * A **false** `:awaiting_input` pages a human at 3am about a build log. That one destroys
      trust in the channel, and once a notification channel is untrusted it is worthless.

  So the bias is deliberate: prompts must look like prompts, and ambiguity resolves to the
  process-state verdict rather than to a page.
  """
  use ExUnit.Case, async: true

  alias Termelix.Tmux.Activity

  describe "the verdict the product exists for" do
    test "a trailing question with an answer affordance is awaiting_input" do
      for tail <- [
            "Do you want to proceed? [y/N]",
            "Continue? (yes/no)",
            "Overwrite existing file? [y/N] ",
            "Are you sure you want to continue connecting (yes/no/[fingerprint])?"
          ] do
        assert %{state: :awaiting_input} = Activity.classify(%{screen_tail: tail}), tail
      end
    end

    test "the interactive tools an unattended agent actually gets stuck on" do
      cases = [
        {"[sudo] password for alice: ", "sudo password prompt"},
        {"Enter passphrase for key '/home/alice/.ssh/id_ed25519':", "ssh key passphrase prompt"},
        {"Username for 'https://github.com': ", "git credential prompt"},
        {"(END)", "pager waiting"}
      ]

      for {tail, label} <- cases do
        assert %{state: :awaiting_input, evidence: [^label]} =
                 Activity.classify(%{screen_tail: tail}),
               tail
      end
    end

    test "a prompt below a trailing blank line still counts" do
      # The ordinary shape: the cursor sits on its own line under the question.
      tail = "Do you want to proceed? [y/N]\n\n"
      assert %{state: :awaiting_input} = Activity.classify(%{screen_tail: tail})
    end

    test "a prompt outranks a busy CPU — a spinner is still a question" do
      assert %{state: :awaiting_input} =
               Activity.classify(%{
                 argv: "claude",
                 cpu_delta: 90.0,
                 screen_tail: "Do you want to make this edit? [y/N]"
               })
    end
  end

  describe "what must NOT page anyone" do
    test "the word 'password' inside a log is not a prompt" do
      tail = """
      2026-07-26 03:14:15 INFO  Rotating password for service account
      2026-07-26 03:14:16 INFO  Done
      """

      refute Activity.classify(%{argv: "make", screen_tail: tail}).state == :awaiting_input
    end

    test "a question mid-scroll, with output after it, is not a prompt" do
      tail = """
      Continue? [y/N] y
      Building target 3 of 91...
      """

      refute Activity.classify(%{argv: "make", screen_tail: tail}).state == :awaiting_input
    end

    test "a long line ending in a colon is prose, not a prompt" do
      tail =
        "note: the following packages were skipped because they are already installed on this system:"

      refute Activity.classify(%{argv: "apt", screen_tail: tail}).state == :awaiting_input
    end

    test "an empty or missing screen never invents a prompt" do
      refute Activity.classify(%{screen_tail: ""}).state == :awaiting_input
      refute Activity.classify(%{screen_tail: "\n\n  \n"}).state == :awaiting_input
      refute Activity.classify(%{}).state == :awaiting_input
    end
  end

  describe "running vs working — the distinction that makes `wait` possible" do
    test "CPU above the threshold is running" do
      assert %{state: :running, confidence: :high} =
               Activity.classify(%{argv: "cargo build", cpu_delta: 87.5})
    end

    test "alive, no CPU, screen unchanged is WORKING, not idle" do
      # Conflating this with `:idle` would have `wait` return the moment a build started
      # downloading — the process is blocked on I/O, which is not the same as absent.
      assert %{state: :working} =
               Activity.classify(%{argv: "cargo build", cpu_delta: 0.0, hash_stable?: true})
    end

    test "an unknown foreground process is working at low confidence, never idle" do
      assert %{state: :working, confidence: :low} = Activity.classify(%{argv: "some-tool"})
    end
  end

  describe "the shell verdicts" do
    test "a shell with no exit status is idle" do
      assert %{state: :idle} = Activity.classify(%{argv: "-bash", shell?: true})
      assert %{state: :idle} = Activity.classify(%{argv: "zsh"})
      assert %{state: :idle} = Activity.classify(%{argv: "/usr/bin/fish"})
    end

    test "exit 0 is finished, anything else is crashed" do
      assert %{state: :finished} = Activity.classify(%{argv: "bash", last_exit_status: 0})
      assert %{state: :crashed} = Activity.classify(%{argv: "bash", last_exit_status: 1})
      assert %{state: :crashed} = Activity.classify(%{argv: "bash", last_exit_status: 130})
    end

    test "an explicit shell? overrides the argv guess" do
      # A pane whose foreground process is named like a shell but is not one.
      assert %{state: :running} =
               Activity.classify(%{argv: "bash", shell?: false, cpu_delta: 50.0})
    end
  end

  describe "notable?/2 — what is worth telling a human" do
    test "arriving at a question or a crash is always news" do
      assert Activity.notable?(:running, :awaiting_input)
      assert Activity.notable?(:working, :awaiting_input)
      assert Activity.notable?(nil, :awaiting_input)
      assert Activity.notable?(:running, :crashed)
    end

    test "finishing is news only if something was actually running" do
      assert Activity.notable?(:running, :finished)
      assert Activity.notable?(:working, :finished)
      refute Activity.notable?(:idle, :finished)
    end

    test "the churn is not news" do
      # This happens constantly and means nothing on its own. Sending it trains people to
      # ignore the channel, which costs more than sending nothing.
      refute Activity.notable?(:running, :working)
      refute Activity.notable?(:working, :running)
      refute Activity.notable?(:idle, :idle)
      refute Activity.notable?(:awaiting_input, :awaiting_input)
    end
  end

  describe "totality" do
    test "every state is reachable and classify/1 never raises on junk" do
      assert length(Activity.states()) == 6

      for junk <- [nil, "", 42, [], %{argv: 7}, %{screen_tail: 7}, %{cpu_delta: "x"}] do
        verdict = Activity.classify(junk)
        assert verdict.state in Activity.states(), inspect(junk)
        assert is_list(verdict.evidence)
      end
    end

    test "every verdict carries evidence — a classification nobody can argue with is useless
          the first time it is wrong" do
      observations = [
        %{screen_tail: "Continue? [y/N]"},
        %{argv: "cargo", cpu_delta: 90.0},
        %{argv: "cargo", cpu_delta: 0.0, hash_stable?: true},
        %{argv: "bash", last_exit_status: 0},
        %{argv: "bash", last_exit_status: 2},
        %{argv: "bash"}
      ]

      for observation <- observations do
        assert [evidence | _] = Activity.classify(observation).evidence
        assert is_binary(evidence) and evidence != ""
      end
    end
  end
end
