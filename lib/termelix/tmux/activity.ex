defmodule Termelix.Tmux.Activity do
  @moduledoc """
  What is this pane *doing*? — the classification the whole agent loop is built on.

  `Termelix.Tmux` already reports what a pane IS (its command, its pid, its title). That is not
  the same question. "Is `claude` running?" is answered by `ps`; "is it waiting for me?" is not,
  and it is the only one that matters to an agent that wants to dispatch work and walk away.

  ## The verdicts

    * `:idle` — a shell prompt with nothing running.
    * `:running` — a foreground process burning CPU.
    * `:working` — a foreground process that is alive but not burning CPU (waiting on I/O, on
      the network, on a subprocess). Distinct from `:running` because "slow" and "stuck" look
      identical for one sample and different across two.
    * `:awaiting_input` — the screen ends in a prompt for a human. **This is the verdict the
      product exists for**: it is what turns "dispatch and poll" into "dispatch and get told".
    * `:finished` — the command ended and the shell is back, with the last exit status 0.
    * `:crashed` — same, non-zero.

  ## Why it is pure

  `classify/1` takes a plain observation and returns a verdict plus its evidence. No SSH, no
  clock, no cache. Every rule below is a judgement call about someone's terminal, and judgement
  calls need to be arguable in a test rather than discovered on a live host — a classifier that
  can only be exercised by connecting to a machine is a classifier nobody will change.

  The evidence travels with the verdict for the same reason: when this gets something wrong (it
  will — heuristics over screen text always do), the operator needs to see WHY it decided that,
  not just what it decided.

  ## The screen-tail rules

  Prompt detection is the interesting part and it is deliberately conservative. A pane is only
  `:awaiting_input` when the LAST non-blank line looks like a question, because a build log full
  of the word "password" is not a prompt and treating it as one would page someone at 3am. In
  order of confidence:

    1. An explicit trailing `?` or `:` with a cursor-ish tail (`[y/N]`, `(yes/no)`, `>`).
    2. A known interactive-tool prompt (sudo, ssh host key, git credential, an agent's own
       "Do you want to…").
    3. Nothing else. Ambiguity resolves to the process-state verdict, never to a page.
  """

  @typedoc "One pane observation. Every field is optional; missing evidence weakens, never lies."
  @type observation :: %{
          optional(:argv) => String.t() | nil,
          optional(:shell?) => boolean(),
          optional(:cpu_delta) => number() | nil,
          optional(:screen_tail) => String.t() | nil,
          optional(:hash_stable?) => boolean() | nil,
          optional(:last_exit_status) => integer() | nil
        }

  @type state :: :idle | :running | :working | :awaiting_input | :finished | :crashed

  @type verdict :: %{state: state(), evidence: [String.t()], confidence: :high | :medium | :low}

  # Above this, a process is doing arithmetic rather than waiting.
  @cpu_busy_threshold 1.0

  # Shells, so "the command finished" is distinguishable from "a command is running".
  @shells ~w(bash sh zsh fish dash ksh tcsh csh ash)

  @doc """
  Classify one observation.

  Never raises and never returns `nil`: a caller with no evidence at all still gets a verdict
  it can act on (`:idle`, low confidence), because a watcher that can fail to answer is a
  watcher every caller has to write a fallback for.
  """
  @spec classify(observation()) :: verdict()
  def classify(observation) when is_map(observation) do
    argv = string_or_nil(Map.get(observation, :argv))
    tail = string_or_nil(Map.get(observation, :screen_tail))
    shell? = shell?(observation, argv)

    cond do
      # A prompt outranks everything, INCLUDING a busy CPU. A tool that spins while it waits for
      # an answer (a spinner, a redraw loop) is still waiting for an answer, and the whole point
      # of this verdict is that somebody has to be told.
      prompt = detect_prompt(tail) ->
        %{state: :awaiting_input, evidence: [prompt], confidence: :high}

      shell? ->
        classify_shell(Map.get(observation, :last_exit_status))

      true ->
        classify_process(
          argv,
          Map.get(observation, :cpu_delta),
          Map.get(observation, :hash_stable?)
        )
    end
  end

  def classify(_observation),
    do: %{state: :idle, evidence: ["no observation"], confidence: :low}

  @doc """
  Whether a transition is worth telling a human about.

  Not every change is news. `:running -> :working` is a process blocking on I/O, which happens
  constantly and means nothing on its own; `:working -> :awaiting_input` is someone being asked
  a question. Sending both trains people to ignore the channel, which costs more than sending
  neither.
  """
  @spec notable?(state() | nil, state()) :: boolean()
  def notable?(from, to)
  def notable?(same, same), do: false
  def notable?(_from, :awaiting_input), do: true
  def notable?(_from, :crashed), do: true
  def notable?(from, :finished) when from in [:running, :working], do: true
  def notable?(_from, _to), do: false

  @doc "Every state this module can return — for exhaustiveness checks in callers and tests."
  @spec states() :: [state()]
  def states, do: [:idle, :running, :working, :awaiting_input, :finished, :crashed]

  # --- shell vs process -------------------------------------------------------

  defp classify_shell(nil),
    do: %{state: :idle, evidence: ["shell prompt, no command"], confidence: :medium}

  defp classify_shell(0),
    do: %{state: :finished, evidence: ["shell prompt, last exit 0"], confidence: :high}

  defp classify_shell(status) when is_integer(status),
    do: %{state: :crashed, evidence: ["shell prompt, last exit #{status}"], confidence: :high}

  defp classify_shell(_other),
    do: %{state: :idle, evidence: ["shell prompt"], confidence: :low}

  defp classify_process(argv, cpu_delta, hash_stable?) do
    name = argv || "a process"

    cond do
      is_number(cpu_delta) and cpu_delta >= @cpu_busy_threshold ->
        %{
          state: :running,
          evidence: ["#{name} using #{format_cpu(cpu_delta)}% CPU"],
          confidence: :high
        }

      # Alive, not burning CPU, and the screen has not changed between samples. That is the
      # signature of blocked-on-something, which is `:working` and NOT `:idle`: an idle pane has
      # no foreground process at all, and conflating the two would have `wait` return the moment
      # a build started downloading.
      hash_stable? == true ->
        %{
          state: :working,
          evidence: ["#{name} running, screen unchanged, no CPU"],
          confidence: :medium
        }

      true ->
        %{state: :working, evidence: ["#{name} running"], confidence: :low}
    end
  end

  defp shell?(observation, argv) do
    case Map.get(observation, :shell?) do
      value when is_boolean(value) -> value
      _ -> argv == nil or basename(argv) in @shells
    end
  end

  defp basename(argv) do
    argv
    |> String.split(~r/\s+/, parts: 2)
    |> List.first()
    |> to_string()
    |> Path.basename()
    |> String.trim_leading("-")
  end

  # --- prompt detection -------------------------------------------------------

  # Tool prompts specific enough that seeing one anywhere on the last line is conclusive.
  @known_prompts [
    {~r/\[sudo\] password for /i, "sudo password prompt"},
    {~r/^Password:\s*$/i, "password prompt"},
    {~r/Are you sure you want to continue connecting/i, "ssh host-key prompt"},
    {~r/Enter passphrase for key/i, "ssh key passphrase prompt"},
    {~r/^Username for /i, "git credential prompt"},
    {~r/^Password for /i, "git credential prompt"},
    {~r/Do you want to (proceed|continue)/i, "confirmation prompt"},
    {~r/Overwrite\b.*\?/i, "overwrite prompt"},
    {~r/\(END\)\s*$/, "pager waiting"},
    {~r/^--More--/, "pager waiting"}
  ]

  # A trailing affordance: the shapes a program uses when it is about to read a line.
  @answer_shapes ~r/(\[y\/n\]|\[Y\/n\]|\[y\/N\]|\(yes\/no(\/\[fingerprint\])?\)|\[\d+\/\d+\])\s*[:?>]?\s*$/i

  defp detect_prompt(nil), do: nil

  defp detect_prompt(tail) do
    case last_meaningful_line(tail) do
      nil ->
        nil

      line ->
        cond do
          # Checked before the generic shapes: a known tool prompt is conclusive wherever it
          # appears on the line, and its label is better evidence than "ends with a question".
          hit = known_prompt(line) -> hit
          Regex.match?(@answer_shapes, line) -> "prompt: #{truncate(line)}"
          question?(line) -> "prompt: #{truncate(line)}"
          true -> nil
        end
    end
  end

  defp known_prompt(line) do
    Enum.find_value(@known_prompts, fn {pattern, label} ->
      if Regex.match?(pattern, line), do: label
    end)
  end

  # A question only counts on the LAST line, and only with an answer affordance after it. A
  # build log that happens to contain "continue?" mid-scroll is not someone waiting.
  defp question?(line) do
    trimmed = String.trim_trailing(line)

    String.ends_with?(trimmed, "?") or
      (String.ends_with?(trimmed, ":") and String.length(trimmed) < 80) or
      Regex.match?(~r/\?\s*[>»]\s*$/, trimmed)
  end

  # The last line with something on it. A pane whose cursor sits on a blank line below a prompt
  # is the ordinary case, not an exception — reading only the very last line would miss every
  # prompt that ends with a newline.
  defp last_meaningful_line(tail) do
    tail
    |> String.split(~r/\r?\n/)
    |> Enum.reverse()
    |> Enum.find(fn line -> String.trim(line) != "" end)
  end

  defp truncate(line) do
    line = String.trim(line)
    if String.length(line) > 120, do: String.slice(line, 0, 117) <> "...", else: line
  end

  defp string_or_nil(value) when is_binary(value), do: if(value == "", do: nil, else: value)
  defp string_or_nil(_value), do: nil

  defp format_cpu(value), do: :erlang.float_to_binary(value / 1, decimals: 1)
end
