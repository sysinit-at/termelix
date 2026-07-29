defmodule Termelix.Tmux do
  @moduledoc """
  Tmux monitor over one-shot SSH exec — the port of the Node tmux backend
  (`src/backend/hosts/tmux/{index,helper,monitor-helpers}.ts`, port 30010). Two surfaces are
  implemented here: the request-driven **overview** (list the host's tmux sessions, their
  windows, and their panes) and the per-user **session-tags CRUD** (`tmux_session_tags`).

  Each overview runs ONE combined command per poll (`tmux -V` as the availability probe, then
  `list-sessions` / `list-windows -a` / `list-panes -a` with a printable-ASCII field
  separator), with marker-delimited sections parsed out of the single output — the same
  batching pattern as `Termelix.Metrics.build_command/0`. Tmux is invoked through a small
  `/bin/sh -c` wrapper that prepends the common Homebrew/pkg bin dirs to `PATH`
  (`helper.ts:withTmuxPath`) so it is found under a non-login shell.

  The Node backend held one pooled SSH client per host and ran the three list commands in
  parallel over it; this port opens one short-lived connection per overview via
  `Termelix.SSH.Exec.run/2`. A connection/transport
  failure of that single exec surfaces as `{:error, {:ssh, reason}}` (Node's
  `HOST_UNREACHABLE`) — where Node could still render partial data when a later probe's
  connection dropped, the combined exec is all-or-nothing. Connection pooling, jump-hosts,
  and SOCKS5 proxying are deferred with the rest of the interactive-auth breadth work.

  The **mutating actions** (focus, create session/window, rename, kill session/window/pane,
  split) run as one-shot execs through `run_action/2`; the Node routes' remote error text
  (duplicate session / can't find session…) travels back verbatim in `{:error, {:command,
  msg}}` so the controller can map it onto the contract's 404/409s. The pane **search**
  (`capture-pane | grep`) and per-pane **metrics** (`ps` process-tree + `nvidia-smi` GPU
  aggregation) batch their whole remote workload into a single marker-delimited script per
  request — where Node fanned out per-pane execs over one pooled connection, this port pays
  one connection per request instead.

  ## Deferred (not ported here)

    * There is **no dedicated tmux WebSocket**: the frontend keeps the view "live" by polling
      `/tmux_monitor/:hostId/overview` on an interval, and the monitor's embedded terminal
      reuses the ordinary SSH terminal WebSocket. The polled overview + tags are implemented.
    * **RBAC shared-host access**: `Termelix.Hosts.get_for_user/2` is owned-only, so a host the
      user does not own is simply not found (the Node `checkHostAccess` 403 path collapses
      into the 404).
  """

  import Ecto.Query, only: [from: 2]

  alias Termelix.Hosts
  alias Termelix.Repo
  alias Termelix.SSH.Credential
  alias Termelix.SSH.Exec
  alias Termelix.Schema.TmuxSessionTag

  # Field separator in tmux `-F` format strings. Session names, pane titles and paths may
  # contain "|", and tmux rewrites control/multibyte characters in format output to "_", so a
  # printable-ASCII token is the only separator that survives everywhere (monitor-helpers.ts).
  @sep "<<TMX>>"

  # Section markers delimiting the four probes inside the single combined overview command
  # (same pattern as `Termelix.Metrics`' `@marker_prefix`).
  @marker_prefix "===TERMELIX-TMUX:"
  @marker_suffix "==="
  # The overview probe now also samples `ps` so each pane/session carries an activity
  # status (the flagship "what is each session doing" view — docs/TMUX_FEATURE_EVALUATION.md).
  @sections [:version, :sessions, :windows, :panes, :ps, :tails]

  # How many lines of each pane's visible screen the overview brings back. Enough for
  # `Termelix.Tmux.Activity` to see a prompt and the line or two of context above it; small
  # enough that a host with 40 panes is still one modest payload.
  @tail_lines 20

  # Homebrew / pkg bin dirs prepended to PATH so tmux is found under a non-login shell.
  @tmux_path_dirs ["/opt/homebrew/bin", "/usr/local/bin", "/opt/bin", "/usr/pkg/bin"]

  # Foreground-command classification for per-pane / per-session activity status. tmux
  # reports the bare command name (`pane_current_command`), so these match base names.
  @shell_commands ~w(bash zsh sh fish dash ash tcsh csh ksh -bash -zsh -sh -fish login)
  @ssh_commands ~w(ssh mosh mosh-client autossh et sshrc sshpass sftp)
  @agent_commands ~w(claude codex aider goose gemini cursor-agent cursor aichat cody
                     continue llm ollama chatgpt copilot)

  # A pane whose descendant process tree draws at least this much CPU counts as actively
  # "working" rather than idle / waiting-for-input.
  @busy_cpu 5.0

  # Session-status roll-up priority (highest wins): a waiting agent outranks a working one,
  # which outranks a plain running program, which outranks an idle shell prompt.
  @status_rank %{"waiting" => 3, "working" => 2, "running" => 1, "idle" => 0}

  # Options applied on every attach/create written into an interactive PTY
  # (`helper.ts:TMUX_OPTS`): mouse scrollback, deep history, OSC 52 clipboard sync,
  # vi copy-mode with keep-selection-on-drag-end + Enter-to-copy, and a hint on
  # copy-mode entry. `-q` suppresses errors on older tmux versions.
  @tmux_attach_opts ~S(set -gq mouse on \; set -gq history-limit 50000 \; ) <>
                      ~S(set -gq set-clipboard on \; set -gq aggressive-resize on \; ) <>
                      ~S(set -gq mode-keys vi \; ) <>
                      ~S(bind-key -T copy-mode-vi MouseDragEnd1Pane send-keys -X stop-selection \; ) <>
                      ~S(bind-key -T copy-mode-vi Enter send-keys -X copy-selection-and-cancel \; ) <>
                      ~S(set-hook -g pane-mode-changed 'if -F "#{pane_in_mode}" ) <>
                      ~S("display-message -d 2500 \"Adjust selection and press Enter to copy\""')

  # Prefix of every session name Termelix derives itself (`session_name/1`). It is what an
  # operator greps for in `tmux ls` when taking a session over from a plain `ssh host` —
  # directive 3 of docs/ARCHITECTURE_REVIEW.md §6.0 ("a human must be able to take over any
  # agent session at any time") only holds if the name is recognisable and predictable.
  @session_name_prefix "termelix-"

  # Digest bytes kept before base32 — 40 bits, exactly 8 base32 characters, no padding.
  @session_name_digest_bytes 5

  # Search limits (`tmux/index.ts`): panes per search, matches per pane, scrollback depth.
  @max_search_panes 100
  @max_matches_per_pane 50
  @search_history_lines 2000

  @type overview :: %{
          available: boolean(),
          sessions: [map()]
        }

  # --- overview (per-host listing) --------------------------------------------

  @doc """
  Aggregate tmux overview across every tmux-enabled host the user owns — backs the global
  tmux view (all sessions on all hosts, one poll). Fans out `overview/2` concurrently
  (bounded, per-host timeout) and returns one entry per host:

      %{hostId, hostName, available: boolean, sessions: [...], error: nil | binary}

  A host that is unreachable or errors yields `available: false` with an `error` message
  rather than failing the whole aggregate — one dead host never hides the others.

  ## Why the bounds are what they are

  This is on the SPA's startup path: the sessions column is part of the shell now, and its
  default scope is every host, so this runs on every load rather than when somebody opens a
  view. Worst case is `ceil(hosts / concurrency) * timeout`, which at the old 8-wide/20s was
  100 seconds for a fleet of forty unreachable hosts. 16-wide with an 8s timeout puts the same
  fleet at 24 seconds, and a probe that has not answered in eight seconds over SSH is not about
  to answer usefully — the per-host view, which is what you open when you actually care about
  that machine, keeps its own longer budget.
  """
  @spec overview_all(String.t()) :: [map()]
  def overview_all(user_id) do
    # Filter before decrypting: this runs on the SPA's startup path, and decrypting
    # every host to discard the non-monitor ones materializes plaintext secrets
    # nobody uses on a hot path.
    hosts =
      Termelix.Hosts.list_for_user(user_id,
        decrypt: true,
        filter: &(&1.enableTmuxMonitor == true)
      )

    hosts
    |> Task.async_stream(
      fn host -> overview(host, user_id) end,
      max_concurrency: 16,
      timeout: 8_000,
      on_timeout: :kill_task,
      ordered: true
    )
    # Zipped back against the input rather than carrying the host through the task: on timeout
    # `async_stream` yields a bare `{:exit, :timeout}` with no reference to what timed out, and
    # the previous version dropped those rows entirely. A host slow enough to time out then
    # vanished from the list — indistinguishable from one that has no sessions, when it is the
    # case most worth seeing.
    |> Enum.zip(hosts)
    |> Enum.map(fn
      {{:ok, {:ok, %{available: available, sessions: sessions}}}, host} ->
        host_entry(host, available, sessions, nil)

      {{:ok, {:error, reason}}, host} ->
        host_entry(host, false, [], overview_error(reason))

      {{:exit, :timeout}, host} ->
        host_entry(host, false, [], "Timed out")

      {{:exit, reason}, host} ->
        host_entry(host, false, [], "Probe failed: #{inspect(reason)}")
    end)
  end

  defp host_entry(host, available, sessions, error) do
    %{
      hostId: host.id,
      hostName: host.name || "#{host.username}@#{host.ip}",
      available: available,
      sessions: sessions,
      error: error
    }
  end

  defp overview_error({:ssh, _}), do: "Could not connect to the host"
  defp overview_error({:command, msg}) when is_binary(msg), do: msg
  defp overview_error(other), do: inspect(other)

  @doc """
  Build the tmux overview for a resolved, DEK-decrypted `host` (a `Termelix.Schema.Host`, so its
  `password`/`key` are already plaintext). Runs the single combined `overview_command/0`;
  an empty `version` section (or the whole script failing with no stdout) means tmux is
  absent and yields `%{available: false, sessions: []}` — matching the Node route. When
  available, folds panes into their windows and merges the caller's saved tags per session
  name. A connection/transport failure surfaces as `{:error, {:ssh, reason}}` so the
  controller can classify it (Node's `HOST_UNREACHABLE`).
  """
  @spec overview(map(), String.t()) :: {:ok, overview()} | {:error, term()}
  def overview(host, user_id) do
    case exec(host, overview_command(), :overview) do
      {:error, {:ssh, _reason}} = err ->
        err

      {:error, {:command, _msg}} ->
        # The whole script produced no stdout — the same shape the standalone `tmux -V`
        # probe surfaced when tmux was absent.
        {:ok, %{available: false, sessions: []}}

      {:ok, out} ->
        sections = split_sections(out)

        if section(sections, :version) == "" do
          {:ok, %{available: false, sessions: []}}
        else
          sessions = parse_sessions(section(sections, :sessions))
          windows = parse_windows(section(sections, :windows))
          panes = parse_panes(section(sections, :panes))
          windows = attach_panes_to_windows(windows, panes)
          tags = list_tags_by_session(user_id, host.id)

          # Per-pane CPU/top-command from the `ps` snapshot → per-pane and per-session
          # activity status. `ps` absent/empty leaves everything "idle"/"running" by command.
          metrics_by_pane =
            panes
            |> build_pane_metrics(parse_ps_output(section(sections, :ps)), %{})
            |> Map.new(&{&1.paneId, &1})

          tails = parse_tails(section(sections, :tails))

          full =
            Enum.map(sessions, fn s ->
              enriched_windows =
                windows |> Map.get(s.name, []) |> enrich_windows(metrics_by_pane, tails)

              %{
                name: s.name,
                created: s.created,
                lastActivity: s.lastActivity,
                attachedClients: s.attachedClients,
                windows: enriched_windows,
                tags: Map.get(tags, s.name, []),
                status: session_status(enriched_windows)
              }
            end)

          {:ok, %{available: true, sessions: full}}
        end
    end
  end

  # --- mutating actions (one-shot execs) --------------------------------------

  @doc """
  Select a pane's window and pane on the server so every attached client switches to it
  (a pane id is a valid window target — tmux resolves it to the containing window).
  """
  @spec focus(map(), String.t()) :: :ok | {:error, term()}
  def focus(host, pane_id) do
    esc = shell_escape(pane_id)
    run_action(host, "select-window -t #{esc} \\; select-pane -t #{esc}")
  end

  @doc "Create a detached session (starts the tmux server if none is running)."
  @spec create_session(map(), String.t()) :: :ok | {:error, term()}
  def create_session(host, name),
    do: run_action(host, "new-session -d -s #{shell_escape(name)}")

  @doc "Create a window in an existing session (`=` forces exact-name target matching)."
  @spec create_window(map(), String.t()) :: :ok | {:error, term()}
  def create_window(host, session_name),
    do: run_action(host, "new-window -t #{shell_escape("=" <> session_name)}")

  @doc "Rename a session. The caller reconciles saved tags via `rename_session_tags/3`."
  @spec rename_session(map(), String.t(), String.t()) :: :ok | {:error, term()}
  def rename_session(host, session_name, new_name) do
    run_action(
      host,
      "rename-session -t #{shell_escape("=" <> session_name)} #{shell_escape(new_name)}"
    )
  end

  @doc "Kill a session. The caller drops saved tags via `delete_session_tags/2`."
  @spec kill_session(map(), String.t()) :: :ok | {:error, term()}
  def kill_session(host, session_name),
    do: run_action(host, "kill-session -t #{shell_escape("=" <> session_name)}")

  @doc "Kill a window (killing the last window of a session ends the session)."
  @spec kill_window(map(), String.t(), non_neg_integer()) :: :ok | {:error, term()}
  def kill_window(host, session_name, window_index) do
    run_action(host, "kill-window -t #{shell_escape("=#{session_name}:#{window_index}")}")
  end

  @doc "Kill a single pane (the last pane of a window closes the window)."
  @spec kill_pane(map(), String.t()) :: :ok | {:error, term()}
  def kill_pane(host, pane_id),
    do: run_action(host, "kill-pane -t #{shell_escape(pane_id)}")

  @doc """
  Split the window containing a pane: `"h"` adds a pane to the right, `"v"` below (tmux
  `-h`/`-v` semantics). The new pane starts in the source pane's working directory.
  """
  @spec split_pane(map(), String.t(), String.t()) :: :ok | {:error, term()}
  def split_pane(host, pane_id, direction) do
    flag = if direction == "v", do: "-v", else: "-h"

    run_action(
      host,
      "split-window #{flag} -t #{shell_escape(pane_id)} -c #{shell_escape("\#{pane_current_path}")}"
    )
  end

  # A mutation succeeds silently; its remote error text (duplicate session / can't find
  # session…) travels back in `{:error, {:command, msg}}` for the controller to classify.
  defp run_action(host, args) do
    case exec(host, tmux_command(args), :action) do
      {:ok, _out} -> :ok
      {:error, _} = err -> err
    end
  end

  # --- search / metrics (batched one-shot execs) -------------------------------

  @doc """
  Search every pane's scrollback for `query` (fixed-string, case-insensitive). Lists the
  panes first, then runs ONE combined remote script — a `capture-pane | grep | head` block
  per pane, each prefixed by a pane marker — so one SSH round-trip replaces Node's bounded
  per-pane fan-out. Returns `{:ok, %{matches, truncated, searchedLines, maxPanes}}`;
  `truncated` flips when the pane cap or a per-pane match cap was hit.
  """
  @spec search(map(), String.t()) :: {:ok, map()} | {:error, term()}
  def search(host, query) do
    with {:ok, all_panes} <- list_panes(host) do
      panes = Enum.take(all_panes, @max_search_panes)
      truncated = length(all_panes) > @max_search_panes

      case panes do
        [] ->
          {:ok, search_result([], truncated)}

        panes ->
          case exec(host, search_command(panes, query), :search) do
            {:ok, out} ->
              {matches, hit_cap} = parse_search_output(out, panes)
              {:ok, search_result(matches, truncated or hit_cap)}

            # grep matching nothing anywhere exits non-zero with empty stdout.
            {:error, {:command, _}} ->
              {:ok, search_result([], truncated)}

            {:error, _} = err ->
              err
          end
      end
    end
  end

  defp search_result(matches, truncated) do
    %{
      matches: matches,
      truncated: truncated,
      searchedLines: @search_history_lines,
      maxPanes: @max_search_panes
    }
  end

  @doc """
  The combined remote search script: per pane, a marker line then
  `capture-pane -p -J | grep -n -i -F | head`, under the PATH shim. Pane ids come from
  tmux's own listing (`%N`), and the query is single-quote escaped.
  """
  @spec search_command([map()], String.t()) :: String.t()
  def search_command(panes, query) do
    esc_query = shell_escape(query)

    panes
    |> Enum.map(fn pane ->
      "echo #{@marker_prefix}pane:#{pane.id}#{@marker_suffix}\n" <>
        "tmux capture-pane -p -J -t #{shell_escape(pane.id)} -S -#{@search_history_lines} 2>/dev/null" <>
        " | grep -n -i -F -- #{esc_query} | head -#{@max_matches_per_pane}"
    end)
    |> Enum.join("\n")
    |> with_tmux_path()
  end

  @doc """
  Parse combined search output back into frontend matches (`grep -n` lines, capped text),
  attributing each section to its pane via the marker lines. Returns
  `{matches, hit_match_cap?}`.
  """
  @spec parse_search_output(String.t(), [map()]) :: {[map()], boolean()}
  def parse_search_output(output, panes) do
    by_id = Map.new(panes, fn p -> {p.id, p} end)
    marker_re = ~r/^#{Regex.escape(@marker_prefix)}pane:(%\d+)#{Regex.escape(@marker_suffix)}$/

    {matches, counts} =
      output
      |> String.split("\n")
      |> Enum.reduce({[], %{current: nil}}, fn line, {acc, counts} ->
        case Regex.run(marker_re, String.trim(line)) do
          [_, pane_id] ->
            {acc, Map.put(counts, :current, Map.get(by_id, pane_id))}

          nil ->
            pane = counts.current

            case pane && parse_grep_line(line) do
              {line_no, text} ->
                match = %{
                  paneId: pane.id,
                  sessionName: pane.sessionName,
                  windowIndex: pane.windowIndex,
                  line: line_no,
                  text: text
                }

                {[match | acc], Map.update(counts, pane.id, 1, &(&1 + 1))}

              _ ->
                {acc, counts}
            end
        end
      end)

    hit_cap =
      counts
      |> Map.drop([:current])
      |> Map.values()
      |> Enum.any?(&(&1 >= @max_matches_per_pane))

    {Enum.reverse(matches), hit_cap}
  end

  # "12:some text" → {12, "some text"} (text capped at 500 chars); anything else nil.
  defp parse_grep_line(line) do
    case String.split(line, ":", parts: 2) do
      [no, text] ->
        case Integer.parse(no) do
          {n, ""} -> {n, String.slice(text, 0, 500)}
          _ -> nil
        end

      _ ->
        nil
    end
  end

  @doc """
  Per-pane resource metrics: ONE combined script lists panes, dumps `ps` (pid/ppid/cpu/
  mem/rss/comm) and best-effort `nvidia-smi` GPU memory, then each pane's shell pid is
  mapped to its descendant process tree and aggregated (`monitor-helpers.ts`). Returns
  `{:ok, [pane_metrics]}` — empty when tmux has no panes or `ps` produced nothing.
  """
  @spec pane_metrics(map()) :: {:ok, [map()]} | {:error, term()}
  def pane_metrics(host) do
    case exec(host, metrics_command(), :metrics) do
      {:error, {:ssh, _}} = err ->
        err

      {:error, {:command, _}} ->
        {:ok, []}

      {:ok, out} ->
        sections = split_sections(out, [:panes, :ps, :gpu])
        panes = parse_panes(section(sections, :panes))
        processes = parse_ps_output(section(sections, :ps))

        if panes == [] or processes == [] do
          {:ok, []}
        else
          gpu = parse_gpu_output(section(sections, :gpu))
          {:ok, build_pane_metrics(panes, processes, gpu)}
        end
    end
  end

  @doc "The combined metrics script: pane listing + `ps` snapshot + GPU per-pid memory."
  @spec metrics_command() :: String.t()
  def metrics_command do
    [
      probe(:panes, "tmux #{panes_args()}"),
      probe(:ps, "ps -eo pid=,ppid=,pcpu=,pmem=,rss=,comm= 2>/dev/null"),
      probe(
        :gpu,
        "command -v nvidia-smi >/dev/null 2>&1 && " <>
          "nvidia-smi --query-compute-apps=pid,used_gpu_memory --format=csv,noheader,nounits 2>/dev/null || true"
      )
    ]
    |> Enum.join("\n")
    |> with_tmux_path()
  end

  # One short-lived exec listing all panes; `{:error, {:command, _}}` (no tmux server)
  # collapses to an empty pane list, matching Node's `runTmuxList` catch.
  defp list_panes(host) do
    case exec(host, tmux_command(panes_args()), :list_panes) do
      {:ok, out} -> {:ok, parse_panes(out)}
      {:error, {:command, _}} -> {:ok, []}
      {:error, _} = err -> err
    end
  end

  # --- terminal attach helpers (written into an interactive PTY) ---------------

  @doc """
  The shell line a PTY runs to attach to an existing session with the standard options
  applied (`helper.ts:attachOrCreateTmuxSession`): `&& exit` closes the wrapping shell only
  when tmux itself started; `=` forces exact-name matching.
  """
  @spec attach_command(String.t()) :: String.t()
  def attach_command(session_name) do
    tmux_command(
      "#{@tmux_attach_opts} \\; attach-session -t #{shell_escape("=" <> session_name)}"
    ) <> " && exit"
  end

  @doc """
  The shell line a PTY runs to make the remote tmux session `session_name` the shell:
  `tmux new-session -A -s <name>` attaches when it exists and creates it otherwise, so one
  command covers first connect and every reconnect (P4 — the tmux session is the session of
  record, the BEAM session is a disposable attachment).

  Options:

    * `:start_directory` — `-c <dir>`, the working directory of the session's first pane.
      Only honoured on creation; tmux ignores it when it attaches.

  Two details that are easy to get wrong:

    * `-s` takes a literal NAME, not a target, so the `=` prefix that forces exact matching on
      `attach-session -t` must NOT appear here — it would become part of the created session's
      name. `-A` compares names exactly on its own (tmux's `session_find`).
    * `&& exit` closes the wrapping login shell only when tmux itself started, exactly as in
      `attach_command/1`: a host without tmux falls back to a plain shell (one "command not
      found" line) rather than a dead session.

  Returns `{:error, reason}` rather than raising, because the result is typed into a live PTY:
  a caller that cannot build a safe command must be able to fall back to a plain shell instead
  of crashing the session. See `safe_session_name?/1` for what "safe" means here.
  """
  @spec new_or_attach_command(String.t(), keyword()) ::
          {:ok, String.t()} | {:error, :unsafe_session_name | :unsafe_start_directory}
  def new_or_attach_command(session_name, opts \\ []) do
    start_directory = Keyword.get(opts, :start_directory)

    cond do
      not safe_session_name?(session_name) ->
        {:error, :unsafe_session_name}

      not is_nil(start_directory) and not safe_start_directory?(start_directory) ->
        {:error, :unsafe_start_directory}

      true ->
        args = "#{@tmux_attach_opts} \\; #{new_session_args(session_name, start_directory)}"
        {:ok, tmux_command(args) <> " && exit"}
    end
  end

  defp new_session_args(session_name, start_directory) do
    base = "new-session -A -s #{shell_escape(session_name)}"

    case start_directory do
      nil -> base
      dir -> "#{base} -c #{shell_escape(dir)}"
    end
  end

  @doc """
  The one-shot exec that answers "does this session already exist on the host": `tmux
  has-session -t =<name>`. The `=` forces exact matching — without it tmux resolves the target
  as a prefix and `has-session -t work` answers yes for a session named `workbench`, which
  would make a resume attach the wrong session.
  """
  @spec session_exists_command(String.t()) :: {:ok, String.t()} | {:error, :unsafe_session_name}
  def session_exists_command(session_name) do
    if safe_session_name?(session_name) do
      {:ok, tmux_command("has-session -t #{shell_escape("=" <> session_name)} 2>/dev/null")}
    else
      {:error, :unsafe_session_name}
    end
  end

  @doc """
  The standalone tmux-presence probe (`tmux -V`) — the same probe `overview_command/0`
  batches as its `:version` section, for callers that only need the yes/no.
  """
  @spec available_command() :: String.t()
  def available_command, do: tmux_command("-V 2>/dev/null")

  @doc """
  Whether tmux is installed on `host` (one short-lived exec). `{:ok, false}` covers both
  "not installed" and "installed but refused to run"; a connect/transport failure still
  surfaces as `{:error, {:ssh, reason}}` so the caller can tell an unreachable host from a
  tmux-less one.
  """
  @spec available?(map()) :: {:ok, boolean()} | {:error, term()}
  def available?(host) do
    case exec(host, available_command(), :available) do
      {:ok, out} -> {:ok, out != ""}
      {:error, {:command, _}} -> {:ok, false}
      {:error, _} = err -> err
    end
  end

  @doc """
  Whether `session_name` exists on `host` right now. `has-session` exits non-zero with empty
  stdout when the session is gone, which `exec/3` reports as `{:error, {:command, _}}`.
  """
  @spec session_exists?(map(), String.t()) :: {:ok, boolean()} | {:error, term()}
  def session_exists?(host, session_name) do
    case session_exists_command(session_name) do
      {:ok, command} ->
        case exec(host, command, :has_session) do
          {:ok, _} -> {:ok, true}
          {:error, {:command, _}} -> {:ok, false}
          {:error, _} = err -> err
        end

      {:error, :unsafe_session_name} ->
        {:ok, false}
    end
  end

  @doc """
  The deterministic tmux session name for a durable identity: `session_name(["u", user_id,
  "h", host_id])`, or the `terminal_bindings` row id once P4's binding table lands.

  Determinism is the whole point — the name may not depend on anything that changes per
  connection (the BEAM session id is regenerated on every `connectToHost`, so deriving from it
  would create a fresh tmux session per reconnect and lose the session of record on the first
  redeploy). `parts` are joined with NUL and hashed, so no user id or host name reaches the
  remote process list, and the result is always `safe_session_name?/1`-clean.
  """
  @spec session_name([term()]) :: String.t()
  def session_name(parts) when is_list(parts) do
    digest =
      parts
      |> Enum.map_join(<<0>>, &to_string/1)
      |> then(&:crypto.hash(:sha256, &1))
      |> binary_part(0, @session_name_digest_bytes)
      |> Base.encode32(case: :lower, padding: false)

    @session_name_prefix <> digest
  end

  @doc """
  Whether `name` is usable as a tmux session name in a command Termelix builds. Two
  independent reasons a name can be rejected:

    * tmux treats `.` and `:` as target separators, so `-t =a.b` / `-t =a:b` select a pane or
      window of some other session rather than the session called `a.b`;
    * these commands are typed into a live PTY, where quoting is irrelevant — `\\x15`
      (`unix-line-discard`), `\\x03` and `\\x7f` edit the line the shell will run, so a name
      carrying one runs a different command entirely (see `safe_initial_path?/1` in
      `terminal_socket.ex` for the same argument about paths).

  `terminal_socket.ex:292` still carries a private copy of this predicate (`safe_tmux_name?/1`)
  for the SPA's `tmuxAttachSession`; it should call this one instead — that copy allows `\\x7f`,
  which this one rejects.
  """
  @spec safe_session_name?(term()) :: boolean()
  def safe_session_name?(name) when is_binary(name) do
    name != "" and byte_size(name) <= 64 and not Regex.match?(~r/[:.\n\r\x00-\x1f\x7f]/, name)
  end

  def safe_session_name?(_), do: false

  @doc """
  Whether a starting directory is safe to interpolate into a PTY-typed command: C0 controls
  plus DEL are rejected outright. Same predicate as `safe_initial_path?/1`
  (`terminal_socket.ex:297`), which should call this one rather than keep its own copy.
  """
  @spec safe_start_directory?(term()) :: boolean()
  def safe_start_directory?(dir) when is_binary(dir),
    do: dir != "" and not Regex.match?(~r/[\x00-\x1f\x7f]/, dir)

  def safe_start_directory?(_), do: false

  # --- command builders (pure) ------------------------------------------------

  @doc "The printable-ASCII field separator used in the `-F` format strings."
  @spec sep() :: String.t()
  def sep, do: @sep

  @doc """
  The single combined command an overview runs: one shell script under the PATH-prefixing
  shim that echoes a section marker before each probe (`tmux -V`, `list-sessions`,
  `list-windows -a`, `list-panes -a`), so one SSH round-trip replaces four. Every probe's
  stderr is suppressed; a missing tmux yields an empty `version` section (the same signal
  the standalone `tmux -V` probe gave).
  """
  @spec overview_command() :: String.t()
  def overview_command do
    [
      probe(:version, "tmux -V 2>/dev/null"),
      probe(:sessions, "tmux #{sessions_args()}"),
      probe(:windows, "tmux #{windows_args()}"),
      probe(:panes, "tmux #{panes_args()}"),
      # One `ps` snapshot feeds per-pane CPU (→ activity status). No GPU probe here — the
      # dedicated metrics endpoint keeps that; status only needs CPU + the process tree.
      probe(:ps, "ps -eo pid=,ppid=,pcpu=,pmem=,rss=,comm= 2>/dev/null"),
      # The last few lines of every pane's screen. Without this `Termelix.Tmux.Activity` can
      # only ever decide from process state, which cannot distinguish "running" from "stopped
      # and asking you a question" — and that distinction is the entire point of the watcher.
      #
      # A shell loop over tmux's OWN pane ids, inside the same script, so it stays one SSH
      # round trip. Nothing user-supplied is interpolated: `%N` comes from tmux, and it is
      # quoted anyway (same argument as `search_command/2`).
      tails_probe()
    ]
    |> Enum.join("\n")
    |> with_tmux_path()
  end

  defp probe(key, cmd), do: "echo #{marker(key)}\n#{cmd}"

  defp tails_probe do
    """
    echo #{marker(:tails)}
    for __tp in $(tmux list-panes -a -F '\#{pane_id}' 2>/dev/null); do
      echo "#{@marker_prefix}pane:$__tp#{@marker_suffix}"
      tmux capture-pane -p -J -t "$__tp" -S -#{@tail_lines} 2>/dev/null
    done
    """
    |> String.trim_trailing()
  end

  @doc """
  Parse the `tails` section into `%{pane_id => screen_text}`.

  Public because it is the one piece of the overview whose output shape is decided by a remote
  shell loop rather than by a tmux format string, so it is worth pinning directly.
  """
  @spec parse_tails(String.t()) :: %{optional(String.t()) => String.t()}
  def parse_tails(text) do
    marker_re = ~r/^#{Regex.escape(@marker_prefix)}pane:(%\d+)#{Regex.escape(@marker_suffix)}$/

    text
    |> String.split("\n")
    |> Enum.reduce({nil, %{}}, fn line, {current, acc} ->
      case Regex.run(marker_re, String.trim(line)) do
        [_, pane_id] ->
          {pane_id, Map.put_new(acc, pane_id, [])}

        nil ->
          if current, do: {current, Map.update!(acc, current, &[line | &1])}, else: {nil, acc}
      end
    end)
    |> elem(1)
    |> Map.new(fn {pane_id, lines} ->
      {pane_id, lines |> Enum.reverse() |> Enum.join("\n") |> String.trim_trailing()}
    end)
  end

  defp marker(key), do: "#{@marker_prefix}#{key}#{@marker_suffix}"

  @doc """
  Split combined script stdout into a `%{section => text}` map keyed by the given section
  atoms (default: the overview's `#{inspect(@sections)}`). A line equal to a section marker
  starts that section; the lines until the next marker are its content.
  """
  @spec split_sections(String.t(), [atom()]) :: %{optional(atom()) => String.t()}
  def split_sections(stdout, sections \\ @sections) do
    markers = Map.new(sections, fn key -> {marker(key), key} end)

    {_current, acc} =
      stdout
      |> String.split("\n")
      |> Enum.reduce({nil, %{}}, fn line, {current, acc} ->
        case Map.get(markers, String.trim(line)) do
          nil ->
            if current,
              do: {current, Map.update(acc, current, [line], &[line | &1])},
              else: {nil, acc}

          key ->
            {key, Map.put_new(acc, key, [])}
        end
      end)

    Map.new(acc, fn {key, lines} -> {key, lines |> Enum.reverse() |> Enum.join("\n")} end)
  end

  # A section's text, trimmed, defaulting to "" when the marker never appeared.
  defp section(sections, key), do: sections |> Map.get(key, "") |> String.trim()

  @doc "`tmux list-sessions -F ...` (name/created/activity/attached), stderr suppressed."
  @spec list_sessions_cmd() :: String.t()
  def list_sessions_cmd, do: tmux_command(sessions_args())

  @doc "`tmux list-windows -a -F ...` (session/index/active/name), stderr suppressed."
  @spec list_windows_cmd() :: String.t()
  def list_windows_cmd, do: tmux_command(windows_args())

  @doc "`tmux list-panes -a -F ...` (11 pane fields), stderr suppressed."
  @spec list_panes_cmd() :: String.t()
  def list_panes_cmd, do: tmux_command(panes_args())

  defp sessions_args do
    ~s(list-sessions -F "\#{session_name}#{@sep}\#{session_created}#{@sep}\#{session_activity}#{@sep}\#{session_attached}" 2>/dev/null)
  end

  defp windows_args do
    ~s(list-windows -a -F "\#{session_name}#{@sep}\#{window_index}#{@sep}\#{window_active}#{@sep}\#{window_name}" 2>/dev/null)
  end

  defp panes_args do
    fields =
      [
        "session_name",
        "window_index",
        "pane_id",
        "pane_index",
        "pane_pid",
        "pane_active",
        "pane_width",
        "pane_height",
        "pane_current_command",
        "pane_current_path",
        "pane_title"
      ]
      |> Enum.map_join(@sep, &"\#{#{&1}}")

    ~s(list-panes -a -F "#{fields}" 2>/dev/null)
  end

  @doc "Wrap `tmux <args>` in the PATH-prefixing `/bin/sh -c` shim (`helper.ts:tmuxCommand`)."
  @spec tmux_command(String.t()) :: String.t()
  def tmux_command(args), do: with_tmux_path("tmux #{args}")

  @doc "Prefix the common bin dirs to PATH and run `command` under `/bin/sh -c`."
  @spec with_tmux_path(String.t()) :: String.t()
  def with_tmux_path(command) do
    script = "PATH=#{Enum.join(@tmux_path_dirs, ":")}:$PATH; export PATH; #{command}"
    "/bin/sh -c #{shell_escape(script)}"
  end

  @doc "POSIX single-quote escaping (`helper.ts:shellEscape`)."
  @spec shell_escape(String.t()) :: String.t()
  def shell_escape(s), do: "'" <> String.replace(s, "'", "'\\''") <> "'"

  # --- output parsers (pure) --------------------------------------------------

  @doc """
  Parse `list-sessions` output into session summaries (`monitor-helpers.ts:parseSessions`):
  one map per non-blank line with `:name`, `:created`, `:lastActivity`, `:attachedClients`
  (numeric fields default to 0).
  """
  @spec parse_sessions(String.t()) :: [map()]
  def parse_sessions(output) do
    output
    |> nonblank_lines()
    |> Enum.map(fn line ->
      [name, created, activity, attached] = split_fields(line, 4)

      %{
        name: name,
        created: to_int(created),
        lastActivity: to_int(activity),
        attachedClients: to_int(attached)
      }
    end)
  end

  @doc """
  Parse `list-windows` output into a `%{session_name => [window]}` map
  (`monitor-helpers.ts:parseWindows`), preserving tmux's line order. Each window is
  `%{index, name, active, panes: []}`; panes are filled in by `attach_panes_to_windows/2`.
  """
  @spec parse_windows(String.t()) :: %{optional(String.t()) => [map()]}
  def parse_windows(output) do
    output
    |> nonblank_lines()
    |> Enum.reduce(%{}, fn line, acc ->
      [session, index, active, name] = split_fields(line, 4)

      window = %{index: to_int(index), name: name || "", active: active == "1", panes: []}
      Map.update(acc, session, [window], &(&1 ++ [window]))
    end)
  end

  @doc """
  Parse `list-panes` output into raw panes (`monitor-helpers.ts:parsePanes`). Each map carries
  the pane fields plus `:sessionName` / `:windowIndex` used to group it into a window.
  """
  @spec parse_panes(String.t()) :: [map()]
  def parse_panes(output) do
    output
    |> nonblank_lines()
    |> Enum.map(fn line ->
      [session, window_index, id, index, pid, active, width, height, command, path, title] =
        split_fields(line, 11)

      %{
        sessionName: session,
        windowIndex: to_int(window_index),
        id: id,
        index: to_int(index),
        pid: to_int(pid),
        active: active == "1",
        width: to_int(width),
        height: to_int(height),
        command: command || "",
        path: path || "",
        title: title || ""
      }
    end)
  end

  @doc """
  Fold each pane into its window's `:panes` list (`monitor-helpers.ts:attachPanesToWindows`).
  A pane whose session/window is absent from `windows` is dropped. The grouping fields
  (`:sessionName`, `:windowIndex`) are stripped from the stored pane so the shape matches the
  frontend `TmuxPane`.
  """
  @spec attach_panes_to_windows(%{optional(String.t()) => [map()]}, [map()]) ::
          %{optional(String.t()) => [map()]}
  def attach_panes_to_windows(windows, panes) do
    Enum.reduce(panes, windows, fn pane, acc ->
      case Map.get(acc, pane.sessionName) do
        nil ->
          acc

        session_windows ->
          pane_fields = Map.drop(pane, [:sessionName, :windowIndex])

          updated =
            Enum.map(session_windows, fn w ->
              if w.index == pane.windowIndex, do: %{w | panes: w.panes ++ [pane_fields]}, else: w
            end)

          Map.put(acc, pane.sessionName, updated)
      end
    end)
  end

  # --- activity status classification -----------------------------------------

  @doc """
  Enrich each pane in `windows` with `status`, `cpuPercent`, `topCommand` and `isRemote`,
  looked up from `metrics_by_pane` (`%{pane_id => pane_metrics}`). Additive — the existing
  pane fields are untouched.
  """
  @spec enrich_windows([map()], %{optional(String.t()) => map()}, %{
          optional(String.t()) => String.t()
        }) :: [map()]
  def enrich_windows(windows, metrics_by_pane, tails \\ %{}) do
    Enum.map(windows, fn window ->
      panes =
        Enum.map(
          window.panes,
          &enrich_pane(&1, Map.get(metrics_by_pane, &1.id), Map.get(tails, &1.id))
        )

      %{window | panes: panes}
    end)
  end

  defp enrich_pane(pane, metric, tail) do
    cpu = (metric && metric.cpuPercent) || 0.0

    pane
    |> Map.put(:cpuPercent, cpu)
    |> Map.put(:topCommand, metric && metric.topCommand)
    |> Map.put(:isRemote, ssh_command?(base_command(pane.command)))
    |> Map.put(:status, classify_pane(pane, metric, cpu))
    # The raw screen tail, for `Termelix.Tmux.Activity`. Kept out of `classify_pane/3`, which
    # stays exactly as the SPA has always consumed it — the richer verdict is additive.
    |> Map.put(:screenTail, tail)
  end

  @doc """
  Classify one pane's activity from its foreground command and CPU:

    * `"waiting"` — a known agent (claude/codex/aider/…) that is idle → awaiting input;
    * `"working"` — an agent that is busy, or any non-shell foreground drawing CPU;
    * `"running"` — a non-shell foreground program that is not busy (server, editor, less);
    * `"idle"`    — a shell prompt.
  """
  @spec classify_pane(map(), map() | nil, float()) :: String.t()
  def classify_pane(pane, metric, cpu) do
    cmd = base_command(pane.command)
    top = metric && metric.topCommand && base_command(metric.topCommand)
    agent? = agent_command?(cmd) or (top != nil and agent_command?(top))

    cond do
      agent? and cpu < @busy_cpu -> "waiting"
      agent? -> "working"
      shell_command?(cmd) -> "idle"
      cpu >= @busy_cpu -> "working"
      true -> "running"
    end
  end

  @doc "Roll a session's status up from its panes: the highest-priority pane status wins."
  @spec session_status([map()]) :: String.t()
  def session_status(windows) do
    windows
    |> Enum.flat_map(& &1.panes)
    |> Enum.map(&Map.get(&1, :status, "idle"))
    |> Enum.max_by(&Map.get(@status_rank, &1, 0), fn -> "idle" end)
  end

  @doc "Whether a base command name is a shell (a pane at its prompt → idle)."
  @spec shell_command?(String.t()) :: boolean()
  def shell_command?(cmd), do: cmd in @shell_commands

  @doc "Whether a base command name is an ssh-family client (a nested remote session)."
  @spec ssh_command?(String.t()) :: boolean()
  def ssh_command?(cmd), do: cmd in @ssh_commands

  @doc "Whether a base command name is a known interactive agent CLI."
  @spec agent_command?(String.t()) :: boolean()
  def agent_command?(cmd), do: cmd in @agent_commands

  # tmux already reports the bare comm, but strip any leading `-` (login shells) and a path
  # for robustness against `ps` comm values.
  defp base_command(nil), do: ""

  defp base_command(cmd) when is_binary(cmd) do
    cmd
    |> String.trim()
    |> String.split("/")
    |> List.last()
    |> to_string()
  end

  @doc """
  Parse `ps -eo pid=,ppid=,pcpu=,pmem=,rss=,comm=` output into process maps
  (`monitor-helpers.ts:parsePsOutput`). Lines with fewer than 6 whitespace-separated
  fields or non-numeric pid/ppid are skipped; `comm` keeps its embedded spaces.
  """
  @spec parse_ps_output(String.t()) :: [map()]
  def parse_ps_output(output) do
    output
    |> String.split("\n")
    |> Enum.flat_map(fn line ->
      case String.split(String.trim(line), ~r/\s+/) do
        [pid, ppid, cpu, mem, rss | comm] when comm != [] ->
          with {pid, _} <- Integer.parse(pid),
               {ppid, _} <- Integer.parse(ppid) do
            [
              %{
                pid: pid,
                ppid: ppid,
                cpu: to_float(cpu),
                mem: to_float(mem),
                rss: to_int(rss),
                comm: Enum.join(comm, " ")
              }
            ]
          else
            _ -> []
          end

        _ ->
          []
      end
    end)
  end

  @doc """
  Parse `nvidia-smi --query-compute-apps=pid,used_gpu_memory` CSV output into a
  `%{pid => total_mb}` map (`monitor-helpers.ts:parseGpuOutput`); one pid may appear
  once per GPU process, so values accumulate.
  """
  @spec parse_gpu_output(String.t()) :: %{optional(integer()) => integer()}
  def parse_gpu_output(output) do
    output
    |> nonblank_lines()
    |> Enum.reduce(%{}, fn line, acc ->
      case String.split(line, ",") do
        [pid, mem | _] ->
          with {pid, _} <- Integer.parse(String.trim(pid)),
               {mem, _} <- Integer.parse(String.trim(mem)) do
            Map.update(acc, pid, mem, &(&1 + mem))
          else
            _ -> acc
          end

        _ ->
          acc
      end
    end)
  end

  @doc """
  Map each pane's shell pid to its descendant process tree and aggregate CPU / RSS / GPU
  usage per pane (`monitor-helpers.ts:buildPaneMetrics`). `topCommand` is the busiest
  descendant other than the pane shell itself (falling back to the shell when it is alone).
  """
  @spec build_pane_metrics([map()], [map()], %{optional(integer()) => integer()}) :: [map()]
  def build_pane_metrics(panes, processes, gpu_by_pid) do
    by_pid = Map.new(processes, fn p -> {p.pid, p} end)
    children_of = Enum.group_by(processes, & &1.ppid, & &1.pid)

    Enum.map(panes, fn pane ->
      tree_pids = descendant_pids(pane.pid, by_pid, children_of)

      {cpu, rss, gpu, top_command, _top_cpu} =
        Enum.reduce(tree_pids, {0.0, 0, 0, nil, -1.0}, fn pid,
                                                          {cpu, rss, gpu, top_comm, top_cpu} ->
          p = Map.fetch!(by_pid, pid)
          gpu_mb = Map.get(gpu_by_pid, pid, 0)

          # The pane shell itself is rarely the interesting process.
          {top_comm, top_cpu} =
            if p.cpu > top_cpu and pid != pane.pid,
              do: {p.comm, p.cpu},
              else: {top_comm, top_cpu}

          {cpu + p.cpu, rss + p.rss, gpu + gpu_mb, top_comm, top_cpu}
        end)

      top_command =
        case {top_command, tree_pids} do
          {nil, [first | _]} -> Map.fetch!(by_pid, first).comm
          {comm, _} -> comm
        end

      %{
        paneId: pane.id,
        sessionName: pane.sessionName,
        pid: pane.pid,
        processCount: length(tree_pids),
        cpuPercent: Float.round(cpu * 1.0, 1),
        memRssKb: rss,
        gpuMemMb: gpu,
        topCommand: top_command
      }
    end)
  end

  # BFS over the ppid→pids map starting at (and including) the pane's shell pid, keeping
  # only pids `ps` actually reported.
  defp descendant_pids(root, by_pid, children_of) do
    walk_descendants(:queue.from_list([root]), MapSet.new(), [], by_pid, children_of)
  end

  defp walk_descendants(queue, seen, acc, by_pid, children_of) do
    case :queue.out(queue) do
      {:empty, _} ->
        Enum.reverse(acc)

      {{:value, pid}, rest} ->
        if MapSet.member?(seen, pid) do
          walk_descendants(rest, seen, acc, by_pid, children_of)
        else
          seen = MapSet.put(seen, pid)
          acc = if Map.has_key?(by_pid, pid), do: [pid | acc], else: acc
          queue = Enum.reduce(Map.get(children_of, pid, []), rest, &:queue.in/2)
          walk_descendants(queue, seen, acc, by_pid, children_of)
        end
    end
  end

  # parseFloat(x) || 0 — leading float, else 0.0.
  defp to_float(v) when is_binary(v) do
    case Float.parse(v) do
      {f, _rest} -> f
      :error -> 0.0
    end
  end

  # --- session-tags CRUD ------------------------------------------------------

  @doc """
  All of a user's tags for a host, grouped `%{session_name => [tag]}` in insertion order
  (`TmuxSessionTagRepository.listByUserAndHost`).
  """
  @spec list_tags_by_session(String.t(), integer()) :: %{optional(String.t()) => [String.t()]}
  def list_tags_by_session(user_id, host_id) do
    from(t in TmuxSessionTag,
      where: t.userId == ^user_id and t.hostId == ^host_id,
      order_by: [asc: t.id],
      select: {t.sessionName, t.tag}
    )
    |> Repo.all()
    |> Enum.reduce(%{}, fn {session, tag}, acc ->
      Map.update(acc, session, [tag], &(&1 ++ [tag]))
    end)
  end

  @doc """
  Set the tags for one (user, host, session): sanitize the supplied list, then replace the
  user's stored tags for that session. Returns `{:ok, clean_tags}` — the cleaned list the
  route echoes back. Mirrors the `PUT /tmux_monitor/:hostId/tags` cleanup +
  `replaceForUserHostSession`.
  """
  @spec set_session_tags(String.t(), integer(), String.t(), [String.t()]) :: {:ok, [String.t()]}
  def set_session_tags(user_id, host_id, session_name, tags) do
    clean = sanitize_tags(tags)
    replace_session_tags(user_id, host_id, session_name, clean)
    {:ok, clean}
  end

  @doc """
  Sanitize a tag list the way the route does: trim each, cap length at 64 chars, drop blanks,
  de-duplicate (first occurrence wins), and keep at most 20.
  """
  @spec sanitize_tags([term()]) :: [String.t()]
  def sanitize_tags(tags) when is_list(tags) do
    tags
    |> Enum.filter(&is_binary/1)
    |> Enum.map(&String.slice(String.trim(&1), 0, 64))
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
    |> Enum.take(20)
  end

  def sanitize_tags(_), do: []

  @doc """
  Replace the user's stored tags for one session (delete the existing set, insert `clean_tags`)
  in a single transaction (`TmuxSessionTagRepository.replaceForUserHostSession`).
  """
  @spec replace_session_tags(String.t(), integer(), String.t(), [String.t()]) :: :ok
  def replace_session_tags(user_id, host_id, session_name, clean_tags) do
    now = DateTime.utc_now() |> DateTime.to_iso8601()

    Repo.transaction(fn ->
      Repo.delete_all(
        from t in TmuxSessionTag,
          where: t.userId == ^user_id and t.hostId == ^host_id and t.sessionName == ^session_name
      )

      entries =
        Enum.map(clean_tags, fn tag ->
          %{
            userId: user_id,
            hostId: host_id,
            sessionName: session_name,
            tag: tag,
            createdAt: now
          }
        end)

      if entries != [], do: Repo.insert_all(TmuxSessionTag, entries)
    end)

    :ok
  end

  @doc """
  Move every tag row for a host's session to a new session name (all users — the session is
  shared on the host). Returns the number of rows updated. Used by the deferred rename
  endpoint (`TmuxSessionTagRepository.renameSessionForHost`).
  """
  @spec rename_session_tags(integer(), String.t(), String.t()) :: non_neg_integer()
  def rename_session_tags(host_id, session_name, new_session_name) do
    {count, _} =
      Repo.update_all(
        from(t in TmuxSessionTag,
          where: t.hostId == ^host_id and t.sessionName == ^session_name
        ),
        set: [sessionName: new_session_name]
      )

    count
  end

  @doc """
  Drop every tag row for a host's session (all users). Returns the number of rows deleted. Used
  by the deferred kill endpoint (`TmuxSessionTagRepository.deleteSessionForHost`).
  """
  @spec delete_session_tags(integer(), String.t()) :: non_neg_integer()
  def delete_session_tags(host_id, session_name) do
    {count, _} =
      Repo.delete_all(
        from t in TmuxSessionTag,
          where: t.hostId == ^host_id and t.sessionName == ^session_name
      )

    count
  end

  # --- execution --------------------------------------------------------------

  # Run one command over a short-lived SSH connection, mirroring `helper.ts:execCommand`:
  # resolve with trimmed stdout unless the command exited non-zero *with no stdout*, in which
  # case reject with stderr. A connect/transport failure is a distinct `{:ssh, reason}` so the
  # availability probe can tell "unreachable host" from "tmux not installed".
  #
  # Every exec emits exactly one `[:termelix, :tmux, :exec]` event tagged with the host and the
  # `kind` of probe. That is the measurement behind "one exec per interval per host regardless
  # of viewer count": count `kind: :overview` events per `host_id` over a poll interval.
  @doc """
  Run one tmux command on `host`, tagged with `kind` for telemetry.

  Public for `Termelix.Tmux.Orchestrator`, which issues the write verbs. Keeping them in a
  separate module is deliberate — reading the fleet and typing into it are different
  authorities, and P8 scopes an agent key to one without the other — but they must go through
  the same instrumented exec, or "one exec per interval per host" stops being measurable the
  moment an agent starts working.
  """
  @spec exec(map(), String.t(), atom()) :: {:ok, String.t()} | {:error, term()}
  def exec(host, command, kind) do
    started_at = System.monotonic_time()
    result = do_exec(host, command)

    :telemetry.execute(
      [:termelix, :tmux, :exec],
      %{count: 1, duration: System.monotonic_time() - started_at, bytes: result_bytes(result)},
      %{host_id: Map.get(host, :id), kind: kind, result: result_tag(result)}
    )

    result
  end

  defp do_exec(host, command) do
    case Exec.run(conn_opts(host), command) do
      {:ok, %{stdout: out, stderr: err, exit_status: status}} ->
        out = String.trim(out)

        if command_failed?(status, out, err),
          do: {:error, {:command, failure_message(err, status)}},
          else: {:ok, out}

      {:error, reason} ->
        {:error, {:ssh, reason}}
    end
  end

  defp result_bytes({:ok, out}), do: byte_size(out)
  defp result_bytes(_), do: 0

  # Coarse outcome only — the remote error text travels back to the controller in the result,
  # but it is remote-authored and must not become a telemetry tag.
  defp result_tag({:ok, _}), do: :ok
  defp result_tag({:error, {:command, _}}), do: :command_error
  defp result_tag({:error, {:ssh, _}}), do: :ssh_error

  # execCommand rejects only when the exit code is non-zero AND stdout is empty.
  defp command_failed?(status, out, _err) when is_integer(status), do: status != 0 and out == ""
  defp command_failed?(nil, out, err), do: out == "" and String.trim(err) != ""

  defp failure_message(err, status) do
    case String.trim(err) do
      "" -> "Command exited with code #{status}"
      trimmed -> trimmed
    end
  end

  # Same conn_opts shape `Termelix.SSH.Exec` expects; port ordering per the port contract.
  # Public only so `test/termelix/ssh/host_key_coverage_test.exs` can assert on the REAL map
  # this subsystem hands to `:ssh`. A test that mirrors the shape instead proves nothing about
  # this function — which is precisely how the missing host-key pin survived here.
  @doc false
  def conn_opts(host) do
    %{
      host: host.ip,
      port: Hosts.effective_ssh_port(host),
      username: host.username,
      password: host.password,
      private_key: host.key,
      key_password: host.keyPassword,
      host_id: host.id,
      owner_id: Map.get(host, :userId),
      # The pin travels WITH the conn_opts: this map is built by hand rather than through
      # `Credential.resolve/2`'s host-row path, and omitting it meant `HostKeyPolicy` saw first
      # contact on every connect — i.e. this path was never actually verified.
      host_key: Credential.host_key(host)
    }
  end

  # --- small helpers ----------------------------------------------------------

  defp nonblank_lines(output) do
    output
    |> String.split("\n")
    |> Enum.reject(&(&1 == ""))
  end

  # Take exactly the first `n` separator-delimited fields, padding missing ones with nil —
  # matches JS array destructuring of `line.split(SEP)` (extra fields ignored, absent fields
  # `undefined`; the last captured field is a single segment, not the line remainder).
  defp split_fields(line, n) do
    parts = String.split(line, @sep)
    (parts ++ List.duplicate(nil, max(n - length(parts), 0))) |> Enum.take(n)
  end

  # parseInt(x, 10) || 0 — leading integer, else 0.
  defp to_int(nil), do: 0

  defp to_int(v) when is_binary(v) do
    case Integer.parse(v) do
      {n, _rest} -> n
      :error -> 0
    end
  end
end
