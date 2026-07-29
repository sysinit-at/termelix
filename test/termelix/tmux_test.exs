defmodule Termelix.TmuxTest do
  @moduledoc """
  Tmux monitor: request-driven overview (list sessions/windows/panes) + per-user session-tags
  CRUD, over one-shot SSH exec.

  The pure parsers and command builders (ported from `monitor-helpers.ts` / `helper.ts`) are
  tested in isolation. The per-host overview and the `TermelixWeb.TmuxController` surface run
  against throwaway in-VM `:ssh` daemons whose `{exec, {:direct, fun}}` handlers fake tmux:
  one daemon returns the canned combined `tmux -V`/`list-sessions`/`list-windows`/`list-panes`
  marker-delimited output the single overview command produces, a second fails every command
  (tmux absent → `available: false`). A real user + host row is created through the normal
  API, so the host password is DEK-encrypted at rest and decrypted by `Hosts.get_for_user`,
  exactly as production does. The tags CRUD is exercised against the Repo.

  The mutating actions (focus/create/rename/kill/split) and the batched search/metrics run
  against the same fake daemon: its handler answers mutation commands with tmux's own
  success/error shapes (empty stdout / "duplicate session…" stderr), so the controller's
  remote-error classification (404/409) is proven end-to-end.
  """
  use TermelixWeb.ConnCase, async: false

  alias Termelix.{Accounts, Hosts, Tmux}
  alias TermelixWeb.TmuxController

  @sep "<<TMX>>"

  setup_all do
    {:ok, _} = Application.ensure_all_started(:ssh)

    dir = Path.join(System.tmp_dir!(), "termelix_tmux_test_#{System.unique_integer([:positive])}")
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

    {:ok, tmux_daemon} =
      :ssh.daemon(0,
        system_dir: String.to_charlist(dir),
        user_passwords: [{~c"tester", ~c"secret"}],
        auth_methods: ~c"password",
        exec: {:direct, &fake_tmux/1}
      )

    {:ok, notmux_daemon} =
      :ssh.daemon(0,
        system_dir: String.to_charlist(dir),
        user_passwords: [{~c"tester", ~c"secret"}],
        auth_methods: ~c"password",
        exec: {:direct, &fake_no_tmux/1}
      )

    on_exit(fn ->
      :ssh.stop_daemon(tmux_daemon)
      :ssh.stop_daemon(notmux_daemon)
      File.rm_rf(dir)
    end)

    %{tmux_port: daemon_port(tmux_daemon), notmux_port: daemon_port(notmux_daemon)}
  end

  setup %{tmux_port: tmux_port} do
    {token, user} = register_and_login("alice", "correct horse battery staple")
    host_id = create_host(token, port: tmux_port, enable_tmux_monitor: true)
    %{user: user, token: token, host_id: host_id}
  end

  # --- pure parsers + builders ------------------------------------------------

  describe "pure parsers" do
    test "sep/0 matches the wire separator" do
      assert Tmux.sep() == @sep
    end

    test "parse_sessions maps each line, defaulting numeric fields to 0" do
      out = line(["work", "100", "150", "1"]) <> line(["play", "200", "", "x"])

      assert Tmux.parse_sessions(out) == [
               %{name: "work", created: 100, lastActivity: 150, attachedClients: 1},
               %{name: "play", created: 200, lastActivity: 0, attachedClients: 0}
             ]
    end

    test "parse_windows groups by session, in order, active on '1'" do
      out =
        line(["work", "0", "1", "editor"]) <>
          line(["work", "1", "0", "shell"]) <> line(["play", "0", "1", "main"])

      assert Tmux.parse_windows(out) == %{
               "work" => [
                 %{index: 0, name: "editor", active: true, panes: []},
                 %{index: 1, name: "shell", active: false, panes: []}
               ],
               "play" => [%{index: 0, name: "main", active: true, panes: []}]
             }
    end

    test "parse_panes keeps grouping fields and pane detail" do
      out = line(["work", "0", "%0", "0", "1234", "1", "80", "24", "vim", "/home/x", "title"])

      assert Tmux.parse_panes(out) == [
               %{
                 sessionName: "work",
                 windowIndex: 0,
                 id: "%0",
                 index: 0,
                 pid: 1234,
                 active: true,
                 width: 80,
                 height: 24,
                 command: "vim",
                 path: "/home/x",
                 title: "title"
               }
             ]
    end

    test "attach_panes_to_windows folds panes into matching windows, stripping group fields" do
      windows = %{
        "work" => [
          %{index: 0, name: "editor", active: true, panes: []},
          %{index: 1, name: "shell", active: false, panes: []}
        ]
      }

      panes = [
        pane("work", 0, "%0", "vim"),
        pane("work", 1, "%1", "bash"),
        pane("orphan", 0, "%9", "top")
      ]

      %{"work" => [w0, w1]} = Tmux.attach_panes_to_windows(windows, panes)

      assert [%{id: "%0", command: "vim"}] = w0.panes
      assert [%{id: "%1", command: "bash"}] = w1.panes
      refute Map.has_key?(hd(w0.panes), :sessionName)
      refute Map.has_key?(hd(w0.panes), :windowIndex)
    end

    test "sanitize_tags trims, caps length, dedupes (first wins), and caps count" do
      long = String.duplicate("x", 100)

      assert Tmux.sanitize_tags(["  a ", "a", "b", "", "   ", long]) ==
               ["a", "b", String.duplicate("x", 64)]

      twenty_five = for n <- 1..25, do: "t#{n}"
      assert length(Tmux.sanitize_tags(twenty_five)) == 20
    end
  end

  describe "command builders" do
    test "commands are PATH-wrapped and carry the -F format + separator" do
      sessions = Tmux.list_sessions_cmd()
      assert String.starts_with?(sessions, "/bin/sh -c ")
      assert sessions =~ "tmux list-sessions -F"
      assert sessions =~ "#{@sep}"
      assert sessions =~ "\#{session_name}"
      assert sessions =~ "2>/dev/null"

      assert Tmux.list_windows_cmd() =~ "tmux list-windows -a -F"
      assert Tmux.list_panes_cmd() =~ "tmux list-panes -a -F"
      assert Tmux.list_panes_cmd() =~ "\#{pane_current_path}"
      assert Tmux.tmux_command("-V") =~ "tmux -V"
    end

    test "overview_command combines all four probes into one marker-delimited script" do
      cmd = Tmux.overview_command()

      assert String.starts_with?(cmd, "/bin/sh -c ")
      assert cmd =~ "echo ===TERMELIX-TMUX:version===\ntmux -V 2>/dev/null"
      assert cmd =~ "echo ===TERMELIX-TMUX:sessions===\ntmux list-sessions -F"
      assert cmd =~ "echo ===TERMELIX-TMUX:windows===\ntmux list-windows -a -F"
      assert cmd =~ "echo ===TERMELIX-TMUX:panes===\ntmux list-panes -a -F"
    end

    test "split_sections splits combined output on the markers" do
      out =
        "noise before the first marker is dropped\n" <>
          "===TERMELIX-TMUX:version===\ntmux 3.4\n" <>
          "===TERMELIX-TMUX:sessions===\nwork#{@sep}100\n===TERMELIX-TMUX:panes===\n"

      sections = Tmux.split_sections(out)
      assert sections[:version] == "tmux 3.4"
      assert sections[:sessions] == "work#{@sep}100"
      assert sections[:panes] == ""
      refute Map.has_key?(sections, :windows)
    end

    test "shell_escape single-quotes and escapes embedded quotes" do
      assert Tmux.shell_escape("a'b") == "'a'\\''b'"
    end

    test "attach_command applies the standard options, exact-name target, and && exit" do
      cmd = Tmux.attach_command("work")

      assert String.starts_with?(cmd, "/bin/sh -c ")
      assert String.ends_with?(cmd, " && exit")
      assert cmd =~ "set -gq mouse on"

      script = cmd |> String.trim_trailing(" && exit") |> unwrap_script()
      assert script =~ "attach-session -t '=work'"
    end

    test "search_command emits one marked capture-pane|grep block per pane, query escaped" do
      panes = [pane("work", 0, "%0", "vim"), pane("play", 0, "%2", "htop")]
      cmd = Tmux.search_command(panes, "err'or")

      assert String.starts_with?(cmd, "/bin/sh -c ")

      script = unwrap_script(cmd)
      assert script =~ "echo ===TERMELIX-TMUX:pane:%0==="
      assert script =~ "echo ===TERMELIX-TMUX:pane:%2==="
      assert script =~ "capture-pane -p -J -t '%0' -S -2000"
      assert script =~ "grep -n -i -F -- 'err'\\''or'"
      assert script =~ "head -50"
    end

    test "metrics_command combines panes, ps, and gpu probes" do
      cmd = Tmux.metrics_command()

      assert cmd =~ "echo ===TERMELIX-TMUX:panes===\ntmux list-panes -a -F"
      assert cmd =~ "ps -eo pid=,ppid=,pcpu=,pmem=,rss=,comm="
      assert cmd =~ "nvidia-smi --query-compute-apps=pid,used_gpu_memory"
    end

    test "split_sections accepts custom section lists" do
      out = "===TERMELIX-TMUX:ps===\nline\n===TERMELIX-TMUX:gpu===\n"
      sections = Tmux.split_sections(out, [:ps, :gpu])
      assert sections[:ps] == "line"
      assert sections[:gpu] == ""
    end
  end

  describe "activity status classification" do
    defp pane_with(cmd), do: %{id: "%0", command: cmd}

    test "shell/ssh/agent command predicates" do
      assert Tmux.shell_command?("zsh")
      assert Tmux.shell_command?("-bash")
      refute Tmux.shell_command?("vim")

      assert Tmux.ssh_command?("ssh")
      assert Tmux.ssh_command?("mosh")
      refute Tmux.ssh_command?("bash")

      assert Tmux.agent_command?("claude")
      assert Tmux.agent_command?("codex")
      refute Tmux.agent_command?("vim")
    end

    test "classify_pane: idle shell, running program, working program" do
      assert Tmux.classify_pane(pane_with("zsh"), nil, 0.0) == "idle"
      assert Tmux.classify_pane(pane_with("vim"), nil, 0.5) == "running"
      assert Tmux.classify_pane(pane_with("cargo"), nil, 80.0) == "working"
    end

    test "classify_pane: an idle agent is waiting, a busy agent is working" do
      assert Tmux.classify_pane(pane_with("claude"), nil, 0.2) == "waiting"
      assert Tmux.classify_pane(pane_with("claude"), nil, 40.0) == "working"
    end

    test "classify_pane: an agent detected as the busiest descendant still counts" do
      # A shell foreground whose hot child is an agent → treat as an agent pane.
      metric = %{topCommand: "claude", cpuPercent: 0.1}
      assert Tmux.classify_pane(pane_with("zsh"), metric, 0.1) == "waiting"
    end

    test "session_status rolls up to the highest-priority pane" do
      windows = [
        %{panes: [%{status: "idle"}, %{status: "running"}]},
        %{panes: [%{status: "waiting"}]}
      ]

      assert Tmux.session_status(windows) == "waiting"
      assert Tmux.session_status([%{panes: [%{status: "idle"}]}]) == "idle"
      assert Tmux.session_status([]) == "idle"
    end

    test "enrich_windows adds status/cpu/isRemote/topCommand per pane" do
      windows = [%{index: 0, panes: [%{id: "%0", command: "ssh"}]}]
      metrics = %{"%0" => %{cpuPercent: 1.0, topCommand: "ssh"}}

      [%{panes: [pane]}] = Tmux.enrich_windows(windows, metrics)
      assert pane.isRemote == true
      assert pane.cpuPercent == 1.0
      assert pane.status == "running"
      assert pane.topCommand == "ssh"
    end
  end

  describe "metrics parsers" do
    test "parse_ps_output keeps 6-field lines, joining multi-word commands" do
      out = "  10   1  2.5  1.0  512 zsh\n  20  10 90.0  5.0 4096 cargo build\nbogus line\n"

      assert Tmux.parse_ps_output(out) == [
               %{pid: 10, ppid: 1, cpu: 2.5, mem: 1.0, rss: 512, comm: "zsh"},
               %{pid: 20, ppid: 10, cpu: 90.0, mem: 5.0, rss: 4096, comm: "cargo build"}
             ]
    end

    test "parse_gpu_output accumulates memory per pid" do
      assert Tmux.parse_gpu_output("100, 512\n100, 256\n200, 64\nnoise\n") ==
               %{100 => 768, 200 => 64}
    end

    test "build_pane_metrics aggregates each pane's descendant tree" do
      panes = [pane("work", 0, "%0", "zsh") |> Map.put(:pid, 10)]

      processes = [
        %{pid: 10, ppid: 1, cpu: 1.0, mem: 0.5, rss: 1000, comm: "zsh"},
        %{pid: 20, ppid: 10, cpu: 40.5, mem: 2.0, rss: 8000, comm: "cargo build"},
        %{pid: 30, ppid: 999, cpu: 99.0, mem: 9.0, rss: 9000, comm: "unrelated"}
      ]

      assert [m] = Tmux.build_pane_metrics(panes, processes, %{20 => 512})
      assert m.paneId == "%0"
      assert m.processCount == 2
      assert m.cpuPercent == 41.5
      assert m.memRssKb == 9000
      assert m.gpuMemMb == 512
      assert m.topCommand == "cargo build"
    end

    test "build_pane_metrics falls back to the shell when it is the only process" do
      panes = [pane("work", 0, "%0", "zsh") |> Map.put(:pid, 10)]
      processes = [%{pid: 10, ppid: 1, cpu: 0.5, mem: 0.1, rss: 100, comm: "zsh"}]

      assert [%{topCommand: "zsh", processCount: 1}] =
               Tmux.build_pane_metrics(panes, processes, %{})
    end

    test "parse_search_output attributes grep lines to their pane and caps text" do
      panes = [pane("work", 0, "%0", "vim"), pane("play", 3, "%2", "htop")]

      out =
        "===TERMELIX-TMUX:pane:%0===\n3:hit one\n===TERMELIX-TMUX:pane:%2===\n5:" <>
          String.duplicate("x", 600) <> "\n"

      {matches, hit_cap} = Tmux.parse_search_output(out, panes)
      refute hit_cap

      assert [
               %{paneId: "%0", sessionName: "work", windowIndex: 0, line: 3, text: "hit one"},
               %{paneId: "%2", sessionName: "play", windowIndex: 3, line: 5, text: capped}
             ] = matches

      assert String.length(capped) == 500
    end
  end

  # --- session-tags CRUD ------------------------------------------------------

  describe "session-tags CRUD" do
    test "set + list round-trips, sanitizing on the way in", %{user: user, host_id: id} do
      assert {:ok, ["a", "b"]} = Tmux.set_session_tags(user.id, id, "work", ["a", " b ", "a", ""])
      assert Tmux.list_tags_by_session(user.id, id) == %{"work" => ["a", "b"]}
    end

    test "replace overwrites the previous set for that session", %{user: user, host_id: id} do
      Tmux.set_session_tags(user.id, id, "work", ["x"])
      Tmux.set_session_tags(user.id, id, "work", ["y", "z"])
      assert Tmux.list_tags_by_session(user.id, id) == %{"work" => ["y", "z"]}
    end

    test "tags are scoped per user and per session", %{user: user, host_id: id} do
      {_, other} = register_and_login("bob", "another good passphrase here")
      Tmux.set_session_tags(user.id, id, "work", ["mine"])
      Tmux.set_session_tags(other.id, id, "work", ["theirs"])

      assert Tmux.list_tags_by_session(user.id, id) == %{"work" => ["mine"]}
      assert Tmux.list_tags_by_session(other.id, id) == %{"work" => ["theirs"]}
    end

    test "rename_session_tags moves the host's tags to the new name", %{user: user, host_id: id} do
      Tmux.set_session_tags(user.id, id, "old", ["t1", "t2"])
      assert Tmux.rename_session_tags(id, "old", "new") == 2
      assert Tmux.list_tags_by_session(user.id, id) == %{"new" => ["t1", "t2"]}
    end

    test "delete_session_tags drops the host's tags for a session", %{user: user, host_id: id} do
      Tmux.set_session_tags(user.id, id, "gone", ["t"])
      Tmux.set_session_tags(user.id, id, "stay", ["k"])
      assert Tmux.delete_session_tags(id, "gone") == 1
      assert Tmux.list_tags_by_session(user.id, id) == %{"stay" => ["k"]}
    end
  end

  # --- overview against the live daemon ---------------------------------------

  describe "overview" do
    test "lists sessions with windows, panes, and merged tags", %{user: user, host_id: id} do
      Tmux.set_session_tags(user.id, id, "work", ["prod"])
      host = Hosts.get_for_user(id, user.id)

      assert {:ok, %{available: true, sessions: sessions}} = Tmux.overview(host, user.id)

      work = Enum.find(sessions, &(&1.name == "work"))
      assert work.created == 1_710_000_000
      assert work.attachedClients == 1
      assert work.tags == ["prod"]

      assert [w0, w1] = work.windows
      assert w0.index == 0 and w0.name == "editor" and w0.active
      assert [%{id: "%0", command: "vim", path: "/home/tester"}] = w0.panes
      assert [%{id: "%1", command: "bash"}] = w1.panes

      play = Enum.find(sessions, &(&1.name == "play"))
      assert play.tags == []
      assert [%{index: 0, name: "main", panes: [%{id: "%2", command: "htop"}]}] = play.windows
    end

    # The end-to-end path the whole phase exists for: a real prompt on a real pane's screen
    # comes back from the host, survives the section parsing, and is classified as someone
    # waiting for an answer. Before the `tails` section existed, `Activity` could only see
    # process state — and process state cannot tell "running" from "stopped and asking you a
    # question", which is the only distinction that matters to an unattended agent.
    test "a pane's screen tail reaches Activity and produces awaiting_input", %{
      user: user,
      host_id: id
    } do
      host = Hosts.get_for_user(id, user.id)
      {:ok, %{sessions: sessions}} = Tmux.overview(host, user.id)

      pane =
        sessions
        |> Enum.flat_map(& &1.windows)
        |> Enum.flat_map(& &1.panes)
        |> Enum.find(&(&1.id == "%1"))

      assert pane.screenTail =~ "Do you want to proceed? [y/N]"

      assert %{state: :awaiting_input} =
               Termelix.Tmux.Activity.classify(%{
                 argv: pane.topCommand || pane.command,
                 cpu_delta: pane.cpuPercent,
                 screen_tail: pane.screenTail
               })

      # And a pane whose tail is ordinary output is NOT a prompt, from the same pipe.
      other = sessions |> Enum.flat_map(& &1.windows) |> Enum.flat_map(& &1.panes)
      vim = Enum.find(other, &(&1.id == "%0"))

      refute Termelix.Tmux.Activity.classify(%{
               argv: vim.topCommand || vim.command,
               cpu_delta: vim.cpuPercent,
               screen_tail: vim.screenTail
             }).state == :awaiting_input
    end

    test "parse_tails attributes each block to its pane and tolerates junk" do
      text =
        "===TERMELIX-TMUX:pane:%0===\nline one\nline two\n" <>
          "===TERMELIX-TMUX:pane:%7===\nContinue? [y/N]\n"

      assert Tmux.parse_tails(text) == %{
               "%0" => "line one\nline two",
               "%7" => "Continue? [y/N]"
             }

      # Output before the first marker belongs to no pane and must not be attributed to one.
      assert Tmux.parse_tails("stray\n===TERMELIX-TMUX:pane:%3===\nreal\n") == %{"%3" => "real"}
      assert Tmux.parse_tails("") == %{}
    end

    test "enriches panes and sessions with activity status from ps", %{user: user, host_id: id} do
      host = Hosts.get_for_user(id, user.id)
      assert {:ok, %{sessions: sessions}} = Tmux.overview(host, user.id)

      work = Enum.find(sessions, &(&1.name == "work"))
      # %0 vim @42% cpu → working; %1 bash → idle. Session rolls up to the busiest.
      assert work.status == "working"
      [%{status: "working", cpuPercent: cpu} = vim] = Enum.at(work.windows, 0).panes
      assert cpu >= 5.0
      assert vim.isRemote == false
      assert [%{command: "bash", status: "idle"}] = Enum.at(work.windows, 1).panes

      play = Enum.find(sessions, &(&1.name == "play"))
      # %2 htop @0.5% cpu, non-shell → running.
      assert play.status == "running"
    end

    test "reports available:false when tmux is absent", %{
      user: user,
      token: token,
      notmux_port: port
    } do
      id = create_host(token, port: port, enable_tmux_monitor: true)
      host = Hosts.get_for_user(id, user.id)
      assert {:ok, %{available: false, sessions: []}} = Tmux.overview(host, user.id)
    end

    test "surfaces an ssh error for an unreachable host", %{user: user, token: token} do
      id = create_host(token, port: 1, enable_tmux_monitor: true)
      host = Hosts.get_for_user(id, user.id)
      assert {:error, {:ssh, _reason}} = Tmux.overview(host, user.id)
    end
  end

  describe "overview_all (aggregate across hosts)" do
    test "returns one entry per tmux-enabled host, isolating failures", %{
      user: user,
      token: token,
      tmux_port: tmux_port,
      notmux_port: notmux_port
    } do
      # host_id (from setup) is tmux-enabled against the working daemon; add a
      # tmux-disabled host (excluded), a tmux-absent host (available:false), and an
      # unreachable host (error, but doesn't sink the aggregate).
      _disabled = create_host(token, port: tmux_port, enable_tmux_monitor: false)
      notmux_id = create_host(token, port: notmux_port, enable_tmux_monitor: true)
      unreachable_id = create_host(token, port: 1, enable_tmux_monitor: true)

      entries = Tmux.overview_all(user.id)
      by_id = Map.new(entries, &{&1.hostId, &1})

      # The tmux-disabled host is excluded entirely.
      refute Enum.any?(entries, &(&1.available == true and &1.sessions == []))
      assert map_size(by_id) >= 3

      work_host = by_id[hd(entries).hostId]
      assert is_binary(work_host.hostName)

      assert by_id[notmux_id].available == false
      assert by_id[notmux_id].sessions == []

      assert by_id[unreachable_id].available == false
      assert by_id[unreachable_id].error =~ "connect"
    end

    @tag timeout: 30_000
    test "a host that hangs is reported, not dropped from the list", %{
      user: user,
      token: token
    } do
      # A socket that completes the TCP handshake and then says nothing: the SSH banner never
      # arrives, so the probe hangs until the fan-out's own timeout fires.
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, backlog: 8])
      {:ok, hang_port} = :inet.port(listener)
      on_exit(fn -> :gen_tcp.close(listener) end)

      hung_id = create_host(token, port: hang_port, enable_tmux_monitor: true)

      by_id = Map.new(Tmux.overview_all(user.id), &{&1.hostId, &1})

      # `async_stream` reports a timeout as a bare `{:exit, :timeout}` with no reference to the
      # task's input, and the previous version dropped those rows — so the one host you most
      # want to know about looked exactly like a host with no sessions.
      assert Map.has_key?(by_id, hung_id)
      assert by_id[hung_id].available == false
      assert by_id[hung_id].error != nil
      assert is_binary(by_id[hung_id].hostName)
    end
  end

  describe "TmuxController.overview_all" do
    test "returns the aggregate shape", %{user: user, host_id: id} do
      resp =
        user |> user_conn() |> TmuxController.overview_all(%{}) |> json_response(200)

      assert is_list(resp["hosts"])
      assert Enum.any?(resp["hosts"], &(&1["hostId"] == id))

      host = Enum.find(resp["hosts"], &(&1["hostId"] == id))
      assert host["available"] == true
      assert "work" in Enum.map(host["sessions"], & &1["name"])
    end
  end

  # --- controller surface -----------------------------------------------------

  describe "TmuxController.overview" do
    test "returns the TmuxOverview shape", %{user: user, host_id: id} do
      resp =
        user |> user_conn() |> TmuxController.overview(%{"hostId" => id}) |> json_response(200)

      assert resp["available"] == true
      assert "work" in Enum.map(resp["sessions"], & &1["name"])
      work = Enum.find(resp["sessions"], &(&1["name"] == "work"))
      assert length(work["windows"]) == 2
    end

    test "a monitor-disabled host is 403", %{user: user, token: token, tmux_port: port} do
      id = create_host(token, port: port, enable_tmux_monitor: false)

      resp =
        user |> user_conn() |> TmuxController.overview(%{"hostId" => id}) |> json_response(403)

      assert resp["error"] =~ "not enabled"
    end

    test "an unknown host is 404", %{user: user} do
      resp =
        user
        |> user_conn()
        |> TmuxController.overview(%{"hostId" => 999_999})
        |> json_response(404)

      assert resp["error"] == "Host not found"
    end

    test "a non-numeric host id is 400", %{user: user} do
      resp =
        user |> user_conn() |> TmuxController.overview(%{"hostId" => "abc"}) |> json_response(400)

      assert resp["error"] == "Invalid host ID"
    end

    test "an unreachable host is 503 HOST_UNREACHABLE", %{user: user, token: token} do
      id = create_host(token, port: 1, enable_tmux_monitor: true)

      resp =
        user |> user_conn() |> TmuxController.overview(%{"hostId" => id}) |> json_response(503)

      assert resp["code"] == "HOST_UNREACHABLE"
    end
  end

  describe "TmuxController.set_tags" do
    test "persists and echoes the cleaned tags", %{user: user, host_id: id} do
      resp =
        user
        |> user_conn()
        |> TmuxController.set_tags(%{
          "hostId" => id,
          "sessionName" => "work",
          "tags" => ["a", " b ", "a"]
        })
        |> json_response(200)

      assert resp["sessionName"] == "work"
      assert resp["tags"] == ["a", "b"]
      assert Tmux.list_tags_by_session(user.id, id) == %{"work" => ["a", "b"]}
    end

    test "a missing session name is 400", %{user: user, host_id: id} do
      resp =
        user
        |> user_conn()
        |> TmuxController.set_tags(%{"hostId" => id, "tags" => ["a"]})
        |> json_response(400)

      assert resp["error"] == "Missing session name"
    end

    test "non-string tags are 400", %{user: user, host_id: id} do
      resp =
        user
        |> user_conn()
        |> TmuxController.set_tags(%{
          "hostId" => id,
          "sessionName" => "work",
          "tags" => ["ok", 5]
        })
        |> json_response(400)

      assert resp["error"] == "Tags must be an array of strings"
    end

    test "a monitor-disabled host is 403 before touching tags", %{
      user: user,
      token: token,
      tmux_port: port
    } do
      id = create_host(token, port: port, enable_tmux_monitor: false)

      resp =
        user
        |> user_conn()
        |> TmuxController.set_tags(%{"hostId" => id, "sessionName" => "work", "tags" => ["a"]})
        |> json_response(403)

      assert resp["error"] =~ "not enabled"
    end
  end

  describe "mutating actions (controller, against the fake daemon)" do
    test "create_window succeeds for an existing session", %{user: user, host_id: id} do
      resp =
        user
        |> user_conn()
        |> TmuxController.create_window(%{"hostId" => id, "sessionName" => "work"})
        |> json_response(200)

      assert resp["ok"] == true
    end

    test "create_window on a missing session is 404", %{user: user, host_id: id} do
      resp =
        user
        |> user_conn()
        |> TmuxController.create_window(%{"hostId" => id, "sessionName" => "nope"})
        |> json_response(404)

      assert resp["error"] == "Session not found"
    end

    test "create_session rejects invalid names and maps duplicates to 409", %{
      user: user,
      host_id: id
    } do
      conn = user_conn(user)

      assert %{"error" => "Invalid session name"} =
               conn
               |> TmuxController.create_session(%{"hostId" => id, "name" => "bad:name"})
               |> json_response(400)

      assert %{"error" => "A session with this name already exists"} =
               user
               |> user_conn()
               |> TmuxController.create_session(%{"hostId" => id, "name" => "work"})
               |> json_response(409)

      assert %{"ok" => true, "name" => "fresh"} =
               user
               |> user_conn()
               |> TmuxController.create_session(%{"hostId" => id, "name" => "fresh"})
               |> json_response(200)
    end

    test "rename moves saved tags to the new name", %{user: user, host_id: id} do
      Tmux.set_session_tags(user.id, id, "work", ["prod"])

      resp =
        user
        |> user_conn()
        |> TmuxController.rename(%{
          "hostId" => id,
          "sessionName" => "work",
          "newName" => "work2"
        })
        |> json_response(200)

      assert resp["name"] == "work2"
      assert Tmux.list_tags_by_session(user.id, id) == %{"work2" => ["prod"]}
    end

    test "kill drops the session's saved tags", %{user: user, host_id: id} do
      Tmux.set_session_tags(user.id, id, "work", ["prod"])

      assert %{"ok" => true} =
               user
               |> user_conn()
               |> TmuxController.kill(%{"hostId" => id, "sessionName" => "work"})
               |> json_response(200)

      assert Tmux.list_tags_by_session(user.id, id) == %{}
    end

    test "kill_pane validates the pane id and maps a missing pane to 404", %{
      user: user,
      host_id: id
    } do
      assert %{"error" => "Invalid pane ID"} =
               user
               |> user_conn()
               |> TmuxController.kill_pane(%{"hostId" => id, "paneId" => "0; rm -rf /"})
               |> json_response(400)

      assert %{"error" => "Pane not found"} =
               user
               |> user_conn()
               |> TmuxController.kill_pane(%{"hostId" => id, "paneId" => "%9"})
               |> json_response(404)

      assert %{"ok" => true} =
               user
               |> user_conn()
               |> TmuxController.kill_pane(%{"hostId" => id, "paneId" => "%0"})
               |> json_response(200)
    end

    test "split validates the direction", %{user: user, host_id: id} do
      assert %{"error" => "Invalid split direction"} =
               user
               |> user_conn()
               |> TmuxController.split(%{"hostId" => id, "paneId" => "%0", "direction" => "x"})
               |> json_response(400)

      assert %{"ok" => true} =
               user
               |> user_conn()
               |> TmuxController.split(%{"hostId" => id, "paneId" => "%0", "direction" => "v"})
               |> json_response(200)
    end
  end

  describe "search + metrics (controller, against the fake daemon)" do
    test "search returns per-pane matches with the query echoed", %{user: user, host_id: id} do
      resp =
        user
        |> user_conn()
        |> TmuxController.search(%{"hostId" => id, "q" => "error"})
        |> json_response(200)

      assert resp["query"] == "error"
      assert resp["searchedLines"] == 2000
      assert resp["maxPanes"] == 100
      assert resp["truncated"] == false

      assert [
               %{"paneId" => "%0", "sessionName" => "work", "line" => 3},
               %{"paneId" => "%0", "line" => 17},
               %{"paneId" => "%2", "sessionName" => "play", "line" => 5}
             ] = resp["matches"]
    end

    test "a blank query is 400", %{user: user, host_id: id} do
      assert %{"error" => "Missing search query"} =
               user
               |> user_conn()
               |> TmuxController.search(%{"hostId" => id, "q" => "  "})
               |> json_response(400)
    end

    test "metrics aggregates the pane's process tree", %{user: user, host_id: id} do
      resp =
        user
        |> user_conn()
        |> TmuxController.metrics(%{"hostId" => id})
        |> json_response(200)

      assert [pane] = resp["panes"]
      assert pane["paneId"] == "%0"
      assert pane["cpuPercent"] == 41.5
      assert pane["gpuMemMb"] == 512
      assert pane["topCommand"] == "cargo build"
    end
  end

  # --- fake tmux (in-VM direct exec handlers) ---------------------------------

  # Canned output for every command the module issues, exactly as a real shell emits it.
  # The overview: two sessions ("work" with two windows/panes, "play" with one). Mutations
  # answer with tmux's own shapes: silent success, or its error text on stderr (the
  # `{:error, msg}` form of a direct exec handler) for the not-found/duplicate paths.
  defp fake_tmux(command) do
    # Every module command arrives as `/bin/sh -c '<escaped script>'`; match on the
    # unwrapped script so quoted targets (`-t '=work'`) read naturally below.
    cmd = command |> to_string() |> unwrap_script()

    cond do
      # ORDER MATTERS. The overview script now also contains `capture-pane` — it captures a
      # screen tail per pane — so the search branch must not claim it. Matching on the
      # `:version` section, which only the overview emits, keeps the two apart.
      String.contains?(cmd, "TERMELIX-TMUX:version") ->
        overview_fixture()

      # Batched search script (one capture-pane|grep block per pane, pane markers between).
      String.contains?(cmd, "capture-pane") ->
        {:ok,
         "===TERMELIX-TMUX:pane:%0===\n" <>
           "3:error: something failed\n" <>
           "17:another ERROR here\n" <>
           "===TERMELIX-TMUX:pane:%1===\n" <>
           "===TERMELIX-TMUX:pane:%2===\n" <>
           "5:error in htop\n"}

      # Batched pane-metrics script (panes + ps + gpu sections). Distinguished from the
      # overview by the `:gpu` section, which only the metrics command emits — the overview
      # now also carries a `:ps` section, so matching on `:ps` alone would be ambiguous.
      String.contains?(cmd, "TERMELIX-TMUX:gpu") ->
        {:ok,
         "===TERMELIX-TMUX:panes===\n" <>
           line(["work", "0", "%0", "0", "1234", "1", "80", "24", "vim", "/home/tester", "e"]) <>
           "===TERMELIX-TMUX:ps===\n" <>
           "  1234     1  1.0  0.5  1000 zsh\n" <>
           "  2000  1234 40.5  2.0  8000 cargo build\n" <>
           "===TERMELIX-TMUX:gpu===\n" <>
           "2000, 512\n"}

      # Standalone pane listing (the search's first exec).
      String.contains?(cmd, "list-panes") ->
        {:ok,
         line(["work", "0", "%0", "0", "1234", "1", "80", "24", "vim", "/home/tester", "e"]) <>
           line(["work", "1", "%1", "0", "1250", "0", "80", "24", "bash", "/home/tester", "s"]) <>
           line(["play", "0", "%2", "0", "1300", "1", "120", "40", "htop", "/root", "p"])}

      # Mutations: tmux's own not-found/duplicate stderr for the canned failure targets.
      String.contains?(cmd, "new-session -d -s 'work'") ->
        {:error, "duplicate session: work"}

      String.contains?(cmd, "-t '=nope'") or String.contains?(cmd, "-t '=nope:") ->
        {:error, "can't find session: nope"}

      String.contains?(cmd, "kill-pane -t '%9'") ->
        {:error, "can't find pane: %9"}

      true ->
        {:ok, ""}
    end
  end

  # The combined overview probe. Panes: %0 vim (busy → working), %1 bash (shell → idle),
  # %2 htop (running). The `:ps` section drives the per-pane CPU used for status, and the
  # `:tails` section is what `Termelix.Tmux.Activity` reads — %1's tail is a real prompt, so
  # `awaiting_input` is exercised through the whole pipe rather than only in the classifier's
  # own unit tests.
  defp overview_fixture do
    {:ok,
     "===TERMELIX-TMUX:version===\ntmux 3.4\n" <>
       "===TERMELIX-TMUX:sessions===\n" <>
       line(["work", "1710000000", "1710000500", "1"]) <>
       line(["play", "1710001000", "1710001200", "0"]) <>
       "===TERMELIX-TMUX:windows===\n" <>
       line(["work", "0", "1", "editor"]) <>
       line(["work", "1", "0", "shell"]) <>
       line(["play", "0", "1", "main"]) <>
       "===TERMELIX-TMUX:panes===\n" <>
       line(["work", "0", "%0", "0", "1234", "1", "80", "24", "vim", "/home/tester", "e"]) <>
       line(["work", "1", "%1", "0", "1250", "0", "80", "24", "bash", "/home/tester", "s"]) <>
       line(["play", "0", "%2", "0", "1300", "1", "120", "40", "htop", "/root", "p"]) <>
       "===TERMELIX-TMUX:ps===\n" <>
       "  1234     1 42.0  2.0  8000 vim\n" <>
       "  1250     1  0.0  0.1  1000 bash\n" <>
       "  1300     1  0.5  0.3  2000 htop\n" <>
       "===TERMELIX-TMUX:tails===\n" <>
       "===TERMELIX-TMUX:pane:%0===\n" <>
       "~/src/app\n" <>
       "===TERMELIX-TMUX:pane:%1===\n" <>
       "Applying migration 003_add_index...\n" <>
       "Do you want to proceed? [y/N]\n" <>
       "===TERMELIX-TMUX:pane:%2===\n" <>
       "  PID USER      PR  NI\n"}
  end

  # A host without tmux: every command fails (OTP delivers the error as stderr + non-zero exit).
  defp fake_no_tmux(_command), do: {:error, "sh: tmux: command not found"}

  # --- helpers ----------------------------------------------------------------

  # Undo the outer `/bin/sh -c '<script>'` quoting layer, restoring the script text with
  # its own (inner) quoting intact.
  defp unwrap_script("/bin/sh -c " <> quoted) do
    quoted
    |> binary_part(1, byte_size(quoted) - 2)
    |> String.replace("'\\''", "'")
  end

  defp unwrap_script(other), do: other

  defp line(fields), do: Enum.join(fields, @sep) <> "\n"

  defp pane(session, window_index, id, command) do
    %{
      sessionName: session,
      windowIndex: window_index,
      id: id,
      index: 0,
      pid: 0,
      active: true,
      width: 80,
      height: 24,
      command: command,
      path: "/tmp",
      title: ""
    }
  end

  defp user_conn(user) do
    build_conn()
    |> Plug.Conn.assign(:current_user_id, user.id)
    |> Plug.Conn.assign(:current_user, user)
  end

  defp register_and_login(username, password) do
    conn = build_conn()
    conn |> post("/users/create", %{username: username, password: password}) |> json_response(200)
    login = post(conn, "/users/login", %{username: username, password: password})
    %{"jwt" => %{value: token}} = login.resp_cookies
    {token, Accounts.get_user_by_username(username)}
  end

  defp create_host(token, opts) do
    body = %{
      name: "tmux-target",
      ip: "127.0.0.1",
      port: Keyword.fetch!(opts, :port),
      username: "tester",
      connectionType: "ssh",
      authType: "password",
      password: "secret",
      enableTmuxMonitor: Keyword.get(opts, :enable_tmux_monitor, true)
    }

    %{"id" => id} =
      build_conn()
      |> put_req_header("authorization", "Bearer #{token}")
      |> put_req_header("content-type", "application/json")
      |> post("/host/db/host", Jason.encode!(body))
      |> json_response(200)

    id
  end

  defp daemon_port(daemon) do
    case :ssh.daemon_info(daemon) do
      {:ok, info} when is_list(info) -> :proplists.get_value(:port, info)
      {:ok, info} when is_map(info) -> Map.get(info, :port)
    end
  end
end
