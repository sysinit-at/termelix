defmodule Termelix.Tmux.WatcherTest do
  @moduledoc """
  The watcher is what moves the polling loop off the browser and onto the server, so the
  properties worth pinning are the ones that make that move worth doing:

    * it keeps observing after every viewer has gone (for a while), because "tell me when it
      finishes" cannot be built on a loop that stops when a tab closes;
    * it polls once per host regardless of how many viewers there are;
    * it publishes CHANGES, not ticks;
    * and it never turns an unwatchable host into a crash loop.
  """
  use Termelix.DataCase, async: false

  alias Termelix.{Accounts, Hosts}
  alias Termelix.Tmux.Watcher

  setup do
    {:ok, user, _} = Accounts.register_user("watch-#{unique()}", "password-123-abc")

    {:ok, host} =
      Hosts.create_host(user.id, %{
        name: "watched",
        ip: "127.0.0.1",
        port: closed_port(),
        username: "tester",
        authType: "password",
        password: "secret",
        connectionType: "ssh",
        enableTmuxMonitor: true
      })

    on_exit(fn -> Watcher.stop(user.id, host.id) end)
    %{user: user, host: host}
  end

  defp unique, do: System.unique_integer([:positive])

  defp closed_port do
    {:ok, socket} = :gen_tcp.listen(0, [])
    {:ok, port} = :inet.port(socket)
    :gen_tcp.close(socket)
    port
  end

  describe "lifecycle" do
    test "ensure_started/2 is idempotent — a second subscriber joins, it does not fork a
          second SSH loop",
         %{user: user, host: host} do
      assert {:ok, pid} = Watcher.ensure_started(user.id, host.id)
      assert {:ok, ^pid} = Watcher.ensure_started(user.id, host.id)
      assert Watcher.whereis(user.id, host.id) == pid
    end

    test "one watcher per (user, host), not per host", %{host: host} do
      {:ok, a, _} = Accounts.register_user("wa-#{unique()}", "password-123-abc")
      {:ok, b, _} = Accounts.register_user("wb-#{unique()}", "password-123-abc")

      {:ok, pid_a} = Watcher.ensure_started(a.id, host.id)
      {:ok, pid_b} = Watcher.ensure_started(b.id, host.id)

      # Two users watching the same host row are two different credentials and two different
      # scopes; sharing a watcher between them would leak one user's fleet state to the other.
      refute pid_a == pid_b

      on_exit(fn ->
        Watcher.stop(a.id, host.id)
        Watcher.stop(b.id, host.id)
      end)
    end

    test "stop/2 is idempotent and safe on a host nobody watches", %{user: user, host: host} do
      assert Watcher.stop(user.id, host.id) == :ok
      assert Watcher.stop(user.id, host.id) == :ok
      assert Watcher.whereis(user.id, host.id) == nil
    end

    test "snapshot/2 on a host nobody watches is a miss, not a crash", %{user: user, host: host} do
      assert Watcher.snapshot(user.id, host.id) == :miss
    end
  end

  describe "an unwatchable host stops cleanly instead of crash-looping" do
    test "a deleted host publishes the reason and the watcher exits", %{user: user, host: host} do
      Phoenix.PubSub.subscribe(Termelix.PubSub, Watcher.user_topic(user.id))
      {:ok, pid} = Watcher.ensure_started(user.id, host.id)
      ref = Process.monitor(pid)

      Termelix.Repo.delete!(Termelix.Repo.get(Termelix.Schema.Host, host.id))
      send(pid, :tick)

      # The reason reaches the operator rather than only the log. A watcher that dies silently
      # is indistinguishable from one that is working and finding nothing.
      assert_receive {:tmux_state, _host_id, %{unwatchable: :not_found}}, 5000
      assert_receive {:DOWN, ^ref, :process, ^pid, _}, 5000
    end

    test "restart: :transient means a clean stop is NOT restarted", %{user: user, host: host} do
      {:ok, pid} = Watcher.ensure_started(user.id, host.id)
      ref = Process.monitor(pid)
      Watcher.stop(user.id, host.id)
      assert_receive {:DOWN, ^ref, :process, ^pid, _}, 5000

      # A `:permanent` child here would reopen the SSH loop for a host the operator just
      # stopped watching, forever.
      Process.sleep(50)
      assert Watcher.whereis(user.id, host.id) == nil
    end
  end

  # These are the tests that were missing, and their absence is exactly why the watcher shipped
  # reading `:paneId` and `:cpu` — fields the overview does not produce. Nothing failed: the
  # classifier is total by design, so every pane silently became "no evidence", and every pane
  # hashed to the same `nil` key so N panes collapsed into one entry. The watcher LOOKED like it
  # worked. Only an assertion on the transitions it actually publishes can tell the difference.
  describe "classification and transitions, driven through a real overview" do
    setup do
      {:ok, user, _} = Accounts.register_user("wc-#{unique()}", "password-123-abc")
      {port, daemon} = fake_tmux_host()
      on_exit(fn -> :ssh.stop_daemon(daemon) end)

      {:ok, host} =
        Hosts.create_host(user.id, %{
          name: "faked",
          ip: "127.0.0.1",
          port: port,
          username: "tester",
          authType: "password",
          password: "secret",
          enableTmuxMonitor: true
        })

      on_exit(fn -> Watcher.stop(user.id, host.id) end)
      %{user: user, host: host}
    end

    test "every pane gets its OWN verdict, keyed by its own id", %{user: user, host: host} do
      Phoenix.PubSub.subscribe(Termelix.PubSub, Watcher.user_topic(user.id))
      {:ok, _pid} = Watcher.ensure_started(user.id, host.id)

      assert_receive {:tmux_state, _id, snapshot}, 10_000

      panes =
        snapshot.sessions
        |> Enum.flat_map(& &1.windows)
        |> Enum.flat_map(& &1.panes)
        |> Map.new(&{&1.id, &1.activity})

      # Three DISTINCT panes. With the old `:paneId` key they all collapsed into one `nil`
      # entry and only the last survived.
      assert map_size(panes) == 3
      assert panes["%1"] == :awaiting_input, "the pane with a prompt on screen"
      refute panes["%0"] == :awaiting_input
      refute panes["%2"] == :awaiting_input
    end

    test "the CPU sample reaches the classifier", %{user: user, host: host} do
      Phoenix.PubSub.subscribe(Termelix.PubSub, Watcher.user_topic(user.id))
      {:ok, _pid} = Watcher.ensure_started(user.id, host.id)
      assert_receive {:tmux_state, _id, snapshot}, 10_000

      vim =
        snapshot.sessions
        |> Enum.flat_map(& &1.windows)
        |> Enum.flat_map(& &1.panes)
        |> Enum.find(&(&1.id == "%0"))

      # %0 is vim at 42% CPU in the fixture. Reading `:cpu` instead of `:cpuPercent` made this
      # `:working` at low confidence — plausible enough to never be noticed.
      assert vim.activity == :running
      assert [evidence] = vim.activityEvidence
      assert evidence =~ "CPU"
    end

    test "a notable transition is published, with the pane it belongs to", %{
      user: user,
      host: host
    } do
      Phoenix.PubSub.subscribe(Termelix.PubSub, Watcher.user_topic(user.id))
      {:ok, _pid} = Watcher.ensure_started(user.id, host.id)

      # First observation: `from` is nil, and arriving at a prompt is always news.
      assert_receive {:tmux_transition, _id, %{pane_id: "%1", to: :awaiting_input}}, 10_000
    end
  end

  describe "completion — the outcome `wait` most often asks for" do
    test "a pane that was running and is now a shell prompt reports :finished" do
      # `Activity.classify/1` is pure and sees ONE sample, so a shell prompt is `:idle` whether
      # a build just exited or the operator has been reading email for an hour. Those are the
      # same picture and different events, and the second one is the entire answer to "tell me
      # when it finishes".
      assert Watcher.promote_finished(%{"%1" => :running}, %{"%1" => :idle}) ==
               %{"%1" => :finished}

      assert Watcher.promote_finished(%{"%1" => :working}, %{"%1" => :idle}) ==
               %{"%1" => :finished}
    end

    test "nothing else is promoted" do
      # A prompt someone answered is not a completed command...
      assert Watcher.promote_finished(%{"%1" => :awaiting_input}, %{"%1" => :idle}) ==
               %{"%1" => :idle}

      # ...an idle pane that stays idle is not an event...
      assert Watcher.promote_finished(%{"%1" => :idle}, %{"%1" => :idle}) == %{"%1" => :idle}

      # ...and the FIRST observation of a host must not report every idle pane as having just
      # finished something.
      assert Watcher.promote_finished(%{}, %{"%1" => :idle}) == %{"%1" => :idle}
    end

    test ":finished does not stick, so it cannot churn" do
      once = Watcher.promote_finished(%{"%1" => :running}, %{"%1" => :idle})
      assert once == %{"%1" => :finished}

      # Next tick: previous is now `:finished`, so it falls back to `:idle` — and
      # `Activity.notable?(:finished, :idle)` is false, so no event is published for it.
      assert Watcher.promote_finished(once, %{"%1" => :idle}) == %{"%1" => :idle}
      refute Termelix.Tmux.Activity.notable?(:finished, :idle)
    end

    test "a completion is a NOTABLE transition, so it is actually published" do
      # Before the promotion existed the transition was `running -> idle`, which
      # `notable?/2` correctly calls uninteresting — so nothing was published at all and a
      # human watching the monitor saw the pane go quiet with no event.
      refute Termelix.Tmux.Activity.notable?(:running, :idle)
      assert Termelix.Tmux.Activity.notable?(:running, :finished)
    end
  end

  describe "revocation" do
    test "stops a user's watchers — they hold credentials and dial on a timer", %{
      user: user,
      host: host
    } do
      {:ok, pid} = Watcher.ensure_started(user.id, host.id)
      ref = Process.monitor(pid)

      assert %{watchers: 1} = Termelix.Revocation.revoke_user(user.id, :test)

      assert_receive {:DOWN, ^ref, :process, ^pid, _}, 5000

      # On the PROCESS, not on the registry listing: `Registry` unregisters when it handles the
      # dead process's own `:DOWN`, and the VM promises nothing about the order of that relative
      # to ours. `stop_user_watchers/1` guarantees the watchers are stopped; asserting on the
      # listing would be testing `Registry`'s bookkeeping latency.
      refute Process.alive?(pid)
    end

    test "one user's revocation does not stop another's watcher", %{host: host} do
      {:ok, a, _} = Accounts.register_user("rev-a-#{unique()}", "password-123-abc")
      {:ok, b, _} = Accounts.register_user("rev-b-#{unique()}", "password-123-abc")

      # Each user needs a host they OWN: a watcher for someone else's host resolves
      # `:not_found` on its first tick and stops itself, which would make this pass for the
      # wrong reason.
      {:ok, host_a} = clone_host(a.id, host)
      {:ok, host_b} = clone_host(b.id, host)

      {:ok, pid_a} = Watcher.ensure_started(a.id, host_a.id)
      {:ok, pid_b} = Watcher.ensure_started(b.id, host_b.id)

      Termelix.Revocation.revoke_user(a.id, :test)

      ref = Process.monitor(pid_a)
      assert_receive {:DOWN, ^ref, :process, ^pid_a, _}, 5000
      assert Process.alive?(pid_b)

      on_exit(fn -> Watcher.stop(b.id, host_b.id) end)
    end
  end

  defp clone_host(user_id, host) do
    Hosts.create_host(user_id, %{
      name: host.name,
      ip: host.ip,
      port: host.port,
      username: host.username,
      authType: "password",
      password: "secret",
      enableTmuxMonitor: true
    })
  end

  describe "the adaptive interval" do
    test "a pane awaiting input is polled fast, whatever else is true" do
      # The whole value of the verdict is that somebody finds out quickly.
      state = %{failures: 0, last_change_at: nil, states: %{"%1" => :awaiting_input}}
      assert Watcher.interval_ms(state) == 2_000
    end

    test "quiet is slow, recent activity is medium" do
      quiet = %{failures: 0, last_change_at: nil, states: %{"%1" => :idle}}
      assert Watcher.interval_ms(quiet) == 30_000

      recent = %{
        failures: 0,
        last_change_at: System.monotonic_time(:millisecond) - 10_000,
        states: %{"%1" => :idle}
      }

      assert Watcher.interval_ms(recent) == 5_000
    end

    test "failures back off, and the backoff is bounded" do
      # A host that is down does not become reachable faster by being asked more often — but an
      # unbounded backoff would mean a host that recovers is never noticed.
      base = %{last_change_at: nil, states: %{}}

      intervals =
        for failures <- 1..12, do: Watcher.interval_ms(Map.put(base, :failures, failures))

      assert intervals == Enum.sort(intervals), "backoff must be monotonic"
      assert List.first(intervals) >= 30_000
      assert List.last(intervals) == 300_000
    end
  end

  # --- a fake tmux host -------------------------------------------------------

  # The same canned overview `Termelix.TmuxTest` uses, cut down to what the watcher reads: three
  # panes, one of which has a real prompt as the last line of its screen.
  defp fake_tmux_host do
    {:ok, _} = Application.ensure_all_started(:ssh)
    dir = Path.join(System.tmp_dir!(), "termelix_watcher_#{unique()}")
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

    {:ok, daemon} =
      :ssh.daemon(0,
        system_dir: String.to_charlist(dir),
        user_passwords: [{~c"tester", ~c"secret"}],
        auth_methods: ~c"password",
        exec: {:direct, &fake_overview/1}
      )

    on_exit(fn -> File.rm_rf(dir) end)
    {daemon |> :ssh.daemon_info() |> elem(1) |> Keyword.fetch!(:port), daemon}
  end

  defp fake_overview(_command) do
    sep = Termelix.Tmux.sep()
    line = fn fields -> Enum.join(fields, sep) <> "\n" end

    {:ok,
     "===TERMELIX-TMUX:version===\ntmux 3.4\n" <>
       "===TERMELIX-TMUX:sessions===\n" <>
       line.(["work", "1710000000", "1710000500", "1"]) <>
       "===TERMELIX-TMUX:windows===\n" <>
       line.(["work", "0", "1", "editor"]) <>
       "===TERMELIX-TMUX:panes===\n" <>
       line.(["work", "0", "%0", "0", "1234", "1", "80", "24", "vim", "/home/t", "e"]) <>
       line.(["work", "0", "%1", "1", "1250", "0", "80", "24", "bash", "/home/t", "s"]) <>
       line.(["work", "0", "%2", "2", "1300", "0", "80", "24", "htop", "/home/t", "p"]) <>
       "===TERMELIX-TMUX:ps===\n" <>
       "  1234     1 42.0  2.0  8000 vim\n" <>
       "  1250     1  0.0  0.1  1000 bash\n" <>
       "  1300     1  0.5  0.3  2000 htop\n" <>
       "===TERMELIX-TMUX:tails===\n" <>
       "===TERMELIX-TMUX:pane:%0===\n~/src\n" <>
       "===TERMELIX-TMUX:pane:%1===\nApplying migration...\nDo you want to proceed? [y/N]\n" <>
       "===TERMELIX-TMUX:pane:%2===\n  PID USER\n"}
  end

  describe "topics" do
    test "per-host and per-user topics are distinct and user-scoped", %{user: user, host: host} do
      assert Watcher.topic(user.id, host.id) =~ user.id
      assert Watcher.topic(user.id, host.id) =~ to_string(host.id)
      assert Watcher.user_topic(user.id) =~ user.id
      refute Watcher.user_topic(user.id) == Watcher.topic(user.id, host.id)

      # A user topic must not be a prefix collision with another user's.
      refute Watcher.user_topic("a") == Watcher.user_topic("ab")
    end
  end
end
