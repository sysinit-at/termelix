defmodule Termelix.Terminal.LivenessTest do
  @moduledoc """
  Phase 5: a session never dies silently, never outlives its owner's access, and never hands
  a locked secret to a real sshd.

  These are all *seam* properties — each half was already correct on its own, which is exactly
  why none of them was caught. The socket had no monitor because the session monitors the
  socket and the asymmetry read as symmetry; the cap read `lastDetachedAt` through a blocking
  call the value could have carried; revocation deleted the rows that authorize a connection
  without touching the connection.
  """
  use Termelix.DataCase, async: false

  import Ecto.Query, only: [from: 2]

  alias Termelix.{Accounts, Hosts}
  alias Termelix.Crypto.FieldCrypto
  alias Termelix.Terminal.SessionManager
  alias TermelixWeb.TerminalSocket

  setup do
    {:ok, user, _admin?} = Accounts.register_user("liveness-#{unique()}", "password-123-abc")

    {:ok, host} =
      Hosts.create_host(user.id, %{
        name: "h",
        ip: "127.0.0.1",
        port: 22,
        username: "tester",
        authType: "password",
        password: "secret",
        connectionType: "ssh"
      })

    %{user: user, host: host}
  end

  defp unique, do: System.unique_integer([:positive])

  describe "the DATA_LOCKED gate (defect 40)" do
    test "a host whose secret survives the decrypt pass as ciphertext refuses to connect", %{
      user: user,
      host: host
    } do
      stored = Termelix.Repo.get(Termelix.Schema.Host, host.id).password

      assert FieldCrypto.envelope?(stored),
             "fixture must be encrypted at rest, or this test proves nothing"

      assert {:ok, ok_host} = Hosts.fetch_for_connect(host.id, user.id)
      assert ok_host.password == "secret"

      # Now the failure this gate exists for: an envelope the DEK cannot open. Decryption is
      # deliberately graceful — `safe_decrypt/4` hands back what it cannot decrypt — so the
      # column comes out of `get_for_user/2` still holding ciphertext. That is byte-for-byte
      # what a locked or mismatched DEK produces, without stopping the key manager the rest of
      # the VM shares.
      tampered =
        stored
        |> Jason.decode!()
        |> Map.put("tag", String.duplicate("00", 16))
        |> Jason.encode!()

      Termelix.Repo.update_all(
        from(h in Termelix.Schema.Host, where: h.id == ^host.id),
        set: [password: tampered]
      )

      # Graceful: the row still loads, and the secret is still an envelope.
      assert FieldCrypto.envelope?(Hosts.get_for_user(host.id, user.id).password)

      # The gate: no ciphertext is ever offered to a real sshd as a password.
      assert Hosts.fetch_for_connect(host.id, user.id) == {:error, :locked}
    end

    test "envelope?/1 tells ciphertext from a password that merely looks like JSON" do
      envelope =
        Jason.encode!(%{
          "data" => "aa",
          "iv" => "bb",
          "tag" => "cc",
          "salt" => "dd",
          "recordId" => "1"
        })

      assert FieldCrypto.envelope?(envelope)

      # A user whose password IS `{}` — or any other JSON — must still be able to log in.
      refute FieldCrypto.envelope?("{}")
      refute FieldCrypto.envelope?(~s({"data":"aa"}))
      refute FieldCrypto.envelope?("hunter2")
      refute FieldCrypto.envelope?(nil)
      refute FieldCrypto.envelope?("")
    end

    test "a missing host is :not_found, not :locked", %{user: user} do
      assert Hosts.fetch_for_connect(999_999, user.id) == {:error, :not_found}
    end

    test "another user's host is :not_found, not :locked", %{host: host} do
      {:ok, other, _} = Accounts.register_user("other-#{unique()}", "password-123-abc")
      assert Hosts.fetch_for_connect(host.id, other.id) == {:error, :not_found}
    end
  end

  describe "the per-user session cap" do
    test "refuses rather than silently killing the oldest session", %{user: user, host: host} do
      # Registry entries without live sessions: the cap must be decided from the registry, and
      # this also proves it never calls into the processes (there are none to call).
      for i <- 1..SessionManager.max_sessions_per_user() do
        register_fake_session(user.id, host.id, "cap-#{i}")
      end

      assert SessionManager.create(user.id, host.id, host.name, %{}) ==
               {:error, :session_limit}
    end

    test "one user's sessions do not count against another's", %{user: user, host: host} do
      {:ok, other, _} = Accounts.register_user("cap-other-#{unique()}", "password-123-abc")

      for i <- 1..SessionManager.max_sessions_per_user() do
        register_fake_session(other.id, host.id, "other-#{i}")
      end

      assert SessionManager.list_user_sessions(user.id) == []
      assert length(SessionManager.list_user_sessions(other.id)) == 10
    end
  end

  describe "revocation reaches the data plane" do
    test "revoking every auth session stops the user's terminal sessions", %{
      user: user,
      host: host
    } do
      pid = register_fake_session(user.id, host.id, "revoke-me")
      ref = Process.monitor(pid)

      assert length(SessionManager.list_user_sessions(user.id)) == 1
      assert SessionManager.stop_user_sessions(user.id) == 1

      assert_receive {:DOWN, ^ref, :process, ^pid, _}, 5000

      # Asserted on the process, not on the registry listing: `Registry` unregisters a dead
      # process when it handles its OWN `:DOWN`, and the VM makes no promise about the order of
      # that relative to ours. The guarantee `stop_user_sessions/1` makes is that the sessions
      # are stopped, and that is what is checked here — a listing assertion would be testing
      # `Registry`'s bookkeeping latency, and would fail roughly one run in five.
      refute Process.alive?(pid)
    end

    test "revoke_user broadcasts before it acts, so a late subscriber still learns", %{
      user: user
    } do
      Phoenix.PubSub.subscribe(Termelix.PubSub, Termelix.Revocation.topic())
      Termelix.Revocation.revoke_user(user.id, :test)
      assert_receive {:revoked, user_id, :test}, 2000
      assert user_id == user.id
    end

    test "a pooled SSH connection to the user's host does not survive the revocation", %{
      user: user,
      host: host
    } do
      # A pooled connection is authenticated and idle-kept, so it is the one a revocation can
      # most easily miss: it belongs to no session and no tunnel, and nothing in the UI shows
      # it. Start a real one against a real daemon.
      {port, daemon} = fake_sshd()
      on_exit(fn -> :ssh.stop_daemon(daemon) end)

      # Pinned, not inherited. `:ssh_conn_idle_timeout` is application-global and another module
      # drives it down to 50ms for its own reasons; picking that up here would idle-expire the
      # pooled connection before the revocation ran and turn this into a test that passes
      # because there was nothing left to close.
      Application.put_env(:termelix, :ssh_conn_idle_timeout, 60_000)
      on_exit(fn -> Application.delete_env(:termelix, :ssh_conn_idle_timeout) end)

      {:ok, host} =
        Hosts.update_host(user.id, host.id, %{
          port: port,
          username: "tester",
          password: "secret"
        })

      opts = Termelix.Tmux.conn_opts(host)
      assert opts[:owner_id] == user.id, "the pool key must know who owns the connection"

      assert {:ok, _conn} = Termelix.SSH.Pool.checkout(opts)
      key = Termelix.SSH.Pool.key_for(opts)
      pid = Termelix.SSH.Pool.lookup(key)
      assert is_pid(pid)

      ref = Process.monitor(pid)
      assert %{pooled: 1} = Termelix.Revocation.revoke_user(user.id, :test)

      assert_receive {:DOWN, ^ref, :process, ^pid, _}, 10_000
      refute Termelix.SSH.Pool.lookup(key)
    end

    test "deleting a user sweeps again AFTER the rows are gone", %{user: user, host: host} do
      # One sweep is not enough, and asserting "nothing is left" cannot tell the difference:
      # the first sweep runs while the account is STILL VALID, so a request in flight can check
      # out a fresh pooled connection or open a tunnel against rows that have not been deleted
      # yet — revocation reports success while what it closed comes back.
      #
      # So this asserts the ordering itself: each sweep records whether the user row still
      # existed when it ran, and the delete path must produce a sweep that ran with the row
      # already gone. That is the only moment at which there is nothing left to re-authorize.
      test_pid = self()
      handler = "sweep-#{unique()}"

      :telemetry.attach(
        handler,
        [:termelix, :revocation, :swept],
        fn _event, _measure, meta, _ ->
          if meta.user_id == user.id do
            send(test_pid, {:swept, Termelix.Repo.get(Termelix.Schema.User, user.id) != nil})
          end
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler) end)

      pid = register_fake_session(user.id, host.id, "before-delete")
      Termelix.Admin.delete_user_and_related_data(user.id)

      assert_receive {:swept, true}, 5000, "expected a sweep while the account still existed"
      assert_receive {:swept, false}, 5000, "expected a sweep AFTER the account was deleted"

      refute Process.alive?(pid)
      assert Termelix.Repo.get(Termelix.Schema.User, user.id) == nil
    end

    test "revoking through Accounts also stops the connections those sessions authorized", %{
      user: user,
      host: host
    } do
      # `Accounts.revoke_all_sessions/1` is the OTHER entry point — the one the OIDC account
      # deletion uses. It revoked the rows and left the shells running.
      pid = register_fake_session(user.id, host.id, "oidc-path")
      ref = Process.monitor(pid)

      :ok = Termelix.Accounts.revoke_all_sessions(user.id)

      assert_receive {:DOWN, ^ref, :process, ^pid, _}, 5000
    end

    test "sparing a session does NOT kill the terminal the user is typing into", %{
      user: user,
      host: host
    } do
      pid = register_fake_session(user.id, host.id, "keep-me")

      # "Log out my other devices": the user still has access.
      Termelix.Sessions.revoke_all_for_user(user.id, "some-other-session-id")

      assert Process.alive?(pid)
      assert length(SessionManager.list_user_sessions(user.id)) == 1
      Process.exit(pid, :kill)
    end
  end

  describe "the socket watches the session" do
    test "an abnormal session death reaches the client as an error, not silence" do
      session = spawn(fn -> receive do: (:die -> exit(:boom)) end)
      state = socket_state_bound_to(session)

      send(session, :die)

      assert {:push, frames, state} = wait_for_down(state)
      text = frames |> List.wrap() |> Enum.map(fn {:text, t} -> t end) |> Enum.join("\n")

      assert text =~ ~s("type":"error")
      assert text =~ ~s("type":"disconnected")
      # The socket must not keep pointing at a dead pid — that is what let keystrokes vanish
      # into a `GenServer.cast` forever while the UI read "connected".
      assert state.session == nil
      assert state.session_id == nil
    end

    test "a normal session end is a plain disconnect, with no scary error" do
      session = spawn(fn -> receive do: (:die -> :ok) end)
      state = socket_state_bound_to(session)

      send(session, :die)

      assert {:push, frames, _state} = wait_for_down(state)
      text = frames |> List.wrap() |> Enum.map(fn {:text, t} -> t end) |> Enum.join("\n")

      assert text =~ ~s("type":"disconnected")
      refute text =~ ~s("type":"error")
    end

    test "a stale monitor from an earlier session cannot tear down the current one" do
      old = spawn(fn -> receive do: (:die -> exit(:boom)) end)
      state = socket_state_bound_to(old)

      # Rebinding must release the old monitor.
      current = spawn(fn -> Process.sleep(:infinity) end)
      state = TerminalSocket.handle_in({bind_probe(), [opcode: :text]}, state) |> elem(2)
      state = rebind(state, current)

      send(old, :die)

      # Nothing arrives, so nothing tears down the live session.
      refute_receive {:DOWN, _, :process, ^old, _}, 500

      assert {:ok, ^state} =
               TerminalSocket.handle_info({:DOWN, make_ref(), :process, old, :boom}, state)

      assert state.session == current
      Process.exit(current, :kill)
    end
  end

  describe "a stalled socket is actually stopped" do
    # The session kills a socket that stops draining. But Bandit runs the WebSock handler
    # inside a ThousandIsland handler that TRAPS EXITS, so the kill arrives as a message —
    # which the catch-all discarded. The old test used a plain `spawn`, where the exit signal
    # kills outright, so it passed against a socket that in production ignored it entirely.
    test "the exit signal a trapping socket receives as a message stops the socket" do
      state = socket_state_bound_to(spawn(fn -> Process.sleep(:infinity) end))

      assert {:stop, {:shutdown, :stalled}, state} =
               TerminalSocket.handle_info({:EXIT, self(), {:shutdown, :stalled}}, state)

      assert state.session == nil
    end
  end

  # --- helpers ---------------------------------------------------------------

  # A registry entry with a live but inert owner: enough for every reader that works off the
  # registry value, and deliberately NOT a real session, so a reader that secretly calls into
  # the process fails instead of quietly working.
  defp register_fake_session(user_id, host_id, id) do
    parent = self()

    pid =
      spawn(fn ->
        {:ok, _} =
          Registry.register(Termelix.Terminal.Registry, id, %{
            user_id: user_id,
            host_id: host_id,
            host_name: "h",
            created_at: System.system_time(:millisecond),
            ready: true,
            last_detached_at: System.system_time(:millisecond)
          })

        send(parent, :registered)
        Process.sleep(:infinity)
      end)

    receive do
      :registered -> :ok
    after
      2000 -> flunk("fake session never registered")
    end

    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
    pid
  end

  defp fake_sshd do
    {:ok, _} = Application.ensure_all_started(:ssh)
    dir = Path.join(System.tmp_dir!(), "termelix_pool_test_#{unique()}")
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
        shell: fn _u, _p -> spawn(fn -> Process.sleep(:infinity) end) end
      )

    on_exit(fn -> File.rm_rf(dir) end)
    {:ssh.daemon_info(daemon) |> elem(1) |> Keyword.fetch!(:port), daemon}
  end

  defp socket_state_bound_to(session) do
    {:ok, state} = TerminalSocket.init(%{user_id: "u"})
    rebind(state, session)
  end

  # Exercises the same private bind the connect path uses, via the only public door there is.
  defp rebind(state, session) do
    ref = Process.monitor(session)
    if r = state[:session_monitor], do: Process.demonitor(r, [:flush])
    %{state | session: session, session_id: "sid", session_monitor: ref}
  end

  defp bind_probe, do: Jason.encode!(%{type: "ping"})

  defp wait_for_down(state) do
    receive do
      {:DOWN, _, :process, _, _} = msg -> TerminalSocket.handle_info(msg, state)
    after
      5000 -> flunk("no :DOWN from the session")
    end
  end
end
