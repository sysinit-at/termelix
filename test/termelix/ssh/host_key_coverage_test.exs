defmodule Termelix.SSH.HostKeyCoverageTest do
  @moduledoc """
  Every SSH path that connects to a *known host* must verify its host key.

  This file exists because the obvious way to check that — read `HostKeyPolicy`, see that it is
  correct, see that `KeyCb` calls it — proves nothing about the paths that never hand it a pin.
  Three subsystems build their `conn_opts` map by hand from a host row instead of going through
  `Credential.resolve/2`, and each silently omitted the pin. `HostKeyPolicy` then saw first
  contact on *every* connect, so the tmux monitor (which polls every tmux-enabled host on an
  interval, unattended) and tunnels were never verified at all, while the code they call was
  provably correct in isolation.

  The failure was invisible in three ways at once: nothing errored, the policy's own tests
  passed, and the columns simply stayed NULL — which is indistinguishable from "not connected
  yet". So the assertion here is deliberately structural rather than behavioural: given a host
  row, does the map that reaches `:ssh` carry a pin?
  """
  use Termelix.DataCase

  alias Termelix.{Accounts, Hosts}
  alias Termelix.SSH.{ConnectOpts, Credential}

  setup do
    {:ok, user, _} = Accounts.register_user("alice", "correct horse battery staple")

    {:ok, host} =
      Hosts.create_host(user.id, %{
        name: "web-1",
        ip: "10.0.0.5",
        port: 22,
        username: "root",
        authType: "password",
        password: "s3cr3t",
        connectionType: "ssh"
      })

    {1, _} =
      Repo.update_all(
        from(h in Termelix.Schema.Host, where: h.id == ^host.id),
        set: [hostKeyFingerprint: "SHA256:pinned-for-test", hostKeyType: "ssh-ed25519"]
      )

    %{user: user, host: Hosts.get_for_user(host.id, user.id)}
  end

  describe "Credential.host_key/1" do
    test "carries the stored pin, the owner and the mode", %{host: host, user: user} do
      pin = Credential.host_key(host)

      assert pin.host_id == host.id
      assert pin.user_id == user.id
      assert pin.fingerprint == "SHA256:pinned-for-test"
      assert pin.key_type == "ssh-ed25519"
      # Without the mode the settings-row kill switch applies to nothing.
      assert pin.mode in [:tofu_warn, :enforce]
    end
  end

  describe "every conn_opts builder that has a host row" do
    # Named rather than derived: a builder that is added later and forgets the pin is exactly
    # the regression this file exists to catch, and a derived list would silently not cover it.
    # If a fourth subsystem appears, it belongs here.
    test "tmux, tunnels and the terminal socket all resolve to a verified credential", ctx do
      %{host: host, user: user} = ctx

      builders = %{
        "tmux monitor" => tmux_conn_opts(host),
        "tunnel" => tunnel_conn_opts(host),
        "terminal socket" => terminal_conn_opts(host)
      }

      for {name, conn_opts} <- builders do
        cred = Credential.resolve(conn_opts)

        assert cred.host_key.fingerprint == "SHA256:pinned-for-test",
               "#{name}: conn_opts reach :ssh with no host-key pin, so every connect looks " <>
                 "like first contact and the host is never verified"

        assert cred.host_key.host_id == host.id, "#{name}: pin is not for this host"

        assert cred.host_key.user_id == user.id,
               "#{name}: pin carries no owner, so the " <>
                 "audit row for a key change cannot be written"

        opts = ConnectOpts.build(cred, :pooled)
        assert Keyword.has_key?(opts, :key_cb), "#{name}: no key_cb, so no policy runs at all"

        refute Keyword.has_key?(opts, :silently_accept_hosts),
               "#{name}: silently_accept_hosts would override whatever the policy decides"
      end
    end
  end

  describe "a stored conn_opts map re-reads the pin instead of trusting its snapshot" do
    # `Tunnels.Tunnel` builds conn_opts once and reuses them for EVERY reconnect
    # (tunnels/tunnel.ex:257). If the pin travelled inside that map, a long-lived retry loop
    # would keep verifying against whatever was true when the tunnel was created — so a tunnel
    # started before the host was ever pinned would wave through any key for as long as it ran,
    # and flipping the mode to :enforce would never reach it.
    test "a pin that appears after the map was built is picked up", %{host: host} do
      # The snapshot a tunnel would have captured while the host was still unpinned.
      stale = %{
        host: host.ip,
        port: 22,
        username: host.username,
        password: host.password,
        host_id: host.id,
        host_key: %{
          host_id: host.id,
          user_id: nil,
          fingerprint: nil,
          key_type: nil,
          mode: :tofu_warn
        }
      }

      # setup/0 already pinned the row, so the stale snapshot disagrees with the database.
      cred = Credential.resolve(stale)

      assert cred.host_key.fingerprint == "SHA256:pinned-for-test",
             "a reconnect verified against the snapshot, not the stored pin"

      assert cred.host_key.user_id != nil,
             "the snapshot's nil owner survived, so a key-change audit row could not be written"
    end

    test "a mode change reaches a connection whose map was built earlier", %{host: host} do
      Application.put_env(:termelix, :ssh_host_key_policy, "enforce")
      on_exit(fn -> Application.delete_env(:termelix, :ssh_host_key_policy) end)

      stale = %{
        host: host.ip,
        port: 22,
        username: host.username,
        password: host.password,
        host_id: host.id,
        host_key: %{
          host_id: host.id,
          user_id: nil,
          fingerprint: nil,
          key_type: nil,
          mode: :tofu_warn
        }
      }

      assert Credential.resolve(stale).host_key.mode == :enforce,
             "the kill switch does not reach a long-lived connection built before it flipped"
    end
  end

  describe "the enforcement kill switch cannot be overridden by a stale map" do
    # `HostKeyPolicy.pin/2` rescues a database error to nil, so the fallback chain is reachable
    # without the host row being gone. If the snapshot supplied the MODE on that path, a
    # transient SQLite hiccup would drop a long-lived reconnect back to whatever enforcement
    # setting was in force when it was created — the one thing a stale map must never decide.
    test "a host id that resolves to nothing still gets the current mode", %{host: _host} do
      Application.put_env(:termelix, :ssh_host_key_policy, "enforce")
      on_exit(fn -> Application.delete_env(:termelix, :ssh_host_key_policy) end)

      # No such host row: `pin/2` returns nil and the snapshot is all that is left.
      orphaned = %{
        host: "10.0.0.5",
        port: 22,
        username: "root",
        password: "p",
        host_id: 999_999,
        host_key: %{
          host_id: 999_999,
          user_id: nil,
          fingerprint: "SHA256:from-the-snapshot",
          key_type: nil,
          mode: :tofu_warn
        }
      }

      pin = Credential.resolve(orphaned).host_key

      assert pin.mode == :enforce,
             "the snapshot's frozen mode overrode the kill switch"

      # The fingerprint fallback is deliberate: it can only cause a refusal, never an
      # acceptance, so keeping it is strictly safer than dropping to no pin at all.
      assert pin.fingerprint == "SHA256:from-the-snapshot"
    end

    test "a conn_opts map with no host id at all still gets the current mode" do
      Application.put_env(:termelix, :ssh_host_key_policy, "enforce")
      on_exit(fn -> Application.delete_env(:termelix, :ssh_host_key_policy) end)

      # A quick connect: nothing to look up, so the snapshot is the only source.
      quick = %{
        host: "10.0.0.9",
        port: 22,
        username: "root",
        password: "p",
        host_key: %{host_id: nil, user_id: nil, fingerprint: nil, key_type: nil, mode: :tofu_warn}
      }

      assert Credential.resolve(quick).host_key.mode == :enforce
    end
  end

  # The REAL builders, not copies of them.
  defp tmux_conn_opts(host), do: Termelix.Tmux.conn_opts(host)
  defp tunnel_conn_opts(host), do: Termelix.Tunnels.conn_opts(host)

  # The terminal socket's builder is inline in `resolve_conn/4` behind a websocket frame, so
  # this one is a mirror by necessity — noted rather than hidden.
  defp terminal_conn_opts(host) do
    host |> Termelix.Tmux.conn_opts() |> Map.merge(%{cols: 80, rows: 24})
  end
end
