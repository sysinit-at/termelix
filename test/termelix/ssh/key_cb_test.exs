defmodule Termelix.SSH.KeyCbTest do
  @moduledoc """
  The OTP `ssh_client_key_api` shell (`Termelix.SSH.KeyCb`) and the trust decision behind it
  (`Termelix.SSH.HostKeyPolicy`).

  Two things are under test here. The **policy** — first contact pins, an unchanged key
  verifies, a rotated key is refused under `:enforce` and recorded-but-allowed under
  `:tofu_warn` — and the **OTP contract**, which is what makes the policy reachable at all:

    * `ssh_transport.erl:1188-1197` calls `is_host_key/5` inside `try … catch error:undef ->
      is_host_key/4`, so an `undef` raised *inside* the /5 body silently downgrades to the
      legacy arity. `is_host_key/4` therefore raises instead of answering, and the
      `otp_known_host_key/4` helper below reproduces OTP's exact dispatch to prove /5 is the
      arity that answers.
    * A refusal must be `{:error, reason}`. `false` means "unknown key" to OTP, which under
      `silently_accept_hosts: true` accepts anyway (ssh_transport.erl:1200-1212).

  Host keys are generated per test with `:crypto.generate_key/2` rather than fixtured, so the
  fingerprints under comparison are the ones OTP itself would compute
  (`:ssh.hostkey_fingerprint/2` cross-checks that in `fingerprint/1`).
  """
  use Termelix.DataCase, async: false

  import ExUnit.CaptureLog

  alias Termelix.Accounts
  alias Termelix.Hosts
  alias Termelix.Repo
  alias Termelix.Schema.AuditLog
  alias Termelix.Schema.Host
  alias Termelix.Settings
  alias Termelix.SSH.HostKeyPolicy
  alias Termelix.SSH.KeyCb

  @setting "ssh_host_key_policy"
  @peer [~c"web-1.example", {10, 0, 0, 5}]
  @port 22
  @algorithm :"ssh-ed25519"

  # --- fixtures ---------------------------------------------------------------

  # An ed25519 public key in the shape `:public_key` uses for it: OTP encodes ed25519 as an
  # ECPoint with a namedCurve parameter, not as a type of its own (ssh_message.erl:656-659).
  defp host_key do
    {public, _private} = :crypto.generate_key(:eddsa, :ed25519)
    {{:ECPoint, public}, {:namedCurve, {1, 3, 101, 112}}}
  end

  defp fingerprint(key), do: :sha256 |> :ssh.hostkey_fingerprint(key) |> to_string()

  defp wire_blob(key), do: :ssh_file.encode(key, :ssh2_pubkey)

  # The option list OTP builds for the callbacks: `[{:key_cb_private, KeyCbOpts} | UserOpts]`
  # (ssh_transport.erl:1103-1105). `:host_key` is what `Termelix.SSH.ConnectOpts` puts there.
  defp opts(state), do: [key_cb_private: [key: nil, passphrase: nil, host_key: state]]

  # `user_id` defaults to a placeholder because most tests here never touch the database. The
  # persistence block MUST override it with the host's real owner: `audit_logs.user_id` is a
  # foreign key, so a placeholder makes `Audit.record/1` fail — and it fails quietly, leaving a
  # green-looking test that asserted nothing.
  defp pin(overrides \\ []) do
    %{host_id: 4242, user_id: "user-1", fingerprint: nil, key_type: nil, mode: :tofu_warn}
    |> Map.merge(Map.new(overrides))
    |> Map.put(:recorder, self())
  end

  # `ssh_transport.erl:1186-1197` verbatim: prefer /5, fall back to /4 on `error:undef`.
  defp otp_known_host_key(key, port, algorithm, opts) do
    KeyCb.is_host_key(key, @peer, port, algorithm, opts)
  rescue
    UndefinedFunctionError -> KeyCb.is_host_key(key, peer_name(), algorithm, opts)
  end

  defp peer_name, do: hd(@peer)

  defp check(key, state), do: KeyCb.is_host_key(key, @peer, @port, @algorithm, opts(state))

  # --- the trust decision -----------------------------------------------------

  describe "is_host_key/5 — first contact" do
    test "pins the presented key and allows the handshake" do
      key = host_key()

      assert check(key, pin()) == true

      assert_receive {:host_key_observation, observation}
      assert observation.status == :first_seen
      assert observation.allowed
      assert observation.fingerprint == fingerprint(key)
      assert observation.key_type == "ssh-ed25519"
      assert observation.peer == "web-1.example"
      assert observation.port == 22
      assert observation.algorithm == "ssh-ed25519"
    end

    test "an empty host_key map means 'no host to pin against' and records nothing" do
      # `Termelix.SSH.Credential` hands `%{}` (or a nil host_id) to quick connects, which have
      # no row to compare against — the Node reference's `if (!hostId) verify(true)`.
      assert check(host_key(), %{}) == true
      assert check(host_key(), %{host_id: nil}) == true
      refute_receive {:host_key_observation, _observation}
    end
  end

  describe "is_host_key/5 — unchanged key" do
    test "verifies against the stored fingerprint" do
      key = host_key()

      assert check(key, pin(fingerprint: fingerprint(key))) == true

      assert_receive {:host_key_observation, observation}
      assert observation.status == :verified
      assert observation.allowed
    end

    test "the Node reference's hex-blob pin is recognised as the same key and re-pinned" do
      # host-key-verifier.ts stored `hostkey.toString("hex")` — the raw SSH2 wire blob. An
      # upgraded install must not read every one of those as a changed key.
      key = host_key()
      legacy = key |> wire_blob() |> Base.encode16(case: :lower)

      assert check(key, pin(fingerprint: legacy, mode: :enforce)) == true

      assert_receive {:host_key_observation, observation}
      assert observation.status == :repin
      assert observation.fingerprint == fingerprint(key)
    end

    test "a pin in no format we emit is treated as no pin, not as a change" do
      # Fail open on an unreadable pin: reading it as "changed" would refuse a whole fleet at
      # once under :enforce, which is the outcome this phase exists to avoid.
      assert check(host_key(), pin(fingerprint: "whatever-this-is", mode: :enforce)) == true

      assert_receive {:host_key_observation, observation}
      assert observation.status == :repin
    end
  end

  describe "is_host_key/5 — rotated key" do
    test "refuses under :enforce with an error tuple, never `false`" do
      pinned = host_key()
      presented = host_key()

      result = check(presented, pin(fingerprint: fingerprint(pinned), mode: :enforce))

      # `false` would be read by OTP as "unknown host, ask accepted_host/5", which accepts
      # under silently_accept_hosts: true (ssh_transport.erl:1200-1212).
      assert result == {:error, {:host_key_changed, 4242}}

      assert_receive {:host_key_observation, observation}
      assert observation.status == :changed
      refute observation.allowed
      assert observation.mode == :enforce
      assert observation.previous_fingerprint == fingerprint(pinned)
      assert observation.fingerprint == fingerprint(presented)
    end

    test "records and allows under :tofu_warn" do
      pinned = host_key()
      presented = host_key()

      assert check(presented, pin(fingerprint: fingerprint(pinned), mode: :tofu_warn)) == true

      assert_receive {:host_key_observation, observation}
      assert observation.status == :changed
      assert observation.allowed
      assert observation.mode == :tofu_warn
    end
  end

  # --- the OTP contract -------------------------------------------------------

  describe "arity dispatch (the undef trap)" do
    test "the legacy /4 arity raises instead of deciding" do
      # OTP reaches /4 only after /5 raised `error:undef`. If it answered `true` there, every
      # undef in the /5 path — a typo, an unloaded module — would silently trust any host key.
      assert_raise RuntimeError, ~r/is_host_key\/4 was consulted/, fn ->
        KeyCb.is_host_key(host_key(), peer_name(), @algorithm, opts(pin()))
      end
    end

    test "OTP's own dispatch reaches /5, so the raising /4 is never taken" do
      key = host_key()

      assert otp_known_host_key(key, @port, @algorithm, opts(pin())) == true

      # Proof it was /5 that answered: only /5 produces an observation.
      assert_receive {:host_key_observation, %{status: :first_seen}}
    end

    test "an internal failure answers per mode instead of escaping as undef" do
      # A key term `:ssh_file.encode/2` cannot handle. Letting the exception through would put
      # us back in OTP's `catch error:undef` and downgrade the decision to the legacy arity.
      enforcing = opts(pin(mode: :enforce))

      capture_log(fn ->
        assert KeyCb.is_host_key(:not_a_key, @peer, @port, @algorithm, opts(pin())) == true

        assert KeyCb.is_host_key(:not_a_key, @peer, @port, @algorithm, enforcing) ==
                 {:error, :host_key_check_unavailable}
      end)
    end

    test "the legacy add_host_key/3 arity is the same tripwire" do
      assert_raise RuntimeError, ~r/add_host_key\/3 was consulted/, fn ->
        KeyCb.add_host_key(peer_name(), host_key(), opts(pin()))
      end

      # /4 is reachable only if is_host_key/5 ever returned `false`; OTP has already accepted
      # the connection by then, so it must not raise.
      capture_log(fn ->
        assert KeyCb.add_host_key(@peer, @port, host_key(), opts(pin())) == :ok
      end)
    end
  end

  # --- mode resolution and rollback -------------------------------------------

  describe "mode/0" do
    test "defaults to :tofu_warn, including for an unrecognised setting" do
      assert HostKeyPolicy.mode() == :tofu_warn

      Settings.put_value(@setting, "paranoid")
      assert HostKeyPolicy.mode() == :tofu_warn
    end

    test "the setting switches enforcement on, and back off — the documented rollback" do
      Settings.put_value(@setting, "enforce")
      assert HostKeyPolicy.mode() == :enforce

      Settings.put_value(@setting, "tofu_warn")
      assert HostKeyPolicy.mode() == :tofu_warn
    end

    test "application config wins, so the kill switch survives an unreachable database" do
      Settings.put_value(@setting, "enforce")
      Application.put_env(:termelix, :ssh_host_key_policy, "tofu_warn")
      on_exit(fn -> Application.delete_env(:termelix, :ssh_host_key_policy) end)

      assert HostKeyPolicy.mode() == :tofu_warn
    end
  end

  # --- persistence ------------------------------------------------------------

  describe "pin/2 and record/1" do
    setup do
      {:ok, user, _first?} = Accounts.register_user("alice", "correct horse battery staple")

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

      %{user: user, host: host}
    end

    test "pin/2 reads the stored state and the mode; a missing host yields no pin", %{
      host: host
    } do
      assert %{host_id: id, fingerprint: nil, mode: :tofu_warn} = HostKeyPolicy.pin(host.id)
      assert id == host.id

      assert HostKeyPolicy.pin(host.id + 1_000) == nil
      assert HostKeyPolicy.pin(nil) == nil
    end

    test "first contact writes the fingerprint, the timestamps and an audit row", ctx do
      %{host: host, user: user} = ctx
      key = host_key()

      assert check(key, pin(host_id: host.id, user_id: user.id)) == true
      assert_receive {:host_key_observation, observation}
      assert HostKeyPolicy.record(observation) == :ok

      stored = Repo.get(Host, host.id)
      assert stored.hostKeyFingerprint == fingerprint(key)
      assert stored.hostKeyType == "ssh-ed25519"
      assert stored.hostKeyAlgorithm == "sha256"
      assert stored.hostKeyFirstSeen
      assert stored.hostKeyLastVerified

      assert [audit] = Repo.all(from(a in AuditLog, where: a.action == "host_key_pinned"))
      assert audit.resourceId == to_string(host.id)
      assert audit.success
    end

    test "a first-contact write never overwrites a row that is already pinned", %{host: host} do
      # `Termelix.SSH.Credential.empty_host_key/1` hands the callback `fingerprint: nil` for any
      # conn_opts map with a host_id but no host_key, which classifies as a first contact. If
      # that wrote through, such a connection would silently re-pin the host to whatever key it
      # was shown.
      pinned = host_key()
      presented = host_key()

      Repo.update_all(from(h in Host, where: h.id == ^host.id),
        set: [hostKeyFingerprint: fingerprint(pinned)]
      )

      assert check(presented, pin(host_id: host.id, fingerprint: nil)) == true
      assert_receive {:host_key_observation, %{status: :first_seen} = observation}

      capture_log(fn -> assert HostKeyPolicy.record(observation) == :ok end)

      assert Repo.get(Host, host.id).hostKeyFingerprint == fingerprint(pinned)
      assert Repo.all(from(a in AuditLog, where: a.action == "host_key_pinned")) == []
    end

    test "a verify only touches hostKeyLastVerified and writes no audit row", %{host: host} do
      key = host_key()
      pinned_at = "2020-01-01T00:00:00Z"

      Repo.update_all(from(h in Host, where: h.id == ^host.id),
        set: [hostKeyFingerprint: fingerprint(key), hostKeyLastVerified: pinned_at]
      )

      assert check(key, pin(host_id: host.id, fingerprint: fingerprint(key))) == true
      assert_receive {:host_key_observation, observation}
      assert HostKeyPolicy.record(observation) == :ok

      stored = Repo.get(Host, host.id)
      assert stored.hostKeyFingerprint == fingerprint(key)
      assert stored.hostKeyLastVerified != pinned_at
      assert Repo.all(from(a in AuditLog, where: like(a.action, "host_key%"))) == []
    end

    test "under :tofu_warn a rotation re-pins and counts once", ctx do
      %{host: host, user: user} = ctx
      pinned = host_key()
      presented = host_key()
      Repo.update_all(from(h in Host, where: h.id == ^host.id), set: [hostKeyChangedCount: nil])

      assert check(
               presented,
               pin(host_id: host.id, user_id: user.id, fingerprint: fingerprint(pinned))
             ) ==
               true

      assert_receive {:host_key_observation, observation}
      assert HostKeyPolicy.record(observation) == :ok

      stored = Repo.get(Host, host.id)
      # Re-pinned, so the next connection is a plain verify rather than another change.
      assert stored.hostKeyFingerprint == fingerprint(presented)
      # NULL + 1 is NULL in SQLite; the counter is read and set, never `inc:`-ed.
      assert stored.hostKeyChangedCount == 1

      assert [audit] = Repo.all(from(a in AuditLog, where: a.action == "host_key_changed"))
      assert audit.success
      assert audit.details =~ fingerprint(pinned)
      assert audit.details =~ fingerprint(presented)
    end

    test "under :enforce a rotation counts and audits but leaves the pin alone", ctx do
      %{host: host, user: user} = ctx
      pinned = host_key()
      presented = host_key()

      Repo.update_all(from(h in Host, where: h.id == ^host.id),
        set: [hostKeyFingerprint: fingerprint(pinned)]
      )

      changed =
        pin(host_id: host.id, user_id: user.id, fingerprint: fingerprint(pinned), mode: :enforce)

      assert check(presented, changed) == {:error, {:host_key_changed, host.id}}
      assert_receive {:host_key_observation, observation}
      assert HostKeyPolicy.record(observation) == :ok

      stored = Repo.get(Host, host.id)
      # Re-pinning here would trust the presented key on the very next handshake.
      assert stored.hostKeyFingerprint == fingerprint(pinned)
      assert stored.hostKeyChangedCount == 1

      assert [audit] = Repo.all(from(a in AuditLog, where: a.action == "host_key_changed"))
      refute audit.success
    end
  end

  # --- the paths that were NOT verified --------------------------------------

  describe "conn_opts built from a flat map (the interactive terminal and tunnels)" do
    setup do
      {:ok, user, _} = Accounts.register_user("carol", "correct horse battery staple")

      {:ok, host} =
        Hosts.create_host(user.id, %{
          name: "web-2",
          ip: "10.0.0.7",
          port: 22,
          username: "root",
          authType: "password",
          password: "s3cr3t",
          connectionType: "ssh"
        })

      %{user: user, host: host}
    end

    # `SSH.Client` and `Tunnels.Tunnel` build a FLAT conn_opts map — a host_id, no host_key. They
    # went through `empty_host_key/1`, which is `fingerprint: nil`, so every connect classified
    # as first contact and the product's main surface was the one path host identity was never
    # checked on. `Credential.resolve/2` now resolves the pin from the host row for that shape.
    test "resolve/2 fills in the stored pin from the host id alone", %{host: host, user: user} do
      Repo.update_all(from(h in Host, where: h.id == ^host.id),
        set: [hostKeyFingerprint: "SHA256:pinned", hostKeyType: "ssh-ed25519"]
      )

      resolved =
        Termelix.SSH.Credential.resolve(%{
          host: "10.0.0.7",
          port: 22,
          username: "root",
          password: "s3cr3t",
          host_id: host.id
        })

      assert resolved.host_key.fingerprint == "SHA256:pinned"
      assert resolved.host_key.key_type == "ssh-ed25519"
      assert resolved.host_key.user_id == user.id
      assert resolved.host_key.mode in [:tofu_warn, :enforce]
    end

    test "a host id with no row still yields a usable, non-verifying pin" do
      resolved =
        Termelix.SSH.Credential.resolve(%{
          host: "10.0.0.8",
          port: 22,
          username: "root",
          password: "x",
          host_id: 999_999
        })

      assert resolved.host_key.fingerprint == nil
      assert resolved.host_key.mode in [:tofu_warn, :enforce]
    end

    # A pinned host reached through that flat shape must now REFUSE a rotated key under
    # :enforce. Before the pin was resolved it would have been waved through as first contact.
    test "a rotated key on the flat path is refused under :enforce", %{host: host, user: user} do
      pinned = host_key()
      presented = host_key()

      Repo.update_all(from(h in Host, where: h.id == ^host.id),
        set: [hostKeyFingerprint: fingerprint(pinned), hostKeyType: "ssh-ed25519"]
      )

      resolved =
        Termelix.SSH.Credential.resolve(%{
          host: "10.0.0.7",
          port: 22,
          username: "root",
          password: "s3cr3t",
          host_id: host.id
        })

      state =
        resolved.host_key
        |> Map.put(:mode, :enforce)
        |> Map.put(:recorder, self())

      assert {:error, {:host_key_changed, _}} = check(presented, state)
      assert user.id == resolved.host_key.user_id
    end
  end

  describe "mode/0 does not fail open" do
    setup do
      Application.delete_env(:termelix, :ssh_host_key_policy)
      :persistent_term.erase({Termelix.SSH.HostKeyPolicy, :mode})

      on_exit(fn ->
        Application.delete_env(:termelix, :ssh_host_key_policy)
        :persistent_term.erase({Termelix.SSH.HostKeyPolicy, :mode})
      end)

      :ok
    end

    test "a settings row saying enforce is honoured" do
      Termelix.Settings.put_value("ssh_host_key_policy", "enforce")
      assert HostKeyPolicy.mode() == :enforce
    end

    # The bug: a settings read that FAILS looked identical to a row saying "tofu_warn", so any
    # SQLite hiccup silently turned enforcement off — during exactly the kind of incident where
    # it should stay on. Asserted on the pure decision rather than by contriving a database
    # failure, because the failure is what the branch is FOR and faking it well is harder than
    # the branch itself.
    test "a failed read keeps the last known answer instead of downgrading" do
      assert HostKeyPolicy.decide_mode(:error, :enforce) == :enforce
      assert HostKeyPolicy.decide_mode(:error, :tofu_warn) == :tofu_warn
    end

    test "a row that genuinely says something else is NOT a failure" do
      assert HostKeyPolicy.decide_mode({:ok, "tofu_warn"}, :enforce) == :tofu_warn
      assert HostKeyPolicy.decide_mode({:ok, nil}, :enforce) == :tofu_warn
      assert HostKeyPolicy.decide_mode({:ok, "enforce"}, :tofu_warn) == :enforce
    end

    test "an instance that never enforced still does not start refusing on a failed read" do
      # Nothing remembered, nothing configured: the permissive default is correct here, and is
      # the property the fail-open behaviour existed to protect.
      assert HostKeyPolicy.mode() == :tofu_warn
    end

    test "application config still wins over the settings row" do
      Termelix.Settings.put_value("ssh_host_key_policy", "tofu_warn")
      Application.put_env(:termelix, :ssh_host_key_policy, "enforce")
      assert HostKeyPolicy.mode() == :enforce
    end
  end
end
