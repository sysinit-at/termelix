defmodule Termelix.SSH.ConnectOpts do
  @moduledoc """
  The one `:ssh.connect/4` option builder in the app. Every SSH entry point routes here:
  `Termelix.SSH.Client` (`:interactive`), the pooled data plane — `Termelix.SSH.Pool` /
  `Termelix.SSH.Conn` for `Termelix.SSH.Exec` and `Termelix.SSH.Sftp` — (`:pooled`),
  `Termelix.Tunnels.Tunnel` (`:tunnel`) and `Termelix.SSH.JumpChain` (`:hop`). Each used to
  hand-roll the same ~15 lines and had already drifted: only this module set `idle_time`, only
  `Client` set TCP keepalive, the other two set neither.

  Credentials are not decided here — `Termelix.SSH.Credential.resolve/2` does that, and
  `build/2` calls it, so callers may pass a host row, a conn_opts map, or an already-resolved
  credential.

  ## What a profile selects

  Only what genuinely differs; auth and trust are shared.

    * `:interactive` — TCP keepalive, so a shell survives idle periods and NAT rebinding, and
      deliberately **no** `idle_time`: an interactive session legitimately sits with a channel
      open and no traffic.
    * `:pooled` — an `idle_time` backstop and no keepalive (see below).
    * `:tunnel`, `:hop` — neither. A tunnel connection idles channel-less by design (the
      forward listener is not an SSH channel until a TCP client arrives), so an `idle_time`
      would reap a healthy tunnel; the same holds for an intermediate hop carrying only
      forwards.

  The `idle_time` backstop exists because an established OTP `:ssh` connection is started under
  `sshc_sup`, is NOT linked to the caller, and defaults to `idle_time: infinity` — a connection
  whose owner dies (a crashed `Conn`, an `Exec`/`Sftp` operation killed mid-flight) would
  otherwise survive forever with no channels open. It is safe only for `:pooled`, because the
  data plane never keeps a legitimately-idle connection open with zero channels: the pooled
  `Termelix.SSH.Conn` closes an idle connection after 60 s anyway (so the backstop never fires
  for a healthy pooled conn), and every operation holds a channel for its whole duration.

  Keepalive is *not* added to `:pooled` here even though the architecture review recommends it
  (half-open pooled connections are never evicted): this change is meant to be per-profile
  behaviour-preserving, and that eviction work needs its own health check to be worth anything.

  ## Trust

  `key_cb` is attached on **every** authentication branch, not just the private-key one. Before
  this change a password-auth host fell through to OTP's default `ssh_file` callback, which
  writes accepted host keys into `$HOME/.ssh/known_hosts` — inside an ephemeral container layer
  — and, because password auth was silently preferred over a stored key, that was the branch a
  host row carrying both took. With `key_cb` always set, host-key policy is total: whatever
  `Termelix.SSH.KeyCb` decides applies to every connection this app makes.

  `silently_accept_hosts` is NOT set. It was a second, independent trust path: OTP consults its
  own accept logic only when the callback answers `false` (`ssh_transport.erl:1186-1200`), so
  with it on, a `false` from us would have been overridden and the host accepted anyway. It is
  gone now that `Termelix.SSH.KeyCb` decides. Note this is not what makes refusals work —
  `HostKeyPolicy.check/5` deliberately never returns `false`, it returns an error tuple — but
  leaving a switch that can override the policy is not something to keep for symmetry.

  ## Rollback

  `Termelix.SSH.Credential.mode/0` (setting `ssh_auth_selection`, or
  `config :termelix, ssh_auth_selection: …`) selects the behaviour; `"legacy"` restores the
  pre-unification option list exactly, `key_cb`-only-on-the-key-branch included.
  """

  alias Termelix.SSH.Credential
  alias Termelix.SSH.KeyCb

  # Idle backstop for orphaned data-plane connections (ms). Comfortably exceeds the pooled
  # `Termelix.SSH.Conn` 60 s idle expiry and any normal exec/sftp op, so it only ever closes a
  # connection the pool no longer tracks.
  @idle_time 600_000

  @profiles [:interactive, :pooled, :tunnel, :hop]

  @type profile :: :interactive | :pooled | :tunnel | :hop

  @type conn_opts :: %{
          required(:host) => String.t(),
          required(:port) => pos_integer(),
          required(:username) => String.t(),
          optional(:password) => String.t() | nil,
          optional(:private_key) => String.t() | nil,
          optional(:key_password) => String.t() | nil,
          optional(:auth) => Credential.auth(),
          optional(:host_id) => term(),
          optional(:host_key) => Credential.host_key()
        }

  @doc """
  Build the `:ssh.connect/4` option list for `source` under `profile`.

  `source` is anything `Termelix.SSH.Credential.resolve/2` accepts — a host row, a conn_opts
  map, or a resolved credential. Extra keys are ignored, so `Termelix.SSH.Client` can pass its
  whole option map (`:cols`, `:rows`, `:subscriber`, …).
  """
  @spec build(map(), profile()) :: keyword()
  def build(source, profile) when profile in @profiles do
    # Read once and hand it to the resolver: one connect must not straddle a mode flip, and
    # `mode/0` may go to the settings table.
    mode = Credential.mode()
    cred = Credential.resolve(source, mode: mode)

    shared(cred, mode) ++ profile_opts(profile) ++ password_opt(cred) ++ trust_opt(cred, mode)
  end

  @doc """
  Pooled-profile shim for the two call sites that predate profiles and are owned elsewhere:
  `Termelix.SSH.Pool.fresh_conn/1` (`pool.ex:63`) and the `Termelix.SSH.Conn` connector
  (`conn.ex:131`). Both are pooled data-plane connections, so `:pooled` reproduces exactly what
  they got before. New code passes a profile explicitly.
  """
  @spec build(map()) :: keyword()
  def build(source), do: build(source, :pooled)

  defp shared(cred, mode) do
    [
      user: String.to_charlist(cred.username),
      user_interaction: false,
      quiet_mode: true,
      auth_methods: auth_methods(cred.auth, mode)
    ]
  end

  defp profile_opts(:interactive) do
    # gen_tcp socket option — keeps the TCP connection alive through idle periods / NATs.
    [socket_options: [{:keepalive, true}]]
  end

  defp profile_opts(:pooled), do: [idle_time: @idle_time]
  defp profile_opts(profile) when profile in [:tunnel, :hop], do: []

  # The client's method order (`ssh_connection_handler.erl:442` feeds this into
  # `userauth_supported_methods`, which `ssh_auth.erl:70-79` intersects with the server's list
  # *in this order*). Putting the resolved method first is the whole behavioural effect of the
  # explicit `:auth`: in the default mode both stored secrets stay attached, so this reorders
  # what is tried, it does not narrow it.
  defp auth_methods(_auth, :legacy), do: ~c"publickey,password,keyboard-interactive"
  defp auth_methods(:password, _mode), do: ~c"password,keyboard-interactive,publickey"
  defp auth_methods(_auth, _mode), do: ~c"publickey,password,keyboard-interactive"

  # The password is the only credential OTP takes as a plain option; a private key reaches the
  # handshake through `key_cb` below. In `:strict`/`:legacy` mode `Credential.resolve/2` has
  # already dropped the non-primary secret, so this attaches whatever survived.
  defp password_opt(cred) do
    if present?(cred[:password]),
      do: [password: String.to_charlist(cred.password)],
      else: []
  end

  # `:legacy` reproduces the pre-unification bug — no client-key callback at all unless a
  # private key is being used — so the kill switch really is a full revert.
  defp trust_opt(%{auth: auth}, :legacy) when auth != :key, do: []
  defp trust_opt(cred, _mode), do: [key_cb: {KeyCb, key_cb_private(cred)}]

  # OTP surfaces this list to the `ssh_client_key_api` callbacks as `:key_cb_private`
  # (`ssh_transport.erl` `call_KeyCb/3`). `:key`/`:passphrase` keep their names — `KeyCb` reads
  # them today; `:auth` and `:host_key` are what the host-key policy needs, and are inert until
  # `KeyCb` looks at them.
  defp key_cb_private(cred) do
    [
      key: nilify(cred[:private_key]),
      passphrase: nilify(cred[:key_password]),
      auth: cred.auth,
      host_key: cred[:host_key] || %{}
    ]
  end

  defp nilify(v), do: if(present?(v), do: v, else: nil)

  defp present?(v) when is_binary(v), do: String.trim(v) != ""
  defp present?(_), do: false
end
