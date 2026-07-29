defmodule Termelix.SSH.Credential do
  @moduledoc """
  The one place an SSH credential is derived, for every `:ssh` entry point in the app:
  `Termelix.SSH.Client` (interactive shells), `Termelix.SSH.Exec`/`Termelix.SSH.Sftp` through
  `Termelix.SSH.Pool`, `Termelix.Tunnels.Tunnel` and `Termelix.SSH.JumpChain`.
  `Termelix.SSH.ConnectOpts.build/2` calls `resolve/2` itself, so a caller holding a conn_opts
  map never has to — but a caller that starts from a host *row* should call it, because that is
  the only shape carrying the `authType` this module reads.

  ## Why this exists

  Four call sites each ran the same `cond`: password first, private key second. That silently
  authenticated a host row carrying *both* with the password — and because `:key_cb` was only
  attached on the private-key branch (`connect_opts.ex:48-58`, `client.ex:250-262` before this
  change), the password path had no client-key callback at all, so OTP fell back to its default
  `ssh_file` callback and wrote host-key trust state into `$HOME/.ssh/known_hosts` inside an
  ephemeral container layer. `Termelix.SSH.ConnectOpts` now attaches `key_cb` on every branch;
  this module replaces the `cond` with an explicit `:auth` derived from the host row's
  `authType` column — the column the host editor already writes and `Schema.Host.changeset/2`
  already requires — instead of from whichever secret happens to be non-empty.

  ## Sources `resolve/2` accepts

    * a `Termelix.Schema.Host` struct, or a host-shaped map with `:ip` (secrets already
      decrypted by `Termelix.Hosts.get_for_user/2`);
    * a flat conn_opts map (`:host`, `:port`, `:username`, `:password`, `:private_key`,
      `:key_password`) — what `Termelix.Tunnels`, `Termelix.Tmux` and
      `TermelixWeb.TerminalSocket` build today. Those carry no `authType`, so they resolve by
      presence (see `@doc` on `resolve/2`); routing them through this module is a one-line
      change in each and is what makes the explicit-auth fix reach those paths;
    * a map `resolve/2` already returned. It is idempotent, which matters: `Termelix.SSH.Pool`
      stores the resolved map and `Termelix.SSH.Conn` rebuilds `:ssh` options from it later
      (`conn.ex:131`), and re-resolving must not throw the decided `:auth` away.

  Extra keys are ignored, so `Termelix.SSH.Client` can hand over its whole option map
  (`:cols`, `:rows`, `:subscriber`, …) unchanged.

  ## Rollback

  Every behavioural change here is selected by one setting, `ssh_auth_selection`, read from
  `Termelix.Settings` (and overridable without the database via
  `config :termelix, ssh_auth_selection: …`, the lever that still works when the DB is the
  problem):

    * `"explicit"` (**default**) — `:auth` comes from `authType`; both stored secrets stay
      attached so OTP can still fall back to the other method. Permissive: it changes the
      *order* methods are tried in, never the set.
    * `"strict"` — as above, but only the primary secret is attached. This is the end state
      the architecture review asks for ("exactly one credential option built"); it is not the
      default because a host whose declared key is unusable would stop connecting.
    * `"legacy"` — the pre-unification behaviour, bug for bug: password over key, and
      `key_cb` only on the key branch. The kill switch if this phase breaks the fleet.

  An unreadable setting (no DB, or a caller process without a sandbox checkout — the pooled
  connector at `conn.ex:127` runs in a bare `spawn_link`) falls back to the default rather than
  failing the connection.
  """

  alias Termelix.SSH.HostKeyPolicy
  alias Termelix.Hosts
  alias Termelix.Schema.Host
  alias Termelix.Settings

  @typedoc """
  Which authentication method this credential is *primarily* for. `:agent` is recorded but not
  yet executable — see `Termelix.SSH.ConnectOpts` for why OTP's own `ssh_agent` key callback is
  deliberately not used.
  """
  @type auth :: :password | :key | :agent | :none

  @typedoc """
  Pinned host-key state handed to the trust callback through `:key_cb_private`. Deliberately
  the same shape as `Termelix.SSH.HostKeyPolicy.pin/0` minus its `:mode`/`:recorder` — that
  module reads every field through `Access` and treats a `nil` `:host_id` as "no pin: allow,
  record nothing", which is what a conn_opts map with no host row resolves to.
  """
  @type host_key :: %{
          host_id: term(),
          user_id: String.t() | nil,
          fingerprint: String.t() | nil,
          key_type: String.t() | nil
        }

  @type t :: %{
          host: String.t(),
          port: pos_integer(),
          username: String.t(),
          auth: auth(),
          password: String.t() | nil,
          private_key: String.t() | nil,
          key_password: String.t() | nil,
          host_id: term(),
          host_key: host_key()
        }

  @type mode :: :explicit | :strict | :legacy

  @setting_key "ssh_auth_selection"
  @default_mode :explicit

  @doc """
  Normalize any supported source into a `t:t/0`.

  `opts` overrides what the source says: `:port`, `:username`, `:auth` (forces the method,
  skipping derivation), and `:mode` (skips `mode/0`; `Termelix.SSH.ConnectOpts.build/2` passes
  the mode it already read, so one connect cannot straddle a mode flip).

  Derivation, in `:explicit`/`:strict` mode:

    * a declared `authType` wins whenever the matching secret is present;
    * a declared method whose secret is *missing* falls back to the other stored secret rather
      than resolving to `:none` — refusing to try the only credential we hold would take hosts
      offline for a data problem;
    * with nothing declared (the flat conn_opts maps) the old password-first order is kept,
      because there is no signal to do better and changing it blind is exactly the kind of
      guess this module exists to remove. Those resolutions are recorded (see below).

  Emits `[:termelix, :ssh, :credential, :resolve]` only for the resolutions worth reviewing —
  two secrets present, or a declaration that did not match what is stored. Metadata carries the
  method, the *normalized* declaration and the mode; never a secret, and never the raw
  `authType` string, which is caller-supplied (`host_controller.ex:152`) and so must not enter
  telemetry.
  """
  @spec resolve(map(), keyword()) :: t()
  def resolve(source, opts \\ [])

  def resolve(%Host{} = host, opts), do: from_host(host, opts)
  def resolve(%{ip: _} = host, opts), do: from_host(host, opts)
  def resolve(%{host: _} = conn_opts, opts), do: from_conn_opts(conn_opts, opts)

  # Only the *shape* is reported, never the value: an unrecognized map is still a credential
  # map, and an exception message is the last place a password should turn up.
  def resolve(other, _opts) do
    shape = if is_map(other), do: "keys #{inspect(Map.keys(other))}", else: "a non-map"

    raise ArgumentError,
          "Termelix.SSH.Credential.resolve/2 needs a host row (`:ip`) or a conn_opts map " <>
            "(`:host`), got #{shape}"
  end

  @doc """
  The active selection mode. Application config wins over the `ssh_auth_selection` setting so
  the kill switch is reachable when the database is not; an unreadable/unknown value is the
  default. Public because `Termelix.SSH.ConnectOpts` needs it for the one `:legacy` branch it
  keeps.
  """
  @spec mode() :: mode()
  def mode do
    case Application.get_env(:termelix, :ssh_auth_selection) || setting() do
      v when v in ["legacy", :legacy] -> :legacy
      v when v in ["strict", :strict] -> :strict
      _ -> @default_mode
    end
  end

  # A settings read must never be the reason a connection fails: the pooled connector runs in a
  # bare `spawn_link` (conn.ex:127) and the tunnel connector in a task, neither of which owns a
  # sandbox checkout under test, so `Repo` raises there instead of answering.
  defp setting do
    Settings.get_value(@setting_key)
  rescue
    _ -> nil
  catch
    _, _ -> nil
  end

  # --- sources --------------------------------------------------------------

  defp from_host(host, opts) do
    build(
      %{
        host: Map.get(host, :ip),
        port: Keyword.get(opts, :port) || Hosts.effective_ssh_port(host),
        username: Keyword.get(opts, :username) || Map.get(host, :username),
        password: Map.get(host, :password),
        private_key: Map.get(host, :key),
        key_password: Map.get(host, :keyPassword),
        host_id: Map.get(host, :id),
        # Who this connection belongs to. Part of the pool key (`Pool.key_for/1`) so a pooled,
        # authenticated connection is never shared across accounts and revocation can find it.
        owner_id: Map.get(host, :userId),
        # `hostKeyAlgorithm` is deliberately not carried: that column holds the *digest* the
        # fingerprint uses (`DEFAULT 'sha256'`), not the negotiated host-key algorithm, which
        # `HostKeyPolicy.check/5` gets from the handshake itself.
        host_key: host_key(host)
      },
      Map.get(host, :authType),
      opts,
      _record? = true
    )
  end

  defp from_conn_opts(conn_opts, opts) do
    build(
      %{
        host: Map.get(conn_opts, :host),
        port: Keyword.get(opts, :port) || Map.get(conn_opts, :port) || 22,
        username: Keyword.get(opts, :username) || Map.get(conn_opts, :username),
        password: Map.get(conn_opts, :password),
        private_key: Map.get(conn_opts, :private_key),
        key_password: Map.get(conn_opts, :key_password),
        host_id: Map.get(conn_opts, :host_id),
        host_key: resolve_pin(conn_opts)
      },
      # A map we produced already decided its method; re-deriving from presence would undo the
      # host row's `authType` on the pooled rebuild path (conn.ex:131).
      Map.get(conn_opts, :auth),
      opts,
      # …and it was recorded when it was first resolved, so the rebuild stays silent.
      _record? = not Map.has_key?(conn_opts, :auth)
    )
  end

  # The pin is read FRESH from the database on every resolve, and a pin embedded in the
  # conn_opts map is only a fallback for the case where there is no host id to look up.
  #
  # Freshness is not an optimisation detail, it is the correctness property. `Tunnels.Tunnel`
  # stores its conn_opts once and reuses them for every reconnect (tunnel.ex:257), so a
  # snapshot taken at creation is what a long-lived retry loop would keep verifying against:
  # a tunnel started while the host was unpinned would see `fingerprint: nil` forever and wave
  # through any key, and the snapshotted `mode` meant flipping the setting to `:enforce` never
  # reached a running tunnel. The same applies to any pooled connection rebuilt from a stored
  # map.
  #
  # The cost is one primary-key SELECT per connect attempt, next to an SSH handshake. Carrying
  # the row's own columns to avoid that query is exactly the trade that introduced the bug.
  #
  # The read happens in the CALLER's process while conn_opts are being built, never inside the
  # handshake callback — which is the whole reason `HostKeyPolicy.check/5` takes a pre-resolved
  # pin instead of doing its own lookup.
  defp resolve_pin(conn_opts) do
    conn_opts
    |> stored_pin()
    # The mode is ALWAYS taken fresh, whatever the pin came from. `pin/2` rescues a database
    # error to nil, so without this a transient SQLite hiccup drops a long-lived reconnect onto
    # its snapshot — and that snapshot's `mode` was frozen when the tunnel was created, which
    # silently downgrades `:enforce` back to whatever was set then. The kill switch has to be
    # the one thing a stale map cannot override, and `mode/0` reads application config before
    # the settings row precisely so it still answers when the database is the broken thing.
    |> Map.put(:mode, HostKeyPolicy.mode())
  end

  # A fingerprint from a stale snapshot is still better than none — it can only cause a refusal,
  # never an acceptance — so it stays as the fallback when the fresh read comes back empty.
  defp stored_pin(conn_opts) do
    case Map.get(conn_opts, :host_id) do
      nil ->
        Map.get(conn_opts, :host_key) || empty_host_key(nil)

      host_id ->
        HostKeyPolicy.pin(host_id) || Map.get(conn_opts, :host_key) ||
          empty_host_key(host_id)
    end
  end

  # No host id (quick connect, a jump hop, a bare exec) means nothing to verify against. The
  # policy's first-contact write is guarded on the row still being unpinned, so this shape can
  # never re-pin an already-trusted host to whatever key it was shown.
  defp empty_host_key(host_id) do
    %{host_id: host_id, user_id: nil, fingerprint: nil, key_type: nil, mode: HostKeyPolicy.mode()}
  end

  @doc """
  The host-key pin for a host row already in memory.

  Public because three call sites build `conn_opts` by hand from a host row rather than going
  through `resolve/2` — the tmux monitor, tunnels, and the terminal socket. Each of those was
  omitting the pin entirely, so `HostKeyPolicy` saw first contact on every connect and the
  host was never actually verified. Handing it the row's own columns costs no extra query,
  which matters for the tmux monitor: it polls every tmux-enabled host on an interval, so a
  lookup here would be one SELECT per host per tick.

  `mode` is carried too. Without it the callback can only see the mode from application config,
  so the `ssh_host_key_policy` settings row — the documented no-restart kill switch — would
  silently apply to nothing.
  """
  @spec host_key(map()) :: host_key()
  def host_key(host) do
    %{
      host_id: Map.get(host, :id),
      user_id: Map.get(host, :userId),
      fingerprint: Map.get(host, :hostKeyFingerprint),
      key_type: Map.get(host, :hostKeyType),
      mode: HostKeyPolicy.mode()
    }
  end

  # --- derivation -----------------------------------------------------------

  defp build(fields, declared, opts, record?) do
    mode = Keyword.get(opts, :mode) || mode()
    declared = normalize_declared(declared)
    password? = present?(fields.password)
    key? = present?(fields.private_key)
    auth = Keyword.get(opts, :auth) || derive(mode, declared, password?, key?)

    if record?, do: record(mode, declared, auth, password?, key?, fields.host_id)

    fields
    |> Map.put(:username, to_string(fields.username || ""))
    |> Map.put(:auth, auth)
    |> prune(mode, auth)
  end

  # `authType` is a free-form string off the API (`host_controller.ex:152` takes it straight
  # from params), so it is folded into a closed set before it is matched on or recorded.
  defp normalize_declared(declared) when is_atom(declared) and not is_nil(declared) do
    if declared in [:password, :key, :agent, :none], do: declared, else: :other
  end

  defp normalize_declared(declared) when is_binary(declared) do
    case String.downcase(String.trim(declared)) do
      "password" -> :password
      "key" -> :key
      "agent" -> :agent
      "" -> nil
      _ -> :other
    end
  end

  defp normalize_declared(_), do: nil

  # Bug-for-bug pre-unification behaviour, kept reachable as the kill switch.
  defp derive(:legacy, _declared, true, _key?), do: :password
  defp derive(:legacy, _declared, false, true), do: :key
  defp derive(:legacy, _declared, false, false), do: :none

  defp derive(_mode, :key, _password?, true), do: :key
  defp derive(_mode, :key, true, false), do: :password
  defp derive(_mode, :password, true, _key?), do: :password
  defp derive(_mode, :password, false, true), do: :key
  # Declared agent auth keeps its label even with secrets stored: the label is what the trust
  # callback and the telemetry see, and in the default mode both secrets stay attached anyway.
  defp derive(_mode, :agent, _password?, _key?), do: :agent
  # Nothing declared (or something we don't recognize): keep the historical password-first
  # order rather than guess. Recorded, so the paths that still land here are visible.
  defp derive(_mode, _declared, true, _key?), do: :password
  defp derive(_mode, _declared, false, true), do: :key
  defp derive(_mode, _declared, false, false), do: :none

  # Only `:strict` (and `:legacy`, which never attached more than one) narrows the credential
  # set to the resolved method; the default mode leaves the other secret in place so OTP can
  # fall back to it when the primary method is refused.
  defp prune(fields, mode, auth) when mode in [:strict, :legacy] do
    fields
    |> maybe_drop(auth != :password, [:password])
    |> maybe_drop(auth not in [:key, :agent], [:private_key, :key_password])
  end

  defp prune(fields, _mode, _auth), do: fields

  defp maybe_drop(fields, false, _keys), do: fields

  defp maybe_drop(fields, true, keys) do
    Enum.reduce(keys, fields, &Map.put(&2, &1, nil))
  end

  # --- recording ------------------------------------------------------------

  # Quiet on the boring resolutions (exactly one secret, matching what was declared) so the
  # interesting ones — two secrets on one row, or a declaration that doesn't match what is
  # stored — are not buried under one event per pooled connect.
  defp record(mode, declared, auth, password?, key?, host_id) do
    both? = password? and key?
    mismatch? = declared not in [nil, auth, :other]

    if both? or mismatch? do
      :telemetry.execute(
        [:termelix, :ssh, :credential, :resolve],
        %{count: 1},
        %{
          auth: auth,
          declared: declared,
          mode: mode,
          both_secrets: both?,
          host_id: host_id
        }
      )
    end

    :ok
  end

  defp present?(v) when is_binary(v), do: String.trim(v) != ""
  defp present?(_), do: false
end
