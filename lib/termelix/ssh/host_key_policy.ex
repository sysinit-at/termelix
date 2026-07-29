defmodule Termelix.SSH.HostKeyPolicy do
  @moduledoc """
  Host-identity (trust-on-first-use) decision for outbound SSH, over the `ssh_data`
  `host_key_*` columns the schema has carried since the initial migration
  (priv/repo/migrations/20260723000001_create_initial_schema.exs:186-191) and that nothing
  read until now.

  ## Why this exists

  `Termelix.SSH.KeyCb.is_host_key/5` used to return a bare `true`. OTP consults that callback
  first and only falls through to its own accept logic when it returns `false`
  (ssh_transport.erl:1186-1218), so `true` meant "already trusted, ask no further": every
  outbound connection accepted whatever host key the peer presented, and
  `silently_accept_hosts: true` (ssh/connect_opts.ex:116) meant OTP would not have caught it
  either. Nothing in the app detected a man-in-the-middle.

  ## Decision

  `check/5` runs inside the OTP handshake process, so it does no I/O: the pinned state comes
  in through `:key_cb_private` (`Termelix.SSH.Credential`'s `host_key` map, built while
  resolving the credential), and the observation it produces is handed to an owner process —
  `Termelix.TaskSupervisor` — which does the DB writes.

    * **first sight** (`host_key_fingerprint` NULL/blank) — pin the fingerprint, allow.
    * **unchanged** — allow, touch `host_key_last_verified`.
    * **re-pin** — the stored value is the same key in an older encoding (the Node reference
      stored `hostkey.toString("hex")`, the raw SSH2 wire blob — see
      `src/backend/hosts/host-key-verifier.ts` in the frontend checkout), or it is in no
      format we ever emit. Rewrite it to the canonical form and allow. Treating an
      un-parseable pin as "changed" would refuse every host of an upgraded install at once,
      which is precisely the failure this phase must not have.
    * **changed** — bump `host_key_changed_count`, write an audit row, then allow or refuse
      per the mode below.

  The first-sight write is conditional on the column still being empty. Not every call site
  fills the stored fingerprint into the pin yet (`Termelix.SSH.Credential.empty_host_key/1`
  leaves it `nil` for a conn_opts map that carries a `host_id` but no `host_key`), and an
  unguarded write would let such a connection silently re-pin a host that was already pinned.
  When the guard bites, the skipped write is logged.

  Fingerprints are stored in OpenSSH's canonical `SHA256:<base64>` form. `host_key_algorithm`
  keeps the reference's meaning — the *digest* the fingerprint uses, hence the column's
  `DEFAULT 'sha256'` — and the negotiated host-key algorithm goes into the audit row's
  `details` instead.

  ## Modes and rollback

  Two modes, resolved by `mode/0` from application config first and the `ssh_host_key_policy`
  setting second (the same order as `Termelix.SSH.Credential.mode/0`, so the kill switch is
  reachable when the database is not):

    * `:tofu_warn` — the default, and what any unset/unrecognised value maps to. A changed key
      is recorded, audited, re-pinned, and **allowed**. This is the one-release grace window:
      it produces the evidence (one audit row and one `host_key_changed_count` increment per
      actual rotation) needed to judge whether enforcement is safe for a given fleet, and it
      can never make a host unconnectable.
    * `:enforce` — a changed key is recorded and audited but **not** re-pinned (re-pinning
      would trust the new key on the very next handshake, defeating the point), and the
      handshake is refused with `{:error, {:host_key_changed, host_id}}`.

  **Rollback**, in order of reach:

      # 1. no redeploy, no restart — takes effect on the next connection
      Termelix.Settings.put_value("ssh_host_key_policy", "tofu_warn")

      # 2. config, for when the database is unreachable (config/runtime.exs)
      config :termelix, ssh_host_key_policy: "tofu_warn"

      # 3. one host only: NULL its pin and the next connection re-pins as a first sight
      UPDATE ssh_data SET host_key_fingerprint = NULL WHERE id = ?;

  Prefer `Termelix.Settings.put_value/2` over `UPDATE settings …`: settings reads are cached
  in `:persistent_term` and only invalidated by that module's own writes, so a direct DB edit
  is not observed until the node restarts.

  A caveat on where the mode is read. `check/5` may not touch the database, so it takes the
  mode from the pin when one is there (`pin/2` puts it there) and otherwise from application
  config. A pin built by `Termelix.SSH.Credential` carries no mode, so for those connections
  only the config route (2) can raise the mode to `:enforce` — the setting row alone will not.
  Wiring `pin/2` into the credential resolver removes that asymmetry.

  Under `:enforce` a host whose key genuinely rotated writes one audit row per connection
  *attempt* until an operator clears the pin. That is deliberate — a refused handshake is a
  security event — but it is another reason `:tofu_warn` is the default: it audits once per
  rotation.
  """

  import Ecto.Query, only: [from: 2]

  require Logger

  alias Termelix.Audit
  alias Termelix.Repo
  alias Termelix.Schema.Host
  alias Termelix.Schema.User
  alias Termelix.Settings

  @setting_key "ssh_host_key_policy"
  @default_mode :tofu_warn

  # Last successfully-read mode, so a database error cannot downgrade enforcement.
  @mode_term {__MODULE__, :mode}

  # `hostKeyLastVerified` is touched at most this often. See `record(%{status: :verified})`:
  # writing on every successful handshake turned a read-only connect into a SQLite write on a
  # single-writer database.
  @verify_touch_interval_ms 60 * 60 * 1000

  # OpenSSH's default and the only form we write; `host_key_algorithm` records its name.
  @digest :sha256
  @digest_name "sha256"

  @type mode :: :tofu_warn | :enforce

  @typedoc """
  The pinned state `check/5` reads inside the handshake. A plain map, and every field read
  through `Access`: `Termelix.SSH.Credential.host_key/0` builds this shape without `:mode` or
  `:recorder`, and a half-built pin has to degrade to "allow and record", never to a crash
  inside the handshake process.
  """
  @type pin :: %{
          required(:host_id) => term(),
          optional(:user_id) => String.t() | nil,
          optional(:fingerprint) => String.t() | nil,
          optional(:key_type) => String.t() | nil,
          optional(:mode) => mode(),
          optional(:recorder) => pid() | nil
        }

  @type observation :: map()

  # --- resolution (connecting process; touches the DB) ------------------------

  @doc """
  Resolve the trust context for `host_id`, mode included. Returns `nil` when there is no host
  row to pin against (a quick connect, a deleted host, a DB error) — `check/5` then allows
  without recording, matching the Node reference's `if (!hostId) verify(true)`.

  Call this from the process that is about to connect, never from the callback: it is a DB
  read, and the callback runs inside the SSH handshake where a SQLite stall eats the remote's
  `LoginGraceTime`.

  `opts[:recorder]` overrides where observations go: a pid receives
  `{:host_key_observation, observation}` instead of the write being dispatched to
  `Termelix.TaskSupervisor`. Used by tests, and available to a call site that would rather own
  its own writes.
  """
  @spec pin(term(), keyword()) :: pin() | nil
  def pin(host_id, opts \\ [])

  def pin(host_id, _opts) when not is_integer(host_id), do: nil

  def pin(host_id, opts) do
    query =
      from(h in Host,
        where: h.id == ^host_id,
        select: %{
          host_id: h.id,
          user_id: h.userId,
          fingerprint: h.hostKeyFingerprint,
          key_type: h.hostKeyType
        }
      )

    case Repo.one(query) do
      nil -> nil
      row -> Map.merge(row, %{mode: mode(), recorder: Keyword.get(opts, :recorder)})
    end
  rescue
    error ->
      # A pin we cannot read must not stop the connection: no pin means "allow, record
      # nothing", which is exactly where the app was before this module existed.
      Logger.warning("Host key pin lookup failed for host #{inspect(host_id)}: #{safe(error)}")
      nil
  end

  @doc """
  The configured mode. Application config wins over the setting row so the kill switch stays
  reachable when the database is not; anything other than `"enforce"` — unset, misspelled,
  left over from an older release — is `:tofu_warn`, because an unreadable setting must not
  start refusing connections.
  """
  @spec mode() :: mode()
  def mode do
    case Application.get_env(:termelix, :ssh_host_key_policy) do
      value when value in ["enforce", :enforce] -> :enforce
      nil -> mode_from_setting()
      _explicitly_something_else -> @default_mode
    end
  end

  # A FAILED settings read and a settings row that says "tofu_warn" are not the same thing, and
  # collapsing them is a fail-open on a security control: an operator who turned `:enforce` on
  # through the settings row — the documented no-restart kill switch — would have had it
  # silently drop back to `:tofu_warn` for the duration of any SQLite hiccup. That is exactly
  # the incident during which you want it on.
  #
  # So a successful read is remembered, and a failed one reuses the last known answer instead of
  # defaulting. An instance that was never enforcing still does not start refusing connections
  # over an unreadable setting, which is the property the permissive default existed to protect.
  defp mode_from_setting, do: remember(decide_mode(setting(), last_known_mode()))

  @doc """
  The mode implied by a settings read plus the last known answer. Pure, and public so the
  fail-open case is testable without contriving a database failure — which is the point: the
  bug was that `:error` and `{:ok, "tofu_warn"}` took the same branch, and a test that cannot
  tell them apart cannot catch that.
  """
  @spec decide_mode({:ok, term()} | :error, mode()) :: mode()
  def decide_mode({:ok, value}, _last_known) when value in ["enforce", :enforce], do: :enforce
  def decide_mode({:ok, _other}, _last_known), do: @default_mode
  def decide_mode(:error, last_known), do: last_known

  # Written only on CHANGE: `:persistent_term.put/2` triggers a global literal-area GC scan
  # across every process, and this is called on every connect.
  defp remember(mode) do
    if last_known_mode() != mode, do: :persistent_term.put(@mode_term, mode)
    mode
  end

  defp last_known_mode, do: :persistent_term.get(@mode_term, @default_mode)

  # Same reasoning as `Termelix.SSH.Credential.setting/0`: a settings read must never be why a
  # connection fails, and the pooled connector runs in a bare `spawn_link` with no sandbox
  # checkout under test, where `Repo` raises instead of answering. `:error` is distinct from
  # `{:ok, nil}` — see `mode_from_setting/0`.
  defp setting do
    {:ok, Settings.get_value(@setting_key)}
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end

  # --- decision (handshake process; no I/O) ----------------------------------

  @doc """
  The trust decision for one presented host key. `true` accepts; `{:error, reason}` refuses
  (OTP formats the reason into the `SSH_DISCONNECT_KEY_EXCHANGE_FAILED` description at
  ssh_transport.erl:678-681, so it stays a short, secret-free term).

  Never returns `false`: with `silently_accept_hosts: true` OTP reads `false` as "not known
  yet" and accepts anyway through `accepted_host/5` (ssh_transport.erl:1200-1212), which would
  turn a refusal into a silent accept.
  """
  @spec check(term(), term(), term(), term(), pin() | nil) :: true | {:error, term()}
  def check(key, host, port, algorithm, %{host_id: host_id} = pin) when is_integer(host_id) do
    case :ssh_file.encode(key, :ssh2_pubkey) do
      blob when is_binary(blob) ->
        decide(blob, host, port, algorithm, pin)

      other ->
        # A key OTP itself just verified but cannot re-encode: there is no fingerprint to
        # record, so allow rather than make the host unconnectable over an OTP quirk.
        Logger.warning("Host key encode failed for host #{host_id}: #{inspect(other)}")
        true
    end
  end

  # No pin, an empty one (`Credential.empty_host_key/1` for a quick connect), or a shape we do
  # not recognise: allow without recording. There is nothing to compare against.
  def check(_key, _host, _port, _algorithm, _no_pin), do: true

  defp decide(blob, host, port, algorithm, pin) do
    fingerprint = fingerprint(blob)
    status = classify(pin[:fingerprint], blob, fingerprint)
    mode = pin_mode(pin)
    refuse? = status == :changed and mode == :enforce

    observation = %{
      status: status,
      allowed: not refuse?,
      host_id: pin.host_id,
      user_id: pin[:user_id],
      peer: peer_label(host),
      port: port_number(port),
      fingerprint: fingerprint,
      key_type: key_type(blob),
      algorithm: algorithm_name(algorithm),
      previous_fingerprint: pin[:fingerprint],
      previous_key_type: pin[:key_type],
      mode: mode
    }

    dispatch(pin[:recorder], observation)

    if refuse?, do: {:error, {:host_key_changed, pin.host_id}}, else: true
  end

  # `pin/2` resolved the mode against the database up front. A `Credential`-built pin did not,
  # and this runs in the handshake process, so the only other source allowed here is
  # application config — an ETS read, never SQLite. See the moduledoc caveat.
  defp pin_mode(%{mode: mode}) when mode in [:tofu_warn, :enforce], do: mode

  defp pin_mode(_pin) do
    case Application.get_env(:termelix, :ssh_host_key_policy) do
      value when value in ["enforce", :enforce] -> :enforce
      _other -> @default_mode
    end
  end

  # `:first_seen` and `:verified` are the two cheap answers; everything else has to separate
  # "same key, older encoding" from "different key". Only a stored value in a format we
  # recognise can prove a difference — anything else is treated as no pin at all (moduledoc).
  defp classify(stored, blob, canonical) when is_binary(stored) do
    cond do
      String.trim(stored) == "" -> :first_seen
      stored == canonical -> :verified
      legacy_encoding?(stored, blob) -> :repin
      known_encoding?(stored) -> :changed
      true -> :repin
    end
  end

  defp classify(_stored, _blob, _canonical), do: :first_seen

  # The encodings a Termelix (or an upgraded Termix) install can plausibly hold for this key.
  defp legacy_encoding?(stored, blob) do
    cond do
      # The Node reference stored the raw SSH2 wire blob as lowercase hex.
      hex_blob?(stored) -> String.downcase(stored) == Base.encode16(blob, case: :lower)
      String.starts_with?(stored, "MD5:") -> stored == format_fingerprint(:md5, blob)
      String.starts_with?(stored, "SHA1:") -> stored == format_fingerprint(:sha, blob)
      true -> false
    end
  end

  defp known_encoding?(stored) do
    String.starts_with?(stored, "SHA256:") or String.starts_with?(stored, "SHA1:") or
      String.starts_with?(stored, "MD5:") or hex_blob?(stored)
  end

  # 40 hex chars is shorter than any real SSH2 pubkey blob (ed25519, the smallest, is 51 bytes
  # / 102 chars), so the bound only keeps a short opaque string out of this branch.
  defp hex_blob?(value), do: value =~ ~r/\A[0-9a-fA-F]{40,}\z/

  defp fingerprint(blob), do: format_fingerprint(@digest, blob)

  # `:ssh.hostkey_fingerprint/2` (ssh.erl:1184-1215) takes a decoded key and re-encodes it to
  # the wire blob we already hold, so the digest is applied to the blob directly: same bytes,
  # one less encode, and no dependency on the key term surviving a round-trip.
  defp format_fingerprint(:md5, blob) do
    hex = for <<byte <- :crypto.hash(:md5, blob)>>, do: Base.encode16(<<byte>>, case: :lower)
    "MD5:" <> Enum.join(hex, ":")
  end

  defp format_fingerprint(digest, blob) do
    name = if digest == :sha, do: "SHA1", else: digest |> Atom.to_string() |> String.upcase()
    body = digest |> :crypto.hash(blob) |> Base.encode64(padding: false)
    name <> ":" <> body
  end

  # The blob is `string(keytype) || key material` (RFC 4253 §6.6): a 32-bit length then the
  # algorithm name. Same parse as the reference's `getKeyType`.
  defp key_type(<<len::unsigned-big-32, type::binary-size(len), _rest::binary>>)
       when len > 0 and len <= 64 do
    if String.printable?(type), do: type, else: "unknown"
  end

  defp key_type(_blob), do: "unknown"

  # OTP hands `is_host_key/5` the host as `[PeerName, IP]` (ssh_transport.erl:1191) where
  # PeerName is a charlist and IP an `:inet` address tuple (ssh_connection_handler.erl:456-476).
  defp peer_label([first | _rest]) when is_list(first) or is_binary(first) or is_tuple(first),
    do: peer_label(first)

  defp peer_label(host) when is_binary(host), do: host
  defp peer_label(host) when is_list(host), do: List.to_string(host)

  defp peer_label(host) when is_tuple(host) do
    case :inet.ntoa(host) do
      address when is_list(address) -> List.to_string(address)
      _error -> "unknown"
    end
  end

  defp peer_label(_host), do: "unknown"

  defp port_number(port) when is_integer(port) and port > 0, do: port
  defp port_number(_port), do: 0

  defp algorithm_name(algorithm) when is_atom(algorithm) and not is_nil(algorithm),
    do: Atom.to_string(algorithm)

  defp algorithm_name(algorithm) when is_binary(algorithm), do: algorithm
  defp algorithm_name(algorithm) when is_list(algorithm), do: List.to_string(algorithm)
  defp algorithm_name(_algorithm), do: "unknown"

  # --- recording (owner process; touches the DB) -----------------------------

  # Never the handshake process: `Termelix.TaskSupervisor` owns the write. A pid recorder
  # short-circuits that for tests and for call sites that own their writes. Every failure is
  # swallowed — a lost audit row must not cost a connection.
  defp dispatch(recorder, observation) when is_pid(recorder) do
    send(recorder, {:host_key_observation, observation})
    :ok
  end

  defp dispatch(_recorder, observation) do
    case Process.whereis(Termelix.TaskSupervisor) do
      nil -> :ok
      _pid -> Task.Supervisor.start_child(Termelix.TaskSupervisor, fn -> record(observation) end)
    end

    :ok
  catch
    kind, reason ->
      Logger.warning("Host key observation dropped: #{inspect(kind)} #{inspect(reason)}")
      :ok
  end

  @doc """
  Apply one observation: update the host's `host_key_*` columns and, for anything but a plain
  verify, write the audit row. Runs in the owner process, never in the handshake. Never
  raises.

  The changed counter and the audit row's user/host names are read here rather than carried in
  the pin, so the pin stays exactly the shape `Termelix.SSH.Credential` already builds.
  """
  @spec record(observation()) :: :ok
  def record(%{status: :first_seen} = observation) do
    # Guarded on the column still being empty. A `:first_seen` observation only says "the pin
    # we were handed was blank", and not every call site fills one in —
    # `Termelix.SSH.Credential.empty_host_key/1` builds `fingerprint: nil` for any conn_opts map
    # that carries a `host_id` but no `host_key`. Overwriting a stored pin from one of those
    # would silently re-trust whatever key was presented, which is the exact failure this module
    # exists to catch. Losing the race against a genuine concurrent first contact costs one
    # warning and nothing else.
    if write_pin(observation, first_seen?: true, only_unpinned?: true) > 0 do
      audit(observation, "host_key_pinned")
    else
      Logger.warning(
        "Host key first contact for host #{observation.host_id} was not recorded: the row is " <>
          "already pinned (the pin handed to the callback was incomplete, so the connection " <>
          "was not checked against it), or the write failed — see any preceding warning."
      )

      :ok
    end
  end

  # A successful handshake is the overwhelmingly common case, and this used to issue a SQLite
  # UPDATE on every single one — turning a read-only connect path into a write path on a
  # single-writer database that also serves every request. `hostKeyLastVerified` is an
  # operator-facing "when did we last see this key" timestamp, not an audit record, so
  # second-level precision buys nothing: touch it at most once per `@verify_touch_interval_ms`
  # and skip the write entirely in between. A host connected to in a loop now writes hourly
  # rather than per connect.
  def record(%{status: :verified} = observation) do
    if stale_verification?(observation.host_id) do
      update_columns(observation.host_id, hostKeyLastVerified: now())
    end

    :ok
  end

  def record(%{status: :repin} = observation) do
    # Same key in a different encoding (or one we cannot read): rewrite it in place and keep
    # `host_key_first_seen` — the host was first seen when it was first seen. Unguarded, unlike
    # `:first_seen`: this status is only reachable from a pin that *did* carry a stored value.
    write_pin(observation, first_seen?: false)
    audit(observation, "host_key_repinned")
  end

  def record(%{status: :changed} = observation) do
    changed_count = changed_count(observation.host_id) + 1

    if observation.allowed do
      # tofu_warn: re-pin, so the next connection is a plain verify and the trail holds one row
      # per rotation instead of one per connection.
      write_pin(observation, first_seen?: false, changed_count: changed_count)
    else
      # enforce: count and audit the attempt, but leave the pin alone — re-pinning here would
      # trust the presented key on the very next handshake.
      update_columns(observation.host_id, hostKeyChangedCount: changed_count)
    end

    audit(observation, "host_key_changed")
  end

  def record(_observation), do: :ok

  defp write_pin(observation, opts) do
    columns =
      [
        hostKeyFingerprint: observation.fingerprint,
        hostKeyType: observation.key_type,
        hostKeyAlgorithm: @digest_name,
        hostKeyLastVerified: now()
      ]
      |> maybe_put(:hostKeyFirstSeen, opts[:first_seen?] && now())
      |> maybe_put(:hostKeyChangedCount, opts[:changed_count])

    update_columns(observation.host_id, columns, opts)
  end

  defp maybe_put(columns, _key, nil), do: columns
  defp maybe_put(columns, _key, false), do: columns
  defp maybe_put(columns, key, value), do: Keyword.put(columns, key, value)

  # Read-then-set rather than Ecto's `inc:`: the column is nullable, and SQLite's NULL + 1 is
  # NULL, which would erase the counter the first time a legacy row rotated its key.
  defp changed_count(host_id) do
    Repo.one(from(h in Host, where: h.id == ^host_id, select: h.hostKeyChangedCount)) || 0
  rescue
    _error -> 0
  end

  # Returns the number of rows written, which is how `record/1` tells a real first contact from
  # a stale one (`opts[:only_unpinned?]`).
  defp stale_verification?(host_id) do
    case Repo.one(from(h in Host, where: h.id == ^host_id, select: h.hostKeyLastVerified)) do
      nil ->
        true

      stamp ->
        case DateTime.from_iso8601(stamp) do
          {:ok, at, _} ->
            DateTime.diff(DateTime.utc_now(), at, :millisecond) >= @verify_touch_interval_ms

          # An unparseable stamp is exactly the thing worth rewriting.
          _ ->
            true
        end
    end
  rescue
    _ -> false
  end

  defp update_columns(host_id, columns, opts \\ []) do
    query = from(h in Host, where: h.id == ^host_id)

    query =
      if opts[:only_unpinned?],
        do: from(h in query, where: is_nil(h.hostKeyFingerprint) or h.hostKeyFingerprint == ""),
        else: query

    {count, _returning} = Repo.update_all(query, set: columns)
    count
  rescue
    error ->
      Logger.warning("Host key column update failed for host #{host_id}: #{safe(error)}")
      0
  end

  defp audit(observation, action) do
    Audit.record(%{
      userId: observation.user_id,
      username: username(observation.user_id) || observation.user_id,
      action: action,
      resourceType: "host",
      resourceId: to_string(observation.host_id),
      resourceName: host_label(observation.host_id),
      details:
        Jason.encode!(%{
          peer: observation.peer,
          port: observation.port,
          fingerprint: observation.fingerprint,
          keyType: observation.key_type,
          previousFingerprint: observation.previous_fingerprint,
          previousKeyType: observation.previous_key_type,
          negotiatedAlgorithm: observation.algorithm,
          mode: observation.mode,
          allowed: observation.allowed
        }),
      success: observation.allowed
    })

    :ok
  rescue
    error ->
      Logger.warning("Host key audit write failed: #{safe(error)}")
      :ok
  end

  defp username(nil), do: nil

  defp username(user_id) do
    Repo.one(from(u in User, where: u.id == ^user_id, select: u.username))
  rescue
    _error -> nil
  end

  defp host_label(host_id) do
    Repo.one(from(h in Host, where: h.id == ^host_id, select: h.name))
  rescue
    _error -> nil
  end

  defp now, do: DateTime.utc_now() |> DateTime.to_iso8601()

  # The exception's type and message only. The `:key_cb` options that reach this module's
  # callers carry the decrypted private key and its passphrase; nothing derived from them may
  # reach a log line, and `inspect/1` on an arbitrary term is not a promise we can keep.
  defp safe(%{__struct__: module} = error), do: "#{inspect(module)}: #{Exception.message(error)}"
end
