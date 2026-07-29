defmodule Termelix.Schema.Host do
  @moduledoc """
  The `ssh_data` table (called "Host" everywhere in the app). Struct keys use schema.ts
  camelCase; secret fields (password, key, sudoPassword, …) are field-encrypted at rest
  under the owning user's DEK.

  The table still carries the legacy remote-desktop columns (`enable_rdp`, `rdp_*`, `vnc_*`,
  `telnet_*`, `domain`, `security`, `ignore_cert`, `guacamole_config`) from the removed
  Guacamole subsystem. They are deliberately left unmapped — all are nullable or DEFAULTed,
  so inserts that omit them succeed, and existing databases keep opening unmigrated.
  """
  use Ecto.Schema

  import Ecto.Changeset

  @primary_key {:id, :id, autogenerate: true}
  schema "ssh_data" do
    field :userId, :string, source: :user_id
    field :connectionType, :string, source: :connection_type
    field :name, :string
    field :ip, :string
    field :port, :integer
    field :username, :string
    field :folder, :string
    field :tags, :string
    field :pin, :boolean
    field :authType, :string, source: :auth_type
    field :useWarpgate, :boolean, source: :use_warpgate
    field :forceKeyboardInteractive, :string, source: :force_keyboard_interactive
    field :password, :string
    field :key, :string
    field :keyPassword, :string, source: :key_password
    field :keyType, :string, source: :key_type
    field :sudoPassword, :string, source: :sudo_password
    field :autostartPassword, :string, source: :autostart_password
    field :autostartKey, :string, source: :autostart_key
    field :autostartKeyPassword, :string, source: :autostart_key_password
    field :credentialId, :integer, source: :credential_id
    field :overrideCredentialUsername, :boolean, source: :override_credential_username
    field :vaultProfileId, :integer, source: :vault_profile_id
    field :enableTerminal, :boolean, source: :enable_terminal
    field :enableSessionLogging, :boolean, source: :enable_session_logging
    field :enableCommandHistory, :boolean, source: :enable_command_history
    field :enableTunnel, :boolean, source: :enable_tunnel
    field :tunnelConnections, :string, source: :tunnel_connections
    field :jumpHosts, :string, source: :jump_hosts
    field :enableFileManager, :boolean, source: :enable_file_manager
    field :scpLegacy, :boolean, source: :scp_legacy
    # On by default for newly created hosts (Termelix 520) — the monitor is still gated
    # per-host and can be switched off in the host editor.
    field :enableTmuxMonitor, :boolean, source: :enable_tmux_monitor, default: true
    # Whether a terminal on this host runs inside `tmux new-session -A` (making the remote tmux
    # session the session of record, so work survives a redeploy and a human can take it over
    # with `ssh host && tmux attach`). **Tri-state, and no default** — the column is NULL for
    # every existing and newly created row (migration 20260726000001):
    #
    #   * `nil`   — not decided: detect tmux on the host and wrap the shell if it is there.
    #               This is the default-on behaviour, without the lie of claiming the operator
    #               chose it.
    #   * `true`  — always wrap. A host missing tmux then fails loudly rather than silently
    #               opening an unbound shell.
    #   * `false` — never wrap, even where tmux exists.
    #
    # `default: true` would be wrong: it would force tmux onto every host that does not have it.
    # This is deliberately NOT `enableTmuxMonitor`, which means "poll this host for the monitor
    # view" — reusing it would change shell startup for every install running the monitor.
    field :enableTmuxShell, :boolean, source: :enable_tmux_shell
    field :showTerminalInSidebar, :boolean, source: :show_terminal_in_sidebar
    field :showFileManagerInSidebar, :boolean, source: :show_file_manager_in_sidebar
    field :showTunnelInSidebar, :boolean, source: :show_tunnel_in_sidebar
    field :showServerStatsInSidebar, :boolean, source: :show_server_stats_in_sidebar
    field :defaultPath, :string, source: :default_path
    field :statsConfig, :string, source: :stats_config
    field :terminalConfig, :string, source: :terminal_config
    field :quickActions, :string, source: :quick_actions
    field :notes, :string
    field :enableSsh, :boolean, source: :enable_ssh
    field :sshPort, :integer, source: :ssh_port
    field :useSocks5, :boolean, source: :use_socks5
    field :socks5Host, :string, source: :socks5_host
    field :socks5Port, :integer, source: :socks5_port
    field :socks5Username, :string, source: :socks5_username
    field :socks5Password, :string, source: :socks5_password
    field :socks5ProxyChain, :string, source: :socks5_proxy_chain
    field :macAddress, :string, source: :mac_address
    field :wolBroadcastAddress, :string, source: :wol_broadcast_address
    field :portKnockSequence, :string, source: :port_knock_sequence
    field :hostKeyFingerprint, :string, source: :host_key_fingerprint
    field :hostKeyType, :string, source: :host_key_type
    field :hostKeyAlgorithm, :string, source: :host_key_algorithm
    field :hostKeyFirstSeen, :string, source: :host_key_first_seen
    field :hostKeyLastVerified, :string, source: :host_key_last_verified
    field :hostKeyChangedCount, :integer, source: :host_key_changed_count
    field :createdAt, :string, source: :created_at
    field :updatedAt, :string, source: :updated_at
  end

  @doc """
  Changeset for host writes. Casts every column but `id` with `empty_values: []` so an
  explicit `""` round-trips as `""` (the semantics the previous `Ecto.Changeset.change/2`
  writes had), casts give type errors instead of DB crashes, and the `ssh_data` NOT NULL
  columns the routes rely on are validated: non-empty `ip`, `port` within 1..65535, and a
  present `authType`. Secret fields pass through untouched — encryption happens in the
  context, after the row id is known.
  """
  def changeset(host, attrs) do
    cast_fields = __MODULE__.__schema__(:fields) -- [:id]

    host
    |> cast(attrs, cast_fields, empty_values: [])
    |> validate_required([:userId, :ip, :port, :authType])
    |> validate_nonblank(:ip)
    |> validate_number(:port, greater_than: 0, less_than_or_equal_to: 65_535)
  end

  # With `empty_values: []`, validate_required no longer treats "" as missing (Ecto 3.14
  # semantics), so blank-ness is enforced explicitly where the routes require it.
  defp validate_nonblank(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and String.trim(value) == "",
        do: [{field, "can't be blank"}],
        else: []
    end)
  end
end
