defmodule Termelix.Repo.Migrations.CreateInitialSchema do
  @moduledoc """
  Faithful port of the Termelix drizzle schema (`src/backend/database/db/schema.ts`,
  v2.5.1) to SQLite DDL. Column names, types, defaults, and foreign keys mirror the
  original so the port is data-compatible with an existing Termelix database.

  Booleans are stored as INTEGER (0/1); timestamps are stored as TEXT defaulting to
  CURRENT_TIMESTAMP, exactly as the original schema does. SQLite permits forward
  foreign-key references at CREATE TABLE time, so table order here is irrelevant.
  """
  use Ecto.Migration

  # Raw DDL keeps us byte-faithful to the original schema instead of routing through
  # Ecto's opinionated `create table` defaults (auto id, inserted_at/updated_at, etc.).
  @tables [
    """
    CREATE TABLE users (
      id TEXT PRIMARY KEY NOT NULL,
      username TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      is_oidc INTEGER NOT NULL DEFAULT 0,
      oidc_identifier TEXT,
      sso_provider_id INTEGER,
      client_id TEXT,
      client_secret TEXT,
      issuer_url TEXT,
      authorization_url TEXT,
      token_url TEXT,
      identifier_path TEXT,
      name_path TEXT,
      scopes TEXT DEFAULT 'openid email profile',
      totp_secret TEXT,
      totp_enabled INTEGER NOT NULL DEFAULT 0,
      totp_backup_codes TEXT,
      registered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      donation_modal_dismissed INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE settings (
      key TEXT PRIMARY KEY NOT NULL,
      value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE sso_providers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      display_order INTEGER NOT NULL DEFAULT 0,
      config TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE sessions (
      id TEXT PRIMARY KEY NOT NULL,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      jwt_token TEXT NOT NULL,
      device_type TEXT NOT NULL,
      device_info TEXT NOT NULL,
      oidc_sub TEXT,
      oidc_sid TEXT,
      sso_provider_id INTEGER,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      expires_at TEXT NOT NULL,
      last_active_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE trusted_devices (
      id TEXT PRIMARY KEY NOT NULL,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      device_fingerprint TEXT NOT NULL,
      device_type TEXT NOT NULL,
      device_info TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      expires_at TEXT NOT NULL,
      last_used_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE webauthn_credentials (
      id TEXT PRIMARY KEY NOT NULL,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      credential_id TEXT NOT NULL,
      public_key TEXT NOT NULL,
      counter INTEGER NOT NULL DEFAULT 0,
      device_type TEXT,
      backed_up INTEGER NOT NULL DEFAULT 0,
      transports TEXT,
      user_verification TEXT NOT NULL DEFAULT 'preferred',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_used_at TEXT
    )
    """,
    """
    CREATE TABLE ssh_data (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      connection_type TEXT NOT NULL DEFAULT 'ssh',
      name TEXT,
      ip TEXT NOT NULL,
      port INTEGER NOT NULL,
      username TEXT NOT NULL,
      folder TEXT,
      tags TEXT,
      pin INTEGER NOT NULL DEFAULT 0,
      auth_type TEXT NOT NULL,
      use_warpgate INTEGER NOT NULL DEFAULT 0,
      force_keyboard_interactive TEXT,
      password TEXT,
      key TEXT,
      key_password TEXT,
      key_type TEXT,
      sudo_password TEXT,
      autostart_password TEXT,
      autostart_key TEXT,
      autostart_key_password TEXT,
      credential_id INTEGER REFERENCES ssh_credentials(id) ON DELETE SET NULL,
      override_credential_username INTEGER,
      vault_profile_id INTEGER REFERENCES vault_profiles(id) ON DELETE SET NULL,
      enable_terminal INTEGER NOT NULL DEFAULT 1,
      enable_session_logging INTEGER NOT NULL DEFAULT 1,
      enable_command_history INTEGER NOT NULL DEFAULT 1,
      enable_tunnel INTEGER NOT NULL DEFAULT 1,
      tunnel_connections TEXT,
      jump_hosts TEXT,
      enable_file_manager INTEGER NOT NULL DEFAULT 1,
      scp_legacy INTEGER NOT NULL DEFAULT 0,
      enable_docker INTEGER NOT NULL DEFAULT 0,
      enable_tmux_monitor INTEGER NOT NULL DEFAULT 0,
      show_terminal_in_sidebar INTEGER NOT NULL DEFAULT 1,
      show_file_manager_in_sidebar INTEGER NOT NULL DEFAULT 0,
      show_tunnel_in_sidebar INTEGER NOT NULL DEFAULT 0,
      show_docker_in_sidebar INTEGER NOT NULL DEFAULT 0,
      show_server_stats_in_sidebar INTEGER NOT NULL DEFAULT 0,
      default_path TEXT,
      stats_config TEXT,
      docker_config TEXT,
      enable_proxmox INTEGER NOT NULL DEFAULT 0,
      proxmox_config TEXT,
      terminal_config TEXT,
      quick_actions TEXT,
      notes TEXT,
      enable_ssh INTEGER NOT NULL DEFAULT 1,
      enable_rdp INTEGER NOT NULL DEFAULT 0,
      enable_vnc INTEGER NOT NULL DEFAULT 0,
      enable_telnet INTEGER NOT NULL DEFAULT 0,
      ssh_port INTEGER DEFAULT 22,
      rdp_port INTEGER DEFAULT 3389,
      vnc_port INTEGER DEFAULT 5900,
      telnet_port INTEGER DEFAULT 23,
      rdp_credential_id INTEGER REFERENCES ssh_credentials(id) ON DELETE SET NULL,
      rdp_user TEXT,
      rdp_password TEXT,
      rdp_domain TEXT,
      rdp_security TEXT,
      rdp_ignore_cert INTEGER DEFAULT 0,
      vnc_credential_id INTEGER REFERENCES ssh_credentials(id) ON DELETE SET NULL,
      vnc_password TEXT,
      vnc_user TEXT,
      telnet_user TEXT,
      telnet_password TEXT,
      telnet_credential_id INTEGER REFERENCES ssh_credentials(id) ON DELETE SET NULL,
      rdp_auth_type TEXT,
      vnc_auth_type TEXT,
      telnet_auth_type TEXT,
      domain TEXT,
      security TEXT,
      ignore_cert INTEGER DEFAULT 0,
      guacamole_config TEXT,
      use_socks5 INTEGER,
      socks5_host TEXT,
      socks5_port INTEGER,
      socks5_username TEXT,
      socks5_password TEXT,
      socks5_proxy_chain TEXT,
      mac_address TEXT,
      wol_broadcast_address TEXT,
      port_knock_sequence TEXT,
      host_key_fingerprint TEXT,
      host_key_type TEXT,
      host_key_algorithm TEXT DEFAULT 'sha256',
      host_key_first_seen TEXT,
      host_key_last_verified TEXT,
      host_key_changed_count INTEGER DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE file_manager_recent (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      host_id INTEGER NOT NULL REFERENCES ssh_data(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      path TEXT NOT NULL,
      last_opened TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE file_manager_pinned (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      host_id INTEGER NOT NULL REFERENCES ssh_data(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      path TEXT NOT NULL,
      pinned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE file_manager_shortcuts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      host_id INTEGER NOT NULL REFERENCES ssh_data(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      path TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE transfer_recent (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      source_host_id INTEGER NOT NULL REFERENCES ssh_data(id) ON DELETE CASCADE,
      dest_host_id INTEGER NOT NULL REFERENCES ssh_data(id) ON DELETE CASCADE,
      dest_path TEXT NOT NULL,
      dest_path_label TEXT NOT NULL,
      last_used TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE dismissed_alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      alert_id TEXT NOT NULL,
      dismissed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE ssh_credentials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      description TEXT,
      folder TEXT,
      tags TEXT,
      auth_type TEXT NOT NULL,
      username TEXT,
      password TEXT,
      key TEXT,
      private_key TEXT,
      public_key TEXT,
      key_password TEXT,
      key_type TEXT,
      detected_key_type TEXT,
      cert_public_key TEXT,
      usage_count INTEGER NOT NULL DEFAULT 0,
      last_used TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE ssh_credential_usage (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      credential_id INTEGER NOT NULL REFERENCES ssh_credentials(id) ON DELETE CASCADE,
      host_id INTEGER NOT NULL REFERENCES ssh_data(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      used_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE snippets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      content TEXT NOT NULL,
      description TEXT,
      folder TEXT,
      "order" INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      host_filter TEXT
    )
    """,
    """
    CREATE TABLE snippet_folders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      color TEXT,
      icon TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE c2s_tunnel_presets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      config TEXT NOT NULL,
      platform TEXT,
      computer_name TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE snippet_access (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      snippet_id INTEGER NOT NULL REFERENCES snippets(id) ON DELETE CASCADE,
      user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
      role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
      granted_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      permission_level TEXT NOT NULL DEFAULT 'view',
      expires_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE ssh_folders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      color TEXT,
      icon TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE recent_activity (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      host_id INTEGER NOT NULL REFERENCES ssh_data(id) ON DELETE CASCADE,
      host_name TEXT,
      timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE command_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      host_id INTEGER NOT NULL REFERENCES ssh_data(id) ON DELETE CASCADE,
      command TEXT NOT NULL,
      executed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE network_topology (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      topology TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE host_access (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      host_id INTEGER NOT NULL REFERENCES ssh_data(id) ON DELETE CASCADE,
      user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
      role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
      granted_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      permission_level TEXT NOT NULL DEFAULT 'connect',
      expires_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_accessed_at TEXT,
      access_count INTEGER NOT NULL DEFAULT 0,
      override_credential_id INTEGER REFERENCES ssh_credentials(id) ON DELETE SET NULL
    )
    """,
    """
    CREATE TABLE shared_host_secrets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      host_access_id INTEGER NOT NULL REFERENCES host_access(id) ON DELETE CASCADE,
      target_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      protocol TEXT NOT NULL DEFAULT 'ssh',
      source_type TEXT NOT NULL DEFAULT 'credential',
      original_credential_id INTEGER REFERENCES ssh_credentials(id) ON DELETE CASCADE,
      encrypted_username TEXT,
      encrypted_auth_type TEXT,
      encrypted_password TEXT,
      encrypted_key TEXT,
      encrypted_key_password TEXT,
      encrypted_key_type TEXT,
      encrypted_domain TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      description TEXT,
      is_system INTEGER NOT NULL DEFAULT 0,
      permissions TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE user_roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
      granted_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      granted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      username TEXT NOT NULL,
      action TEXT NOT NULL,
      resource_type TEXT NOT NULL,
      resource_id TEXT,
      resource_name TEXT,
      details TEXT,
      ip_address TEXT,
      user_agent TEXT,
      success INTEGER NOT NULL,
      error_message TEXT,
      timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE session_recordings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      host_id INTEGER NOT NULL REFERENCES ssh_data(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      access_id INTEGER REFERENCES host_access(id) ON DELETE SET NULL,
      started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      ended_at TEXT,
      duration INTEGER,
      commands TEXT,
      dangerous_actions TEXT,
      recording_path TEXT,
      protocol TEXT NOT NULL DEFAULT 'ssh',
      format TEXT NOT NULL DEFAULT 'text',
      terminated_by_owner INTEGER DEFAULT 0,
      termination_reason TEXT
    )
    """,
    """
    CREATE TABLE opkssh_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      host_id INTEGER NOT NULL REFERENCES ssh_data(id) ON DELETE CASCADE,
      ssh_cert TEXT NOT NULL,
      private_key TEXT NOT NULL,
      email TEXT,
      sub TEXT,
      issuer TEXT,
      audience TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      expires_at TEXT NOT NULL,
      last_used TEXT
    )
    """,
    """
    CREATE TABLE vault_profiles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      description TEXT,
      folder TEXT,
      tags TEXT,
      vault_addr TEXT NOT NULL,
      vault_namespace TEXT,
      oidc_mount TEXT,
      oidc_role TEXT,
      ssh_mount TEXT,
      ssh_role TEXT NOT NULL,
      valid_principals TEXT,
      key_type TEXT,
      shared INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE vault_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      profile_id INTEGER NOT NULL REFERENCES vault_profiles(id) ON DELETE CASCADE,
      ssh_cert TEXT NOT NULL,
      private_key TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      expires_at TEXT NOT NULL,
      last_used TEXT
    )
    """,
    """
    CREATE TABLE api_keys (
      id TEXT PRIMARY KEY NOT NULL,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      token_hash TEXT NOT NULL,
      token_prefix TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      expires_at TEXT,
      last_used_at TEXT,
      is_active INTEGER NOT NULL DEFAULT 1
    )
    """,
    """
    CREATE TABLE user_open_tabs (
      id TEXT PRIMARY KEY NOT NULL,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      tab_type TEXT NOT NULL,
      host_id INTEGER REFERENCES ssh_data(id) ON DELETE CASCADE,
      label TEXT NOT NULL,
      tab_order INTEGER NOT NULL DEFAULT 0,
      backend_session_id TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE user_preferences (
      user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reopen_tabs_on_login INTEGER NOT NULL DEFAULT 0,
      theme TEXT,
      font_size TEXT,
      accent_color TEXT,
      language TEXT,
      storage_mode TEXT,
      command_autocomplete INTEGER,
      command_palette_enabled INTEGER,
      show_host_tags INTEGER,
      host_tray_on_click INTEGER,
      pin_app_rail INTEGER,
      expand_app_rail_on_hover INTEGER,
      folders_collapsed INTEGER,
      confirm_snippet_execution INTEGER,
      disable_update_check INTEGER,
      confirm_tab_close INTEGER,
      hidden_rail_tabs TEXT,
      compact_host_view INTEGER,
      status_color_scheme TEXT,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE host_metrics_preferences (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      host_id INTEGER NOT NULL REFERENCES ssh_data(id) ON DELETE CASCADE,
      layout TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE host_health_checks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      host_id INTEGER NOT NULL REFERENCES ssh_data(id) ON DELETE CASCADE,
      checks TEXT NOT NULL,
      interval_seconds INTEGER NOT NULL DEFAULT 300,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE host_health_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      host_id INTEGER NOT NULL REFERENCES ssh_data(id) ON DELETE CASCADE,
      check_id TEXT NOT NULL,
      ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      ok INTEGER NOT NULL,
      latency_ms INTEGER,
      detail TEXT
    )
    """,
    """
    CREATE TABLE dashboard_service_links (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      label TEXT NOT NULL,
      url TEXT NOT NULL,
      "order" INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE termix_identities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      handle TEXT NOT NULL UNIQUE,
      description TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE termix_identity_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      identity_id INTEGER NOT NULL REFERENCES termix_identities(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      public_key TEXT NOT NULL,
      key_type TEXT NOT NULL,
      algorithm TEXT NOT NULL,
      label TEXT,
      comment TEXT,
      source TEXT NOT NULL DEFAULT 'manual',
      credential_id INTEGER REFERENCES ssh_credentials(id) ON DELETE SET NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE termix_identity_ca (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      identity_id INTEGER NOT NULL UNIQUE REFERENCES termix_identities(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      public_key TEXT NOT NULL,
      private_key TEXT NOT NULL,
      validity_days INTEGER NOT NULL DEFAULT 90,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE tmux_session_tags (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      host_id INTEGER NOT NULL REFERENCES ssh_data(id) ON DELETE CASCADE,
      session_name TEXT NOT NULL,
      tag TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE host_metrics_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      host_id INTEGER NOT NULL REFERENCES ssh_data(id) ON DELETE CASCADE,
      ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      cpu_percent REAL,
      mem_percent REAL,
      disk_percent REAL,
      net_rx_bytes INTEGER,
      net_tx_bytes INTEGER
    )
    """,
    """
    CREATE TABLE alert_rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      host_id INTEGER REFERENCES ssh_data(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      trigger_type TEXT NOT NULL,
      threshold_value REAL,
      threshold_duration_seconds INTEGER,
      cooldown_minutes INTEGER NOT NULL DEFAULT 15,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE notification_channels (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      config TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE alert_rule_channels (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      rule_id INTEGER NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
      channel_id INTEGER NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE alert_firings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      rule_id INTEGER NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
      host_id INTEGER NOT NULL,
      host_name TEXT NOT NULL,
      fired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      resolved_at TEXT,
      value REAL,
      message TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'warning',
      acknowledged INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE homepage_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type_id TEXT NOT NULL,
      title TEXT,
      config TEXT NOT NULL DEFAULT '{}',
      folder_id INTEGER,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE homepage_layouts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      layout TEXT NOT NULL DEFAULT '{}',
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """
  ]

  @indexes [
    "CREATE UNIQUE INDEX idx_host_metrics_prefs_user_host ON host_metrics_preferences(user_id, host_id)",
    "CREATE UNIQUE INDEX idx_host_health_checks_user_host ON host_health_checks(user_id, host_id)",
    "CREATE INDEX idx_host_health_history_lookup ON host_health_history(user_id, host_id, check_id, ts)",
    "CREATE UNIQUE INDEX idx_termix_identities_user ON termix_identities(user_id)",
    "CREATE INDEX idx_termix_identity_keys_identity ON termix_identity_keys(identity_id)",
    "CREATE INDEX idx_host_metrics_history_host_ts ON host_metrics_history(host_id, ts)",
    "CREATE INDEX idx_audit_logs_user_ts ON audit_logs(user_id, timestamp)",
    "CREATE INDEX idx_sessions_user ON sessions(user_id)",
    "CREATE INDEX idx_ssh_data_user ON ssh_data(user_id)",
    "CREATE INDEX idx_host_access_host ON host_access(host_id)",
    "CREATE INDEX idx_host_access_user ON host_access(user_id)"
  ]

  # Tables/indexes are dropped in reverse dependency order on rollback.
  @table_names ~w(
    homepage_layouts homepage_items alert_firings alert_rule_channels notification_channels
    alert_rules host_metrics_history tmux_session_tags termix_identity_ca termix_identity_keys
    termix_identities dashboard_service_links host_health_history host_health_checks
    host_metrics_preferences user_preferences user_open_tabs api_keys vault_tokens vault_profiles
    opkssh_tokens session_recordings audit_logs user_roles roles shared_host_secrets host_access
    network_topology command_history recent_activity ssh_folders snippet_access c2s_tunnel_presets
    snippet_folders snippets ssh_credential_usage ssh_credentials dismissed_alerts transfer_recent
    file_manager_shortcuts file_manager_pinned file_manager_recent ssh_data webauthn_credentials
    trusted_devices sessions sso_providers settings users
  )

  def up do
    Enum.each(@tables, &execute/1)
    Enum.each(@indexes, &execute/1)
  end

  def down do
    Enum.each(@table_names, fn t -> execute("DROP TABLE IF EXISTS #{t}") end)
  end
end
