defmodule Termelix.Repo.Migrations.AddQueryIndexes do
  @moduledoc """
  Secondary indexes matching the actual query shapes of the per-user repositories
  (listings scoped by `user_id`, per-(user, host) lookups), plus the unique constraints
  that were always logically true but never enforced:

    * `users(username)` — registration rejects duplicate usernames; the index turns the
      check-then-insert race into a constraint error.
    * `user_roles(user_id, role_id)` — the RBAC assign path treats a duplicate (user, role)
      as "already assigned" (409).
    * `dismissed_alerts(user_id, alert_id)` — dismissing the same alert twice is a 409.

  Everything is emitted as raw DDL with `IF NOT EXISTS` so the migration is idempotent and
  composes safely with migrations added by parallel workstreams. No unique index is added to
  `file_manager_*` or `host_access`: existing databases may legitimately carry duplicates
  there, and the application already resolves them at read/upsert time.

  Because these constraints never existed before, a database upgraded from an older Termelix
  may already hold rows that violate them. `ecto_sqlite3` runs each migration inside a DDL
  transaction, so a `CREATE UNIQUE INDEX` that hits a pre-existing duplicate would raise an
  opaque SQLite error, roll the whole migration back (losing the plain indexes too), and
  abort boot. Each unique index is therefore preceded by a guard:

    * `user_roles` / `dismissed_alerts` — a duplicate row is pure redundancy, so we collapse
      each group to its lowest `rowid` before creating the index. A legacy database
      reconciles itself instead of failing.
    * `users(username)` — collapsing here would silently merge distinct accounts (each owns
      its own hosts, credentials, and sessions), so we refuse: a preflight raises a clear
      Elixir error naming the offending usernames, telling the operator to resolve them
      before upgrading. Matching stays BINARY (case-sensitive), consistent with the app's
      existing username lookups — switching to NOCASE would change authentication semantics.
  """
  use Ecto.Migration

  # {index_name, ddl} pairs — the name list doubles as the rollback manifest.
  @plain_indexes [
    {"idx_command_history_user_host",
     "CREATE INDEX IF NOT EXISTS idx_command_history_user_host ON command_history(user_id, host_id)"},
    {"idx_recent_activity_user_ts",
     "CREATE INDEX IF NOT EXISTS idx_recent_activity_user_ts ON recent_activity(user_id, timestamp)"},
    {"idx_file_manager_recent_user_host",
     "CREATE INDEX IF NOT EXISTS idx_file_manager_recent_user_host ON file_manager_recent(user_id, host_id)"},
    {"idx_file_manager_pinned_user_host",
     "CREATE INDEX IF NOT EXISTS idx_file_manager_pinned_user_host ON file_manager_pinned(user_id, host_id)"},
    {"idx_file_manager_shortcuts_user_host",
     "CREATE INDEX IF NOT EXISTS idx_file_manager_shortcuts_user_host ON file_manager_shortcuts(user_id, host_id)"},
    {"idx_user_open_tabs_user",
     "CREATE INDEX IF NOT EXISTS idx_user_open_tabs_user ON user_open_tabs(user_id)"},
    {"idx_snippets_user", "CREATE INDEX IF NOT EXISTS idx_snippets_user ON snippets(user_id)"},
    {"idx_ssh_folders_user",
     "CREATE INDEX IF NOT EXISTS idx_ssh_folders_user ON ssh_folders(user_id)"},
    {"idx_ssh_credentials_user",
     "CREATE INDEX IF NOT EXISTS idx_ssh_credentials_user ON ssh_credentials(user_id)"},
    {"idx_homepage_items_user",
     "CREATE INDEX IF NOT EXISTS idx_homepage_items_user ON homepage_items(user_id)"},
    {"idx_network_topology_user",
     "CREATE INDEX IF NOT EXISTS idx_network_topology_user ON network_topology(user_id)"},
    {"idx_dashboard_service_links_user",
     "CREATE INDEX IF NOT EXISTS idx_dashboard_service_links_user ON dashboard_service_links(user_id)"},
    {"idx_tmux_session_tags_user_host",
     "CREATE INDEX IF NOT EXISTS idx_tmux_session_tags_user_host ON tmux_session_tags(user_id, host_id)"},
    {"idx_ssh_credential_usage_credential",
     "CREATE INDEX IF NOT EXISTS idx_ssh_credential_usage_credential ON ssh_credential_usage(credential_id)"}
  ]

  # Each unique index carries the guard that makes it safe against a pre-existing violation.
  # `:dedup` runs a DELETE that keeps the lowest rowid per group; `:preflight_usernames`
  # runs the raising duplicate-username check. The guard is applied immediately before the
  # matching CREATE, and the name list doubles as the rollback manifest.
  @unique_indexes [
    %{
      name: "idx_user_roles_user_role_unique",
      guard:
        {:dedup,
         "DELETE FROM user_roles WHERE rowid NOT IN (SELECT MIN(rowid) FROM user_roles GROUP BY user_id, role_id)"},
      ddl:
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_user_roles_user_role_unique ON user_roles(user_id, role_id)"
    },
    %{
      name: "idx_dismissed_alerts_user_alert_unique",
      guard:
        {:dedup,
         "DELETE FROM dismissed_alerts WHERE rowid NOT IN (SELECT MIN(rowid) FROM dismissed_alerts GROUP BY user_id, alert_id)"},
      ddl:
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_dismissed_alerts_user_alert_unique ON dismissed_alerts(user_id, alert_id)"
    },
    %{
      name: "idx_users_username_unique",
      guard: :preflight_usernames,
      ddl: "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_unique ON users(username)"
    }
  ]

  # BINARY (case-sensitive) match, consistent with the app's existing username lookups.
  @duplicate_usernames_query "SELECT username, COUNT(*) AS c FROM users GROUP BY username HAVING c > 1 ORDER BY username"

  def up do
    Enum.each(@plain_indexes, fn {_name, ddl} -> execute(ddl) end)

    Enum.each(@unique_indexes, fn %{guard: guard, ddl: ddl} ->
      apply_guard(guard)
      execute(ddl)
    end)
  end

  def down do
    index_names =
      Enum.map(@plain_indexes, fn {name, _ddl} -> name end) ++
        Enum.map(@unique_indexes, & &1.name)

    Enum.each(index_names, fn name -> execute("DROP INDEX IF EXISTS #{name}") end)
  end

  defp apply_guard({:dedup, sql}), do: execute(sql)
  defp apply_guard(:preflight_usernames), do: preflight_unique_usernames!(repo())

  @doc """
  Raises with an actionable, operator-facing message if any username is held by more than one
  account; otherwise returns `:ok`. Exposed so migration tests can drive the real check.
  """
  def preflight_unique_usernames!(repo) do
    case repo.query!(@duplicate_usernames_query, []) do
      %{rows: []} ->
        :ok

      %{rows: rows} ->
        usernames = Enum.map_join(rows, ", ", fn [username | _] -> username end)

        raise """
        Cannot enforce the users(username) unique index: #{length(rows)} username(s) are held \
        by more than one account: #{usernames}.

        This database predates username uniqueness enforcement and now contains duplicate \
        accounts. They cannot be merged automatically — each account owns its own hosts, \
        credentials, and sessions — so resolve the duplicates by renaming or removing the \
        extra accounts, then re-run the upgrade.
        """
    end
  end

  # Exposed for migration tests: the exact statements this migration ships.
  @doc false
  def unique_indexes, do: @unique_indexes
  @doc false
  def duplicate_usernames_query, do: @duplicate_usernames_query
end
