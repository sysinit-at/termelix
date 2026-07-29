defmodule Termelix.Repo.Migrations.AddTmuxSessionBinding do
  @moduledoc """
  The durable half of "the remote tmux session is the session of record": a per-host opt-in
  for wrapping the login shell in tmux, and a `terminal_bindings` row that outlives the BEAM.

  Today a terminal lives only in `Termelix.Terminal.Session` (`restart: :temporary`, in-memory
  state), so the ordinary `docker compose up -d` update path destroys every running session and
  the persisted `user_open_tabs.backend_session_id` then points at nothing. A row here records
  *which tmux session on which host* a user was attached to, so a fresh BEAM can re-attach — and
  so a human can take the same session over out-of-band with `ssh host && tmux attach`.

  Two additions, both additive (no existing column is dropped or rewritten — this migration runs
  unattended at container boot, see `lib/termelix/application.ex`):

    * `ssh_data.enable_tmux_shell` — a **new** column, deliberately not a reuse of
      `enable_tmux_monitor`. That one means "poll this host for the monitor view"; overloading it
      would silently change shell startup on every install that has the monitor switched on.
      It is left NULL for every existing and new row: NULL is the tri-state "not decided —
      detect tmux and use it if present" (see `Termelix.Schema.Host`), so no host without tmux
      is forced into `tmux new-session -A` by an upgrade.

    * `terminal_bindings` — one row per (user, host, tmux session name). The UNIQUE index is
      what makes `Termelix.Terminal.Bindings.upsert/3` a real upsert rather than a
      check-then-insert race; the `user_id` index serves the per-user listing. Both FKs cascade:
      a binding is meaningless once its user or host is gone, and `guacamole`-era experience says
      orphan rows outlive the feature that created them.

  Reversible, unlike the initial schema: `down/0` drops what `up/0` added. Dropping the column
  needs SQLite >= 3.35 (2021); exqlite 0.39 bundles far newer.
  """
  use Ecto.Migration

  @column "enable_tmux_shell"

  def up do
    add_enable_tmux_shell()

    # No DEFAULT on `last_attached_at`: a binding that has never been attached should say so
    # rather than claim its creation time. `created_at` keeps the CURRENT_TIMESTAMP default
    # every other table here has, as a backstop — the context always writes ISO-8601 UTC.
    execute("""
    CREATE TABLE IF NOT EXISTS terminal_bindings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      host_id INTEGER NOT NULL REFERENCES ssh_data(id) ON DELETE CASCADE,
      tmux_session_name TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_attached_at TEXT
    )
    """)

    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_terminal_bindings_user_host_session
      ON terminal_bindings(user_id, host_id, tmux_session_name)
    """)

    execute("""
    CREATE INDEX IF NOT EXISTS idx_terminal_bindings_user ON terminal_bindings(user_id)
    """)
  end

  def down do
    execute("DROP INDEX IF EXISTS idx_terminal_bindings_user")
    execute("DROP INDEX IF EXISTS idx_terminal_bindings_user_host_session")
    execute("DROP TABLE IF EXISTS terminal_bindings")

    if column_exists?(), do: execute("ALTER TABLE ssh_data DROP COLUMN #{@column}")
  end

  # INTEGER, not BOOLEAN: `ecto_sqlite3` dumps booleans to 0/1 and decodes NULL back to `nil`
  # (`Ecto.Adapters.SQLite3.Codec.bool_encode/1`), which is exactly the tri-state this needs.
  defp add_enable_tmux_shell do
    if not column_exists?() do
      execute("ALTER TABLE ssh_data ADD COLUMN #{@column} INTEGER")
    end
  end

  # SQLite has no `ADD COLUMN IF NOT EXISTS`, and a duplicate-column error inside the boot-time
  # `{Ecto.Migrator, ...}` child aborts startup with no operator at the keyboard, so the column
  # is probed first — the same "make it safe against the database you actually find" stance as
  # the guards in `20260723190712_add_query_indexes.exs`.
  defp column_exists? do
    %{rows: rows} = repo().query!("PRAGMA table_info(ssh_data)", [])
    Enum.any?(rows, fn [_cid, name | _rest] -> name == @column end)
  end
end
