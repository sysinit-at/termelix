defmodule Termelix.Repo.Migrations.AuditUserFkSetNull do
  @moduledoc """
  Rebuild `audit_logs` so `user_id` is nullable with `ON DELETE SET NULL` (SQLite cannot
  alter constraints in place). The original `NOT NULL … ON DELETE CASCADE` erased a user's
  entire audit trail with the account — including error-reporting **consent** rows, which
  must outlive the actor to stay reconstructible. With SET NULL a deleted admin's consent
  rows are anonymized (user id cleared, username kept for audit integrity) instead of
  destroyed; `Termelix.Audit.delete_by_user_id/1` applies the same policy for explicit
  account-data deletion.

  Only the child side is rebuilt (nothing references `audit_logs`), so the copy/drop/rename
  dance is safe under enforced foreign keys.
  """
  use Ecto.Migration

  @columns "id, user_id, username, action, resource_type, resource_id, resource_name, " <>
             "details, ip_address, user_agent, success, error_message, timestamp"

  def up do
    execute("""
    CREATE TABLE audit_logs_new (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
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
    """)

    execute("INSERT INTO audit_logs_new (#{@columns}) SELECT #{@columns} FROM audit_logs")
    execute("DROP TABLE audit_logs")
    execute("ALTER TABLE audit_logs_new RENAME TO audit_logs")
    execute("CREATE INDEX idx_audit_logs_user_ts ON audit_logs(user_id, timestamp)")
  end

  def down do
    execute("""
    CREATE TABLE audit_logs_old (
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
    """)

    # Anonymized rows (NULL user_id) cannot exist under the old NOT NULL constraint.
    execute(
      "INSERT INTO audit_logs_old (#{@columns}) SELECT #{@columns} FROM audit_logs " <>
        "WHERE user_id IS NOT NULL"
    )

    execute("DROP TABLE audit_logs")
    execute("ALTER TABLE audit_logs_old RENAME TO audit_logs")
    execute("CREATE INDEX idx_audit_logs_user_ts ON audit_logs(user_id, timestamp)")
  end
end
