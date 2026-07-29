defmodule Termelix.Repo.Migrations.CreateApiKeys do
  @moduledoc """
  Scope the EXISTING `api_keys` table, rather than creating a second one.

  `api_keys` already ships from the Node port (`20260723000001`, `id TEXT PRIMARY KEY`,
  `token_hash`, `token_prefix`, `is_active`) — it simply has no code behind it. Adding a
  parallel table with the same name is impossible, and adding one with a different name would
  leave two tables meaning "API key" forever, which is how the `guacamole` columns happened.
  So the existing shape is kept, including its column names.

  Two additive columns, both defaulting to `'[]'` so every existing row (there are none in
  practice, but the migration must not assume that) reads as a key with **no scopes and no
  hosts** — i.e. a key that can do nothing. That is the right default for a credential whose
  authority is being introduced after the fact: an old key silently gaining agent powers is
  the failure this whole feature exists to prevent.

    * `scopes`   — JSON array of verbs (`tmux:read`, `tmux:write`, `tmux:wait`)
    * `host_ids` — JSON array of host ids the key may act on

  Stored as data rather than encoded into the token on purpose: a key's authority must be
  narrowable and revocable AFTER issue, and a self-describing token can only be revoked by
  revoking the key.

  `token_hash` gets the UNIQUE index it always needed — two rows with the same hash would make
  authentication ambiguous, and the lookup runs on every agent request. Created as a plain
  index if a duplicate somehow exists, so the migration cannot wedge a boot.

  Reversible. Runs unattended at container boot (`lib/termelix/application.ex`).
  """
  use Ecto.Migration

  @columns ~w(scopes host_ids)

  def up do
    # SQLite has no `ADD COLUMN IF NOT EXISTS`, and `add_if_not_exists` is explicitly
    # unsupported by the adapter — a duplicate-column error inside the boot-time
    # `{Ecto.Migrator, ...}` child aborts startup with no operator at the keyboard. So each
    # column is probed first, the same stance as `20260726000001` and the index guards in
    # `20260723190712`.
    for column <- @columns, not column_exists?(column) do
      execute("ALTER TABLE api_keys ADD COLUMN #{column} TEXT NOT NULL DEFAULT '[]'")
    end

    create_if_not_exists unique_index(:api_keys, [:token_hash])
    create_if_not_exists index(:api_keys, [:user_id])
  end

  def down do
    drop_if_exists index(:api_keys, [:token_hash])
    drop_if_exists index(:api_keys, [:user_id])

    for column <- @columns, column_exists?(column) do
      execute("ALTER TABLE api_keys DROP COLUMN #{column}")
    end
  end

  defp column_exists?(column) do
    %{rows: rows} = repo().query!("PRAGMA table_info(api_keys)", [])
    Enum.any?(rows, fn [_cid, name | _rest] -> name == column end)
  end
end
