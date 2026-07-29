defmodule Termelix.Repo.Migrations.AddQueryIndexesTest do
  @moduledoc """
  Guards on `AddQueryIndexes` that make it safe to run against a database upgraded from an
  older Termelix, before the unique constraints existed:

    * redundant `user_roles` / `dismissed_alerts` rows are reconciled to one per group so the
      composite unique index can be created, and
    * duplicate usernames abort the migration with an actionable error naming them, instead
      of the opaque SQLite "UNIQUE constraint failed" that would roll the whole migration back.

  The test drives the exact SQL the migration ships (`AddQueryIndexes.unique_indexes/0`) by
  dropping the already-applied unique index, seeding a legacy-style duplicate, running the
  guard, and asserting the index rebuilds. The sandbox transaction rolls all of it back.
  """
  use Termelix.DataCase, async: false

  alias Ecto.Adapters.SQL
  alias Termelix.Repo
  alias Termelix.Repo.Migrations.AddQueryIndexes

  # Migrations live outside the compile path; `setup_all` loads the module at runtime, so the
  # compiler cannot see it here.
  @compile {:no_warn_undefined, AddQueryIndexes}

  @migration_file "priv/repo/migrations/20260723190712_add_query_indexes.exs"

  setup_all do
    # `mix ecto.migrate` only compiles pending migrations, so the module may not be loaded
    # in the test BEAM when the schema is already up to date. Load it on demand.
    unless Code.ensure_loaded?(AddQueryIndexes) do
      Code.require_file(Path.join(File.cwd!(), @migration_file))
    end

    :ok
  end

  defp query!(sql, params \\ []), do: SQL.query!(Repo, sql, params)

  defp unique_index(name), do: Enum.find(AddQueryIndexes.unique_indexes(), &(&1.name == name))

  defp insert_user!(id, username) do
    query!("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", [id, username, "x"])
  end

  defp count(sql, params), do: query!(sql, params).rows |> hd() |> hd()

  describe "user_roles / dismissed_alerts dedup guards" do
    test "redundant user_roles collapse to one and the unique index rebuilds" do
      %{name: name, guard: {:dedup, dedup_sql}, ddl: ddl} =
        unique_index("idx_user_roles_user_role_unique")

      insert_user!("u-roles", "roleuser")
      query!("INSERT INTO roles (name, display_name) VALUES (?, ?)", ["ops-dup", "Ops"])
      role_id = count("SELECT id FROM roles WHERE name = ?", ["ops-dup"])

      # Drop the shipped index so a pre-enforcement duplicate can be reproduced.
      query!("DROP INDEX IF EXISTS #{name}")

      Enum.each(1..3, fn _ ->
        query!("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", ["u-roles", role_id])
      end)

      assert count("SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ?", [
               "u-roles",
               role_id
             ]) == 3

      query!(dedup_sql)

      assert count("SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ?", [
               "u-roles",
               role_id
             ]) == 1

      # The migration's own CREATE now succeeds against the reconciled data.
      assert %{rows: _} = query!(ddl)
    end

    test "redundant dismissed_alerts collapse to one and the unique index rebuilds" do
      %{name: name, guard: {:dedup, dedup_sql}, ddl: ddl} =
        unique_index("idx_dismissed_alerts_user_alert_unique")

      insert_user!("u-alerts", "alertuser")
      query!("DROP INDEX IF EXISTS #{name}")

      Enum.each(1..3, fn _ ->
        query!("INSERT INTO dismissed_alerts (user_id, alert_id) VALUES (?, ?)", [
          "u-alerts",
          "welcome"
        ])
      end)

      assert count("SELECT COUNT(*) FROM dismissed_alerts WHERE user_id = ? AND alert_id = ?", [
               "u-alerts",
               "welcome"
             ]) == 3

      query!(dedup_sql)

      assert count("SELECT COUNT(*) FROM dismissed_alerts WHERE user_id = ? AND alert_id = ?", [
               "u-alerts",
               "welcome"
             ]) == 1

      assert %{rows: _} = query!(ddl)
    end
  end

  describe "users(username) preflight" do
    test "duplicate usernames abort with an actionable error naming them" do
      %{name: name} = unique_index("idx_users_username_unique")
      query!("DROP INDEX IF EXISTS #{name}")

      insert_user!("dup-a", "dupe")
      insert_user!("dup-b", "dupe")

      error =
        assert_raise RuntimeError, fn -> AddQueryIndexes.preflight_unique_usernames!(Repo) end

      assert error.message =~ "dupe"
      assert error.message =~ "unique index"
      assert error.message =~ "re-run the upgrade"
    end

    test "distinct usernames pass the preflight and the unique index rebuilds" do
      %{name: name, ddl: ddl} = unique_index("idx_users_username_unique")
      query!("DROP INDEX IF EXISTS #{name}")

      insert_user!("uniq-a", "alice-uniq")
      insert_user!("uniq-b", "bob-uniq")

      assert :ok = AddQueryIndexes.preflight_unique_usernames!(Repo)
      assert %{rows: _} = query!(ddl)
    end
  end
end
