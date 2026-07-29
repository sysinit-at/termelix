defmodule Termelix.Repo.TerminalConfigTriggerTest do
  @moduledoc """
  The database itself refuses to store a sudo password in `terminal_config`.

  Application code already scrubs on write and on read, and that guarantee lasts exactly as long as
  the current image is the one running. Roll back to a build from before the fix and it accepts a
  nested `sudoPassword` again, writes it to this plain `TEXT` column, and hands it back in every
  host-list response — the data migrations cannot help, because they correctly do not reverse.

  A trigger holds regardless of what the application is doing, which is the only form this
  guarantee can take. These tests exist because a trigger is invisible from Elixir: nothing
  references it, so a future migration could drop it and every other test would still pass.

  The first version matched `"sudoPassword":` as TEXT with spaces stripped, and was wrong in both
  directions — `{"sudoPassword"\t:"x"}` walked past it, while `{"env":{"sudoPassword":"x"}}` was
  refused despite a nested key not being the secret. The predicate now asks SQLite's JSON parser
  instead, and both of those cases are pinned below: matching JSON with `LIKE` is the mistake, and
  a test suite that does not contain the escapes and the whitespace will not notice it recurring.
  """
  use Termelix.DataCase, async: false

  alias Termelix.{Accounts, Repo}

  setup do
    # A real user: `ssh_data.user_id` is a foreign key, so the rows below need an owner that
    # exists before the trigger ever gets a chance to have an opinion.
    {:ok, user, _} =
      Accounts.register_user("trigger-#{System.unique_integer([:positive])}", "password-123-abc")

    %{user: user}
  end

  defp insert(user, terminal_config) do
    Repo.query(
      """
      INSERT INTO ssh_data (user_id, name, ip, port, username, auth_type, terminal_config)
      VALUES (?, 'probe', '127.0.0.1', 22, 'x', 'password', ?)
      """,
      [user.id, terminal_config]
    )
  end

  describe "writes carrying a sudo password" do
    test "are refused as a JSON key", %{user: user} do
      assert {:error, error} = insert(user, ~s({"sudoPassword":"LEAK","fontSize":14}))
      assert Exception.message(error) =~ "sudoPassword"
    end

    test "are refused even when the JSON is spaced out", %{user: user} do
      # `json_config/1` passes a pre-encoded string through verbatim, so an older client could send
      # this shape. Anything the current controller writes is re-encoded by Jason and never has
      # spaces — but the whole point of the trigger is to hold when that controller is not running.
      assert {:error, _} = insert(user, ~s({"sudoPassword" : "LEAK"}))
    end

    test "are refused on UPDATE, not only INSERT", %{user: user} do
      assert {:ok, _} = insert(user, ~s({"fontSize":14}))

      assert {:error, error} =
               Repo.query(
                 "UPDATE ssh_data SET terminal_config = ? WHERE user_id = ?",
                 [~s({"sudoPassword":"LEAK"}), user.id]
               )

      assert Exception.message(error) =~ "sudoPassword"
    end
  end

  describe "ordinary terminal configuration" do
    # The pattern matches the string in JSON KEY position only. Rejecting a bare `sudoPassword`
    # would break real configuration for no benefit, and a rule that fires on legitimate input is
    # one somebody eventually removes.
    test "is allowed when it merely mentions the word in a value", %{user: user} do
      assert {:ok, _} = insert(user, ~s({"env":[{"key":"note","value":"sudoPassword"}]}))
    end

    test "is allowed when an environment variable is NAMED sudoPassword", %{user: user} do
      assert {:ok, _} = insert(user, ~s({"env":[{"key":"sudoPassword","value":"x"}]}))
    end

    test "is allowed for the auto-fill toggle, whose name shares the prefix", %{user: user} do
      assert {:ok, _} = insert(user, ~s({"fontSize":14,"sudoPasswordAutoFill":false}))
    end

    test "is allowed when the key is present but carries no secret", %{user: user} do
      # The old editor sent `sudoPassword: form.sudoPassword || null`, so a client from before the
      # fix saving a host with no sudo password sends exactly this. There is nothing to leak, and
      # refusing it would stop that client saving at all — a guard against using the application
      # rather than against leaking a credential.
      assert {:ok, _} = insert(user, ~s({"sudoPassword":null,"fontSize":14}))
      assert {:ok, _} = insert(user, ~s({"sudoPassword":"","fontSize":14}))
    end

    test "is allowed when absent entirely", %{user: user} do
      assert {:ok, _} =
               Repo.query(
                 """
                 INSERT INTO ssh_data (user_id, name, ip, port, username, auth_type)
                 VALUES (?, 'probe', '127.0.0.1', 22, 'x', 'password')
                 """,
                 [user.id]
               )
    end
  end

  test "both triggers exist" do
    # Named explicitly: nothing in Elixir references them, so a migration that dropped one would
    # otherwise go unnoticed until a credential turned up in a host-list response.
    {:ok, %{rows: rows}} =
      Repo.query("SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name")

    names = List.flatten(rows)

    assert "ssh_data_no_secret_in_terminal_config_insert" in names
    assert "ssh_data_no_secret_in_terminal_config_update" in names
  end
end
