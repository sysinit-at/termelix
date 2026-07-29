defmodule Termelix.Repo.Migrations.ForbidSecretsInTerminalConfig do
  @moduledoc """
  Refuse, at the database, to store a sudo password inside `terminal_config`.

  Until now this was enforced only by application code — `HostController` scrubs on write and
  `HostNormalizer` scrubs on read. That keeps the running version honest and does nothing about a
  rollback: an image built before the fix accepts a nested `sudoPassword`, writes it to this plain
  `TEXT` column, and returns it in every host-list response. The data migrations cannot help,
  because they correctly do not reverse. So the guarantee lived entirely in whichever image
  happened to be running.

  ## Why a trigger and not a CHECK constraint

  SQLite cannot add a CHECK to an existing table. Doing it means the twelve-step rebuild: create a
  new table, copy every row, drop the original, rename, then recreate every index — on the table
  holding every stored credential, where a mistake in the column list silently drops data. A
  trigger buys the same property (enforced by the database, whatever the application is doing) as
  a purely additive DDL statement, with a `down` that genuinely reverses it.

  ## Why the pattern is what it is

  Matching a bare `sudoPassword` would reject legitimate configuration — an environment variable
  or a snippet that merely mentions the word. `"sudoPassword":` only matches the string in JSON
  KEY position: a value or a variable name serialises as `"key":"sudoPassword"`, with no colon
  after the closing quote, and is therefore untouched.

  Spaces are stripped first because `json_config/1` passes a pre-encoded string through verbatim,
  so an old client could send `{"sudoPassword" : "x"}`. Anything written by the current controller
  is re-encoded by Jason and never has them, but the whole point of this trigger is to hold when
  the current controller is not what is running.

  Scoped to `sudoPassword` deliberately. It is the key that was actually being stored here, and
  widening it to every secret name would start rejecting real terminal configuration for no
  demonstrated benefit — `HostNormalizer` still scrubs the wider set on read.
  """
  use Ecto.Migration

  @message "terminal_config must not contain a sudoPassword — secrets belong in the encrypted column"

  def up do
    for {name, event} <- [{"insert", "INSERT"}, {"update", "UPDATE OF terminal_config"}] do
      execute("""
      CREATE TRIGGER ssh_data_no_secret_in_terminal_config_#{name}
      BEFORE #{event} ON ssh_data
      FOR EACH ROW
      WHEN NEW.terminal_config IS NOT NULL
       AND replace(NEW.terminal_config, ' ', '') LIKE '%"sudoPassword":%'
      BEGIN
        SELECT RAISE(ABORT, '#{@message}');
      END;
      """)
    end
  end

  def down do
    execute("DROP TRIGGER IF EXISTS ssh_data_no_secret_in_terminal_config_insert")
    execute("DROP TRIGGER IF EXISTS ssh_data_no_secret_in_terminal_config_update")
  end
end
