defmodule Termelix.Repo.Migrations.ForbidSecretsAnywhereInTerminalConfig do
  @moduledoc """
  Refuse a `sudoPassword` key **anywhere** in `terminal_config`, not only at the top level.

  `20260726230000` tested `json_extract(…, '$.sudoPassword')`, which asks one question: is there a
  top-level key of that name in an OBJECT? Two shapes answered no while carrying the secret in
  plain text, both confirmed against a running server — stored unencrypted AND returned in the
  host-list response:

      [{"sudoPassword":"..."}]        # the document is an ARRAY, so there is no top-level key
      {"a":{"sudoPassword":"..."}}    # nested one level down

  The second was something this migration's predecessor deliberately ALLOWED, on the reasoning that
  the application only ever reads `terminalConfig.sudoPassword` at the top level so a nested one is
  not "the secret". That reasoning was wrong, and wrong in an instructive way: whether the
  application happens to READ a value has nothing to do with whether it hands it to the browser.
  The rule is that the API never returns a stored secret. A secret it does not use is still a
  secret it returned.

  So the question becomes: is there an object key named `sudoPassword`, at any depth, holding
  anything? `json_tree` walks the whole document and answers exactly that.

  Still no realistic false positive, and the case that motivated the narrower predicate is
  unaffected: `{"env":[{"key":"sudoPassword","value":"x"}]}` has `sudoPassword` as a VALUE, not a
  key, so it remains allowed. `json_tree.key` is only the key when the parent is an object.

  The two exclusions from the previous version are kept, for the same reasons: a key present but
  null or empty passes (the old editor sent `sudoPassword: form.sudoPassword || null`, and refusing
  that would stop a pre-fix client saving at all with no secret involved), and invalid JSON passes
  (it cannot be decoded, so `parse_json/2` returns nil and the field comes back null rather than as
  raw text).
  """
  use Ecto.Migration

  @message "terminal_config must not contain a sudoPassword at any depth — secrets belong in the encrypted column"

  def up do
    drop_triggers()

    for {name, event} <- [{"insert", "INSERT"}, {"update", "UPDATE OF terminal_config"}] do
      execute("""
      CREATE TRIGGER ssh_data_no_secret_in_terminal_config_#{name}
      BEFORE #{event} ON ssh_data
      FOR EACH ROW
      WHEN NEW.terminal_config IS NOT NULL
       AND json_valid(NEW.terminal_config)
       AND EXISTS (
             SELECT 1 FROM json_tree(NEW.terminal_config)
             WHERE json_tree.key = 'sudoPassword'
               AND json_tree.value IS NOT NULL
               AND json_tree.value <> ''
           )
      BEGIN
        SELECT RAISE(ABORT, '#{@message}');
      END;
      """)
    end
  end

  def down do
    # Left unguarded rather than restored to the narrower predicate: reinstating a rule known to
    # miss two shapes is worse than none, because it reads as protection.
    drop_triggers()
  end

  defp drop_triggers do
    execute("DROP TRIGGER IF EXISTS ssh_data_no_secret_in_terminal_config_insert")
    execute("DROP TRIGGER IF EXISTS ssh_data_no_secret_in_terminal_config_update")
  end
end
