defmodule Termelix.Repo.Migrations.ForbidSecretsInTerminalConfigViaJson do
  @moduledoc """
  Replace the text-matching guard on `terminal_config` with one that parses the JSON.

  `20260726220000` matched `"sudoPassword":` as text, with spaces stripped first. That was wrong in
  both directions, and both were demonstrated rather than theorised:

    * **It did not reliably block.** JSON allows any whitespace between a key and its colon, and
      only spaces were stripped — so `{"sudoPassword"\\t:"LEAK"}` and the same with a newline both
      went straight through. The justification for stripping spaces at all (`json_config/1` passes
      a pre-encoded string through verbatim, so an old client can choose the exact bytes) applies
      identically to tabs and newlines, which is precisely what made the omission exploitable.

    * **It rejected valid configuration.** `{"env":{"sudoPassword":"x"}}` was refused, though a
      nested key is not the secret: the application only ever reads `terminalConfig.sudoPassword`
      at the top level. A guard that fires on legitimate input is one somebody eventually deletes.

  Matching JSON with `LIKE` is the underlying mistake. SQLite has had JSON1 since 3.38 (3.53 in
  production, 3.54 in test), so the predicate can ask the parser instead: does this document have a
  top-level `sudoPassword` holding something? Escapes are normalised by the parser, so
  `{"sudo\\u0050assword":"x"}` is caught for the same reason the plain spelling is; whitespace is
  irrelevant; and `$.sudoPassword` cannot match a key nested under anything else.

  ## Two deliberate exclusions

  **A key present but null or empty passes.** The old editor sent `sudoPassword: form.sudoPassword
  || null`, so a client from before the fix saving a host with no sudo password sends
  `{"sudoPassword":null}`. There is no secret in that, and refusing it would stop such a client
  saving at all — turning a guard against leaking a credential into a guard against using the
  application.

  **Invalid JSON passes.** It cannot leak: `HostNormalizer.parse_json/2` falls back to `nil` for a
  blob it cannot decode, so the field comes back as null rather than as raw text, and nothing can
  read a secret out of it. Trying to cover it with a text match would drag back the false positives
  this migration exists to remove.
  """
  use Ecto.Migration

  @message "terminal_config must not contain a sudoPassword — secrets belong in the encrypted column"

  def up do
    drop_triggers()

    for {name, event} <- [{"insert", "INSERT"}, {"update", "UPDATE OF terminal_config"}] do
      execute("""
      CREATE TRIGGER ssh_data_no_secret_in_terminal_config_#{name}
      BEFORE #{event} ON ssh_data
      FOR EACH ROW
      WHEN NEW.terminal_config IS NOT NULL
       AND json_valid(NEW.terminal_config)
       AND json_extract(NEW.terminal_config, '$.sudoPassword') IS NOT NULL
       AND json_extract(NEW.terminal_config, '$.sudoPassword') <> ''
      BEGIN
        SELECT RAISE(ABORT, '#{@message}');
      END;
      """)
    end
  end

  def down do
    # Leaves the table unguarded rather than restoring the previous version. Reinstating a rule
    # known to be evadable would be worse than none: it reads as protection and is not.
    drop_triggers()
  end

  defp drop_triggers do
    execute("DROP TRIGGER IF EXISTS ssh_data_no_secret_in_terminal_config_insert")
    execute("DROP TRIGGER IF EXISTS ssh_data_no_secret_in_terminal_config_update")
  end
end
