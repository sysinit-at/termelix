defmodule Termelix.Repo.Migrations.RequireJsonTerminalConfig do
  @moduledoc """
  Refuse a `terminal_config` that is not valid JSON, and clear the ones already stored.

  The previous trigger was gated on `json_valid(NEW.terminal_config)`, which was reasoned about as
  safe: a blob that will not parse cannot be read as configuration, because
  `HostNormalizer.parse_json/2` resolves it to `nil`, so the field comes back null rather than as
  raw text. That is true of the host-list path and only of the host-list path.

  `Termelix.UserDataExport` builds its rows with `Map.from_struct/1`, so it emits every column
  verbatim — including this one. The `format: "encrypted"` export is documented as "a safe backup
  that never exposes plaintext", and a malformed blob carrying a secret ended up in it, confirmed
  end to end. Checking one exit and concluding the room was sealed is the mistake here.

  Requiring JSON costs nothing: `terminal_config` is written by `json_config/1` from a map or a
  pre-encoded document, so anything that will not parse is already junk that no reader can use.
  Rejecting it removes the whole category rather than trying to pattern-match secrets inside text
  that has no structure to match against.

  Existing malformed values are cleared rather than left. They are unreadable as configuration, so
  nothing is lost, and leaving them means the next export still carries whatever they contain.

  ## Two triggers per event, not one with an OR

  The first attempt merged both rules into one predicate, which meant one `RAISE` message covering
  two unrelated failures — so a host rejected for carrying a secret was told its JSON was malformed.
  Separate triggers keep each message about the thing that actually went wrong.

  The secret trigger keeps its `json_valid` guard. That is load-bearing rather than redundant:
  `json_tree` raises on malformed input, so without the guard an invalid blob would fail with
  SQLite's "malformed JSON" instead of the message written here. Trigger firing order is
  unspecified, so each predicate has to stand on its own.
  """
  use Ecto.Migration

  import Ecto.Query, only: [from: 2]

  @json_message "terminal_config must be valid JSON — an unparseable blob is not readable as configuration and still reaches exports"
  @secret_message "terminal_config must not contain a sudoPassword at any depth — secrets belong in the encrypted column"

  def up do
    # Clear first: the triggers below only guard future writes, and this statement must not trip
    # over rows that predate them.
    repo().update_all(
      from(h in "ssh_data",
        where: not is_nil(h.terminal_config) and fragment("json_valid(?) = 0", h.terminal_config)
      ),
      set: [terminal_config: nil]
    )

    drop_triggers()

    for {suffix, event} <- [{"insert", "INSERT"}, {"update", "UPDATE OF terminal_config"}] do
      execute("""
      CREATE TRIGGER ssh_data_terminal_config_must_be_json_#{suffix}
      BEFORE #{event} ON ssh_data
      FOR EACH ROW
      WHEN NEW.terminal_config IS NOT NULL
       AND NOT json_valid(NEW.terminal_config)
      BEGIN
        SELECT RAISE(ABORT, '#{@json_message}');
      END;
      """)

      execute("""
      CREATE TRIGGER ssh_data_no_secret_in_terminal_config_#{suffix}
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
        SELECT RAISE(ABORT, '#{@secret_message}');
      END;
      """)
    end
  end

  def down do
    drop_triggers()
  end

  defp drop_triggers do
    for suffix <- ["insert", "update"] do
      execute("DROP TRIGGER IF EXISTS ssh_data_terminal_config_must_be_json_#{suffix}")
      execute("DROP TRIGGER IF EXISTS ssh_data_no_secret_in_terminal_config_#{suffix}")
    end
  end
end
