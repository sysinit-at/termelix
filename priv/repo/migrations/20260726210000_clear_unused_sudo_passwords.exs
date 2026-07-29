defmodule Termelix.Repo.Migrations.ClearUnusedSudoPasswords do
  @moduledoc """
  Null every stored `sudo_password`.

  These were collected for sudo auto-fill, where the server typed the secret into the PTY at a
  password prompt. That turned out to be a credential-reveal primitive however it was gated —
  writing into the PTY is indistinguishable from the user typing, and whether the value comes back
  echoed is decided by the REMOTE's terminal settings, which the server cannot observe — so the
  feature was removed (see `docs/BUG_REFERENCE.md`).

  Nothing reads the column now, and the editor no longer asks for one. A stored credential with no
  consumer is not a dormant feature, it is liability: it can still leak and it can no longer help.
  So it is cleared rather than left encrypted-and-forgotten.

  The COLUMN stays. Dropping it would be a schema change for no benefit, `@secret_fields` still
  redacts it, and leaving it in place keeps the door open for a future design that is actually safe
  — one where the secret never enters a channel the client can read.

  Irreversible, deliberately: `down` cannot restore a secret, and pretending it could would be
  worse than saying so.
  """
  use Ecto.Migration

  def up do
    # Unconditional rather than `WHERE NOT NULL`: the point is that no row keeps one, and the
    # statement should read as that guarantee rather than as an optimisation.
    execute("UPDATE ssh_data SET sudo_password = NULL")
  end

  def down do
    :ok
  end
end
