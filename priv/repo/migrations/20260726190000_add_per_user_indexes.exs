defmodule Termelix.Repo.Migrations.AddPerUserIndexes do
  @moduledoc """
  The per-user indexes five tables have always needed.

  Every one of these is queried as "everything belonging to this user" — that is the only way
  the application ever reads them — and every one of those reads is a full table scan today.
  On a single-user box that is invisible; on a box where the audit trail and the recordings
  have been accumulating for a year it is the difference between a listing and a pause.

  Additive and guarded (`create_if_not_exists`), so this runs unattended at container boot
  without a chance of aborting startup on an install where an index was added by hand.
  """
  use Ecto.Migration

  def up do
    create_if_not_exists index(:session_recordings, [:user_id])
    create_if_not_exists index(:trusted_devices, [:user_id])
    create_if_not_exists index(:alert_rules, [:user_id])
    create_if_not_exists index(:alert_firings, [:user_id])
    create_if_not_exists index(:notification_channels, [:user_id])

    # The pruner's ONLY query shape: expired rows ordered by when they started. Without it,
    # every hourly sweep scans the whole recordings table to find nothing.
    create_if_not_exists index(:session_recordings, [:started_at])
  end

  def down do
    drop_if_exists index(:session_recordings, [:started_at])
    drop_if_exists index(:notification_channels, [:user_id])
    drop_if_exists index(:alert_firings, [:user_id])
    drop_if_exists index(:alert_rules, [:user_id])
    drop_if_exists index(:trusted_devices, [:user_id])
    drop_if_exists index(:session_recordings, [:user_id])
  end
end
