defmodule Termelix.Schema.SessionRecording do
  @moduledoc """
  The `session_recordings` table — metadata for a terminal session recording
  (`session-recording-repository.ts`). Struct keys use schema.ts camelCase with snake_case
  `source:` columns.

  Autoincrement integer PK; `host_id` (→ `ssh_data.id`, cascade), `user_id` (→ `users.id`,
  cascade) and `access_id` (→ `host_access.id`, set null) are enforced FKs. `terminatedByOwner`
  is a `:boolean`; every timestamp is an ISO string (no `timestamps()` macro).

  Rows are written by `Termelix.Terminal.Recorder` at the START of a session and completed when
  it closes, so a crashed session still appears in the listing.
  """
  use Ecto.Schema

  import Ecto.Changeset

  @primary_key {:id, :id, autogenerate: true}
  schema "session_recordings" do
    field :hostId, :integer, source: :host_id
    field :userId, :string, source: :user_id
    field :accessId, :integer, source: :access_id
    field :startedAt, :string, source: :started_at
    field :endedAt, :string, source: :ended_at
    field :duration, :integer
    field :commands, :string
    field :dangerousActions, :string, source: :dangerous_actions
    field :recordingPath, :string, source: :recording_path
    field :protocol, :string
    field :format, :string
    field :terminatedByOwner, :boolean, source: :terminated_by_owner
    field :terminationReason, :string, source: :termination_reason
  end

  @doc false
  def changeset(recording, attrs) do
    recording
    |> cast(attrs, __MODULE__.__schema__(:fields) -- [:id])
    |> validate_required([:userId, :hostId, :startedAt])
  end
end
