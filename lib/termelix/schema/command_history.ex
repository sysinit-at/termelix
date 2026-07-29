defmodule Termelix.Schema.CommandHistory do
  @moduledoc """
  The `command_history` table: one row per executed command, scoped to a user and host.
  Struct keys use schema.ts camelCase; no field is encrypted at rest.
  """
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  schema "command_history" do
    field :userId, :string, source: :user_id
    field :hostId, :integer, source: :host_id
    field :command, :string
    field :executedAt, :string, source: :executed_at
  end
end
