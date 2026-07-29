defmodule Termelix.Schema.RecentActivity do
  @moduledoc """
  The `recent_activity` table: a user's recent host interactions (terminal, file manager, …).
  Struct keys use schema.ts camelCase; no field is encrypted at rest.
  """
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  schema "recent_activity" do
    field :userId, :string, source: :user_id
    field :type, :string
    field :hostId, :integer, source: :host_id
    field :hostName, :string, source: :host_name
    field :timestamp, :string
  end
end
