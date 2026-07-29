defmodule Termelix.Schema.FileManagerShortcut do
  @moduledoc """
  The `file_manager_shortcuts` table: a user's saved directory shortcuts per host. Struct keys
  use schema.ts camelCase; no field is encrypted at rest.
  """
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  schema "file_manager_shortcuts" do
    field :userId, :string, source: :user_id
    field :hostId, :integer, source: :host_id
    field :name, :string
    field :path, :string
    field :createdAt, :string, source: :created_at
  end
end
