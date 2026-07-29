defmodule Termelix.Schema.FileManagerPinned do
  @moduledoc """
  The `file_manager_pinned` table: a user's pinned files per host. Struct keys use schema.ts
  camelCase; no field is encrypted at rest.
  """
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  schema "file_manager_pinned" do
    field :userId, :string, source: :user_id
    field :hostId, :integer, source: :host_id
    field :name, :string
    field :path, :string
    field :pinnedAt, :string, source: :pinned_at
  end
end
