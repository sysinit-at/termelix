defmodule Termelix.Schema.FileManagerRecent do
  @moduledoc """
  The `file_manager_recent` table: a user's recently-opened files per host, bumped on each
  open. Struct keys use schema.ts camelCase; no field is encrypted at rest.
  """
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  schema "file_manager_recent" do
    field :userId, :string, source: :user_id
    field :hostId, :integer, source: :host_id
    field :name, :string
    field :path, :string
    field :lastOpened, :string, source: :last_opened
  end
end
