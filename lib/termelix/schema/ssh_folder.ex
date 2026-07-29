defmodule Termelix.Schema.SshFolder do
  @moduledoc "The `ssh_folders` table (per-user SSH host folders; no encrypted fields)."
  use Ecto.Schema

  import Ecto.Changeset

  @primary_key {:id, :id, autogenerate: true}
  schema "ssh_folders" do
    field :userId, :string, source: :user_id
    field :name, :string
    field :color, :string
    field :icon, :string
    field :createdAt, :string, source: :created_at
    field :updatedAt, :string, source: :updated_at
  end

  @doc "Changeset for folder creation; `name` is required (NOT NULL in the DDL)."
  def changeset(folder, attrs) do
    folder
    |> cast(attrs, [:userId, :name, :color, :icon, :createdAt, :updatedAt], empty_values: [])
    |> validate_required([:userId, :name])
  end
end
