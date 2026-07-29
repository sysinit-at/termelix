defmodule Termelix.Schema.Role do
  @moduledoc """
  The `roles` table (RBAC roles). Struct keys use schema.ts camelCase; autoincrement id.
  `permissions` is a JSON-encoded string of permission strings (or NULL) — parsed at the edge.
  """
  use Ecto.Schema

  import Ecto.Changeset

  @primary_key {:id, :id, autogenerate: true}
  schema "roles" do
    field :name, :string
    field :displayName, :string, source: :display_name
    field :description, :string
    field :isSystem, :boolean, source: :is_system
    field :permissions, :string
    field :createdAt, :string, source: :created_at
    field :updatedAt, :string, source: :updated_at
  end

  @cast_fields [
    :name,
    :displayName,
    :description,
    :isSystem,
    :permissions,
    :createdAt,
    :updatedAt
  ]

  @doc """
  Changeset for role creation. Mirrors the route's rules: `name` and `displayName` must be
  non-blank, `name` is lowercase-slug characters only, and the `roles.name` UNIQUE
  constraint (already in the DDL) maps the create race onto a changeset error.
  `empty_values: []` keeps explicit `""` distinguishable from NULL, as before.
  """
  def changeset(role, attrs) do
    role
    |> cast(attrs, @cast_fields, empty_values: [])
    |> validate_required([:name, :displayName])
    |> validate_nonblank(:name)
    |> validate_nonblank(:displayName)
    |> validate_format(:name, ~r/^[a-z0-9_-]+$/)
    |> unique_constraint(:name)
  end

  @doc "Changeset for role updates: only the mutable metadata fields are cast."
  def update_changeset(role, attrs) do
    cast(role, attrs, [:displayName, :description, :permissions, :updatedAt], empty_values: [])
  end

  # With `empty_values: []`, validate_required no longer treats "" as missing (Ecto 3.14
  # semantics), so blank-ness is enforced explicitly where the routes require it.
  defp validate_nonblank(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and String.trim(value) == "",
        do: [{field, "can't be blank"}],
        else: []
    end)
  end
end
