defmodule Termelix.Schema.UserRole do
  @moduledoc "The `user_roles` table — one row per (user, role) assignment. Autoincrement id."
  use Ecto.Schema

  import Ecto.Changeset

  @primary_key {:id, :id, autogenerate: true}
  schema "user_roles" do
    field :userId, :string, source: :user_id
    field :roleId, :integer, source: :role_id
    field :grantedBy, :string, source: :granted_by
    field :grantedAt, :string, source: :granted_at
  end

  @doc """
  Changeset for a role assignment. The (user_id, role_id) unique index maps the assign
  race onto a changeset error (→ the route's existing 409 "Role already assigned").
  """
  def changeset(user_role, attrs) do
    user_role
    |> cast(attrs, [:userId, :roleId, :grantedBy, :grantedAt], empty_values: [])
    |> validate_required([:userId, :roleId])
    |> unique_constraint(:userId, name: "user_roles_user_id_role_id_index")
  end
end
