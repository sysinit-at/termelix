defmodule Termelix.Schema.UserOpenTab do
  @moduledoc """
  The `user_open_tabs` table — persistence of a user's open terminal/file tabs. Struct keys
  use schema.ts camelCase; text PK (`id`, a client-supplied tab instance id). No field is
  encrypted at rest.
  """
  use Ecto.Schema

  import Ecto.Changeset

  @primary_key {:id, :string, autogenerate: false}
  schema "user_open_tabs" do
    field :userId, :string, source: :user_id
    field :tabType, :string, source: :tab_type
    field :hostId, :integer, source: :host_id
    field :label, :string
    field :tabOrder, :integer, source: :tab_order
    field :backendSessionId, :string, source: :backend_session_id
    field :createdAt, :string, source: :created_at
    field :updatedAt, :string, source: :updated_at
  end

  @cast_fields [
    :id,
    :userId,
    :tabType,
    :hostId,
    :label,
    :tabOrder,
    :backendSessionId,
    :createdAt,
    :updatedAt
  ]

  @doc """
  Changeset for a tab upsert. The NOT NULL columns the route checks (`id`, `tabType`,
  `label`) are validated; `empty_values: []` keeps explicit empty strings as-is, matching
  the previous struct-literal insert.
  """
  def changeset(tab, attrs) do
    tab
    |> cast(attrs, @cast_fields, empty_values: [])
    |> validate_required([:id, :userId, :tabType, :label])
  end
end
