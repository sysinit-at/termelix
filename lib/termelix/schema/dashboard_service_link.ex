defmodule Termelix.Schema.DashboardServiceLink do
  @moduledoc """
  The `dashboard_service_links` table: a user's dashboard quick-links
  (`dashboard-service-link-repository.ts`). Struct keys use schema.ts camelCase; no field is
  encrypted at rest.

  The `order` column is a SQL reserved word — the field keeps its `:order` source and every
  query references it via `field(l, :order)` so Ecto quotes the column.
  """
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  schema "dashboard_service_links" do
    field :userId, :string, source: :user_id
    field :label, :string
    field :url, :string
    field :order, :integer, source: :order
    field :createdAt, :string, source: :created_at
  end
end
