defmodule Termelix.Schema.SsoProvider do
  @moduledoc """
  The `sso_providers` table (SSO/OIDC provider configuration for the login screen).

  Struct keys use the schema.ts camelCase names with a snake_case `source:`; the PK is an
  autoincrementing integer. `config` is a JSON string whose secret fields (`client_secret`,
  `bindPassword`) are sealed under the instance key — see `Termelix.SsoProviders` and
  `Termelix.Crypto.SystemSecrets`.
  """
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  schema "sso_providers" do
    field :name, :string
    field :type, :string
    field :enabled, :boolean
    field :displayOrder, :integer, source: :display_order
    field :config, :string
    field :createdAt, :string, source: :created_at
    field :updatedAt, :string, source: :updated_at
  end
end
