defmodule Termelix.Schema.User do
  @moduledoc "The `users` table. Struct keys use schema.ts camelCase; text nanoid PK."
  use Ecto.Schema

  @primary_key {:id, :string, autogenerate: false}
  schema "users" do
    field :username, :string
    field :passwordHash, :string, source: :password_hash
    field :isAdmin, :boolean, source: :is_admin
    field :isOidc, :boolean, source: :is_oidc
    field :oidcIdentifier, :string, source: :oidc_identifier
    field :ssoProviderId, :integer, source: :sso_provider_id
    field :clientId, :string, source: :client_id
    field :clientSecret, :string, source: :client_secret
    field :issuerUrl, :string, source: :issuer_url
    field :authorizationUrl, :string, source: :authorization_url
    field :tokenUrl, :string, source: :token_url
    field :identifierPath, :string, source: :identifier_path
    field :namePath, :string, source: :name_path
    field :scopes, :string
    field :totpSecret, :string, source: :totp_secret
    field :totpEnabled, :boolean, source: :totp_enabled
    field :totpBackupCodes, :string, source: :totp_backup_codes
    field :registeredAt, :string, source: :registered_at
    field :donationModalDismissed, :boolean, source: :donation_modal_dismissed
  end
end
