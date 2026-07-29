defmodule Termelix.Schema.Session do
  @moduledoc "The `sessions` table. Session-bound JWTs require a live row here."
  use Ecto.Schema

  @primary_key {:id, :string, autogenerate: false}
  schema "sessions" do
    field :userId, :string, source: :user_id
    field :jwtToken, :string, source: :jwt_token
    field :deviceType, :string, source: :device_type
    field :deviceInfo, :string, source: :device_info
    field :oidcSub, :string, source: :oidc_sub
    field :oidcSid, :string, source: :oidc_sid
    field :ssoProviderId, :integer, source: :sso_provider_id
    field :createdAt, :string, source: :created_at
    field :expiresAt, :string, source: :expires_at
    field :lastActiveAt, :string, source: :last_active_at
  end
end
