defmodule Termelix.Schema.TrustedDevice do
  @moduledoc """
  The `trusted_devices` table — one row per (user, device fingerprint) that the 2FA
  "remember this device" flow trusts, so TOTP is bypassed on a known device until the row
  expires. Struct keys use schema.ts camelCase with snake_case `source:` columns.

  Text nanoid PK; `user_id` is an enforced FK → `users.id` (cascade). Timestamps are ISO
  strings (no `timestamps()` macro).
  """
  use Ecto.Schema

  @primary_key {:id, :string, autogenerate: false}
  schema "trusted_devices" do
    field :userId, :string, source: :user_id
    field :deviceFingerprint, :string, source: :device_fingerprint
    field :deviceType, :string, source: :device_type
    field :deviceInfo, :string, source: :device_info
    field :createdAt, :string, source: :created_at
    field :expiresAt, :string, source: :expires_at
    field :lastUsedAt, :string, source: :last_used_at
  end
end
