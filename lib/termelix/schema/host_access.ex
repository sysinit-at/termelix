defmodule Termelix.Schema.HostAccess do
  @moduledoc """
  The `host_access` table — a grant of a permission level (`connect|view|edit|manage`) on a
  host to either a user (`userId`) or a role (`roleId`). Autoincrement id.

  Per-recipient secret snapshots (`shared_host_secrets`) are NOT populated by this port yet —
  see `Termelix.Rbac` for the deferral note.
  """
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  schema "host_access" do
    field :hostId, :integer, source: :host_id
    field :userId, :string, source: :user_id
    field :roleId, :integer, source: :role_id
    field :grantedBy, :string, source: :granted_by
    field :permissionLevel, :string, source: :permission_level
    field :expiresAt, :string, source: :expires_at
    field :createdAt, :string, source: :created_at
    field :lastAccessedAt, :string, source: :last_accessed_at
    field :accessCount, :integer, source: :access_count
    field :overrideCredentialId, :integer, source: :override_credential_id
  end
end
