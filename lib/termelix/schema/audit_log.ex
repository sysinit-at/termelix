defmodule Termelix.Schema.AuditLog do
  @moduledoc """
  The `audit_logs` table (`audit-logger.ts` / `audit-log-repository.ts`).

  Autoincrement integer PK; struct keys use schema.ts camelCase with snake_case `source:`.
  `timestamp` is a plain ISO-8601 string (the port's timestamp convention, see
  `Accounts.create_session`), not a `timestamps()` pair.
  """
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  schema "audit_logs" do
    field :userId, :string, source: :user_id
    field :username, :string
    field :action, :string
    field :resourceType, :string, source: :resource_type
    field :resourceId, :string, source: :resource_id
    field :resourceName, :string, source: :resource_name
    field :details, :string
    field :ipAddress, :string, source: :ip_address
    field :userAgent, :string, source: :user_agent
    field :success, :boolean
    field :errorMessage, :string, source: :error_message
    field :timestamp, :string
  end
end
