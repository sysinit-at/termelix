defmodule Termelix.Schema.AlertFiring do
  @moduledoc """
  The `alert_firings` table — one row per alert that fired. `hostId` is a plain integer (NOT a
  FK, so a firing survives host deletion), while `userId` and `ruleId` ARE enforced FKs. Struct
  keys use schema.ts camelCase; `acknowledged` is a boolean, `firedAt`/`resolvedAt` are strings.
  """
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  schema "alert_firings" do
    field :userId, :string, source: :user_id
    field :ruleId, :integer, source: :rule_id
    field :hostId, :integer, source: :host_id
    field :hostName, :string, source: :host_name
    field :firedAt, :string, source: :fired_at
    field :resolvedAt, :string, source: :resolved_at
    field :value, :float
    field :message, :string
    field :severity, :string
    field :acknowledged, :boolean
  end
end
