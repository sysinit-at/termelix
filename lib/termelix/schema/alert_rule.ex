defmodule Termelix.Schema.AlertRule do
  @moduledoc """
  The `alert_rules` table — a user's alert definition (threshold/status/health/login triggers).
  Struct keys use schema.ts camelCase; `enabled` is a boolean, timestamps are strings. Only the
  `*_threshold` trigger types are evaluated by the background collector's engine so far; the
  remaining trigger types persist as rows but their evaluators are deferred.
  """
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  schema "alert_rules" do
    field :userId, :string, source: :user_id
    field :hostId, :integer, source: :host_id
    field :name, :string
    field :enabled, :boolean
    field :triggerType, :string, source: :trigger_type
    field :thresholdValue, :float, source: :threshold_value
    field :thresholdDurationSeconds, :integer, source: :threshold_duration_seconds
    field :cooldownMinutes, :integer, source: :cooldown_minutes
    field :createdAt, :string, source: :created_at
    field :updatedAt, :string, source: :updated_at
  end
end
