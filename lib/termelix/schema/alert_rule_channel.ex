defmodule Termelix.Schema.AlertRuleChannel do
  @moduledoc """
  The `alert_rule_channels` join table — links an `alert_rules` row to the
  `notification_channels` it dispatches to. Both FKs are ENFORCED, so a link is only written
  once the referenced rule and (user-owned) channel exist.
  """
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  schema "alert_rule_channels" do
    field :ruleId, :integer, source: :rule_id
    field :channelId, :integer, source: :channel_id
  end
end
