defmodule Termelix.Schema.DismissedAlert do
  @moduledoc "The `dismissed_alerts` table — one row per (user, alertId) announcement dismissal."
  use Ecto.Schema

  import Ecto.Changeset

  @primary_key {:id, :id, autogenerate: true}
  schema "dismissed_alerts" do
    field :userId, :string, source: :user_id
    field :alertId, :string, source: :alert_id
    field :dismissedAt, :string, source: :dismissed_at
  end

  @doc """
  Changeset for a dismissal. The (user_id, alert_id) unique index maps the
  concurrent-dismiss race onto a changeset error (→ the route's existing 409).
  """
  def changeset(dismissal, attrs) do
    dismissal
    |> cast(attrs, [:userId, :alertId, :dismissedAt], empty_values: [])
    |> validate_required([:userId, :alertId, :dismissedAt])
    |> unique_constraint(:userId, name: "dismissed_alerts_user_id_alert_id_index")
  end
end
