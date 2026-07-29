defmodule Termelix.Schema.NotificationChannel do
  @moduledoc """
  The `notification_channels` table — a user's alert delivery target. `config` is a JSON string
  whose shape depends on `type` (`webhook`: url/headers/method; `ntfy`: url/topic/token).
  Struct keys use schema.ts camelCase; `enabled` is a boolean.
  """
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  schema "notification_channels" do
    field :userId, :string, source: :user_id
    field :name, :string
    field :type, :string
    field :config, :string
    field :enabled, :boolean
    field :createdAt, :string, source: :created_at
  end
end
