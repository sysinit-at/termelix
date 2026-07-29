defmodule Termelix.Schema.Setting do
  @moduledoc "The `settings` key/value table (also the home of wrapped per-user DEKs)."
  use Ecto.Schema

  @primary_key {:key, :string, autogenerate: false}
  @derive {Jason.Encoder, only: [:key, :value]}
  schema "settings" do
    field :value, :string
  end
end
