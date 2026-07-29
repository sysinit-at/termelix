defmodule Termelix.Schema.SshCredential do
  @moduledoc "The `ssh_credentials` table. Secret fields are field-encrypted under the user DEK."
  use Ecto.Schema

  import Ecto.Changeset

  @primary_key {:id, :id, autogenerate: true}
  schema "ssh_credentials" do
    field :userId, :string, source: :user_id
    field :name, :string
    field :description, :string
    field :folder, :string
    field :tags, :string
    field :authType, :string, source: :auth_type
    field :username, :string
    field :password, :string
    field :key, :string
    field :privateKey, :string, source: :private_key
    field :publicKey, :string, source: :public_key
    field :keyPassword, :string, source: :key_password
    field :keyType, :string, source: :key_type
    field :detectedKeyType, :string, source: :detected_key_type
    field :certPublicKey, :string, source: :cert_public_key
    field :usageCount, :integer, source: :usage_count
    field :lastUsed, :string, source: :last_used
    field :createdAt, :string, source: :created_at
    field :updatedAt, :string, source: :updated_at
  end

  @doc """
  Changeset for credential creation. `empty_values: []` keeps the explicit-empty-string
  semantics of the previous `change/2` writes; the NOT NULL columns the route relies on
  (`name`, `authType`) are validated. Secret fields pass through untouched — encryption
  happens in the context, after the row id is known.
  """
  def changeset(credential, attrs) do
    cast_fields = __MODULE__.__schema__(:fields) -- [:id]

    credential
    |> cast(attrs, cast_fields, empty_values: [])
    |> validate_required([:userId, :name, :authType])
    |> validate_nonblank(:name)
  end

  @doc "Changeset for credential updates: cast-only, so partial updates keep untouched fields."
  def update_changeset(credential, attrs) do
    cast(credential, attrs, __MODULE__.__schema__(:fields) -- [:id], empty_values: [])
  end

  # With `empty_values: []`, validate_required no longer treats "" as missing (Ecto 3.14
  # semantics), so blank-ness is enforced explicitly where the routes require it.
  defp validate_nonblank(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and String.trim(value) == "",
        do: [{field, "can't be blank"}],
        else: []
    end)
  end
end
