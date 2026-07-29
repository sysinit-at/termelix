defmodule Termelix.Schema.SshCredentialUsage do
  @moduledoc "The `ssh_credential_usage` table — one row per credential-applied-to-host event."
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  schema "ssh_credential_usage" do
    field :credentialId, :integer, source: :credential_id
    field :hostId, :integer, source: :host_id
    field :userId, :string, source: :user_id
    field :usedAt, :string, source: :used_at
  end
end
