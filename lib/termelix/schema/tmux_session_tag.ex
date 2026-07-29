defmodule Termelix.Schema.TmuxSessionTag do
  @moduledoc """
  The `tmux_session_tags` table — one row per (user, host, session name, tag). Lets a user
  attach free-form labels to a named tmux session living on one of their hosts. The tmux
  session itself is shared on the host, but tags are per-user; several rows share the same
  (userId, hostId, sessionName) with different `tag` values.

  Autoincrement id; `createdAt` is stored as text (DB default `CURRENT_TIMESTAMP`, or the
  ISO-8601 string the context writes on insert).
  """
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  schema "tmux_session_tags" do
    field :userId, :string, source: :user_id
    field :hostId, :integer, source: :host_id
    field :sessionName, :string, source: :session_name
    field :tag, :string
    field :createdAt, :string, source: :created_at
  end
end
