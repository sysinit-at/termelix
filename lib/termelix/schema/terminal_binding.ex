defmodule Termelix.Schema.TerminalBinding do
  @moduledoc """
  The `terminal_bindings` table — one row per (user, host, tmux session name), recording which
  remote tmux session a user's terminal tab is attached to.

  This is the durable half of the session: `Termelix.Terminal.Session` is `restart: :temporary`
  and holds its state in memory, so a redeploy destroys it, while the tmux session on the host
  keeps running. A binding row survives both, which is what lets a fresh BEAM re-attach instead
  of opening a new shell.

  Struct keys use schema.ts camelCase; nothing here is encrypted at rest — a session name is not
  a secret, and `Termelix.Tmux` already puts these names on the wire for the monitor view.

  Timestamps are ISO-8601 UTC strings (`Termelix.Time.parse_iso8601/1` is the canonical parser
  and only accepts that shape). The DB's `CURRENT_TIMESTAMP` default on `created_at` is a
  backstop for direct SQL only — `Termelix.Terminal.Bindings` always writes the value.
  """
  use Ecto.Schema

  import Ecto.Changeset

  # The same shape `tmux_controller.ex:28` accepts for a session name, and a strict subset of
  # what `terminal_socket.ex:292` will type into a PTY: no `:`/`.` (tmux target syntax), no C0
  # control bytes, no quotes, capped at 64 bytes. A name that fails this could never be attached
  # anyway, so it must not become a durable row that fails forever.
  @session_name_re ~r/^[A-Za-z0-9_@%+=-]{1,64}$/

  @primary_key {:id, :id, autogenerate: true}
  schema "terminal_bindings" do
    field :userId, :string, source: :user_id
    field :hostId, :integer, source: :host_id
    field :tmuxSessionName, :string, source: :tmux_session_name
    field :createdAt, :string, source: :created_at
    field :lastAttachedAt, :string, source: :last_attached_at
  end

  @cast_fields [:userId, :hostId, :tmuxSessionName, :createdAt, :lastAttachedAt]

  @doc """
  Changeset for a binding write. Validates the NOT NULL columns and the session-name shape;
  host **ownership** is not checked here — that is the context's job
  (`Termelix.Terminal.Bindings`), which is the only place that knows the acting user.
  """
  def changeset(binding, attrs) do
    binding
    |> cast(attrs, @cast_fields)
    |> validate_required([:userId, :hostId, :tmuxSessionName, :createdAt])
    |> validate_format(:tmuxSessionName, @session_name_re,
      message: "must be 1-64 chars of A-Za-z0-9_@%+=-"
    )
  end

  @doc """
  True when `name` is a tmux session name this table will store — exposed so callers can screen
  a name before building a binding (the terminal socket must decide whether to attach or to open
  a plain shell, without a changeset in hand).
  """
  @spec session_name?(term()) :: boolean()
  def session_name?(name) when is_binary(name), do: Regex.match?(@session_name_re, name)
  def session_name?(_name), do: false
end
