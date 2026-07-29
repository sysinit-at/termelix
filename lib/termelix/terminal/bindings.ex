defmodule Termelix.Terminal.Bindings do
  @moduledoc """
  Durable (user, host, tmux session) bindings — `terminal_bindings`.

  A binding is the record that outlives the BEAM: `Termelix.Terminal.Session` is
  `restart: :temporary` with in-memory state, so the ordinary `docker compose up -d` update path
  destroys it, while the tmux session on the host keeps running. With a binding, a fresh BEAM can
  re-attach the operator to the session they were in instead of dropping them into a new shell —
  and the same session stays takeable out-of-band (`ssh host && tmux attach`), which is the point
  of the whole phase.

  **Ownership is enforced here, never by the caller.** Every function takes the acting user's id
  and every query is scoped by it, the same contract `Termelix.Hosts` keeps: a binding may only
  be created for a host the user owns, and a binding belonging to another user is
  indistinguishable from one that does not exist.
  """
  import Ecto.Query, only: [from: 2]
  import Ecto.Changeset, only: [get_field: 2]

  require Logger

  alias Termelix.Repo
  alias Termelix.Schema.{Host, TerminalBinding}

  # Schema field names, not column names — Ecto dumps them to sources itself
  # (`Ecto.Repo.Schema.conflict_target/2`). Must match the UNIQUE index created in
  # `20260726000001_add_tmux_session_binding.exs`, or SQLite rejects the ON CONFLICT clause.
  @conflict_target [:userId, :hostId, :tmuxSessionName]

  @doc """
  Record that `user_id` is attached to `tmux_session_name` on `host_id`, refreshing
  `lastAttachedAt` when the binding already exists.

  One statement, so two tabs racing to attach to the same session cannot produce a duplicate row
  or a constraint error. Returns `{:error, :not_found}` when the host is not the user's (the same
  answer a non-existent host gets — a binding must never leak that someone else's host id is
  real), or `{:error, changeset}` for a malformed session name.
  """
  @spec upsert(String.t(), integer() | String.t(), String.t()) ::
          {:ok, TerminalBinding.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def upsert(user_id, host_id, tmux_session_name) do
    now = iso_now()

    changeset =
      TerminalBinding.changeset(%TerminalBinding{}, %{
        userId: user_id,
        hostId: host_id,
        tmuxSessionName: tmux_session_name,
        createdAt: now,
        lastAttachedAt: now
      })

    if changeset.valid?, do: insert_owned(user_id, changeset, now), else: {:error, changeset}
  end

  defp insert_owned(user_id, changeset, now) do
    # Read the cast values back: `host_id` arrives from the wire and may be a string, and the
    # query below would raise on a binary against an integer column.
    host_id = get_field(changeset, :hostId)
    session_name = get_field(changeset, :tmuxSessionName)

    if owns_host?(user_id, host_id) do
      # `insert/2`, not `insert!/2`. The only caller is the terminal socket's connect path, and
      # a bang here turns any database error — a busy SQLite writer, a host deleted between the
      # ownership check and the insert — into an exception that kills the terminal the operator
      # just opened. A binding is bookkeeping: failing to record one must degrade to "this
      # session is not resumable", never to "your terminal died".
      case Repo.insert(changeset,
             on_conflict: [set: [lastAttachedAt: now]],
             conflict_target: @conflict_target
           ) do
        {:ok, _inserted} ->
          # Re-read rather than trust the returned struct: on the DO UPDATE path only
          # `last_attached_at` is written, so the struct's `createdAt` would report this attach
          # instead of the binding's real age.
          {:ok, get(user_id, host_id, session_name)}

        {:error, changeset} ->
          {:error, changeset}
      end
    else
      {:error, :not_found}
    end
  rescue
    # Belt and braces: a constraint this changeset does not declare still surfaces as a raise
    # from the adapter, and this runs on the connect path.
    error ->
      Logger.warning("terminal binding upsert failed: #{Exception.message(error)}")
      {:error, :insert_failed}
  end

  @doc """
  The user's bindings, most recently attached first. Bindings that were never attached sort last
  (SQLite orders NULL below every string, and this is a DESC sort).
  """
  @spec list_for_user(String.t()) :: [TerminalBinding.t()]
  def list_for_user(user_id) do
    Repo.all(
      from b in TerminalBinding,
        where: b.userId == ^user_id,
        order_by: [desc: b.lastAttachedAt, desc: b.id]
    )
  end

  @doc "One binding of the user's, or nil when it does not exist or is not theirs."
  @spec get(String.t(), integer() | String.t(), String.t()) :: TerminalBinding.t() | nil
  def get(user_id, host_id, tmux_session_name) do
    Repo.get_by(TerminalBinding,
      userId: user_id,
      hostId: host_id,
      tmuxSessionName: tmux_session_name
    )
  end

  @doc """
  Bump `lastAttachedAt` on an existing binding — the re-attach path, where the row already
  exists and only its freshness changes. The struct carries the owner it was read with and the
  write is scoped by it, so a binding cannot be touched into another user's name.
  `{:error, :not_found}` when the row is gone (its host or user was deleted in between).
  """
  @spec touch(TerminalBinding.t()) :: {:ok, TerminalBinding.t()} | {:error, :not_found}
  def touch(%TerminalBinding{} = binding) do
    now = iso_now()

    {count, _} =
      Repo.update_all(
        from(b in TerminalBinding, where: b.id == ^binding.id and b.userId == ^binding.userId),
        set: [lastAttachedAt: now]
      )

    if count > 0, do: {:ok, %{binding | lastAttachedAt: now}}, else: {:error, :not_found}
  end

  @doc """
  Forget one of the user's bindings, by id or by the struct itself. Idempotent: a tmux session
  that has already died is the ordinary reason to call this, so "no such row" is success, not an
  error. Deleting the binding never touches the remote tmux session — killing that is
  `Termelix.Tmux.kill_session/2`, an explicit and separate act.
  """
  @spec delete(String.t(), integer() | TerminalBinding.t()) :: :ok
  def delete(user_id, %TerminalBinding{id: id}), do: delete(user_id, id)

  def delete(user_id, id) when is_integer(id) do
    Repo.delete_all(from b in TerminalBinding, where: b.id == ^id and b.userId == ^user_id)
    :ok
  end

  # --- helpers --------------------------------------------------------------

  # `Repo.exists?` rather than `Hosts.get_for_user/2`: ownership is the only question here, and
  # loading the host would drag in a DEK unlock and secret decryption for nothing.
  defp owns_host?(user_id, host_id) do
    Repo.exists?(from h in Host, where: h.id == ^host_id and h.userId == ^user_id)
  end

  defp iso_now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
