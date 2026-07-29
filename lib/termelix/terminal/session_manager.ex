defmodule Termelix.Terminal.SessionManager do
  @moduledoc """
  Creates, looks up, and lists persistent terminal sessions (Registry + DynamicSupervisor).

  ## Why the registry *value* carries state

  Every list used to be an unfiltered `Registry.select/2` over the whole node followed by an
  `Enum.filter` in the caller, and the cap check then issued one blocking `Session.info/1` per
  session of that user. That is the Node answer to a question BEAM already answers: a match
  spec runs inside the registry and returns only the rows that match, and `update_value/3`
  keeps the fields a reader needs out of the owning process entirely. `Termelix.Tunnels`
  already did it this way — the codebase contained both answers to the same question.

  Concretely it matters because both are on the connect path: with ten sessions open, listing
  cost ten `GenServer.call`s, and any one of them stuck in an SSH handshake made the *whole*
  connect wait on it.

  So `last_detached_at` lives in the value, written by `Termelix.Terminal.Session` on attach
  and detach, and the cap reads it without talking to anyone.

  ## The cap refuses

  It used to evict: at ten sessions the oldest detached one was stopped to make room. That
  quietly destroyed whatever it was running, and the user was never told — the new session
  simply opened. A refusal is the honest answer, it self-heals (detached sessions expire on
  the usual timer), and since P4 the remote tmux session outlives the refusal anyway, so
  nothing is lost by declining to create an eleventh attachment.
  """

  require Logger

  alias Termelix.Terminal.Session
  alias Termelix.Id

  @registry Termelix.Terminal.Registry
  @max_sessions_per_user 10

  @doc "Sessions one user may hold at once."
  @spec max_sessions_per_user() :: pos_integer()
  def max_sessions_per_user, do: @max_sessions_per_user

  @doc """
  Create a session for a user/host. `{:ok, session_id, pid}`, or `{:error, :session_limit}`
  when the user is already at `max_sessions_per_user/0`.
  """
  @spec create(String.t(), integer(), String.t(), map(), keyword()) ::
          {:ok, String.t(), pid()} | {:error, term()}
  def create(user_id, host_id, host_name, conn_opts, opts \\ []) do
    with :ok <- check_user_cap(user_id) do
      id = Id.generate()

      spec =
        {Session,
         %{
           id: id,
           user_id: user_id,
           host_id: host_id,
           host_name: host_name,
           conn_opts: conn_opts,
           # Recording, when the caller asked for it. Carried here rather than inside
           # `conn_opts` because `conn_opts` is what goes to `:ssh` — putting a DEK-derived key
           # in it would mean a transcript key travelling through every connection builder and
           # into the pool key.
           record: Keyword.get(opts, :record)
         }}

      case DynamicSupervisor.start_child(Termelix.Terminal.SessionSupervisor, spec) do
        {:ok, pid} -> {:ok, id, pid}
        {:error, {reason, _child}} -> {:error, reason}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  @doc "Look up a session pid by id, verifying ownership. Returns pid or nil."
  @spec lookup(String.t(), String.t()) :: pid() | nil
  def lookup(session_id, user_id) do
    case Registry.lookup(@registry, session_id) do
      [{pid, %{user_id: ^user_id}}] -> pid
      _ -> nil
    end
  end

  @doc """
  All live sessions of a user as `{session_id, pid, meta}` tuples.

  The `user_id` guard runs inside the registry, so a node hosting many users' sessions does
  not copy all of them into this process to throw most away.
  """
  @spec list_user_sessions(String.t()) :: [{String.t(), pid(), map()}]
  def list_user_sessions(user_id) do
    Registry.select(@registry, [
      {{:"$1", :"$2", :"$3"}, [{:==, {:map_get, :user_id, :"$3"}, user_id}],
       [{{:"$1", :"$2", :"$3"}}]}
    ])
  end

  @doc "Destroy a session by id (ownership-checked)."
  @spec destroy(String.t(), String.t()) :: :ok
  def destroy(session_id, user_id) do
    case lookup(session_id, user_id) do
      nil -> :ok
      pid -> Session.stop(pid)
    end
  end

  @doc """
  Stop every terminal session belonging to `user_id`, returning how many were stopped.

  This is the data-plane half of revocation. Deleting a user, or revoking their access, used
  to leave their live sessions running: the token was dead, so nothing *new* could be opened
  — while the shell they already had stayed connected to the host indefinitely, because
  authorization was only ever checked when a session was created.
  """
  @spec stop_user_sessions(String.t()) :: non_neg_integer()
  def stop_user_sessions(user_id) do
    sessions = list_user_sessions(user_id)
    Enum.each(sessions, fn {_id, pid, _meta} -> Session.stop(pid) end)

    if sessions != [] do
      Logger.info("revocation: stopped #{length(sessions)} terminal session(s) for #{user_id}")
    end

    length(sessions)
  end

  # Read from the registry values — no call into any session, so one session stuck in an SSH
  # handshake cannot delay another user's connect.
  defp check_user_cap(user_id) do
    if length(list_user_sessions(user_id)) >= @max_sessions_per_user,
      do: {:error, :session_limit},
      else: :ok
  end
end
