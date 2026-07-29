defmodule Termelix.SessionRecordings do
  @moduledoc """
  Session-recording metadata access for a user — the Elixir port of the read/management subset
  of `session-recording-repository.ts` (the surface `session-log-routes.ts` exposes).

  Every read and write is scoped to the owning user (ownership enforced in every query; a
  route `userId` is never trusted). Admins reach any user's recording through the controller,
  mirroring the Node `canAccessRecording` check.

  The actual recording capture (asciinema) is deferred, so rows are created elsewhere;
  this context lists a user's recordings (joined to their host for name/ip), fetches one row's
  metadata, and deletes one — matching `listByUserIdWithHost`, `findByIdForUser`,
  `findPathByIdForUser` and `deleteForUser`.
  """
  import Ecto.Query, only: [from: 2]

  alias Termelix.Repo
  alias Termelix.Schema.{Host, SessionRecording}

  @doc """
  A user's recordings, newest-first, each joined to its host for `hostName`/`hostIp`.

  Returns plain maps in the `SessionRecordingListRecord` shape the frontend's `getSessionLogs`
  consumes (the controller then stamps `sizeBytes` from the file on disk). Mirrors
  `listByUserIdWithHost`.
  """
  @spec list_for_user_with_host(String.t()) :: [map()]
  def list_for_user_with_host(user_id) do
    Repo.all(
      from r in SessionRecording,
        left_join: h in Host,
        on: r.hostId == h.id,
        where: r.userId == ^user_id,
        order_by: [desc: r.startedAt],
        select: %{
          id: r.id,
          hostId: r.hostId,
          userId: r.userId,
          startedAt: r.startedAt,
          endedAt: r.endedAt,
          duration: r.duration,
          recordingPath: r.recordingPath,
          protocol: r.protocol,
          format: r.format,
          hostName: h.name,
          hostIp: h.ip
        }
    )
  end

  @doc "A single recording owned by the user (full row), or nil. Mirrors `findByIdForUser`."
  @spec get_for_user(String.t(), integer()) :: SessionRecording.t() | nil
  def get_for_user(user_id, id), do: Repo.get_by(SessionRecording, id: id, userId: user_id)

  @doc """
  Delete a recording the user owns. Returns `{:ok, recording}` (the deleted row, so the caller
  can unlink its `recordingPath`) or `{:error, :not_found}` when the row is not owned by the
  user (ownership enforced). Mirrors `findPathByIdForUser` + `deleteForUser`.
  """
  @spec delete_for_user(String.t(), integer()) ::
          {:ok, SessionRecording.t()} | {:error, :not_found}
  def delete_for_user(user_id, id) do
    case get_for_user(user_id, id) do
      nil -> {:error, :not_found}
      %SessionRecording{} = recording -> Repo.delete(recording)
    end
  end

  @doc """
  Insert the row for a recording that has just started, returning it (or nil).

  Written at START, not at the end. A session that is killed still leaves a file on disk, and a
  row that only appeared on clean shutdown would mean exactly the recordings an operator most
  wants — the ones from a session that crashed — are the ones that never get listed.

  Never raises: a transcript whose row could not be written is still on disk and still readable,
  and failing the terminal over it would trade a missing record for a missing shell.
  """
  @spec create(map()) :: SessionRecording.t() | nil
  def create(attrs) do
    case %SessionRecording{} |> SessionRecording.changeset(attrs) |> Repo.insert() do
      {:ok, recording} -> recording
      {:error, _changeset} -> nil
    end
  rescue
    _error -> nil
  end

  @doc "Complete a recording's row once its file has been closed. Idempotent, never raises."
  @spec finish(integer(), map()) :: :ok
  def finish(id, attrs) do
    Repo.update_all(from(r in SessionRecording, where: r.id == ^id), set: Map.to_list(attrs))
    :ok
  rescue
    _error -> :ok
  end
end
