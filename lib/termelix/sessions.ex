defmodule Termelix.Sessions do
  @moduledoc """
  Read/revoke access to the `sessions` table for the session-management surface
  (`user-session-routes.ts`). Session *creation* and single-session revocation live in
  `Termelix.Accounts` (`create_session/4`, `revoke_session/1`); this module adds the listing
  (own / all), lookup, bulk revoke-with-exception, and the `unlock-data` token refresh.

  Revoking a session means deleting its row — there is no `is_revoked` column, so a listed
  session is by definition live.
  """
  import Ecto.Query, only: [from: 2]

  alias Termelix.Repo
  alias Termelix.Schema.Session
  alias Termelix.Auth.Token

  @doc "All sessions belonging to a user (insertion order)."
  @spec list_for_user(String.t()) :: [Session.t()]
  def list_for_user(user_id), do: Repo.all(from(s in Session, where: s.userId == ^user_id))

  @doc "Every session (admin view)."
  @spec list_all() :: [Session.t()]
  def list_all, do: Repo.all(Session)

  @doc "Fetch one session by id, or nil."
  @spec get(String.t()) :: Session.t() | nil
  def get(session_id), do: Repo.get(Session, session_id)

  @doc """
  Revoke every session for a user, optionally sparing `except_session_id`. Returns the number
  of rows deleted (`revokeAllUserSessions`).
  """
  @spec revoke_all_for_user(String.t(), String.t() | nil) :: non_neg_integer()
  def revoke_all_for_user(user_id, except_session_id \\ nil)

  def revoke_all_for_user(user_id, nil) do
    {count, _} = Repo.delete_all(from(s in Session, where: s.userId == ^user_id))
    # No auth session left means no basis for a live SSH connection either. Only on the
    # spare-nothing clause: `revoke_all_for_user/2` with an exception is "log out my other
    # devices", where the user still has access and killing their terminal would be a bug.
    Termelix.Revocation.revoke_user(user_id, :sessions_revoked)
    count
  end

  def revoke_all_for_user(user_id, except_session_id) do
    {count, _} =
      Repo.delete_all(
        from(s in Session, where: s.userId == ^user_id and s.id != ^except_session_id)
      )

    count
  end

  @doc """
  Refresh a session's JWT, keeping the same session id and remaining lifetime
  (`refreshSessionToken`). Returns `{:ok, token, ttl_seconds}` or `:error` when the session is
  missing, not owned by `user_id`, or already expired.
  """
  @spec refresh_token(String.t(), String.t()) :: {:ok, String.t(), pos_integer()} | :error
  def refresh_token(user_id, session_id) do
    with %Session{userId: ^user_id, expiresAt: expires_at} = session <-
           Repo.get(Session, session_id),
         ttl when ttl > 0 <- remaining_seconds(expires_at) do
      token = Token.sign(%{"userId" => user_id, "sessionId" => session_id}, ttl)

      session
      |> Ecto.Changeset.change(jwtToken: token, lastActiveAt: iso_now())
      |> Repo.update!()

      {:ok, token, ttl}
    else
      _ -> :error
    end
  end

  defp remaining_seconds(nil), do: 0

  defp remaining_seconds(iso) do
    case DateTime.from_iso8601(iso) do
      {:ok, dt, _} -> max(DateTime.diff(dt, DateTime.utc_now(), :second), 0)
      _ -> 0
    end
  end

  defp iso_now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
