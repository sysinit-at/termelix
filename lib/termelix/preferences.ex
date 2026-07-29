defmodule Termelix.Preferences do
  @moduledoc """
  Per-user UI preferences (`user_preferences`, one row per user, `user_id` is the PK).

  No secret fields live here, so reads and writes are plain — no DEK involvement. Writes
  mirror the Node repository's find-then-insert/update upsert, touching only the columns the
  caller supplied.
  """
  alias Termelix.Repo
  alias Termelix.Schema.UserPreference

  @doc "The user's preferences row, or nil when none has been saved yet."
  @spec get_for_user(String.t()) :: UserPreference.t() | nil
  def get_for_user(user_id), do: Repo.get(UserPreference, user_id)

  @doc """
  Insert or update the user's preferences with `updates` (a map keyed by schema-field atoms;
  values already validated by the caller). Only the supplied fields are written.
  """
  @spec upsert(String.t(), map()) ::
          {:ok, UserPreference.t()} | {:error, Ecto.Changeset.t()}
  def upsert(user_id, updates) do
    case Repo.get(UserPreference, user_id) do
      nil ->
        %UserPreference{userId: user_id}
        |> Ecto.Changeset.change(updates)
        |> Repo.insert()

      %UserPreference{} = pref ->
        pref
        |> Ecto.Changeset.change(updates)
        |> Repo.update()
    end
  end
end
