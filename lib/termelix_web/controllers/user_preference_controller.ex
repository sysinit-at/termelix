defmodule TermelixWeb.UserPreferenceController do
  @moduledoc """
  Ports the `/user-preferences` surface (`routes/user-preferences.ts`) the frontend uses to
  read and persist per-user UI settings (`getUserPreferences` / `saveUserPreferences`).

  GET returns the current user's preferences with sensible defaults where a value is absent.
  PUT validates the supplied fields, upserts the row, and echoes back only what changed.
  """
  use Phoenix.Controller, formats: [:json]

  import Plug.Conn

  alias Termelix.Preferences

  # String-typed preference fields. A supplied value must be a string or null.
  @string_fields ~w(theme fontSize accentColor language storageMode hiddenRailTabs
                    statusColorScheme)a

  # Boolean-typed preference fields. A supplied value must be a boolean or null.
  @bool_fields ~w(commandAutocomplete commandPaletteEnabled showHostTags hostTrayOnClick
                  pinAppRail expandAppRailOnHover foldersCollapsed confirmSnippetExecution
                  disableUpdateCheck confirmTabClose compactHostView)a

  # GET /user-preferences
  def show(conn, _params) do
    prefs =
      conn.assigns.current_user_id
      |> Preferences.get_for_user()
      |> pick_preferences()

    json(conn, prefs)
  end

  # PUT /user-preferences
  def update(conn, params) do
    user_id = conn.assigns.current_user_id

    case build_updates(params) do
      {:error, message} ->
        error(conn, 400, message)

      {:ok, updates} when map_size(updates) == 0 ->
        error(conn, 400, "No preferences provided")

      {:ok, updates} ->
        updates = Map.put(updates, :updatedAt, DateTime.utc_now() |> DateTime.to_iso8601())

        case Preferences.upsert(user_id, updates) do
          {:ok, _pref} -> json(conn, Map.merge(%{success: true}, updates))
          {:error, _changeset} -> error(conn, 500, "Failed to update user preferences")
        end
    end
  end

  # Shape the stored row (or nil) into the response the frontend consumes, applying the same
  # defaults the Node `pickPreferences` uses: reopenTabsOnLogin → false, storageMode → "cloud",
  # every other missing value → null.
  defp pick_preferences(row) do
    %{
      reopenTabsOnLogin: field(row, :reopenTabsOnLogin) || false,
      theme: field(row, :theme),
      fontSize: field(row, :fontSize),
      accentColor: field(row, :accentColor),
      language: field(row, :language),
      storageMode: field(row, :storageMode) || "cloud",
      commandAutocomplete: field(row, :commandAutocomplete),
      commandPaletteEnabled: field(row, :commandPaletteEnabled),
      showHostTags: field(row, :showHostTags),
      hostTrayOnClick: field(row, :hostTrayOnClick),
      pinAppRail: field(row, :pinAppRail),
      expandAppRailOnHover: field(row, :expandAppRailOnHover),
      foldersCollapsed: field(row, :foldersCollapsed),
      confirmSnippetExecution: field(row, :confirmSnippetExecution),
      disableUpdateCheck: field(row, :disableUpdateCheck),
      confirmTabClose: field(row, :confirmTabClose),
      hiddenRailTabs: field(row, :hiddenRailTabs),
      compactHostView: field(row, :compactHostView),
      statusColorScheme: field(row, :statusColorScheme)
    }
  end

  defp field(nil, _key), do: nil
  defp field(row, key), do: Map.get(row, key)

  # Validate (in the Node route's order) then collect the supplied fields. A key that is absent
  # from the body is ignored (undefined); a key present with an explicit null is written as null.
  defp build_updates(params) do
    with :ok <- validate_reopen(params),
         :ok <- validate_type(params, @string_fields, &is_binary/1, "a string"),
         :ok <- validate_type(params, @bool_fields, &is_boolean/1, "a boolean") do
      {:ok, collect_updates(params)}
    end
  end

  # reopenTabsOnLogin is the one field that may not be null: it must be a boolean when supplied.
  defp validate_reopen(params) do
    case Map.fetch(params, "reopenTabsOnLogin") do
      :error -> :ok
      {:ok, v} when is_boolean(v) -> :ok
      {:ok, _} -> {:error, "reopenTabsOnLogin must be a boolean"}
    end
  end

  defp validate_type(params, fields, valid?, type_name) do
    Enum.reduce_while(fields, :ok, fn name, _acc ->
      key = Atom.to_string(name)

      case Map.fetch(params, key) do
        :error ->
          {:cont, :ok}

        {:ok, nil} ->
          {:cont, :ok}

        {:ok, v} ->
          if valid?.(v), do: {:cont, :ok}, else: {:halt, {:error, "#{key} must be #{type_name}"}}
      end
    end)
  end

  defp collect_updates(params) do
    Enum.reduce([:reopenTabsOnLogin | @string_fields ++ @bool_fields], %{}, fn name, acc ->
      case Map.fetch(params, Atom.to_string(name)) do
        {:ok, value} -> Map.put(acc, name, value)
        :error -> acc
      end
    end)
  end

  defp error(conn, status, message) do
    conn |> put_status(status) |> json(%{error: message})
  end
end
