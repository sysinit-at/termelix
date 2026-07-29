defmodule TermelixWeb.HostFolderController do
  @moduledoc """
  Ports the `/host/folders` surface (`host-folder-routes.ts`): folder listing, metadata
  upsert, hierarchical rename, and delete-all-hosts-in-folder.

  The `Authenticate` plug has already run, so the owner is `conn.assigns.current_user_id`; a
  `userId` in the body is never trusted. Folder records carry no secret fields, so they are
  returned as-is.
  """
  use Phoenix.Controller, formats: [:json]

  import TermelixWeb.ControllerHelpers

  alias Termelix.HostFolders

  # GET /host/folders
  def index(conn, _params) do
    folders =
      conn.assigns.current_user_id
      |> HostFolders.list_folders()
      |> Enum.map(&to_json/1)

    json(conn, folders)
  end

  # PUT /host/folders/rename
  def rename_folder(conn, params) do
    old_name = params["oldName"]
    new_name = params["newName"]

    cond do
      blank?(old_name) or blank?(new_name) ->
        error(conn, 400, "Old name and new name are required")

      old_name == new_name ->
        json(conn, %{message: "Folder name unchanged"})

      true ->
        %{updated_hosts: hosts, updated_credentials: creds} =
          HostFolders.rename_folder(conn.assigns.current_user_id, old_name, new_name)

        json(conn, %{
          message: "Folder renamed successfully",
          updatedHosts: hosts,
          updatedCredentials: creds
        })
    end
  end

  # PUT /host/folders/metadata
  def update_metadata(conn, %{"name" => name} = params) when is_binary(name) do
    if blank?(name) do
      error(conn, 400, "Folder name is required")
    else
      HostFolders.upsert_metadata(conn.assigns.current_user_id, name, params)
      json(conn, %{message: "Folder metadata updated successfully"})
    end
  end

  def update_metadata(conn, _params), do: error(conn, 400, "Folder name is required")

  # DELETE /host/folders/:name/hosts
  def delete_hosts(conn, %{"name" => name}) do
    if blank?(name) do
      error(conn, 400, "Invalid folder name")
    else
      count = HostFolders.delete_folder_hosts(conn.assigns.current_user_id, name)
      json(conn, %{message: "All hosts in folder deleted successfully", deletedCount: count})
    end
  end

  # --- helpers --------------------------------------------------------------

  defp to_json(struct), do: struct |> Map.from_struct() |> Map.drop([:__meta__])

  defp blank?(nil), do: true
  defp blank?(value) when is_binary(value), do: String.trim(value) == ""
  defp blank?(_), do: false
end
