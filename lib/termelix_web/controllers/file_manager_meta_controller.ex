defmodule TermelixWeb.FileManagerMetaController do
  @moduledoc """
  Ports the file-manager metadata surface (`host-file-manager-bookmark-routes.ts`) the frontend
  calls under `/host/file_manager/{recent,pinned,shortcuts}` (port 30001, `sshHostApi` base
  `/host` — `file-manager-metadata-api.ts`): per-host lists of recent, pinned, and shortcut
  files, plus add/remove.

  The `Authenticate` plug has run, so the owner is `conn.assigns.current_user_id`; a body
  `userId` is never trusted, and every query is scoped to that user. Lists respond with the raw
  record shape (camelCase keys) the frontend reads. `POST /recent` is the "open recording" path
  (upsert bumps `lastOpened`); pinning or adding a shortcut that already exists is a 409.
  """
  use Phoenix.Controller, formats: [:json]

  import TermelixWeb.ControllerHelpers

  alias Termelix.FileManagerMeta

  @recent_limit 20

  # GET /host/file_manager/recent?hostId=<id>
  def recent(conn, params) do
    with {:ok, host_id} <- require_host_id_query(params) do
      records = FileManagerMeta.list_recent(conn.assigns.current_user_id, host_id, @recent_limit)
      json(conn, Enum.map(records, &to_json/1))
    else
      {:error, :missing_host_id} -> error(conn, 400, "Host ID is required")
    end
  end

  # POST /host/file_manager/recent  body {hostId, path, name?}
  def add_recent(conn, params) do
    with {:ok, host_id, path} <- require_body(params) do
      FileManagerMeta.upsert_recent(conn.assigns.current_user_id, host_id, path, params["name"])
      json(conn, %{message: "Recent file added"})
    else
      {:error, :invalid_data} -> error(conn, 400, "Invalid data")
    end
  end

  # DELETE /host/file_manager/recent  body {hostId, path}
  def remove_recent(conn, params) do
    with {:ok, host_id, path} <- require_body(params) do
      FileManagerMeta.delete_recent(conn.assigns.current_user_id, host_id, path)
      json(conn, %{message: "Recent file removed"})
    else
      {:error, :invalid_data} -> error(conn, 400, "Invalid data")
    end
  end

  # GET /host/file_manager/pinned?hostId=<id>
  def pinned(conn, params) do
    with {:ok, host_id} <- require_host_id_query(params) do
      records = FileManagerMeta.list_pinned(conn.assigns.current_user_id, host_id)
      json(conn, Enum.map(records, &to_json/1))
    else
      {:error, :missing_host_id} -> error(conn, 400, "Host ID is required")
    end
  end

  # POST /host/file_manager/pinned  body {hostId, path, name?}
  def add_pinned(conn, params) do
    with {:ok, host_id, path} <- require_body(params),
         :ok <-
           FileManagerMeta.create_pinned(
             conn.assigns.current_user_id,
             host_id,
             path,
             params["name"]
           ) do
      json(conn, %{message: "File pinned"})
    else
      {:error, :invalid_data} -> error(conn, 400, "Invalid data")
      :exists -> error(conn, 409, "File already pinned")
    end
  end

  # DELETE /host/file_manager/pinned  body {hostId, path}
  def remove_pinned(conn, params) do
    with {:ok, host_id, path} <- require_body(params) do
      FileManagerMeta.delete_pinned(conn.assigns.current_user_id, host_id, path)
      json(conn, %{message: "Pinned file removed"})
    else
      {:error, :invalid_data} -> error(conn, 400, "Invalid data")
    end
  end

  # GET /host/file_manager/shortcuts?hostId=<id>
  def shortcuts(conn, params) do
    with {:ok, host_id} <- require_host_id_query(params) do
      records = FileManagerMeta.list_shortcuts(conn.assigns.current_user_id, host_id)
      json(conn, Enum.map(records, &to_json/1))
    else
      {:error, :missing_host_id} -> error(conn, 400, "Host ID is required")
    end
  end

  # POST /host/file_manager/shortcuts  body {hostId, path, name?}
  def add_shortcut(conn, params) do
    with {:ok, host_id, path} <- require_body(params),
         :ok <-
           FileManagerMeta.create_shortcut(
             conn.assigns.current_user_id,
             host_id,
             path,
             params["name"]
           ) do
      json(conn, %{message: "Shortcut added"})
    else
      {:error, :invalid_data} -> error(conn, 400, "Invalid data")
      :exists -> error(conn, 409, "Shortcut already exists")
    end
  end

  # DELETE /host/file_manager/shortcuts  body {hostId, path}
  def remove_shortcut(conn, params) do
    with {:ok, host_id, path} <- require_body(params) do
      FileManagerMeta.delete_shortcut(conn.assigns.current_user_id, host_id, path)
      json(conn, %{message: "Shortcut removed"})
    else
      {:error, :invalid_data} -> error(conn, 400, "Invalid data")
    end
  end

  # --- param validation -------------------------------------------------------

  # GET guard: `hostId ? parseInt(hostId) : null` then `if (!hostId)` → 400. A missing,
  # unparseable, or zero hostId fails.
  defp require_host_id_query(params) do
    case host_id(params["hostId"]) do
      n when is_integer(n) and n != 0 -> {:ok, n}
      _ -> {:error, :missing_host_id}
    end
  end

  # POST/DELETE guard: `!hostId || !path` → 400 "Invalid data". hostId must be a non-zero
  # integer, path a non-empty string.
  defp require_body(params) do
    hid = host_id(params["hostId"])
    path = params["path"]

    if is_integer(hid) and hid != 0 and is_binary(path) and path != "" do
      {:ok, hid, path}
    else
      {:error, :invalid_data}
    end
  end

  # `hostId` arrives as a JSON number (body) or a query string; coerce to an integer.
  defp host_id(value) when is_integer(value), do: value

  defp host_id(value) when is_binary(value) do
    case Integer.parse(value) do
      {n, _rest} -> n
      :error -> nil
    end
  end

  defp host_id(_), do: nil

  defp to_json(struct), do: struct |> Map.from_struct() |> Map.drop([:__meta__])
end
