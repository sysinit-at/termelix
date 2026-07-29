defmodule TermelixWeb.FileManagerController do
  @moduledoc """
  Ports the SFTP file-manager endpoints the frontend calls under `/ssh/file_manager`
  (port 30004): listing a directory and reading/writing a file's content, plus the operation
  breadth the UI drives — create file/folder, delete, rename, move, multipart upload, and
  download (JSON base64 + streamed octet-stream). Callers in `ssh-file-operations-api.ts`:
  `listSSHFiles`/`readSSHFile`/`writeSSHFile`, `createSSHFile`/`createSSHFolder`,
  `deleteSSHItem`, `renameSSHItem`/`moveSSHItem`, `uploadSSHFile`,
  `downloadSSHFile`/`downloadSSHFileStream`.

  The `Authenticate` plug has run, so the owning user is `conn.assigns.current_user_id` — a
  body `userId` is never trusted. `sessionId` is the host id (the frontend sets it to
  `host.id.toString()`); the host is resolved+decrypted and connected to per request via
  `Termelix.SSH.Sftp` (short-lived connection, closed after).
  """
  use Phoenix.Controller, formats: [:json]

  alias Termelix.FileManagerSessions
  alias Termelix.SSH.Sftp

  # Chunk size for streaming multipart uploads to the host (256 KB).
  @stream_chunk_size 262_144

  # --- session lifecycle (connect / status / keepalive / disconnect) ----------
  #
  # The SPA refuses to browse until `POST /ssh/connect` succeeds, then polls `status` and
  # `keepalive` (`ssh-file-operations-api.ts`). The Node backend managed a live ssh2 client
  # per sessionId here; our SFTP layer opens short-lived connections per operation, so
  # connect *probes* the host once (stat "/") and records a virtual session
  # (`Termelix.FileManagerSessions`) that status/keepalive/disconnect then manage.

  # POST /ssh/file_manager/ssh/connect  body {sessionId, hostId?, ip, username, port, ...}
  def connect(conn, params) do
    user_id = conn.assigns.current_user_id
    session_id = params["sessionId"]

    logs = [
      log_entry(
        "info",
        "sftp_connecting",
        "Initiating SFTP connection to #{params["username"]}@#{params["ip"]}:#{params["port"]}"
      )
    ]

    with {:ok, session_id} <- non_empty(session_id),
         {:ok, host_id} <- connect_host_id(params, session_id),
         {:ok, _stat} <- Sftp.stat(host_id, user_id, "/") do
      FileManagerSessions.register(session_id, user_id)

      logs =
        logs ++ [log_entry("success", "sftp_connected", "SFTP session established successfully")]

      json(conn, %{status: "success", message: "SSH connection established", connectionLogs: logs})
    else
      {:error, :missing} ->
        logs =
          logs ++
            [log_entry("error", "sftp_connecting", "Missing required connection parameters")]

        conn
        |> put_status(400)
        |> json(%{error: "Missing required connection parameters", connectionLogs: logs})

      {:error, :host_not_found} ->
        logs = logs ++ [log_entry("error", "sftp_connecting", "Host not found")]
        conn |> put_status(404) |> json(%{error: "Host not found", connectionLogs: logs})

      {:error, reason} ->
        message = "SSH connection failed: #{format_reason(connect_reason(reason))}"
        logs = logs ++ [log_entry("error", "sftp_error", message)]
        conn |> put_status(500) |> json(%{error: message, connectionLogs: logs})
    end
  end

  # GET /ssh/file_manager/ssh/status?sessionId=
  def status(conn, params) do
    case FileManagerSessions.lookup(params["sessionId"]) do
      {:ok, owner, _last_active} when owner != conn.assigns.current_user_id ->
        error(conn, 403, "Session access denied")

      {:ok, _owner, _last_active} ->
        json(conn, %{status: "success", connected: true})

      :error ->
        json(conn, %{status: "success", connected: false})
    end
  end

  # POST /ssh/file_manager/ssh/keepalive  body {sessionId}
  def keepalive(conn, params) do
    session_id = params["sessionId"]

    with {:ok, _} <- non_empty(session_id),
         {:ok, owner, _} <- FileManagerSessions.lookup(session_id) do
      if owner == conn.assigns.current_user_id do
        {:ok, last_active} = FileManagerSessions.touch(session_id)

        json(conn, %{
          status: "success",
          connected: true,
          message: "Session keepalive successful",
          lastActive: last_active
        })
      else
        error(conn, 403, "Session access denied")
      end
    else
      {:error, :missing} ->
        error(conn, 400, "Session ID is required")

      :error ->
        conn
        |> put_status(400)
        |> json(%{error: "SSH session not found or not connected", connected: false})
    end
  end

  # POST /ssh/file_manager/ssh/disconnect  body {sessionId}
  def disconnect(conn, params) do
    session_id = params["sessionId"]

    case FileManagerSessions.lookup(session_id) do
      {:ok, owner, _} when owner != conn.assigns.current_user_id ->
        error(conn, 403, "Session access denied")

      _ ->
        FileManagerSessions.remove(session_id)
        json(conn, %{status: "success", message: "SSH connection disconnected"})
    end
  end

  # GET /ssh/file_manager/ssh/listFiles?sessionId=<hostId>&path=<path>
  def list_files(conn, params) do
    with {:ok, host_id} <- require_session(params),
         path <- Map.get(params, "path", "/"),
         {:ok, result} <- Sftp.list_directory(host_id, conn.assigns.current_user_id, path) do
      json(conn, result)
    else
      {:error, :missing_session} -> error(conn, 400, "Session ID is required")
      {:error, :not_found} -> error(conn, 404, "Directory not found")
      {:error, reason} -> respond_error(conn, reason)
    end
  end

  # GET /ssh/file_manager/ssh/readFile?sessionId=<hostId>&path=<path>
  def read_file(conn, params) do
    with {:ok, host_id} <- require_session(params),
         {:ok, path} <- require_string(params, "path", "File path is required"),
         {:ok, result} <- Sftp.read_file(host_id, conn.assigns.current_user_id, path) do
      json(conn, result)
    else
      {:error, :missing_session} ->
        error(conn, 400, "Session ID is required")

      {:error, {:missing_field, message}} ->
        error(conn, 400, message)

      {:error, :not_found} ->
        conn |> put_status(404) |> json(%{error: "File not found", fileNotFound: true})

      {:error, {:too_large, size}} ->
        conn
        |> put_status(400)
        |> json(%{
          error:
            "File too large to open in editor. Maximum size is #{div(max_read_size(), 1024 * 1024)}MB. Use download instead.",
          fileSize: size,
          maxSize: max_read_size(),
          tooLarge: true
        })

      {:error, reason} ->
        respond_error(conn, reason)
    end
  end

  # POST /ssh/file_manager/ssh/writeFile  body {sessionId, path, content, ...}
  def write_file(conn, params) do
    with {:ok, host_id} <- require_session(params),
         {:ok, path} <- require_string(params, "path", "File path is required"),
         {:ok, content} <- require_content(params),
         {:ok, result} <- Sftp.write_file(host_id, conn.assigns.current_user_id, path, content) do
      json(conn, result)
    else
      {:error, :missing_session} -> error(conn, 400, "Session ID is required")
      {:error, {:missing_field, message}} -> error(conn, 400, message)
      {:error, :not_found} -> error(conn, 404, "File not found")
      {:error, reason} -> respond_error(conn, reason)
    end
  end

  # POST /ssh/file_manager/ssh/createFile  body {sessionId, path, fileName, ...}
  def create_file(conn, params) do
    with {:ok, host_id} <- require_session(params),
         {:ok, dir} <- require_string(params, "path", "File path and name are required"),
         {:ok, name} <- require_string(params, "fileName", "File path and name are required"),
         {:ok, result} <- Sftp.create_file(host_id, conn.assigns.current_user_id, dir, name) do
      json(conn, result)
    else
      {:error, :missing_session} -> error(conn, 400, "Session ID is required")
      {:error, {:missing_field, message}} -> error(conn, 400, message)
      {:error, reason} -> respond_error(conn, reason)
    end
  end

  # POST /ssh/file_manager/ssh/createFolder  body {sessionId, path, folderName, ...}
  def create_folder(conn, params) do
    with {:ok, host_id} <- require_session(params),
         {:ok, dir} <- require_string(params, "path", "Folder path and name are required"),
         {:ok, name} <- require_string(params, "folderName", "Folder path and name are required"),
         {:ok, result} <- Sftp.create_folder(host_id, conn.assigns.current_user_id, dir, name) do
      json(conn, result)
    else
      {:error, :missing_session} -> error(conn, 400, "Session ID is required")
      {:error, {:missing_field, message}} -> error(conn, 400, message)
      {:error, reason} -> respond_error(conn, reason)
    end
  end

  # DELETE /ssh/file_manager/ssh/deleteItem  body {sessionId, path, isDirectory, ...}
  def delete_item(conn, params) do
    with {:ok, host_id} <- require_session(params),
         {:ok, path} <- require_string(params, "path", "Item path is required"),
         is_dir <- truthy(params["isDirectory"]),
         {:ok, result} <- Sftp.delete_item(host_id, conn.assigns.current_user_id, path, is_dir) do
      json(conn, result)
    else
      {:error, :missing_session} -> error(conn, 400, "Session ID is required")
      {:error, {:missing_field, message}} -> error(conn, 400, message)
      {:error, reason} -> respond_error(conn, reason)
    end
  end

  # PUT /ssh/file_manager/ssh/renameItem  body {sessionId, oldPath, newName, ...}
  def rename_item(conn, params) do
    with {:ok, host_id} <- require_session(params),
         {:ok, old_path} <-
           require_string(params, "oldPath", "Old path and new name are required"),
         {:ok, new_name} <-
           require_string(params, "newName", "Old path and new name are required"),
         {:ok, result} <-
           Sftp.rename_item(host_id, conn.assigns.current_user_id, old_path, new_name) do
      json(conn, result)
    else
      {:error, :missing_session} -> error(conn, 400, "Session ID is required")
      {:error, {:missing_field, message}} -> error(conn, 400, message)
      {:error, reason} -> respond_error(conn, reason)
    end
  end

  # PUT /ssh/file_manager/ssh/moveItem  body {sessionId, oldPath, newPath, ...}
  def move_item(conn, params) do
    with {:ok, host_id} <- require_session(params),
         {:ok, old_path} <-
           require_string(params, "oldPath", "Old path and new path are required"),
         {:ok, new_path} <-
           require_string(params, "newPath", "Old path and new path are required"),
         {:ok, result} <-
           Sftp.move_item(host_id, conn.assigns.current_user_id, old_path, new_path) do
      json(conn, result)
    else
      {:error, :missing_session} -> error(conn, 400, "Session ID is required")
      {:error, {:missing_field, message}} -> error(conn, 400, message)
      {:error, reason} -> respond_error(conn, reason)
    end
  end

  # POST /ssh/file_manager/ssh/uploadFileStream  multipart {sessionId, path, file}
  def upload_file_stream(conn, params) do
    with {:ok, host_id} <- require_session(params),
         {:ok, dir} <- require_string(params, "path", "Missing sessionId or path field"),
         {:ok, %Plug.Upload{filename: name} = upload} <- require_upload(params),
         :ok <- ensure_upload_readable(upload),
         {:ok, result} <-
           Sftp.upload_file_stream(
             host_id,
             conn.assigns.current_user_id,
             dir,
             name,
             File.stream!(upload.path, @stream_chunk_size, [])
           ) do
      json(conn, result)
    else
      {:error, :missing_session} -> error(conn, 400, "Missing sessionId or path field")
      {:error, {:missing_field, message}} -> error(conn, 400, message)
      {:error, :missing_file} -> error(conn, 400, "Missing sessionId or path field")
      {:error, reason} -> respond_error(conn, reason)
    end
  end

  # POST /ssh/file_manager/ssh/downloadFile  body {sessionId, path, ...} -> JSON base64
  def download_file(conn, params) do
    with {:ok, host_id} <- require_session(params),
         {:ok, path} <- require_string(params, "path", "Missing download parameters"),
         {:ok, result} <- Sftp.download_file(host_id, conn.assigns.current_user_id, path) do
      json(conn, result)
    else
      {:error, :missing_session} ->
        error(conn, 400, "Missing download parameters")

      {:error, {:missing_field, message}} ->
        error(conn, 400, message)

      {:error, :not_a_file} ->
        error(conn, 400, "Cannot download directories or special files")

      {:error, {:download_too_large, size}} ->
        error(conn, 400, too_large_message(size))

      {:error, reason} ->
        respond_error(conn, reason)
    end
  end

  # POST /ssh/file_manager/ssh/downloadFileStream  body {sessionId, path} -> octet-stream
  def download_file_stream(conn, params) do
    with {:ok, host_id} <- require_session(params),
         {:ok, path} <- require_string(params, "path", "Missing download parameters"),
         {:ok, download} <- Sftp.open_download(host_id, conn.assigns.current_user_id, path) do
      conn =
        conn
        |> put_resp_content_type("application/octet-stream", nil)
        |> put_resp_header(
          "content-disposition",
          ~s(attachment; filename="#{URI.encode(download.fileName)}")
        )
        |> send_chunked(200)

      # Headers are already sent, so a mid-stream failure can only truncate the download;
      # the conn returned on the error path is simply the pre-stream one.
      case Sftp.stream_download(download, conn, &write_chunk/2) do
        {:ok, conn} -> conn
        {:error, _reason} -> conn
      end
    else
      {:error, :missing_session} -> error(conn, 400, "Missing download parameters")
      {:error, {:missing_field, message}} -> error(conn, 400, message)
      {:error, :not_a_file} -> error(conn, 400, "Cannot download directories")
      {:error, reason} -> respond_error(conn, reason)
    end
  end

  # --- param validation -------------------------------------------------------

  defp non_empty(s) when is_binary(s) and s != "", do: {:ok, s}
  defp non_empty(_), do: {:error, :missing}

  # The host to probe at connect: an explicit numeric `hostId`, else the numeric
  # `sessionId` (the SPA sets sessionId to `host.id.toString()`). `Sftp.stat/3` resolves
  # ownership + decryption, so an unknown/unowned host surfaces as `:host_not_found`.
  defp connect_host_id(params, session_id) do
    case params["hostId"] do
      id when is_integer(id) -> {:ok, id}
      id when is_binary(id) and id != "" -> parse_int(id)
      _ -> parse_int(session_id)
    end
  end

  defp parse_int(s) when is_binary(s) do
    case Integer.parse(s) do
      {n, ""} -> {:ok, n}
      _ -> {:error, :missing}
    end
  end

  # The frontend renders these under the connection-log viewer (`createConnectionLog`
  # shape minus id/timestamp).
  defp log_entry(type, stage, message), do: %{type: type, stage: stage, message: message}

  # Unwrap the Sftp error envelopes into the underlying reason for the 500 message.
  defp connect_reason({:connect_failed, reason}), do: reason
  defp connect_reason({:sftp, reason}), do: reason
  defp connect_reason(reason), do: reason

  # `sessionId` is the host id; require it non-empty.
  defp require_session(params) do
    case params["sessionId"] do
      s when is_binary(s) and s != "" -> {:ok, s}
      s when is_integer(s) -> {:ok, s}
      _ -> {:error, :missing_session}
    end
  end

  defp require_string(params, key, message) do
    case params[key] do
      s when is_binary(s) and s != "" -> {:ok, s}
      _ -> {:error, {:missing_field, message}}
    end
  end

  # Mirrors Node's `content === undefined` guard: a present-but-empty string is allowed, an
  # absent key is not.
  defp require_content(params) do
    if Map.has_key?(params, "content") and is_binary(params["content"]) do
      {:ok, params["content"]}
    else
      {:error, {:missing_field, "File content is required"}}
    end
  end

  # `isDirectory` arrives as a real JSON boolean, but tolerate the stringy "true" too.
  defp truthy(true), do: true
  defp truthy("true"), do: true
  defp truthy(_), do: false

  # The multipart `file` part is delivered by Plug.Parsers as a `%Plug.Upload{}`.
  defp require_upload(params) do
    case params["file"] do
      %Plug.Upload{} = upload -> {:ok, upload}
      _ -> {:error, :missing_file}
    end
  end

  # The multipart tempfile is streamed to the host in chunks; surface an unreadable tempfile
  # in the same envelope the old whole-file `File.read` used.
  defp ensure_upload_readable(%Plug.Upload{path: path}) do
    case File.stat(path) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, {:sftp, reason}}
    end
  end

  # Per-chunk consumer for `Sftp.stream_download/3`: push the chunk to the client, threading
  # the conn (every `Plug.Conn.chunk/2` call returns it updated); abort on send failure.
  defp write_chunk(chunk, conn) do
    case Plug.Conn.chunk(conn, chunk) do
      {:ok, conn} -> {:ok, conn}
      {:error, reason} -> {:error, reason}
    end
  end

  # --- error mapping ----------------------------------------------------------

  # Shared translation for the connection/SFTP-level failures.
  defp respond_error(conn, :host_not_found),
    do: error(conn, 400, "SSH connection not established")

  defp respond_error(conn, :permission_denied), do: error(conn, 403, "Permission denied")

  defp respond_error(conn, {:connect_failed, reason}),
    do: error(conn, 500, "SSH connection failed: #{format_reason(reason)}")

  defp respond_error(conn, {:sftp, reason}),
    do: error(conn, 500, "SFTP error: #{format_reason(reason)}")

  defp respond_error(conn, reason), do: error(conn, 500, "SFTP error: #{format_reason(reason)}")

  defp format_reason(reason) when is_atom(reason), do: to_string(reason)
  defp format_reason(reason) when is_binary(reason), do: reason
  defp format_reason(reason), do: inspect(reason)

  defp max_read_size, do: 500 * 1024 * 1024

  # The JSON/base64 download path holds the whole file in memory — keep it small (see
  # `Termelix.SSH.Sftp`); larger files must go through the streamed download.
  defp max_download_size, do: 100 * 1024 * 1024

  # Mirrors the Node downloadFile message: whole-MB cap, 2-decimal actual size.
  defp too_large_message(size) do
    max_mb = div(max_download_size(), 1024 * 1024)
    file_mb = :erlang.float_to_binary(size / (1024 * 1024), decimals: 2)
    "File too large. Maximum size is #{max_mb}MB, file is #{file_mb}MB"
  end

  defp error(conn, status, message), do: conn |> put_status(status) |> json(%{error: message})
end
