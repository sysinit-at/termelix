defmodule TermelixWeb.SessionRecordingController do
  @moduledoc """
  Ports the `/session_logs` surface (`session-log-routes.ts`): list the signed-in user's
  terminal session recordings, read one recording's metadata, download its content,
  delete one, and the admin-gated retention setting.

  The `Authenticate` plug has run, so the owner is `conn.assigns.current_user_id`; ownership is
  enforced in the context (a recording owned by another user is invisible → `404`). Retention
  read/write sits in the router's admin scope (`TermelixWeb.Plugs.RequireAdmin`, 403
  `{error: "Admin access required"}`), matching Node's `permissionManager.isAdmin` check.

  Deferred (noted): the actual recording capture (asciinema) and the background retention
  pruner. Rows are created by the deferred capture pipeline, so `recordingPath` is normally
  absent here and the content route returns the Node "no recording file" `404`. The path
  allowlist + file read are ported faithfully so the surface is complete once capture lands.
  """
  use Phoenix.Controller, formats: [:json]

  import Plug.Conn

  alias Termelix.{SessionRecordings, Settings}

  @default_retention_days 30
  @min_retention_days 1
  @max_retention_days 3650

  # GET /session_logs
  def index(conn, _params) do
    records =
      conn.assigns.current_user_id
      |> SessionRecordings.list_for_user_with_host()
      |> Enum.map(&Map.put(&1, :sizeBytes, file_size(&1.recordingPath)))

    json(conn, %{logs: records})
  end

  # GET /session_logs/retention  (admin only, :admin_access pipeline)
  def retention(conn, _params), do: json(conn, %{retentionDays: retention_days()})

  # PUT /session_logs/retention  (admin only, :admin_access pipeline)
  def set_retention(conn, params) do
    if valid_retention?(params["retentionDays"]) do
      days = to_int(params["retentionDays"])
      Settings.put_value("session_recording_retention_days", Integer.to_string(days))
      json(conn, %{retentionDays: days})
    else
      error(conn, 400, "Retention must be between 1 and 3650 days")
    end
  end

  # GET /session_logs/:id
  def show(conn, %{"id" => id}) do
    with {:ok, rec_id} <- parse_id(id),
         %{} = recording <- SessionRecordings.get_for_user(conn.assigns.current_user_id, rec_id) do
      json(conn, %{log: to_map(recording)})
    else
      :error -> error(conn, 400, "Invalid id")
      nil -> error(conn, 404, "Not found")
    end
  end

  # GET /session_logs/:id/content
  def content(conn, %{"id" => id}) do
    with {:ok, rec_id} <- parse_id(id),
         %{} = recording <- SessionRecordings.get_for_user(conn.assigns.current_user_id, rec_id),
         {:ok, path} <- recording_path(recording),
         :ok <- allow_path(path),
         {:ok, body} <- read_file(path) do
      conn |> put_resp_content_type(content_type(recording, path)) |> send_resp(200, body)
    else
      :error -> error(conn, 400, "Invalid id")
      nil -> error(conn, 404, "Not found")
      {:error, :no_path} -> error(conn, 404, "No recording file")
      {:error, :forbidden} -> error(conn, 403, "Forbidden")
      {:error, :missing} -> error(conn, 404, "File not found")
    end
  end

  # DELETE /session_logs/:id
  def delete(conn, %{"id" => id}) do
    with {:ok, rec_id} <- parse_id(id),
         {:ok, recording} <-
           SessionRecordings.delete_for_user(conn.assigns.current_user_id, rec_id) do
      unlink_recording(recording.recordingPath)
      json(conn, %{success: true})
    else
      :error -> error(conn, 400, "Invalid id")
      {:error, :not_found} -> error(conn, 404, "Not found")
    end
  end

  # --- retention --------------------------------------------------------------

  # Node `getRetentionDays`: a valid stored setting wins, else a valid env value, else 30.
  defp retention_days do
    cond do
      valid_days?(setting_days()) -> setting_days()
      valid_days?(env_days()) -> env_days()
      true -> @default_retention_days
    end
  end

  defp setting_days, do: to_int(Settings.get_value("session_recording_retention_days"))
  defp env_days, do: to_int(System.get_env("SESSION_RECORDING_RETENTION_DAYS"))

  defp valid_retention?(value) do
    case to_int(value) do
      n when is_integer(n) -> valid_days?(n)
      _ -> false
    end
  end

  defp valid_days?(n) when is_integer(n),
    do: n >= @min_retention_days and n <= @max_retention_days

  defp valid_days?(_), do: false

  # --- content-file serving ---------------------------------------------------

  defp recording_path(%{recordingPath: path}) when is_binary(path) and path != "",
    do: {:ok, path}

  defp recording_path(_), do: {:error, :no_path}

  # Node `isAllowedRecordingPath`: the resolved path must live under one of the
  # recording roots. `recordings/` is where the P10 recorder
  # (`Termelix.Terminal.Recorder.directory/2`) and the retention pruner already agree
  # files live; `session_logs`/`session_recordings` are the legacy Node-era roots
  # existing rows may still point at. Without `recordings/` here, content 403s for
  # every recording this server actually produces, and a delete removes the row while
  # silently orphaning the ciphertext on the volume — the pruner finds files by
  # selecting rows, so an orphaned file is never swept.
  defp allow_path(path) do
    resolved = Path.expand(path)
    # The same resolution chain the recorder's writer (TerminalSocket) and the pruner
    # use — app env first. Reading only DATA_DIR here 403s every recording whenever
    # the directory comes from the application env rather than the environment.
    data_dir =
      Application.get_env(:termelix, :data_dir) || System.get_env("DATA_DIR") || "./db/data"

    allowed? =
      ["session_logs", "session_recordings", "recordings"]
      |> Enum.any?(fn dir ->
        base = Path.expand(dir, data_dir) <> "/"
        String.starts_with?(resolved, base)
      end)

    if allowed?, do: :ok, else: {:error, :forbidden}
  end

  defp read_file(path) do
    case File.read(path) do
      {:ok, body} -> {:ok, body}
      {:error, _} -> {:error, :missing}
    end
  end

  # A known format wins; else infer from the `.cast` extension (asciicast) or fall back to text.
  # A legacy row carrying a retired format (e.g. the removed "guacamole") falls through to
  # text/plain rather than raising.
  defp content_type(%{format: "asciicast"}, _path), do: "application/x-asciicast"
  defp content_type(%{format: "text"}, _path), do: "text/plain"

  defp content_type(_recording, path) do
    if String.ends_with?(path, ".cast"), do: "application/x-asciicast", else: "text/plain"
  end

  # Best-effort unlink of the recording file after the row is deleted (only under the allowed
  # dirs); a missing file or a path outside the allowlist is ignored.
  defp unlink_recording(path) when is_binary(path) and path != "" do
    case allow_path(path) do
      :ok -> File.rm(path)
      _ -> :ok
    end
  end

  defp unlink_recording(_), do: :ok

  # --- helpers ----------------------------------------------------------------

  defp file_size(path) when is_binary(path) and path != "" do
    case File.stat(path) do
      {:ok, %File.Stat{size: size}} -> size
      {:error, _} -> nil
    end
  end

  defp file_size(_), do: nil

  defp to_map(struct), do: struct |> Map.from_struct() |> Map.delete(:__meta__)

  # Node `parseInt(...)` + `isNaN` guard: a non-numeric id is a 400, not a 404.
  defp parse_id(id) when is_integer(id), do: {:ok, id}

  defp parse_id(id) when is_binary(id) do
    case Integer.parse(id) do
      {n, _rest} -> {:ok, n}
      :error -> :error
    end
  end

  defp parse_id(_), do: :error

  defp to_int(v) when is_integer(v), do: v

  defp to_int(v) when is_binary(v) do
    case Integer.parse(String.trim(v)) do
      {n, _} -> n
      :error -> nil
    end
  end

  defp to_int(_), do: nil

  defp error(conn, status, message), do: conn |> put_status(status) |> json(%{error: message})
end
