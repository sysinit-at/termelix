defmodule Termelix.SSH.Sftp do
  @moduledoc """
  Short-lived SFTP operations over OTP's native `:ssh`/`:ssh_sftp`, the engine behind the
  file manager. Ports the SFTP-based file-manager surface: read/write (`list-routes.ts`,
  `content-routes.ts`) plus the operation breadth the UI drives — create file/folder, delete
  (recursive), rename, move (`operation-routes.ts`, `operation-commands.ts`), multipart
  upload (`content-routes.ts` `uploadFileStream`) and download (`download-routes.ts`). The
  Node routes shell out over `exec` (`touch`/`mkdir -p`/`rm -rf`/`mv`); this port drives the
  equivalent `:ssh_sftp` primitives instead, recursing with `list_dir` for `rm -rf`.

  Every call resolves + decrypts the host (`Termelix.Hosts.get_for_user`, so ownership and
  DEK decryption are enforced), turns it into a credential with `Termelix.SSH.Credential`
  (the single resolver every SSH entry point shares), checks a connection out of
  `Termelix.SSH.Pool`, opens an `:ssh_sftp` channel on it, runs the operation, and closes the
  channel; the connection stays in the pool for the next operation. If the pooled connection
  refuses a channel
  (server `MaxSessions` pressure or a stale conn), the operation degrades to a dedicated
  fresh connection.

  Response maps mirror the shapes the React frontend consumes (`ssh-file-operations-api.ts`):
  `list_directory/3` -> `%{files: [...], path: ...}`, `read_file/3` ->
  `%{content, path, encoding}`, `write_file/4` -> success map. Errors are returned as tagged
  tuples the controller translates to the `{error: "..."}` envelope.
  """
  import Bitwise, only: [band: 2]
  require Record
  require Logger

  alias Termelix.Hosts
  alias Termelix.SSH.Credential
  alias Termelix.SSH.Pool

  Record.defrecordp(:file_info, Record.extract(:file_info, from_lib: "kernel/include/file.hrl"))

  @connect_timeout 15_000
  # Matches the Node readFile guard (500 MB) before pulling a file into the editor.
  @max_read_size 500 * 1024 * 1024
  # Cap for the JSON/base64 download path (Node allowed 5 GB). The whole file plus its
  # base64 encoding is held in memory on this path, so it is capped at 100 MB to keep the
  # node safe; larger files must use the streamed download.
  @max_download_size 100 * 1024 * 1024
  # Chunk size for streamed downloads and uploads (256 KB).
  @stream_chunk_size 262_144
  # Extra SFTP channels opened on the same connection to parallelize directory-listing stats.
  @stat_channel_count 8

  @s_ifmt 0o170000
  @s_ifdir 0o040000
  @s_iflnk 0o120000
  @s_ifreg 0o100000

  @months {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

  # Port of `getMimeType` (file-manager/utils.ts) — the download response echoes a mime type
  # the frontend uses to build the drag-to-desktop blob.
  @mime_types %{
    "txt" => "text/plain",
    "json" => "application/json",
    "js" => "text/javascript",
    "html" => "text/html",
    "css" => "text/css",
    "png" => "image/png",
    "jpg" => "image/jpeg",
    "jpeg" => "image/jpeg",
    "gif" => "image/gif",
    "pdf" => "application/pdf",
    "zip" => "application/zip",
    "tar" => "application/x-tar",
    "gz" => "application/gzip"
  }

  @type result :: {:ok, map()} | {:error, term()}

  # --- public API -----------------------------------------------------------

  @doc """
  List a directory on the host. Returns `{:ok, %{files: [entry], path: path}}` where each
  entry mirrors the Node SFTP listing (name/type/size/modified/permissions/owner/group/
  linkTarget/path/executable). `.`/`..` are dropped; symlink targets are resolved.

  The per-entry `lstat`/`readlink` round-trips are fanned out over up to
  #{@stat_channel_count} extra channels on the same connection (see `stat_all/4`); entry
  order matches the server's `list_dir` order exactly.
  """
  @spec list_directory(integer() | String.t(), String.t(), String.t()) :: result()
  def list_directory(host_id, user_id, path) do
    with_channel(host_id, user_id, fn conn, chan ->
      case :ssh_sftp.list_dir(chan, String.to_charlist(path), @connect_timeout) do
        {:ok, names} ->
          entries =
            names
            |> Enum.reject(&(&1 in [~c".", ~c".."]))
            |> Enum.map(&List.to_string/1)

          {:ok, %{files: stat_all(conn, chan, path, entries), path: path}}

        {:error, reason} ->
          {:error, classify(reason)}
      end
    end)
  end

  @doc """
  Read a text-or-binary file. Returns `{:ok, %{content, path, encoding}}` with `encoding`
  either `"utf8"` (content is the raw text) or `"base64"` (content is base64-encoded binary),
  matching `readSSHFile`. Files above the 500 MB cap yield `{:error, {:too_large, size}}`.
  """
  @spec read_file(integer() | String.t(), String.t(), String.t()) :: result()
  def read_file(host_id, user_id, path) do
    with_channel(host_id, user_id, fn _conn, chan ->
      pth = String.to_charlist(path)

      case :ssh_sftp.read_file_info(chan, pth, @connect_timeout) do
        {:ok, fi} ->
          size = file_info(fi, :size) || 0

          if size > @max_read_size do
            {:error, {:too_large, size}}
          else
            case :ssh_sftp.read_file(chan, pth, @connect_timeout) do
              {:ok, data} -> {:ok, content_response(data, path)}
              {:error, reason} -> {:error, classify(reason)}
            end
          end

        {:error, reason} ->
          {:error, classify(reason)}
      end
    end)
  end

  @doc """
  Write `content` to `path`, preserving the existing file's permission bits when it already
  exists (best-effort chmod, like the Node route). `content` is interpreted as base64 when it
  round-trips cleanly, otherwise as UTF-8 text. Returns `{:ok, %{message, path, toast}}`.
  """
  @spec write_file(integer() | String.t(), String.t(), String.t(), binary()) :: result()
  def write_file(host_id, user_id, path, content) do
    with_channel(host_id, user_id, fn _conn, chan ->
      pth = String.to_charlist(path)
      bytes = decode_write_content(content)
      preserved = preserved_mode(chan, pth)

      case :ssh_sftp.write_file(chan, pth, bytes, @connect_timeout) do
        :ok ->
          restore_mode(chan, pth, preserved)
          {:ok, write_success(path)}

        {:error, reason} ->
          {:error, classify(reason)}
      end
    end)
  end

  @doc """
  `stat` a path (via `lstat`, so symlinks report as such). Returns `{:ok, %{type, size,
  permissions, modified, modifiedTimestamp, owner, group, path}}`.
  """
  @spec stat(integer() | String.t(), String.t(), String.t()) :: result()
  def stat(host_id, user_id, path) do
    with_channel(host_id, user_id, fn _conn, chan ->
      case :ssh_sftp.read_link_info(chan, String.to_charlist(path), @connect_timeout) do
        {:ok, fi} -> {:ok, stat_map(fi, path)}
        {:error, reason} -> {:error, classify(reason)}
      end
    end)
  end

  @doc """
  Create an empty file `name` inside `dir` (`touch` semantics: create when missing, leave an
  existing file's content intact — never truncate). Mirrors the Node `createFile` route
  response. Returns `{:ok, %{message, path, toast}}`.
  """
  @spec create_file(integer() | String.t(), String.t(), String.t(), String.t()) :: result()
  def create_file(host_id, user_id, dir, name) do
    full = join_path(dir, name)

    with_channel(host_id, user_id, fn _conn, chan ->
      pth = String.to_charlist(full)

      case :ssh_sftp.read_file_info(chan, pth, @connect_timeout) do
        {:ok, _} ->
          # Already exists — `touch` would just bump mtime, so don't overwrite content.
          {:ok, create_file_success(full)}

        {:error, reason} when reason in [:no_such_file, :no_such_path] ->
          case :ssh_sftp.open(chan, pth, [:write], @connect_timeout) do
            {:ok, handle} ->
              :ssh_sftp.close(chan, handle, @connect_timeout)
              {:ok, create_file_success(full)}

            {:error, open_reason} ->
              {:error, classify(open_reason)}
          end

        {:error, reason} ->
          {:error, classify(reason)}
      end
    end)
  end

  @doc """
  Create directory `name` inside `dir` with `mkdir -p` semantics (intermediate directories
  are created, an already-existing target is a success). Mirrors the Node `createFolder`
  route response. Returns `{:ok, %{message, path, toast}}`.
  """
  @spec create_folder(integer() | String.t(), String.t(), String.t(), String.t()) :: result()
  def create_folder(host_id, user_id, dir, name) do
    full = join_path(dir, name)

    with_channel(host_id, user_id, fn _conn, chan ->
      case make_dir_p(chan, full) do
        :ok -> {:ok, create_folder_success(full)}
        {:error, reason} -> {:error, classify(reason)}
      end
    end)
  end

  @doc """
  Delete `path`. When `is_directory?` is true the directory is removed recursively
  (`:ssh_sftp.list_dir` + recurse, then `del_dir`), mirroring `rm -rf`; otherwise a single
  file/symlink is unlinked. Returns `{:ok, %{message, path, toast}}`.
  """
  @spec delete_item(integer() | String.t(), String.t(), String.t(), boolean()) :: result()
  def delete_item(host_id, user_id, path, is_directory?) do
    with_channel(host_id, user_id, fn _conn, chan ->
      result =
        if is_directory? do
          delete_dir_recursive(chan, path)
        else
          delete_path(chan, path)
        end

      case result do
        :ok -> {:ok, delete_success(path, is_directory?)}
        {:error, reason} -> {:error, classify(reason)}
      end
    end)
  end

  @doc """
  Rename `old_path` to `new_name` within its own directory (`mv`). `new_name` is a bare name;
  the directory is taken from `old_path`, matching the Node `renameItem` route. Returns
  `{:ok, %{message, oldPath, newPath, toast}}`.
  """
  @spec rename_item(integer() | String.t(), String.t(), String.t(), String.t()) :: result()
  def rename_item(host_id, user_id, old_path, new_name) do
    new_path = rename_target(old_path, new_name)

    with_channel(host_id, user_id, fn _conn, chan ->
      case rename(chan, old_path, new_path) do
        :ok -> {:ok, rename_success(old_path, new_path)}
        {:error, reason} -> {:error, classify(reason)}
      end
    end)
  end

  @doc """
  Move `old_path` to the fully-qualified `new_path` (`mv`), matching the Node `moveItem`
  route. Returns `{:ok, %{message, oldPath, newPath, toast}}`.
  """
  @spec move_item(integer() | String.t(), String.t(), String.t(), String.t()) :: result()
  def move_item(host_id, user_id, old_path, new_path) do
    with_channel(host_id, user_id, fn _conn, chan ->
      case rename(chan, old_path, new_path) do
        :ok -> {:ok, move_success(old_path, new_path)}
        {:error, reason} -> {:error, classify(reason)}
      end
    end)
  end

  @doc """
  Write the raw upload `bytes` to `name` inside `dir` (the multipart upload target), matching
  the Node `uploadFileStream` route. Unlike `write_file/4` the bytes are stored verbatim (no
  base64/utf8 heuristic). Returns `{:ok, %{message, path, toast}}`.
  """
  @spec upload_file(integer() | String.t(), String.t(), String.t(), String.t(), binary()) ::
          result()
  def upload_file(host_id, user_id, dir, name, bytes) do
    full = join_path(dir, name)

    with_channel(host_id, user_id, fn _conn, chan ->
      case :ssh_sftp.write_file(chan, String.to_charlist(full), bytes, @connect_timeout) do
        :ok -> {:ok, upload_success(full)}
        {:error, reason} -> {:error, classify(reason)}
      end
    end)
  end

  @doc """
  Stream an upload to `name` inside `dir` from an enumerable of binary chunks (the multipart
  upload target, matching the Node `uploadFileStream` route) — the chunked counterpart of
  `upload_file/5`, so arbitrarily large uploads never sit whole in memory. Bytes are stored
  verbatim. Returns `{:ok, %{message, path, toast}}`.
  """
  @spec upload_file_stream(
          integer() | String.t(),
          String.t(),
          String.t(),
          String.t(),
          Enumerable.t()
        ) :: result()
  def upload_file_stream(host_id, user_id, dir, name, chunks) do
    full = join_path(dir, name)

    with_channel(host_id, user_id, fn _conn, chan ->
      pth = String.to_charlist(full)

      case :ssh_sftp.open(chan, pth, [:write, :binary], @connect_timeout) do
        {:ok, handle} ->
          try do
            write_chunks(chan, handle, write_packet_size(chan), chunks)
          after
            :ssh_sftp.close(chan, handle, @connect_timeout)
          end
          |> case do
            :ok -> {:ok, upload_success(full)}
            {:error, reason} -> {:error, reason}
          end

        {:error, reason} ->
          {:error, classify(reason)}
      end
    end)
  end

  @doc """
  Read a file for download as base64, matching the Node `downloadFile` route. Rejects
  directories/special files (`{:error, :not_a_file}`) and files above the 100 MB cap
  (`{:error, {:download_too_large, size}}`; Node allowed 5 GB, but this path holds the whole
  file plus its base64 encoding in memory). Returns
  `{:ok, %{content, fileName, size, mimeType, path}}`.
  """
  @spec download_file(integer() | String.t(), String.t(), String.t()) :: result()
  def download_file(host_id, user_id, path) do
    with_channel(host_id, user_id, fn _conn, chan ->
      case read_for_download(chan, path, @max_download_size) do
        {:ok, {data, size}} ->
          name = basename(path)

          {:ok,
           %{
             content: Base.encode64(data),
             fileName: name,
             size: size,
             mimeType: mime_type(name),
             path: path
           }}

        {:error, reason} ->
          {:error, reason}
      end
    end)
  end

  @doc """
  Open a file for a streamed download (the Node `downloadFileStream` route): resolve the
  host, check out a pooled connection, reject directories/special files
  (`{:error, :not_a_file}`), and open a read handle. There is deliberately no size cap —
  the file is streamed, never buffered whole.

  Returns `{:ok, download}` where `download` is an opaque handle for `stream_download/3`
  that also carries the public `fileName`/`size` fields the controller needs for response
  headers. Every `{:ok, download}` must be handed to `stream_download/3` exactly once (it
  closes the handle and channel, and releases the connection).
  """
  @spec open_download(integer() | String.t(), String.t(), String.t()) ::
          {:ok, %{fileName: String.t(), size: non_neg_integer()}} | {:error, term()}
  def open_download(host_id, user_id, path) do
    with {:ok, host} <- resolve_host(host_id, user_id) do
      opts = conn_opts(host)

      case Pool.checkout(opts) do
        {:ok, conn} ->
          case sftp_channel(conn) do
            {:ok, chan} -> open_download_on(conn, chan, path, _close_conn? = false)
            {:error, _} -> open_download_fresh(opts, path)
          end

        {:error, reason} ->
          {:error, {:connect_failed, reason}}
      end
    end
  end

  # The pooled connection refused a channel: degrade to a dedicated connection, which
  # `stream_download/3` then closes alongside the channel (`close_conn?: true`).
  defp open_download_fresh(opts, path) do
    case Pool.fresh_conn(opts) do
      {:ok, conn} ->
        case :ssh_sftp.start_channel(conn, timeout: @connect_timeout) do
          {:ok, chan} ->
            open_download_on(conn, chan, path, _close_conn? = true)

          {:error, reason} ->
            close(conn)
            {:error, classify(reason)}
        end

      {:error, reason} ->
        {:error, {:connect_failed, reason}}
    end
  end

  defp open_download_on(conn, chan, path, close_conn?) do
    case open_read_handle(chan, path) do
      {:ok, handle, size} ->
        download = %{
          conn: conn,
          chan: chan,
          handle: handle,
          packet: read_packet_size(chan),
          close_conn?: close_conn?,
          fileName: basename(path),
          size: size
        }

        {:ok, Map.put(download, :guard, guard_download(download, self()))}

      {:error, reason} ->
        :ssh_sftp.stop_channel(chan)
        if close_conn?, do: close(conn)
        {:error, reason}
    end
  end

  @doc """
  Stream an `open_download/3` handle in #{@stream_chunk_size}-byte chunks, invoking
  `chunk_fun.(chunk, acc)` per chunk. The fun threads an accumulator — for the controller
  that accumulator is the `%Plug.Conn{}`, which `Plug.Conn.chunk/2` returns updated on every
  call. It returns `{:ok, acc}` to continue or `{:error, reason}` to abort (e.g. the client
  disconnected). Always closes the handle and channel; the connection is only closed when
  the download fell back to a dedicated one, otherwise it returns to the pool.

  Returns `{:ok, acc}` once the whole file is delivered, or `{:error, reason}` when the read
  or the consumer failed mid-stream (by then the response headers are sent, so an error can
  only truncate the download).
  """
  @spec stream_download(map(), acc, (binary(), acc -> {:ok, acc} | {:error, term()})) ::
          {:ok, acc} | {:error, term()}
        when acc: term()
  def stream_download(
        %{conn: conn, chan: chan, handle: handle, packet: packet} = download,
        acc0,
        chunk_fun
      ) do
    try do
      read_chunks(chan, handle, packet, chunk_fun, acc0)
    after
      # Stand the guard down FIRST and wait for it: it holds the same handle, and a guard that
      # fired concurrently would close an already-closed channel.
      release_guard(download)
      :ssh_sftp.close(chan, handle, @connect_timeout)
      :ssh_sftp.stop_channel(chan)
      if Map.get(download, :close_conn?, false), do: close(conn)
    end
  end

  # `open_download/3` and `stream_download/3` are two calls, and between them sits a whole
  # HTTP response: the controller sends headers, then streams. If the request process dies in
  # that window — the client hangs up, the response times out, the controller raises — nothing
  # ever ran the `after` block, so the sftp channel and (on the fallback path) a whole SSH
  # connection leaked, permanently, once per abandoned download.
  #
  # A monitor closes that. The guard holds no state beyond the handle and exits the moment
  # either side resolves, so it cannot itself become the leak.
  defp guard_download(download, owner) do
    ref = make_ref()

    case Task.Supervisor.start_child(Termelix.TaskSupervisor, fn ->
           mon = Process.monitor(owner)

           receive do
             {:release, ^ref, from} ->
               Process.demonitor(mon, [:flush])
               send(from, {:released, ref})

             {:DOWN, ^mon, :process, ^owner, reason} ->
               Logger.warning(
                 "sftp download abandoned (owner #{inspect(reason)}); closing channel"
               )

               close_download(download)
           end
         end) do
      {:ok, pid} -> {pid, ref}
      # No guard is worse than a guard, but it is not a reason to fail the download.
      _error -> nil
    end
  end

  defp release_guard(%{guard: {pid, ref}}) do
    send(pid, {:release, ref, self()})

    receive do
      {:released, ^ref} -> :ok
    after
      # The guard is already gone (it fired, or the supervisor stopped it). Either way it is
      # not going to touch this handle after this point.
      @connect_timeout -> :ok
    end
  end

  defp release_guard(_download), do: :ok

  defp close_download(%{conn: conn, chan: chan, handle: handle} = download) do
    :ssh_sftp.close(chan, handle, @connect_timeout)
    :ssh_sftp.stop_channel(chan)
    if Map.get(download, :close_conn?, false), do: close(conn)
  catch
    _, _ -> :ok
  end

  # --- connection lifecycle -------------------------------------------------

  # Resolve+decrypt the host, check out a pooled connection, open an sftp channel on it
  # (with an explicit 15 s timeout — `:ssh_sftp.start_channel/1` defaults to `:infinity`),
  # run `fun`, and always stop the channel. The connection itself stays in the pool.
  # `fun` receives both the connection (for operations that fan extra channels out over
  # it, like `list_directory/3`) and the channel.
  defp with_channel(host_id, user_id, fun) do
    with {:ok, host} <- resolve_host(host_id, user_id) do
      opts = conn_opts(host)

      case Pool.checkout(opts) do
        {:ok, conn} ->
          case sftp_channel(conn) do
            {:ok, chan} ->
              try do
                fun.(conn, chan)
              after
                :ssh_sftp.stop_channel(chan)
              end

            {:error, _} ->
              with_fresh_channel(opts, fun)
          end

        {:error, reason} ->
          {:error, {:connect_failed, reason}}
      end
    end
  end

  # The pooled connection refused a channel (server MaxSessions pressure, or a stale conn
  # on its way down): degrade to a dedicated connection for this one operation — the
  # pre-pool behavior for every operation.
  defp with_fresh_channel(opts, fun) do
    case Pool.fresh_conn(opts) do
      {:ok, conn} ->
        try do
          case :ssh_sftp.start_channel(conn, timeout: @connect_timeout) do
            {:ok, chan} ->
              try do
                fun.(conn, chan)
              after
                :ssh_sftp.stop_channel(chan)
              end

            {:error, reason} ->
              {:error, classify(reason)}
          end
        after
          close(conn)
        end

      {:error, reason} ->
        {:error, {:connect_failed, reason}}
    end
  end

  # `start_channel` on a dead pooled conn raises (a gen call to a vanished pid) instead of
  # returning an error tuple; both shapes mean "try a dedicated connection".
  defp sftp_channel(conn) do
    case :ssh_sftp.start_channel(conn, timeout: @connect_timeout) do
      {:ok, chan} -> {:ok, chan}
      {:error, reason} -> {:error, reason}
    end
  catch
    :exit, _ -> {:error, :conn_down}
  end

  defp resolve_host(host_id, user_id) do
    case normalize_id(host_id) do
      nil ->
        {:error, :host_not_found}

      id ->
        case Hosts.fetch_for_connect(id, user_id) do
          {:ok, host} -> {:ok, host}
          {:error, :locked} -> {:error, :data_locked}
          {:error, :not_found} -> {:error, :host_not_found}
        end
    end
  end

  defp normalize_id(id) when is_integer(id), do: id

  defp normalize_id(id) when is_binary(id) do
    case Integer.parse(id) do
      {n, ""} -> n
      _ -> nil
    end
  end

  defp normalize_id(_), do: nil

  # The `conn_opts` shape `Termelix.SSH.Pool` expects, with the authentication method resolved
  # from the host row's `authType` instead of the local password-over-key `cond` this used to
  # reproduce. The result is a plain map (not a struct) on purpose: `Pool.key_for/1` reads it
  # with `opts[:password]`, and structs do not implement Access. The extra keys it now carries
  # (`:auth`, `:host_id`, `:host_key`) are ignored by `key_for/1`, so pooled connections still
  # bucket by host + credentials exactly as before.
  defp conn_opts(host), do: Credential.resolve(host)

  defp close(conn) do
    :ssh.close(conn)
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  # --- directory entries ----------------------------------------------------

  # Stat every entry of a listing. One `lstat` (+ `readlink` for symlinks) round-trip per
  # entry on a single channel makes large directories painfully serial, so the work is fanned
  # out over up to @stat_channel_count extra channels on the same connection: entries are
  # split into contiguous groups — one group per channel, so no channel is ever shared
  # between concurrent tasks — each group is mapped sequentially inside a task, and the
  # groups are reassembled in the original `list_dir` order. Falls back to the main channel
  # when the server refuses extra channels.
  defp stat_all(_conn, chan, path, entries) when length(entries) < 2 do
    Enum.map(entries, &build_entry(chan, path, &1))
  end

  defp stat_all(conn, chan, path, entries) do
    case open_stat_channels(conn, min(@stat_channel_count, length(entries))) do
      {:ok, chans} ->
        try do
          parallel_stat(chans, path, entries)
        after
          Enum.each(chans, &:ssh_sftp.stop_channel/1)
        end

      :error ->
        Enum.map(entries, &build_entry(chan, path, &1))
    end
  end

  # Open up to `count` extra SFTP channels on the same connection. On any failure, close
  # what was opened and return `:error` so the caller falls back to the sequential path.
  defp open_stat_channels(conn, count) do
    Enum.reduce_while(1..count, {:ok, []}, fn _, {:ok, chans} ->
      case :ssh_sftp.start_channel(conn, timeout: @connect_timeout) do
        {:ok, chan} -> {:cont, {:ok, [chan | chans]}}
        {:error, _reason} -> {:halt, {:partial, chans}}
      end
    end)
    |> case do
      {:ok, chans} ->
        {:ok, chans}

      {:partial, chans} ->
        Enum.each(chans, &:ssh_sftp.stop_channel/1)
        :error
    end
  end

  defp parallel_stat(chans, path, entries) do
    group_count = length(chans)
    group_size = div(length(entries) + group_count - 1, group_count)
    groups = Enum.chunk_every(entries, group_size)

    # No outer deadline: every `:ssh_sftp` call inside `build_entry/3` carries the same 15 s
    # per-call timeout the sequential path used. The stream runs unlinked via the task
    # supervisor: a group task that crashes unexpectedly yields an `{:exit, _}` element
    # (instead of killing the request process), which `merge_stat_results/2` degrades to
    # placeholder entries — one bad group can't 500 the whole listing. `ordered: true` keeps
    # results aligned with their source groups for that recovery.
    zipped = Enum.zip(chans, groups)

    Task.Supervisor.async_stream_nolink(
      Termelix.TaskSupervisor,
      zipped,
      fn {chan, group} -> Enum.map(group, &build_entry(chan, path, &1)) end,
      max_concurrency: group_count,
      timeout: :infinity,
      ordered: true
    )
    |> Enum.zip(groups)
    |> merge_stat_results(path)
  end

  @doc false
  # Reassemble `Task.Supervisor.async_stream_nolink` results — each paired with its source
  # group, in `list_dir` order — into one flat entry list. A successful group contributes its
  # built entries; a group whose stat task crashed (`{:exit, _}`, e.g. a channel that died
  # mid-group) is degraded to `unknown_entry` entries rather than 500ing the entire listing —
  # the same degradation `build_entry/3` already applies to its own per-entry `lstat` failures.
  # Public only so this recovery path can be unit-tested without forcing a live channel crash.
  def merge_stat_results(results_with_groups, path) do
    Enum.flat_map(results_with_groups, fn
      {{:ok, built}, _group} -> built
      {{:exit, _reason}, group} -> Enum.map(group, &unknown_entry(&1, join_path(path, &1)))
    end)
  end

  defp build_entry(chan, dir, name) do
    full = join_path(dir, name)

    case :ssh_sftp.read_link_info(chan, String.to_charlist(full), @connect_timeout) do
      {:ok, fi} -> entry_from_info(fi, name, full, chan)
      {:error, _} -> unknown_entry(name, full)
    end
  end

  defp entry_from_info(fi, name, full, chan) do
    mode = file_info(fi, :mode) || 0
    type_bits = band(mode, @s_ifmt)
    is_dir = type_bits == @s_ifdir
    is_link = type_bits == @s_iflnk
    permissions = mode_to_permissions(mode)
    mtime = file_info(fi, :mtime)
    ts = datetime_to_unix(mtime)

    base = %{
      name: name,
      type: type_string(is_dir, is_link),
      modified: format_mtime(mtime, ts),
      modifiedTimestamp: ts,
      permissions: permissions,
      owner: to_string(file_info(fi, :uid)),
      group: to_string(file_info(fi, :gid)),
      path: full,
      executable: not is_dir and not is_link and executable?(permissions, name)
    }

    base
    # `size` is omitted for directories (Node emits `undefined`), present otherwise.
    |> maybe_put(:size, if(is_dir, do: nil, else: file_info(fi, :size)))
    # `linkTarget` only present for symlinks whose target resolves.
    |> maybe_put(:linkTarget, if(is_link, do: read_link_target(chan, full), else: nil))
  end

  # An entry we could not `lstat` (rare — e.g. lost during the listing). Emit a best-effort
  # regular-file shape rather than dropping it.
  defp unknown_entry(name, full) do
    %{
      name: name,
      type: "file",
      size: 0,
      modified: "",
      modifiedTimestamp: 0,
      permissions: "----------",
      owner: "0",
      group: "0",
      path: full,
      executable: false
    }
  end

  defp read_link_target(chan, full) do
    case :ssh_sftp.read_link(chan, String.to_charlist(full), @connect_timeout) do
      {:ok, target} -> List.to_string(target)
      _ -> nil
    end
  end

  defp stat_map(fi, path) do
    mode = file_info(fi, :mode) || 0
    type_bits = band(mode, @s_ifmt)
    is_dir = type_bits == @s_ifdir
    is_link = type_bits == @s_iflnk
    mtime = file_info(fi, :mtime)
    ts = datetime_to_unix(mtime)

    %{
      type: type_string(is_dir, is_link),
      size: file_info(fi, :size) || 0,
      permissions: mode_to_permissions(mode),
      modified: format_mtime(mtime, ts),
      modifiedTimestamp: ts,
      owner: to_string(file_info(fi, :uid)),
      group: to_string(file_info(fi, :gid)),
      path: path
    }
  end

  # --- file-manager operations ----------------------------------------------

  # `mkdir -p`: walk the path components from the root, creating each missing directory and
  # treating an already-present directory as success (never re-`make_dir` an existing one, so
  # we don't depend on the server's "already exists" error atom).
  defp make_dir_p(chan, path) do
    absolute? = String.starts_with?(path, "/")

    path
    |> String.split("/", trim: true)
    |> Enum.reduce_while({:ok, ""}, fn comp, {_res, acc} ->
      current =
        cond do
          acc == "" and absolute? -> "/" <> comp
          acc == "" -> comp
          true -> acc <> "/" <> comp
        end

      case ensure_dir(chan, current) do
        :ok -> {:cont, {:ok, current}}
        {:error, reason} -> {:halt, {{:error, reason}, current}}
      end
    end)
    |> elem(0)
  end

  defp ensure_dir(chan, path) do
    pth = String.to_charlist(path)

    case :ssh_sftp.read_file_info(chan, pth, @connect_timeout) do
      {:ok, fi} ->
        if directory?(fi), do: :ok, else: {:error, :not_a_directory}

      {:error, _} ->
        :ssh_sftp.make_dir(chan, pth, @connect_timeout)
    end
  end

  # `rm -rf`: empty a directory (recursing into sub-directories) then remove it.
  defp delete_dir_recursive(chan, path) do
    case :ssh_sftp.list_dir(chan, String.to_charlist(path), @connect_timeout) do
      {:ok, names} ->
        names
        |> Enum.reject(&(&1 in [~c".", ~c".."]))
        |> Enum.reduce_while(:ok, fn name, :ok ->
          case delete_entry(chan, join_path(path, List.to_string(name))) do
            :ok -> {:cont, :ok}
            {:error, reason} -> {:halt, {:error, reason}}
          end
        end)
        |> case do
          :ok -> del_dir(chan, path)
          error -> error
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # A child of a directory being deleted: recurse for real directories, unlink everything
  # else (files and symlinks — `lstat` reports a symlink as such, so we remove the link).
  defp delete_entry(chan, path) do
    case :ssh_sftp.read_link_info(chan, String.to_charlist(path), @connect_timeout) do
      {:ok, fi} ->
        if directory?(fi), do: delete_dir_recursive(chan, path), else: delete_path(chan, path)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp delete_path(chan, path) do
    :ssh_sftp.delete(chan, String.to_charlist(path), @connect_timeout)
  end

  defp del_dir(chan, path) do
    :ssh_sftp.del_dir(chan, String.to_charlist(path), @connect_timeout)
  end

  defp rename(chan, from, to) do
    :ssh_sftp.rename(chan, String.to_charlist(from), String.to_charlist(to), @connect_timeout)
  end

  # Node: `oldDir = oldPath.slice(0, lastIndexOf("/") + 1); newPath = oldDir + newName`.
  defp rename_target(old_path, new_name) do
    case last_slash_index(old_path) do
      nil -> new_name
      i -> binary_part(old_path, 0, i + 1) <> new_name
    end
  end

  defp last_slash_index(str) do
    case :binary.matches(str, "/") do
      [] -> nil
      matches -> matches |> List.last() |> elem(0)
    end
  end

  # Shared download read: stat (following symlinks, like Node's `sftp.stat`), reject
  # non-regular files, enforce the caller's size cap, then pull the whole file.
  defp read_for_download(chan, path, max_size) do
    pth = String.to_charlist(path)

    case :ssh_sftp.read_file_info(chan, pth, @connect_timeout) do
      {:ok, fi} ->
        size = file_info(fi, :size) || 0

        cond do
          not regular_file?(fi) ->
            {:error, :not_a_file}

          size > max_size ->
            {:error, {:download_too_large, size}}

          true ->
            case :ssh_sftp.read_file(chan, pth, @connect_timeout) do
              {:ok, data} -> {:ok, {data, size}}
              {:error, reason} -> {:error, classify(reason)}
            end
        end

      {:error, reason} ->
        {:error, classify(reason)}
    end
  end

  # Stat (following symlinks, like `read_for_download/3`), reject non-regular files, and open
  # a read handle for a streamed download. No size cap — the file is never buffered whole.
  defp open_read_handle(chan, path) do
    pth = String.to_charlist(path)

    case :ssh_sftp.read_file_info(chan, pth, @connect_timeout) do
      {:ok, fi} ->
        if regular_file?(fi) do
          case :ssh_sftp.open(chan, pth, [:read, :binary], @connect_timeout) do
            {:ok, handle} -> {:ok, handle, file_info(fi, :size) || 0}
            {:error, reason} -> {:error, classify(reason)}
          end
        else
          {:error, :not_a_file}
        end

      {:error, reason} ->
        {:error, classify(reason)}
    end
  end

  # One delivery chunk is @stream_chunk_size bytes, but a single SSH_FXP_READ of that size
  # is unreliable (servers cap a read at SSH_MAX_PACKET_SIZE - 1024 and the excess bytes are
  # lost), so each chunk is assembled from negotiated-packet-sized reads — the same unit
  # OTP's own `read_file`/`read_repeat` loops use.
  defp read_chunks(chan, handle, packet, chunk_fun, acc) do
    case read_chunk(chan, handle, packet, @stream_chunk_size, []) do
      {:ok, chunk} ->
        case chunk_fun.(chunk, acc) do
          {:ok, acc} -> read_chunks(chan, handle, packet, chunk_fun, acc)
          {:error, reason} -> {:error, reason}
        end

      :eof ->
        {:ok, acc}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp read_chunk(chan, handle, packet, remaining, acc) do
    case :ssh_sftp.read(chan, handle, min(remaining, packet), @connect_timeout) do
      {:ok, data} when byte_size(data) > 0 ->
        remaining = remaining - byte_size(data)

        if remaining == 0 do
          {:ok, IO.iodata_to_binary(Enum.reverse([data | acc]))}
        else
          read_chunk(chan, handle, packet, remaining, [data | acc])
        end

      {:error, reason} ->
        {:error, classify(reason)}

      # :eof, or a (pathological) empty non-eof read: deliver what we have, if anything.
      _ ->
        case acc do
          [] -> :eof
          _ -> {:ok, IO.iodata_to_binary(Enum.reverse(acc))}
        end
    end
  end

  defp write_chunks(chan, handle, packet, chunks) do
    Enum.reduce_while(chunks, :ok, fn chunk, :ok ->
      case write_piece(chan, handle, packet, chunk) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  # Write one local chunk in negotiated-packet-sized pieces (the same unit OTP's
  # `write_file` loop uses — a single oversized SSH_FXP_WRITE is rejected by the server).
  defp write_piece(chan, handle, packet, chunk) do
    case chunk do
      <<piece::binary-size(^packet), rest::binary>> ->
        case :ssh_sftp.write(chan, handle, piece, @connect_timeout) do
          :ok -> write_piece(chan, handle, packet, rest)
          {:error, reason} -> {:error, classify(reason)}
        end

      _ ->
        case :ssh_sftp.write(chan, handle, chunk, @connect_timeout) do
          :ok -> :ok
          {:error, reason} -> {:error, classify(reason)}
        end
    end
  end

  # The negotiated read packet size for this channel (65536 by default); 65536 is a safe
  # fallback if the query fails.
  defp read_packet_size(chan) do
    case :ssh_sftp.recv_window(chan, @connect_timeout) do
      {:ok, {_window, packet}} -> packet
      _ -> 65_536
    end
  end

  defp write_packet_size(chan) do
    case :ssh_sftp.send_window(chan, @connect_timeout) do
      {:ok, {_window, packet}} -> packet
      _ -> 65_536
    end
  end

  # Node: `filePath.split("/").pop() || "download"`.
  defp basename(path) do
    case path |> String.split("/") |> List.last() do
      name when is_binary(name) and name != "" -> name
      _ -> "download"
    end
  end

  defp mime_type(name) do
    ext = name |> String.split(".") |> List.last() |> String.downcase()
    Map.get(@mime_types, ext, "application/octet-stream")
  end

  defp directory?(fi), do: band(file_info(fi, :mode) || 0, @s_ifmt) == @s_ifdir
  defp regular_file?(fi), do: band(file_info(fi, :mode) || 0, @s_ifmt) == @s_ifreg

  # --- operation response maps (mirror the Node route bodies) ---------------

  defp create_file_success(path) do
    %{
      message: "File created successfully",
      path: path,
      toast: %{type: "success", message: "File created: #{path}"}
    }
  end

  defp create_folder_success(path) do
    %{
      message: "Folder created successfully",
      path: path,
      toast: %{type: "success", message: "Folder created: #{path}"}
    }
  end

  defp delete_success(path, is_directory?) do
    kind = if is_directory?, do: "Directory", else: "File"

    %{
      message: "Item deleted successfully",
      path: path,
      toast: %{type: "success", message: "#{kind} deleted: #{path}"}
    }
  end

  defp rename_success(old_path, new_path) do
    %{
      message: "Item renamed successfully",
      oldPath: old_path,
      newPath: new_path,
      toast: %{type: "success", message: "Item renamed: #{old_path} -> #{new_path}"}
    }
  end

  defp move_success(old_path, new_path) do
    %{
      message: "Item moved successfully",
      oldPath: old_path,
      newPath: new_path,
      toast: %{type: "success", message: "Item moved: #{old_path} -> #{new_path}"}
    }
  end

  defp upload_success(path) do
    %{
      message: "File uploaded successfully",
      path: path,
      toast: %{type: "success", message: "File uploaded: #{path}"}
    }
  end

  # --- content helpers ------------------------------------------------------

  defp content_response(data, path) do
    if detect_binary?(data) do
      %{content: Base.encode64(data), path: path, encoding: "base64"}
    else
      %{content: data, path: path, encoding: "utf8"}
    end
  end

  defp write_success(path) do
    %{
      message: "File written successfully",
      path: path,
      toast: %{type: "success", message: "File written: #{path}"}
    }
  end

  # Mirrors the Node heuristic: treat `content` as base64 only when it decodes and re-encodes
  # to the exact same string; otherwise write it as UTF-8 text. `Base.decode64/1` is already
  # strict (valid alphabet, length, and padding placement), so the re-encode comparison only
  # ever rejects *non-canonical* padding — discarded bits that are not zero, e.g. "aGj="
  # (decodes to "hh" but re-encodes to "aGk="). Checking that takes a constant-time look at
  # the final quantum instead of a full-content re-encode + compare, with identical outcomes.
  defp decode_write_content(content) when is_binary(content) do
    case Base.decode64(content) do
      {:ok, decoded} -> if canonical_base64?(content), do: decoded, else: content
      :error -> content
    end
  end

  defp decode_write_content(content), do: to_string(content)

  # A strict-decodable string re-encodes to itself iff the bits discarded by the padding are
  # zero (or there is no padding). Only reachable after a successful strict decode, so the
  # final characters are guaranteed to be alphabet chars (or "=").
  defp canonical_base64?(content) do
    size = byte_size(content)

    cond do
      # Only "" is shorter than one quantum; it round-trips trivially.
      size < 4 ->
        true

      # "xx==": 2 chars encode 1 byte (8 of 12 bits) — low 4 bits of the 2nd char must be 0.
      :binary.at(content, size - 2) == ?= ->
        band(b64_value(:binary.at(content, size - 3)), 0xF) == 0

      # "xxx=": 3 chars encode 2 bytes (16 of 18 bits) — low 2 bits of the 3rd char must be 0.
      :binary.at(content, size - 1) == ?= ->
        band(b64_value(:binary.at(content, size - 2)), 0x3) == 0

      # No padding and a strict-decodable length: every bit is significant.
      true ->
        true
    end
  end

  defp b64_value(c) when c in ?A..?Z, do: c - ?A
  defp b64_value(c) when c in ?a..?z, do: c - ?a + 26
  defp b64_value(c) when c in ?0..?9, do: c - ?0 + 52
  defp b64_value(?+), do: 62
  defp b64_value(?/), do: 63

  # Best-effort: capture the existing regular file's permission bits so `write_file` can
  # restore them afterwards (a truncating write can otherwise reset the mode).
  defp preserved_mode(chan, pth) do
    case :ssh_sftp.read_file_info(chan, pth, @connect_timeout) do
      {:ok, fi} ->
        mode = file_info(fi, :mode) || 0
        if band(mode, @s_ifmt) == @s_ifreg, do: band(mode, 0o7777), else: nil

      _ ->
        nil
    end
  end

  defp restore_mode(_chan, _pth, nil), do: :ok

  defp restore_mode(chan, pth, mode) do
    :ssh_sftp.write_file_info(chan, pth, file_info(mode: mode), @connect_timeout)
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  # Port of `detectBinary`: any NUL byte, or >1 stray control byte, or >1% control density.
  defp detect_binary?(data) when byte_size(data) == 0, do: false

  defp detect_binary?(data) do
    size = min(byte_size(data), 8192)
    sample = binary_part(data, 0, size)

    result =
      sample
      |> :binary.bin_to_list()
      |> Enum.reduce_while(0, fn byte, acc ->
        acc = if byte == 0, do: acc + 1, else: acc

        if byte < 32 and byte != 9 and byte != 10 and byte != 13 do
          acc2 = acc + 1
          if acc2 > 1, do: {:halt, :binary}, else: {:cont, acc2}
        else
          {:cont, acc}
        end
      end)

    case result do
      :binary -> true
      count -> count / size > 0.01
    end
  end

  # --- mode / permission / time formatting ----------------------------------

  defp type_string(true, _), do: "directory"
  defp type_string(false, true), do: "link"
  defp type_string(false, false), do: "file"

  # Port of `modeToPermissions`: "drwxr-xr-x" style string.
  defp mode_to_permissions(mode) do
    prefix =
      case band(mode, @s_ifmt) do
        @s_ifdir -> "d"
        @s_iflnk -> "l"
        _ -> "-"
      end

    bits = [
      {0o400, "r"},
      {0o200, "w"},
      {0o100, "x"},
      {0o040, "r"},
      {0o020, "w"},
      {0o010, "x"},
      {0o004, "r"},
      {0o002, "w"},
      {0o001, "x"}
    ]

    perms = Enum.map_join(bits, fn {bit, ch} -> if band(mode, bit) != 0, do: ch, else: "-" end)
    prefix <> perms
  end

  # Port of `isExecutableFile`.
  @script_exts ~w(.sh .py .pl .rb .js .php .bash .zsh .fish)
  @exec_exts ~w(.bin .exe .out)

  defp executable?(permissions, name) do
    has_exec =
      String.at(permissions, 3) == "x" or String.at(permissions, 6) == "x" or
        String.at(permissions, 9) == "x"

    lower = String.downcase(name)
    has_script = Enum.any?(@script_exts, &String.ends_with?(lower, &1))
    has_exec_ext = Enum.any?(@exec_exts, &String.ends_with?(lower, &1))
    has_no_ext = not String.contains?(name, ".") and has_exec

    has_exec and (has_script or has_exec_ext or has_no_ext)
  end

  # `:ssh_sftp` returns times as a *local* datetime tuple; convert back to Unix seconds
  # (inverse of ssh_sftp's own `unix_to_datetime`).
  defp datetime_to_unix({{_, _, _}, {_, _, _}} = local) do
    utc = :erlang.localtime_to_universaltime(local)
    :calendar.datetime_to_gregorian_seconds(utc) - 62_167_219_200
  end

  defp datetime_to_unix(_), do: 0

  # Port of `formatMtime`, formatting from the same local datetime.
  defp format_mtime({{year, month, day}, {hour, minute, _sec}}, ts) do
    mon = elem(@months, month - 1)
    day_str = String.pad_leading(Integer.to_string(day), 2, " ")
    six_months_ago = System.system_time(:second) - 180 * 24 * 60 * 60

    if ts > six_months_ago do
      "#{mon} #{day_str} #{pad0(hour)}:#{pad0(minute)}"
    else
      "#{mon} #{day_str}  #{year}"
    end
  end

  defp format_mtime(_, _), do: ""

  defp pad0(n), do: String.pad_leading(Integer.to_string(n), 2, "0")

  # --- small helpers --------------------------------------------------------

  defp join_path(dir, name) do
    if String.ends_with?(dir, "/"), do: dir <> name, else: dir <> "/" <> name
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  # Normalize `:ssh_sftp` error reasons into the tags the controller maps to HTTP codes.
  defp classify(reason) when reason in [:no_such_file, :no_such_path], do: :not_found
  defp classify(:permission_denied), do: :permission_denied
  defp classify(reason), do: {:sftp, reason}
end
