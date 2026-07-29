defmodule Termelix.Terminal.Recorder do
  @moduledoc """
  Writes a session's output to an encrypted asciicast v2 transcript, one chunk at a time.

  ## Why a process, and why it is not the session

  The session already has a job (own the shell, fan out to a socket, survive a redeploy), and
  a recorder that lived inside it would put disk I/O on the path between the remote host and
  the operator's screen. A slow disk would show up as a slow terminal.

  So it is a separate process that receives the same chunks and is deliberately *lossy under
  its own failure*: if the recorder dies, the session does not. A missing transcript is bad; a
  terminal that dies because a transcript could not be written is worse, and the operator can
  do nothing about either in the moment.

  ## Format

  asciicast v2 — a JSON header line then one JSON array per event, `[time, "o", data]` — sealed
  chunk-by-chunk through `Termelix.Crypto.StreamEnvelope`. asciicast because it is a real
  format with real players rather than a private one nobody can read, and line-oriented so a
  partially-written file still replays up to the point it stops.

  Each envelope record holds exactly one asciicast line. That costs 20 bytes of framing per
  event and buys the property that matters: a truncated recording loses its last event, not its
  last N kilobytes, and the surviving prefix is still valid JSON lines.

  ## Timing

  Times are relative to the recording's start, in seconds with microsecond resolution, taken
  from the monotonic clock — a recording must not jump backwards because someone stepped the
  system clock during a long session.
  """
  use GenServer, restart: :temporary

  require Logger

  alias Termelix.Crypto.StreamEnvelope
  alias Termelix.SessionRecordings

  @flush_interval_ms 2_000

  # Bound on the one unbounded queue left on the terminal data path. A detached
  # session acks the SSH client immediately, so output arrives here at line rate while
  # each cast is processed synchronously (JSON encode → seal → write). Past this many
  # pending chunks the recorder drops rather than growing VM binary memory without
  # bound — recording is documented as lossy, and a lagging transcript never justifies
  # a dying node. (~1k chunks ≈ tens of MB of worst-case backlog.)
  @max_queue_len 1_000

  # A single event larger than this is split. Terminals emit big paints (a full-screen redraw,
  # a `cat` of a wide file) and a multi-megabyte JSON line is hostile to every player.
  @max_event_bytes 64 * 1024

  @type opts :: %{
          session_id: String.t(),
          user_id: String.t(),
          host_id: integer(),
          host_name: String.t(),
          key: binary(),
          cols: pos_integer(),
          rows: pos_integer(),
          dir: String.t()
        }

  @doc """
  Start recording. `key` is the caller's key material — the envelope derives a per-stream
  content key from it, so the same DEK across many recordings never reuses one.
  """
  @spec start_link(opts()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc """
  Record one chunk of output. Fire-and-forget: recording must never block the terminal.

  Returns `:dropped` instead of casting when the recorder's mailbox is past
  `@max_queue_len` — the loss is counted in telemetry, and the transcript simply has a
  gap, which an asciicast player renders as a time jump.
  """
  @spec record(pid(), binary()) :: :ok | :dropped
  def record(recorder, data) when is_binary(data) do
    case Process.info(recorder, :message_queue_len) do
      {:message_queue_len, n} when n >= @max_queue_len ->
        :telemetry.execute(
          [:termelix, :terminal, :recorder, :drop],
          %{count: 1, queue_len: n},
          %{}
        )

        if rem(n, 500) == 0,
          do: Logger.warning("recorder backlog at #{n} chunks; dropping terminal output")

        :dropped

      # `nil` = the recorder is already gone; the cast below is then a no-op, which is
      # exactly the "lossy under its own failure" contract.
      _ ->
        GenServer.cast(recorder, {:data, data})
    end
  end

  @doc "Note a resize, which asciicast carries as its own event type."
  @spec resize(pid(), pos_integer(), pos_integer()) :: :ok
  def resize(recorder, cols, rows), do: GenServer.cast(recorder, {:resize, cols, rows})

  @doc """
  Finish the recording: flush, seal the trailer, and complete the database row.

  Bounded — a recorder wedged on a slow disk must not hold up the session's shutdown, and the
  file's own trailer is what says whether it was closed cleanly.
  """
  @spec stop(pid()) :: :ok
  def stop(recorder) do
    GenServer.call(recorder, :finish, 5_000)
  catch
    :exit, _ ->
      Process.exit(recorder, :kill)
      :ok
  end

  @doc "Where a user's recordings live."
  @spec directory(String.t(), String.t()) :: String.t()
  def directory(dir, user_id), do: Path.join([dir, "recordings", user_id])

  # --- server -----------------------------------------------------------------

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    {:ok, opts, {:continue, :open}}
  end

  @impl true
  def handle_continue(:open, opts) do
    dir = directory(opts.dir, opts.user_id)
    path = Path.join(dir, "#{opts.session_id}.cast")

    with :ok <- File.mkdir_p(dir),
         {:ok, file} <- File.open(path, [:write, :binary, :raw]) do
      {header, writer} = StreamEnvelope.init(opts.key)
      :ok = IO.binwrite(file, header)

      started_at = DateTime.utc_now()
      writer = write_line(file, writer, asciicast_header(opts, started_at))

      recording = create_row(opts, path, started_at)

      {:noreply,
       %{
         file: file,
         path: path,
         writer: writer,
         opts: opts,
         started_at: started_at,
         origin: System.monotonic_time(:microsecond),
         recording_id: recording && recording.id,
         events: 0,
         bytes: 0,
         timer: schedule_flush()
       }}
    else
      {:error, reason} ->
        # A recorder that cannot open its file stops; the session carries on unrecorded. The
        # alternative — failing the terminal — trades a missing transcript for a missing shell.
        Logger.warning("recorder: cannot open #{path}: #{inspect(reason)}")
        {:stop, :normal, opts}
    end
  end

  @impl true
  def handle_cast({:data, data}, state), do: {:noreply, append(state, "o", data)}

  def handle_cast({:resize, cols, rows}, state) do
    {:noreply, append(state, "r", "#{cols}x#{rows}")}
  end

  @impl true
  def handle_call(:finish, _from, state), do: {:stop, :normal, :ok, close(state)}

  @impl true
  def handle_info(:flush, state) do
    # `:raw` files are not line-buffered, but the OS page cache still holds writes. A periodic
    # sync bounds how much a hard kill loses; every record before it is intact by construction.
    _ = :file.sync(state.file)
    {:noreply, %{state | timer: schedule_flush()}}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{file: _file} = state) do
    close(state)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  # --- writing ----------------------------------------------------------------

  defp append(state, type, data) do
    now = (System.monotonic_time(:microsecond) - state.origin) / 1_000_000

    {writer, events, bytes} =
      data
      |> chunk()
      |> Enum.reduce({state.writer, state.events, state.bytes}, fn piece, {w, e, b} ->
        w = write_line(state.file, w, [now, type, piece])
        {w, e + 1, b + byte_size(piece)}
      end)

    %{state | writer: writer, events: events, bytes: bytes}
  end

  # Terminals emit big paints; a multi-megabyte JSON line is hostile to every player, and a
  # single oversized envelope record also makes the loss from a truncated file coarser.
  defp chunk(data) when byte_size(data) <= @max_event_bytes, do: [data]

  defp chunk(data) do
    <<piece::binary-size(@max_event_bytes), rest::binary>> = data
    [piece | chunk(rest)]
  end

  defp write_line(file, writer, term) do
    {record, writer} = StreamEnvelope.seal(writer, Jason.encode!(term) <> "\n")
    :ok = IO.binwrite(file, record)
    writer
  end

  defp close(%{file: file} = state) do
    if state[:timer], do: Process.cancel_timer(state.timer)

    _ = IO.binwrite(file, StreamEnvelope.finish(state.writer))
    _ = :file.sync(file)
    _ = File.close(file)

    finish_row(state)
    Map.delete(state, :file)
  end

  defp asciicast_header(opts, started_at) do
    %{
      version: 2,
      width: opts.cols,
      height: opts.rows,
      timestamp: DateTime.to_unix(started_at),
      title: "#{opts.host_name} (#{opts.session_id})",
      env: %{"TERM" => "xterm-256color"}
    }
  end

  # --- the database row -------------------------------------------------------

  # Best-effort, both ways. A recording whose row could not be written is still on disk and
  # still readable by an operator who goes looking; a terminal that died because a row could
  # not be inserted is not.
  defp create_row(opts, path, started_at) do
    SessionRecordings.create(%{
      userId: opts.user_id,
      hostId: opts.host_id,
      startedAt: DateTime.to_iso8601(started_at),
      recordingPath: path,
      protocol: "ssh",
      format: "asciicast-v2-enc"
    })
  rescue
    error ->
      Logger.warning("recorder: could not create row: #{Exception.message(error)}")
      nil
  end

  defp finish_row(%{recording_id: nil}), do: :ok

  defp finish_row(state) do
    ended_at = DateTime.utc_now()

    SessionRecordings.finish(state.recording_id, %{
      endedAt: DateTime.to_iso8601(ended_at),
      duration: DateTime.diff(ended_at, state.started_at)
    })
  rescue
    error ->
      Logger.warning("recorder: could not finish row: #{Exception.message(error)}")
      :ok
  end

  defp schedule_flush, do: Process.send_after(self(), :flush, @flush_interval_ms)
end
