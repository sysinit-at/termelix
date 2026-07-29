defmodule Termelix.Terminal.RecordingPruner do
  @moduledoc """
  Deletes recordings past the retention window — the row and the file, in that order.

  The retention setting has existed since the port and has never done anything. A retention
  policy that only appears in a settings screen is worse than none: it tells an operator their
  transcripts are being aged out while the volume fills with encrypted terminal history that
  nobody deleted and nobody can read without the DEK.

  Row first, then file. The reverse leaves a row pointing at nothing, which the listing shows
  and a download 404s on; this way the worst case is an orphaned file that the next sweep
  cannot see — the same failure the `guacamole` columns are a monument to, so it also logs
  loudly enough to be noticed.

  Files outside `DATA_DIR/recordings` are never unlinked, whatever a row says. `recordingPath`
  is data, and data that decides which paths get deleted has to be constrained by something
  other than trust in whoever wrote it.
  """
  use GenServer

  require Logger

  import Ecto.Query, only: [from: 2]

  alias Termelix.Repo
  alias Termelix.Schema.SessionRecording

  # Hourly. Retention is measured in days, so a sweep an hour late is indistinguishable from
  # one on time, and hourly keeps the work per pass small.
  @interval_ms 60 * 60 * 1000
  @default_retention_days 30

  @doc false
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc """
  Sweep now, returning how many recordings were removed.

  Public so the behaviour is testable without waiting an hour, and so an operator can force a
  pass after changing the setting.
  """
  @spec sweep(keyword()) :: non_neg_integer()
  def sweep(opts \\ []) do
    days = Keyword.get_lazy(opts, :retention_days, &retention_days/0)
    root = Keyword.get_lazy(opts, :data_dir, &data_dir/0)
    cutoff = DateTime.utc_now() |> DateTime.add(-days * 86_400, :second) |> DateTime.to_iso8601()

    expired =
      Repo.all(
        from r in SessionRecording,
          where: not is_nil(r.startedAt) and r.startedAt < ^cutoff,
          select: %{id: r.id, path: r.recordingPath}
      )

    Enum.each(expired, &delete(&1, root))

    if expired != [] do
      Logger.info("recording pruner: removed #{length(expired)} recording(s) older than #{days}d")
    end

    length(expired)
  end

  @impl true
  def init(_opts), do: {:ok, %{}, {:continue, :first_sweep}}

  @impl true
  def handle_continue(:first_sweep, state) do
    # Not in `init/1`: a sweep touches the database, and a supervisor child that queries during
    # its own startup blocks every sibling behind it.
    {:noreply, tick(state)}
  end

  @impl true
  def handle_info(:sweep, state), do: {:noreply, tick(state)}
  def handle_info(_message, state), do: {:noreply, state}

  defp tick(state) do
    safely_sweep()
    Process.send_after(self(), :sweep, @interval_ms)
    state
  end

  # A pruner that crashes takes its restart budget with it and eventually stops sweeping
  # entirely — the failure mode being loud but useless. Log and try again next hour.
  defp safely_sweep do
    sweep()
  rescue
    error -> Logger.warning("recording pruner: sweep failed: #{Exception.message(error)}")
  end

  defp delete(%{id: id, path: path}, root) do
    Repo.delete_all(from r in SessionRecording, where: r.id == ^id)
    unlink(path, root)
  end

  defp unlink(nil, _root), do: :ok

  defp unlink(path, root) do
    # `recordingPath` is data. Constrained by the expanded prefix rather than by trust: a row
    # is not permitted to nominate `/etc/passwd` for deletion, whatever put it there.
    expanded = Path.expand(path)
    allowed = Path.expand(Path.join(root, "recordings"))

    if String.starts_with?(expanded, allowed <> "/") do
      case File.rm(expanded) do
        :ok -> :ok
        {:error, :enoent} -> :ok
        {:error, reason} -> Logger.warning("recording pruner: #{expanded}: #{inspect(reason)}")
      end
    else
      Logger.warning("recording pruner: refusing to unlink #{expanded} (outside #{allowed})")
    end
  end

  defp retention_days do
    case to_int(Termelix.Settings.get_value("session_recording_retention_days")) do
      days when is_integer(days) and days >= 1 and days <= 3650 -> days
      _ -> @default_retention_days
    end
  rescue
    _error -> @default_retention_days
  end

  defp data_dir,
    do: Application.get_env(:termelix, :data_dir) || System.get_env("DATA_DIR") || "data"

  defp to_int(value) when is_integer(value), do: value

  defp to_int(value) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> nil
    end
  end

  defp to_int(_value), do: nil
end
