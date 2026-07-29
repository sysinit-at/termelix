defmodule Termelix.Terminal.RecorderTest do
  @moduledoc """
  A transcript is a verbatim copy of everything on an operator's screen — passwords they typed
  at a prompt included. So the tests are about two things: that it is genuinely encrypted at
  rest, and that a session which dies badly still leaves something readable.
  """
  use Termelix.DataCase, async: false

  alias Termelix.Crypto.StreamEnvelope
  alias Termelix.{Accounts, Hosts, SessionRecordings}
  alias Termelix.Terminal.{Recorder, RecordingPruner}

  @key :crypto.strong_rand_bytes(32)

  setup do
    {:ok, user, _} = Accounts.register_user("rec-#{unique()}", "password-123-abc")

    {:ok, host} =
      Hosts.create_host(user.id, %{
        name: "rec-host",
        ip: "127.0.0.1",
        port: 22,
        username: "t",
        authType: "password",
        password: "s"
      })

    dir = Path.join(System.tmp_dir!(), "termelix_rec_#{unique()}")
    on_exit(fn -> File.rm_rf(dir) end)

    %{user: user, host: host, dir: dir}
  end

  defp unique, do: System.unique_integer([:positive])

  defp opts(ctx, overrides \\ %{}) do
    Map.merge(
      %{
        session_id: "sess-#{unique()}",
        user_id: ctx.user.id,
        host_id: ctx.host.id,
        host_name: ctx.host.name,
        key: @key,
        cols: 80,
        rows: 24,
        dir: ctx.dir
      },
      overrides
    )
  end

  defp read(path, key \\ @key), do: path |> File.read!() |> StreamEnvelope.open(key)

  describe "the transcript" do
    test "is asciicast v2, and replays what the shell printed", ctx do
      o = opts(ctx)
      {:ok, rec} = Recorder.start_link(o)

      Recorder.record(rec, "hello ")
      Recorder.record(rec, "world\r\n")
      :ok = Recorder.stop(rec)

      path = Path.join(Recorder.directory(ctx.dir, ctx.user.id), "#{o.session_id}.cast")
      assert {:ok, text} = read(path)

      [header | events] = text |> String.split("\n", trim: true) |> Enum.map(&Jason.decode!/1)

      assert header["version"] == 2
      assert header["width"] == 80
      assert header["height"] == 24

      # `[time, "o", data]` — the format real players read, not a private one nobody can open.
      assert [[t1, "o", "hello "], [t2, "o", "world\r\n"]] = events
      assert is_number(t1) and is_number(t2) and t2 >= t1
    end

    test "is ENCRYPTED at rest — the plaintext is not in the file", ctx do
      o = opts(ctx)
      {:ok, rec} = Recorder.start_link(o)

      # What an operator types at a `read -s` prompt is echoed by many tools, so it lands here.
      Recorder.record(rec, "hunter2-super-secret")
      :ok = Recorder.stop(rec)

      path = Path.join(Recorder.directory(ctx.dir, ctx.user.id), "#{o.session_id}.cast")
      raw = File.read!(path)

      refute raw =~ "hunter2-super-secret"
      assert {:error, _} = StreamEnvelope.open(raw, :crypto.strong_rand_bytes(32))
      assert {:ok, text} = read(path)
      assert text =~ "hunter2-super-secret"
    end

    test "records a resize as its own event", ctx do
      o = opts(ctx)
      {:ok, rec} = Recorder.start_link(o)
      Recorder.resize(rec, 120, 40)
      :ok = Recorder.stop(rec)

      path = Path.join(Recorder.directory(ctx.dir, ctx.user.id), "#{o.session_id}.cast")
      assert {:ok, text} = read(path)
      assert text =~ ~s(,"r","120x40")
    end

    test "a huge paint is split, so no single line is hostile to a player", ctx do
      o = opts(ctx)
      {:ok, rec} = Recorder.start_link(o)
      Recorder.record(rec, :binary.copy("x", 200 * 1024))
      :ok = Recorder.stop(rec)

      path = Path.join(Recorder.directory(ctx.dir, ctx.user.id), "#{o.session_id}.cast")
      assert {:ok, text} = read(path)

      events = text |> String.split("\n", trim: true) |> tl()
      assert length(events) >= 4
      assert Enum.all?(events, &(byte_size(&1) < 100 * 1024))

      rejoined = events |> Enum.map(&(Jason.decode!(&1) |> Enum.at(2))) |> Enum.join()
      assert byte_size(rejoined) == 200 * 1024
    end

    test "drops output past the queue watermark instead of growing without bound", ctx do
      # A detached session acks the SSH client immediately, so a `yes`-class producer
      # arrives at line rate while each cast is written synchronously. The recorder
      # sheds load past the watermark: a gap in the transcript, never a dying node.
      o = opts(ctx)
      {:ok, rec} = Recorder.start_link(o)
      _ = :sys.get_state(rec)
      :ok = :sys.suspend(rec)

      results = for _ <- 1..1_100, do: Recorder.record(rec, "x")

      :ok = :sys.resume(rec)

      cast = Enum.count(results, &(&1 == :ok))
      dropped = Enum.count(results, &(&1 == :dropped))

      assert cast <= 1_000
      assert dropped >= 100
      assert cast + dropped == 1_100

      :ok = Recorder.stop(rec)
    end
  end

  describe "a session that dies badly" do
    test "still leaves a readable transcript, marked unterminated", ctx do
      o = opts(ctx)
      {:ok, rec} = Recorder.start_link(o)
      Recorder.record(rec, "work-that-happened\r\n")

      # Force the cast to be processed before the kill, so this tests an interrupted CLOSE
      # rather than a lost message.
      :sys.get_state(rec)

      # Unlink first: `start_link` ties the recorder to this process, and the point here is to
      # kill the RECORDER, not the test.
      Process.unlink(rec)
      ref = Process.monitor(rec)
      Process.exit(rec, :kill)
      assert_receive {:DOWN, ^ref, :process, ^rec, _}, 5000

      path = Path.join(Recorder.directory(ctx.dir, ctx.user.id), "#{o.session_id}.cast")

      # No trailer, because nothing got to write one — and the bytes are still worth reading.
      assert {:ok, text, :unterminated} = read(path)
      assert text =~ "work-that-happened"
    end

    test "the database row exists from the START, not only on clean shutdown", ctx do
      o = opts(ctx)
      {:ok, rec} = Recorder.start_link(o)
      :sys.get_state(rec)

      # A row written only at the end would mean exactly the recordings an operator most wants
      # — the ones from a session that crashed — are the ones that never get listed.
      rows = SessionRecordings.list_for_user_with_host(ctx.user.id)
      assert length(rows) == 1

      Process.unlink(rec)
      Process.exit(rec, :kill)
      assert length(SessionRecordings.list_for_user_with_host(ctx.user.id)) == 1
    end
  end

  describe "the pruner" do
    test "deletes rows and files past the retention window", ctx do
      recordings = Path.join(ctx.dir, "recordings")
      File.mkdir_p!(recordings)
      old_file = Path.join(recordings, "old.cast")
      File.write!(old_file, "x")

      old =
        SessionRecordings.create(%{
          userId: ctx.user.id,
          hostId: ctx.host.id,
          startedAt: DateTime.utc_now() |> DateTime.add(-40 * 86_400) |> DateTime.to_iso8601(),
          recordingPath: old_file
        })

      SessionRecordings.create(%{
        userId: ctx.user.id,
        hostId: ctx.host.id,
        startedAt: DateTime.utc_now() |> DateTime.to_iso8601(),
        recordingPath: Path.join(recordings, "new.cast")
      })

      assert old
      assert RecordingPruner.sweep(retention_days: 30, data_dir: ctx.dir) == 1

      refute File.exists?(old_file)
      assert [remaining] = SessionRecordings.list_for_user_with_host(ctx.user.id)
      refute remaining.id == old.id
    end

    test "REFUSES to unlink a path outside the recordings directory", ctx do
      # `recordingPath` is data, and data that decides which files get deleted has to be
      # constrained by something other than trust in whoever wrote it.
      outside = Path.join(System.tmp_dir!(), "termelix_not_a_recording_#{unique()}")
      File.write!(outside, "important")
      on_exit(fn -> File.rm_rf(outside) end)

      SessionRecordings.create(%{
        userId: ctx.user.id,
        hostId: ctx.host.id,
        startedAt: DateTime.utc_now() |> DateTime.add(-40 * 86_400) |> DateTime.to_iso8601(),
        recordingPath: outside
      })

      assert RecordingPruner.sweep(retention_days: 30, data_dir: ctx.dir) == 1

      # The ROW goes (it is expired), but the file is left alone.
      assert File.exists?(outside)
    end

    test "a sweep with nothing to do is a no-op", ctx do
      assert RecordingPruner.sweep(retention_days: 30, data_dir: ctx.dir) == 0
    end
  end
end
