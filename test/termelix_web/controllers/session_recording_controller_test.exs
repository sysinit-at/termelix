defmodule TermelixWeb.SessionRecordingControllerTest do
  @moduledoc """
  HTTP tests for the `/session_logs` surface: listing (host-joined, `sizeBytes` stamped),
  single-row metadata, ownership-enforced fetch/delete, the content 404 ladder (capture is
  deferred so no file exists) plus the content-type fallthrough for an unknown format, and the
  admin-gated retention setting. Requires the returned routes wired into an authenticated
  `/session_logs` scope.

  `alice` is admin (first user); `bob` is a non-admin who owns a host and a recording.
  """
  use TermelixWeb.ConnCase

  alias Termelix.{Accounts, Repo}
  alias Termelix.Schema.SessionRecording

  @password "correct horse battery staple"

  setup do
    {alice_token, _alice} = register_and_login("alice", @password)
    {bob_token, bob} = register_and_login("bob", "another good long passphrase")
    host_id = create_host(bob_token)
    rec = insert_recording(host_id, bob.id)

    %{alice_token: alice_token, bob_token: bob_token, bob: bob, host_id: host_id, rec: rec}
  end

  describe "GET /session_logs" do
    test "lists the user's recordings joined to the host, sizeBytes stamped", ctx do
      body = authed(ctx.bob_token) |> get("/session_logs/") |> json_response(200)

      assert [log] = body["logs"]
      assert log["id"] == ctx.rec.id
      assert log["hostId"] == ctx.host_id
      assert log["hostName"] == "web-1"
      assert log["hostIp"] == "10.0.0.5"
      assert log["protocol"] == "ssh"
      assert log["format"] == "text"
      # No recording file on disk (capture deferred) → null.
      assert log["sizeBytes"] == nil
    end

    test "does not leak another user's recordings", ctx do
      body = authed(ctx.alice_token) |> get("/session_logs/") |> json_response(200)
      assert body["logs"] == []
    end
  end

  describe "GET /session_logs/:id" do
    test "returns a single recording's metadata for the owner", ctx do
      body = authed(ctx.bob_token) |> get("/session_logs/#{ctx.rec.id}") |> json_response(200)

      assert body["log"]["id"] == ctx.rec.id
      assert body["log"]["userId"] == ctx.bob.id
      assert body["log"]["hostId"] == ctx.host_id
    end

    test "a non-owner cannot read it (404)", ctx do
      assert %{"error" => "Not found"} =
               authed(ctx.alice_token)
               |> get("/session_logs/#{ctx.rec.id}")
               |> json_response(404)
    end

    test "a non-numeric id is 400", ctx do
      assert %{"error" => "Invalid id"} =
               authed(ctx.bob_token) |> get("/session_logs/abc") |> json_response(400)
    end
  end

  describe "GET /session_logs/:id/content" do
    test "is 404 when the recording has no file (capture deferred)", ctx do
      assert %{"error" => "No recording file"} =
               authed(ctx.bob_token)
               |> get("/session_logs/#{ctx.rec.id}/content")
               |> json_response(404)
    end

    test "a non-owner cannot read content (404)", ctx do
      assert %{"error" => "Not found"} =
               authed(ctx.alice_token)
               |> get("/session_logs/#{ctx.rec.id}/content")
               |> json_response(404)
    end

    # The remote-desktop subsystem is gone, so "guacamole" is no longer a known format; a legacy
    # row carrying it must still serve, falling through to the text/plain default.
    test "a row with the retired \"guacamole\" format serves as text/plain", ctx do
      point_at_file(ctx.rec, "guacamole", "legacy recording bytes")

      resp = authed(ctx.bob_token) |> get("/session_logs/#{ctx.rec.id}/content")

      assert response(resp, 200) == "legacy recording bytes"
      assert ["text/plain" <> _] = get_resp_header(resp, "content-type")
    end

    # The P10 recorder writes under DATA_DIR/recordings/<user_id>/, which the allowlist
    # once refused: every recording the system produced 403'd here.
    test "content is served from the recorder's own recordings/ root", ctx do
      point_at_file(ctx.rec, "asciicast-v2-enc", "sealed envelope bytes", "recordings", ".cast")

      resp = authed(ctx.bob_token) |> get("/session_logs/#{ctx.rec.id}/content")

      assert response(resp, 200) == "sealed envelope bytes"
      assert ["application/x-asciicast" <> _] = get_resp_header(resp, "content-type")
    end

    test "a path outside every recording root is still refused (403)", ctx do
      outside =
        Path.join(System.tmp_dir!(), "not-recordings-#{System.unique_integer([:positive])}")

      File.mkdir_p!(outside)
      path = Path.join(outside, "rec.log")
      File.write!(path, "x")
      on_exit(fn -> File.rm_rf!(outside) end)

      ctx.rec |> Ecto.Changeset.change(%{recordingPath: path}) |> Repo.update!()

      assert %{"error" => "Forbidden"} =
               authed(ctx.bob_token)
               |> get("/session_logs/#{ctx.rec.id}/content")
               |> json_response(403)
    end
  end

  describe "DELETE /session_logs/:id" do
    test "the owner deletes their recording", ctx do
      assert %{"success" => true} =
               authed(ctx.bob_token)
               |> delete("/session_logs/#{ctx.rec.id}")
               |> json_response(200)

      assert Repo.get(SessionRecording, ctx.rec.id) == nil
    end

    test "deleting also unlinks the file, so no ciphertext is orphaned on the volume", ctx do
      path = point_at_file(ctx.rec, "asciicast-v2-enc", "sealed bytes", "recordings")
      assert File.exists?(path)

      assert %{"success" => true} =
               authed(ctx.bob_token)
               |> delete("/session_logs/#{ctx.rec.id}")
               |> json_response(200)

      refute File.exists?(path)
    end

    test "a non-owner cannot delete it (404, row survives)", ctx do
      assert %{"error" => "Not found"} =
               authed(ctx.alice_token)
               |> delete("/session_logs/#{ctx.rec.id}")
               |> json_response(404)

      assert Repo.get(SessionRecording, ctx.rec.id) != nil
    end
  end

  describe "GET/PUT /session_logs/retention (admin)" do
    test "admin reads the default retention", ctx do
      assert %{"retentionDays" => 30} =
               authed(ctx.alice_token) |> get("/session_logs/retention") |> json_response(200)
    end

    test "admin updates retention and reads it back", ctx do
      assert %{"retentionDays" => 45} =
               authed(ctx.alice_token)
               |> put_json("/session_logs/retention", %{retentionDays: 45})
               |> json_response(200)

      assert %{"retentionDays" => 45} =
               authed(ctx.alice_token) |> get("/session_logs/retention") |> json_response(200)
    end

    test "out-of-range retention is rejected", ctx do
      assert %{"error" => "Retention must be between 1 and 3650 days"} =
               authed(ctx.alice_token)
               |> put_json("/session_logs/retention", %{retentionDays: 5000})
               |> json_response(400)
    end

    test "a non-admin cannot read or set retention", ctx do
      assert %{"error" => "Admin access required"} =
               authed(ctx.bob_token) |> get("/session_logs/retention") |> json_response(403)

      assert %{"error" => "Admin access required"} =
               authed(ctx.bob_token)
               |> put_json("/session_logs/retention", %{retentionDays: 45})
               |> json_response(403)
    end
  end

  # --- helpers ---------------------------------------------------------------

  defp register_and_login(username, password) do
    conn = build_conn()
    conn |> post("/users/create", %{username: username, password: password}) |> json_response(200)
    login = post(conn, "/users/login", %{username: username, password: password})
    %{"jwt" => %{value: token}} = login.resp_cookies
    {token, Accounts.get_user_by_username(username)}
  end

  defp authed(token), do: build_conn() |> put_req_header("authorization", "Bearer #{token}")

  defp put_json(conn, path, payload) do
    conn
    |> put_req_header("content-type", "application/json")
    |> put(path, Jason.encode!(payload))
  end

  defp create_host(token) do
    %{"id" => id} =
      authed(token)
      |> put_req_header("content-type", "application/json")
      |> post(
        "/host/db/host",
        Jason.encode!(%{
          name: "web-1",
          ip: "10.0.0.5",
          port: 22,
          username: "root",
          authType: "password",
          password: "s3cr3t"
        })
      )
      |> json_response(200)

    id
  end

  # Writes a recording file under the resolved data dir (the same chain the controller's
  # allowlist uses: app env, then DATA_DIR) so the content route accepts it, and points
  # the row at it with the given format. Returns the path for existence assertions.
  defp point_at_file(rec, format, body, subdir \\ "session_logs", ext \\ ".log") do
    data_dir =
      Application.get_env(:termelix, :data_dir) || System.get_env("DATA_DIR") || "./db/data"

    dir = Path.join(data_dir, subdir)
    File.mkdir_p!(dir)
    path = Path.join(dir, "rec-#{rec.id}-#{System.unique_integer([:positive])}#{ext}")
    File.write!(path, body)

    on_exit(fn -> File.rm(path) end)

    rec |> Ecto.Changeset.change(%{recordingPath: path, format: format}) |> Repo.update!()
    path
  end

  defp insert_recording(host_id, user_id) do
    Repo.insert!(%SessionRecording{
      hostId: host_id,
      userId: user_id,
      startedAt: "2026-07-20T10:00:00.000Z",
      endedAt: "2026-07-20T10:05:00.000Z",
      duration: 300,
      protocol: "ssh",
      format: "text"
    })
  end
end
