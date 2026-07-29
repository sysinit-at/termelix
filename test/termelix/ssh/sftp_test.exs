defmodule Termelix.SSH.SftpTest do
  @moduledoc """
  End-to-end proof of the SFTP file-manager surface over OTP's native `:ssh_sftp`.

  A throwaway `:ssh` daemon with the `ssh_sftpd` subsystem (password auth) runs inside the
  test VM, so this needs no external SFTP server. A real user + host row are created through
  the normal API (so the host password is DEK-encrypted at rest and decrypted by
  `Hosts.get_for_user`, exactly as production does), then the context and the controller are
  exercised against the live daemon: list a directory, round-trip a file, read binary as
  base64, and surface not-found / validation errors.
  """
  use TermelixWeb.ConnCase, async: false

  alias Termelix.{Accounts, Hosts}
  alias Termelix.SSH.Pool
  alias Termelix.SSH.Sftp
  alias TermelixWeb.FileManagerController

  @password "correct horse battery staple"

  setup_all do
    {:ok, _} = Application.ensure_all_started(:ssh)

    dir = Path.join(System.tmp_dir!(), "termelix_sftp_test_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)

    {_, 0} =
      System.cmd("ssh-keygen", [
        "-t",
        "ed25519",
        "-f",
        Path.join(dir, "ssh_host_ed25519_key"),
        "-N",
        "",
        "-q"
      ])

    {:ok, daemon} =
      :ssh.daemon(0,
        system_dir: String.to_charlist(dir),
        user_passwords: [{~c"tester", ~c"secret"}],
        auth_methods: ~c"password",
        subsystems: [:ssh_sftpd.subsystem_spec([])]
      )

    port = daemon_port(daemon)

    on_exit(fn ->
      :ssh.stop_daemon(daemon)
      File.rm_rf(dir)
    end)

    %{port: port, host_key_dir: dir}
  end

  setup %{port: port} do
    # Pooled connections must not leak between tests.
    Pool.stop_all()

    {token, user} = register_and_login("alice", @password)
    host_id = create_host(token, port)

    # A private work directory on the real filesystem the daemon serves.
    work =
      Path.join(System.tmp_dir!(), "termelix_sftp_work_#{System.unique_integer([:positive])}")

    File.mkdir_p!(work)
    on_exit(fn -> File.rm_rf(work) end)

    %{user: user, host_id: host_id, sid: to_string(host_id), work: work}
  end

  describe "connection pooling" do
    test "sequential operations reuse one pooled connection", ctx do
      %{host_id: id, user: user, work: work} = ctx
      File.write!(Path.join(work, "one.txt"), "1")

      assert {:ok, _} = Sftp.list_directory(id, user.id, work)

      key = pool_key(ctx)
      conn_pid = Pool.lookup(key)
      assert is_pid(conn_pid)
      ssh_conn = :sys.get_state(conn_pid).conn

      assert {:ok, _} = Sftp.read_file(id, user.id, Path.join(work, "one.txt"))

      # Same Conn process, same underlying :ssh connection — one handshake for both ops.
      assert Pool.lookup(key) == conn_pid
      assert :sys.get_state(conn_pid).conn == ssh_conn
    end

    test "a connection with an open download does not idle-expire, then expires once released",
         ctx do
      %{host_id: id, user: user, work: work} = ctx

      Application.put_env(:termelix, :ssh_conn_idle_timeout, 50)
      on_exit(fn -> Application.delete_env(:termelix, :ssh_conn_idle_timeout) end)

      full = Path.join(work, "held.bin")
      File.write!(full, "data")

      assert {:ok, download} = Sftp.open_download(id, user.id, full)

      key = pool_key(ctx)
      conn_pid = Pool.lookup(key)
      assert is_pid(conn_pid)

      # Several idle windows pass with the download channel held open: the Conn must
      # survive every one.
      Process.sleep(250)
      assert Pool.lookup(key) == conn_pid

      # Once the download finishes, the channel closes and the now-idle conn expires.
      assert {:ok, :done} =
               Sftp.stream_download(download, :done, fn _chunk, acc -> {:ok, acc} end)

      ref = Process.monitor(conn_pid)
      assert_receive {:DOWN, ^ref, :process, ^conn_pid, :normal}, 2_000
    end
  end

  describe "Sftp context against a live daemon" do
    test "lists a directory with file/dir entries and attributes", ctx do
      %{host_id: id, user: user, work: work} = ctx
      File.write!(Path.join(work, "alpha.txt"), "hello alpha")
      File.mkdir_p!(Path.join(work, "subdir"))

      assert {:ok, %{files: files, path: ^work}} = Sftp.list_directory(id, user.id, work)

      names = Enum.map(files, & &1.name) |> Enum.sort()
      assert names == ["alpha.txt", "subdir"]

      file = Enum.find(files, &(&1.name == "alpha.txt"))
      assert file.type == "file"
      assert file.size == byte_size("hello alpha")
      assert file.path == Path.join(work, "alpha.txt")
      assert String.starts_with?(file.permissions, "-")
      assert file.executable == false

      dir = Enum.find(files, &(&1.name == "subdir"))
      assert dir.type == "directory"
      # Directories omit `size` (Node emits `undefined`).
      refute Map.has_key?(dir, :size)
      assert String.starts_with?(dir.permissions, "d")
    end

    test "round-trips a text file (write then read)", ctx do
      %{host_id: id, user: user, work: work} = ctx
      path = Path.join(work, "rt.txt")
      content = "line1\nline2\n"

      assert {:ok, %{message: "File written successfully", path: ^path}} =
               Sftp.write_file(id, user.id, path, content)

      # The bytes actually landed on the daemon's filesystem.
      assert File.read!(path) == content

      assert {:ok, %{content: ^content, path: ^path, encoding: "utf8"}} =
               Sftp.read_file(id, user.id, path)
    end

    test "reads a binary file as base64", ctx do
      %{host_id: id, user: user, work: work} = ctx
      path = Path.join(work, "blob.bin")
      bytes = <<0, 1, 2, 3, "hi", 0>>
      File.write!(path, bytes)

      assert {:ok, %{content: encoded, encoding: "base64"}} = Sftp.read_file(id, user.id, path)
      assert Base.decode64!(encoded) == bytes
    end

    test "read_file on a missing file is not_found", ctx do
      %{host_id: id, user: user, work: work} = ctx
      assert {:error, :not_found} = Sftp.read_file(id, user.id, Path.join(work, "nope.txt"))
    end

    test "write preserves an existing file's permission bits", ctx do
      %{host_id: id, user: user, work: work} = ctx
      path = Path.join(work, "script.sh")
      File.write!(path, "old")
      File.chmod!(path, 0o750)

      assert {:ok, _} = Sftp.write_file(id, user.id, path, "new content")

      assert File.read!(path) == "new content"
      %File.Stat{mode: mode} = File.stat!(path)
      assert Bitwise.band(mode, 0o7777) == 0o750
    end

    test "a host that is not the user's yields host_not_found", ctx do
      %{user: user} = ctx
      assert {:error, :host_not_found} = Sftp.list_directory(999_999, user.id, "/tmp")
    end

    test "lists mixed entries via the parallel stat fan-out, preserving order", ctx do
      %{host_id: id, user: user, work: work, port: port} = ctx

      # 30 files, 3 directories, 2 symlinks — enough to engage several stat channels.
      for i <- 1..30 do
        name = "file_#{String.pad_leading(Integer.to_string(i), 2, "0")}.txt"
        File.write!(Path.join(work, name), "content #{i}")
      end

      for d <- 1..3, do: File.mkdir_p!(Path.join(work, "dir_#{d}"))
      File.ln_s!(Path.join(work, "file_01.txt"), Path.join(work, "link_file"))
      File.ln_s!(Path.join(work, "dir_1"), Path.join(work, "link_dir"))

      assert {:ok, %{files: files, path: ^work}} = Sftp.list_directory(id, user.id, work)

      # Exactly the daemon's `list_dir` order — what the sequential implementation emitted.
      assert Enum.map(files, & &1.name) == raw_list_dir_order(port, work)
      assert length(files) == 35

      file = Enum.find(files, &(&1.name == "file_01.txt"))
      assert file.type == "file"
      assert file.size == byte_size("content 1")

      dir = Enum.find(files, &(&1.name == "dir_1"))
      assert dir.type == "directory"
      refute Map.has_key?(dir, :size)

      link = Enum.find(files, &(&1.name == "link_file"))
      assert link.type == "link"
      assert link.linkTarget == Path.join(work, "file_01.txt")
      assert link.executable == false

      dir_link = Enum.find(files, &(&1.name == "link_dir"))
      assert dir_link.type == "link"
      assert dir_link.linkTarget == Path.join(work, "dir_1")
    end
  end

  describe "stat fan-out degradation (Sftp.merge_stat_results/2)" do
    test "a crashed stat group degrades to unknown entries, the rest of the listing survives" do
      path = "/srv/data"
      good = ["alpha.txt", "beta.txt"]
      bad = ["gamma.txt", "delta.txt"]

      built_good = Enum.map(good, &%{name: &1, type: "file", path: path <> "/" <> &1})

      # Mirrors `Task.async_stream(ordered: true)` output zipped with its source groups: a
      # healthy group yields `{:ok, entries}`, a group whose stat task crashed (e.g. a channel
      # that died mid-group) yields `{:exit, reason}` — the element the old `flat_map` clause
      # did not match, so it raised a `FunctionClauseError` and 500-ed the entire listing.
      results_with_groups = [
        {{:ok, built_good}, good},
        {{:exit, {:noproc, {:gen_statem, :call, [:chan, :req, 15_000]}}}, bad}
      ]

      merged = Sftp.merge_stat_results(results_with_groups, path)

      # Every entry survives, in order — the crashed group is degraded, never dropped.
      assert Enum.map(merged, & &1.name) == good ++ bad

      # The healthy group passes through untouched.
      assert Enum.take(merged, 2) == built_good

      # The crashed group degrades to best-effort `unknown_entry` shapes instead of raising.
      for name <- bad do
        entry = Enum.find(merged, &(&1.name == name))
        assert entry.type == "file"
        assert entry.permissions == "----------"
        assert entry.size == 0
        assert entry.path == path <> "/" <> name
      end
    end
  end

  describe "FileManagerController actions" do
    test "list_files returns files + path JSON", ctx do
      %{user: user, sid: sid, work: work} = ctx
      File.write!(Path.join(work, "one.txt"), "1")

      resp =
        user
        |> user_conn()
        |> FileManagerController.list_files(%{"sessionId" => sid, "path" => work})
        |> json_response(200)

      assert resp["path"] == work
      assert Enum.any?(resp["files"], &(&1["name"] == "one.txt"))
    end

    test "write_file then read_file round-trips through the controller", ctx do
      %{user: user, sid: sid, work: work} = ctx
      path = Path.join(work, "ctrl.txt")

      write =
        user
        |> user_conn()
        |> FileManagerController.write_file(%{
          "sessionId" => sid,
          "path" => path,
          "content" => "controller body"
        })
        |> json_response(200)

      assert write["message"] == "File written successfully"
      assert write["path"] == path

      read =
        user
        |> user_conn()
        |> FileManagerController.read_file(%{"sessionId" => sid, "path" => path})
        |> json_response(200)

      assert read["content"] == "controller body"
      assert read["encoding"] == "utf8"
    end

    test "read_file on a missing file is 404 with fileNotFound", ctx do
      %{user: user, sid: sid, work: work} = ctx

      resp =
        user
        |> user_conn()
        |> FileManagerController.read_file(%{
          "sessionId" => sid,
          "path" => Path.join(work, "ghost.txt")
        })
        |> json_response(404)

      assert resp["error"] == "File not found"
      assert resp["fileNotFound"] == true
    end

    test "missing sessionId is a 400", %{user: user} do
      resp =
        user
        |> user_conn()
        |> FileManagerController.list_files(%{"path" => "/"})
        |> json_response(400)

      assert resp["error"] == "Session ID is required"
    end

    test "writeFile with no content field is a 400", ctx do
      %{user: user, sid: sid, work: work} = ctx

      resp =
        user
        |> user_conn()
        |> FileManagerController.write_file(%{"sessionId" => sid, "path" => Path.join(work, "x")})
        |> json_response(400)

      assert resp["error"] == "File content is required"
    end

    test "an unknown host session is a 400 connection error", %{user: user} do
      resp =
        user
        |> user_conn()
        |> FileManagerController.list_files(%{"sessionId" => "999999", "path" => "/tmp"})
        |> json_response(400)

      assert resp["error"] == "SSH connection not established"
    end
  end

  describe "Sftp context file-manager operations" do
    test "create_file makes an empty file", ctx do
      %{host_id: id, user: user, work: work} = ctx
      full = Path.join(work, "fresh.txt")

      assert {:ok, %{message: "File created successfully", path: ^full}} =
               Sftp.create_file(id, user.id, work, "fresh.txt")

      assert File.read!(full) == ""
    end

    test "create_file does not truncate an existing file (touch semantics)", ctx do
      %{host_id: id, user: user, work: work} = ctx
      full = Path.join(work, "keep.txt")
      File.write!(full, "precious")

      assert {:ok, %{message: "File created successfully"}} =
               Sftp.create_file(id, user.id, work, "keep.txt")

      assert File.read!(full) == "precious"
    end

    test "create_folder makes a directory and is idempotent (mkdir -p)", ctx do
      %{host_id: id, user: user, work: work} = ctx
      full = Path.join(work, "newdir")

      assert {:ok, %{message: "Folder created successfully", path: ^full}} =
               Sftp.create_folder(id, user.id, work, "newdir")

      assert File.dir?(full)

      # A second create on the existing directory still succeeds.
      assert {:ok, %{message: "Folder created successfully"}} =
               Sftp.create_folder(id, user.id, work, "newdir")
    end

    test "create_folder creates intermediate directories", ctx do
      %{host_id: id, user: user, work: work} = ctx
      full = Path.join(work, "a/b/c")

      assert {:ok, %{path: ^full}} = Sftp.create_folder(id, user.id, work, "a/b/c")
      assert File.dir?(full)
    end

    test "delete_item removes a file", ctx do
      %{host_id: id, user: user, work: work} = ctx
      full = Path.join(work, "gone.txt")
      File.write!(full, "bye")

      assert {:ok, %{message: "Item deleted successfully", path: ^full}} =
               Sftp.delete_item(id, user.id, full, false)

      refute File.exists?(full)
    end

    test "delete_item recursively removes a populated directory", ctx do
      %{host_id: id, user: user, work: work} = ctx
      tree = Path.join(work, "tree")
      File.mkdir_p!(Path.join(tree, "sub/deep"))
      File.write!(Path.join(tree, "top.txt"), "1")
      File.write!(Path.join(tree, "sub/mid.txt"), "2")
      File.write!(Path.join(tree, "sub/deep/leaf.txt"), "3")

      assert {:ok, %{message: "Item deleted successfully"}} =
               Sftp.delete_item(id, user.id, tree, true)

      refute File.exists?(tree)
    end

    test "rename_item renames within the same directory", ctx do
      %{host_id: id, user: user, work: work} = ctx
      old = Path.join(work, "before.txt")
      new = Path.join(work, "after.txt")
      File.write!(old, "x")

      assert {:ok, %{message: "Item renamed successfully", oldPath: ^old, newPath: ^new}} =
               Sftp.rename_item(id, user.id, old, "after.txt")

      refute File.exists?(old)
      assert File.read!(new) == "x"
    end

    test "move_item moves to a fully-qualified path", ctx do
      %{host_id: id, user: user, work: work} = ctx
      old = Path.join(work, "src.txt")
      dest_dir = Path.join(work, "dest")
      File.mkdir_p!(dest_dir)
      new = Path.join(dest_dir, "src.txt")
      File.write!(old, "moved")

      assert {:ok, %{message: "Item moved successfully", oldPath: ^old, newPath: ^new}} =
               Sftp.move_item(id, user.id, old, new)

      refute File.exists?(old)
      assert File.read!(new) == "moved"
    end

    test "upload_file writes raw bytes verbatim", ctx do
      %{host_id: id, user: user, work: work} = ctx
      full = Path.join(work, "blob.bin")
      bytes = <<0, 1, 2, "raw", 255>>

      assert {:ok, %{message: "File uploaded successfully", path: ^full}} =
               Sftp.upload_file(id, user.id, work, "blob.bin", bytes)

      assert File.read!(full) == bytes
    end

    test "download_file returns base64 content with mime type + size", ctx do
      %{host_id: id, user: user, work: work} = ctx
      full = Path.join(work, "doc.json")
      body = ~s({"k":"v"})
      File.write!(full, body)

      assert {:ok, resp} = Sftp.download_file(id, user.id, full)
      assert Base.decode64!(resp.content) == body
      assert resp.fileName == "doc.json"
      assert resp.size == byte_size(body)
      assert resp.mimeType == "application/json"
      assert resp.path == full
    end

    test "download_file rejects a directory", ctx do
      %{host_id: id, user: user, work: work} = ctx
      dir = Path.join(work, "adir")
      File.mkdir_p!(dir)

      assert {:error, :not_a_file} = Sftp.download_file(id, user.id, dir)
    end

    test "open_download/stream_download streams the exact bytes in 256 KB chunks", ctx do
      %{host_id: id, user: user, work: work} = ctx
      full = Path.join(work, "stream.bin")
      # ~2.3 chunks: proves the file is reassembled from multiple reads, byte-identically.
      bytes = :crypto.strong_rand_bytes(600_000)
      File.write!(full, bytes)

      assert {:ok, download} = Sftp.open_download(id, user.id, full)
      assert download.fileName == "stream.bin"
      assert download.size == byte_size(bytes)

      parent = self()

      assert {:ok, :done} =
               Sftp.stream_download(download, :done, fn chunk, acc ->
                 send(parent, {:chunk, chunk})
                 {:ok, acc}
               end)

      chunks = collect_chunks([])
      assert length(chunks) > 1
      assert IO.iodata_to_binary(chunks) == bytes
    end

    test "stream_download aborts when the consumer fails", ctx do
      %{host_id: id, user: user, work: work} = ctx
      full = Path.join(work, "abort.bin")
      File.write!(full, :crypto.strong_rand_bytes(600_000))

      assert {:ok, download} = Sftp.open_download(id, user.id, full)

      assert {:error, :closed} =
               Sftp.stream_download(download, nil, fn _chunk, _acc -> {:error, :closed} end)
    end

    test "open_download rejects a directory", ctx do
      %{host_id: id, user: user, work: work} = ctx
      assert {:error, :not_a_file} = Sftp.open_download(id, user.id, work)
    end

    test "upload_file_stream writes chunked bytes verbatim", ctx do
      %{host_id: id, user: user, work: work} = ctx
      full = Path.join(work, "chunked.bin")
      chunks = [:crypto.strong_rand_bytes(262_144), :crypto.strong_rand_bytes(100), "tail"]

      assert {:ok, %{message: "File uploaded successfully", path: ^full}} =
               Sftp.upload_file_stream(id, user.id, work, "chunked.bin", chunks)

      assert File.read!(full) == IO.iodata_to_binary(chunks)
    end

    test "download_file rejects files above the 100 MB JSON cap", ctx do
      %{host_id: id, user: user, work: work} = ctx
      full = Path.join(work, "huge.bin")
      write_sparse(full, 100 * 1024 * 1024 + 1)

      assert {:error, {:download_too_large, size}} = Sftp.download_file(id, user.id, full)
      assert size == 100 * 1024 * 1024 + 1
    end
  end

  describe "FileManagerController file-manager operation actions" do
    test "create_folder then delete_item (recursive) through the controller", ctx do
      %{user: user, sid: sid, work: work} = ctx

      created =
        user
        |> user_conn()
        |> FileManagerController.create_folder(%{
          "sessionId" => sid,
          "path" => work,
          "folderName" => "ctrl_dir"
        })
        |> json_response(200)

      assert created["message"] == "Folder created successfully"
      full = Path.join(work, "ctrl_dir")
      assert created["path"] == full
      assert File.dir?(full)

      deleted =
        user
        |> user_conn()
        |> FileManagerController.delete_item(%{
          "sessionId" => sid,
          "path" => full,
          "isDirectory" => true
        })
        |> json_response(200)

      assert deleted["message"] == "Item deleted successfully"
      refute File.exists?(full)
    end

    test "rename_item action returns oldPath/newPath", ctx do
      %{user: user, sid: sid, work: work} = ctx
      old = Path.join(work, "r1.txt")
      File.write!(old, "y")

      resp =
        user
        |> user_conn()
        |> FileManagerController.rename_item(%{
          "sessionId" => sid,
          "oldPath" => old,
          "newName" => "r2.txt"
        })
        |> json_response(200)

      assert resp["oldPath"] == old
      assert resp["newPath"] == Path.join(work, "r2.txt")
      assert File.exists?(Path.join(work, "r2.txt"))
    end

    test "upload_file_stream action writes a multipart upload", ctx do
      %{user: user, sid: sid, work: work} = ctx

      tmp = Path.join(System.tmp_dir!(), "up_#{System.unique_integer([:positive])}")
      File.write!(tmp, "uploaded body")
      on_exit(fn -> File.rm_rf(tmp) end)
      upload = %Plug.Upload{path: tmp, filename: "uploaded.txt", content_type: "text/plain"}

      resp =
        user
        |> user_conn()
        |> FileManagerController.upload_file_stream(%{
          "sessionId" => sid,
          "path" => work,
          "file" => upload
        })
        |> json_response(200)

      assert resp["message"] == "File uploaded successfully"
      full = Path.join(work, "uploaded.txt")
      assert resp["path"] == full
      assert File.read!(full) == "uploaded body"
    end

    test "upload_file_stream action streams a large multipart upload byte-identically", ctx do
      %{user: user, sid: sid, work: work} = ctx

      # Crosses the 256 KB chunk boundary twice.
      bytes = :crypto.strong_rand_bytes(600_001)
      tmp = Path.join(System.tmp_dir!(), "up_#{System.unique_integer([:positive])}")
      File.write!(tmp, bytes)
      on_exit(fn -> File.rm_rf(tmp) end)
      upload = %Plug.Upload{path: tmp, filename: "big-upload.bin"}

      resp =
        user
        |> user_conn()
        |> FileManagerController.upload_file_stream(%{
          "sessionId" => sid,
          "path" => work,
          "file" => upload
        })
        |> json_response(200)

      assert resp["message"] == "File uploaded successfully"
      full = Path.join(work, "big-upload.bin")
      assert resp["path"] == full
      assert File.read!(full) == bytes
    end

    test "download_file action rejects a file above the 100 MB cap with the Node envelope",
         ctx do
      %{user: user, sid: sid, work: work} = ctx
      full = Path.join(work, "huge.bin")
      write_sparse(full, 100 * 1024 * 1024 + 1)

      resp =
        user
        |> user_conn()
        |> FileManagerController.download_file(%{"sessionId" => sid, "path" => full})
        |> json_response(400)

      assert resp["error"] == "File too large. Maximum size is 100MB, file is 100.00MB"
    end

    test "download_file action returns base64 JSON", ctx do
      %{user: user, sid: sid, work: work} = ctx
      full = Path.join(work, "dl.txt")
      File.write!(full, "download me")

      resp =
        user
        |> user_conn()
        |> FileManagerController.download_file(%{"sessionId" => sid, "path" => full})
        |> json_response(200)

      assert Base.decode64!(resp["content"]) == "download me"
      assert resp["fileName"] == "dl.txt"
      assert resp["mimeType"] == "text/plain"
    end

    test "download_file_stream action streams a large file byte-identically", ctx do
      %{user: user, sid: sid, work: work} = ctx
      full = Path.join(work, "large stream.bin")
      bytes = :crypto.strong_rand_bytes(700_000)
      File.write!(full, bytes)

      conn =
        user
        |> user_conn()
        |> FileManagerController.download_file_stream(%{"sessionId" => sid, "path" => full})

      assert conn.status == 200
      assert chunked_body(conn) == bytes

      assert ["application/octet-stream"] = Plug.Conn.get_resp_header(conn, "content-type")

      assert [disposition] = Plug.Conn.get_resp_header(conn, "content-disposition")
      assert disposition == ~s(attachment; filename="large%20stream.bin")
    end

    test "download_file_stream action rejects a directory with the 400 envelope", ctx do
      %{user: user, sid: sid, work: work} = ctx

      resp =
        user
        |> user_conn()
        |> FileManagerController.download_file_stream(%{"sessionId" => sid, "path" => work})
        |> json_response(400)

      assert resp["error"] == "Cannot download directories"
    end

    test "download_file_stream action sends bytes with content-disposition", ctx do
      %{user: user, sid: sid, work: work} = ctx
      full = Path.join(work, "stream me.bin")
      bytes = <<1, 2, 3, "streamed">>
      File.write!(full, bytes)

      conn =
        user
        |> user_conn()
        |> FileManagerController.download_file_stream(%{"sessionId" => sid, "path" => full})

      assert conn.status == 200
      assert chunked_body(conn) == bytes

      assert ["application/octet-stream"] = Plug.Conn.get_resp_header(conn, "content-type")

      assert [disposition] = Plug.Conn.get_resp_header(conn, "content-disposition")
      assert disposition == ~s(attachment; filename="stream%20me.bin")
    end

    test "missing fields on create_folder are a 400", ctx do
      %{user: user, sid: sid} = ctx

      resp =
        user
        |> user_conn()
        |> FileManagerController.create_folder(%{"sessionId" => sid, "path" => "/tmp"})
        |> json_response(400)

      assert resp["error"] == "Folder path and name are required"
    end

    test "download of a missing path surfaces the SFTP error", ctx do
      %{user: user, sid: sid, work: work} = ctx

      resp =
        user
        |> user_conn()
        |> FileManagerController.download_file(%{
          "sessionId" => sid,
          "path" => Path.join(work, "nope.bin")
        })
        |> json_response(500)

      assert resp["error"] =~ "SFTP error"
    end
  end

  describe "FileManagerController session lifecycle (connect/status/keepalive/disconnect)" do
    test "connect probes the host, registers the session, and reports success", ctx do
      %{user: user, sid: sid, host_id: id} = ctx

      resp =
        user
        |> user_conn()
        |> FileManagerController.connect(%{"sessionId" => sid, "hostId" => id})
        |> json_response(200)

      assert resp["status"] == "success"
      assert resp["message"] == "SSH connection established"
      assert Enum.any?(resp["connectionLogs"], &(&1["stage"] == "sftp_connected"))

      status =
        user
        |> user_conn()
        |> FileManagerController.status(%{"sessionId" => sid})
        |> json_response(200)

      assert status == %{"status" => "success", "connected" => true}
    end

    test "connect without a resolvable host is 404 with an error log", %{user: user} do
      resp =
        user
        |> user_conn()
        |> FileManagerController.connect(%{"sessionId" => "999999"})
        |> json_response(404)

      assert resp["error"] == "Host not found"
      assert Enum.any?(resp["connectionLogs"], &(&1["type"] == "error"))
    end

    test "connect with no usable session/host id is 400", %{user: user} do
      resp =
        user
        |> user_conn()
        |> FileManagerController.connect(%{"sessionId" => "not-a-number"})
        |> json_response(400)

      assert resp["error"] == "Missing required connection parameters"
    end

    test "status/keepalive for an unknown session report not connected", %{user: user} do
      assert %{"connected" => false} =
               user
               |> user_conn()
               |> FileManagerController.status(%{"sessionId" => "ghost"})
               |> json_response(200)

      assert %{"error" => "SSH session not found or not connected", "connected" => false} =
               user
               |> user_conn()
               |> FileManagerController.keepalive(%{"sessionId" => "ghost"})
               |> json_response(400)

      assert %{"error" => "Session ID is required"} =
               user
               |> user_conn()
               |> FileManagerController.keepalive(%{})
               |> json_response(400)
    end

    test "keepalive renews and disconnect drops a registered session", ctx do
      %{user: user, sid: sid, host_id: id} = ctx

      user
      |> user_conn()
      |> FileManagerController.connect(%{"sessionId" => sid, "hostId" => id})
      |> json_response(200)

      keep =
        user
        |> user_conn()
        |> FileManagerController.keepalive(%{"sessionId" => sid})
        |> json_response(200)

      assert keep["connected"] == true
      assert is_integer(keep["lastActive"])

      user
      |> user_conn()
      |> FileManagerController.disconnect(%{"sessionId" => sid})
      |> json_response(200)

      assert %{"connected" => false} =
               user
               |> user_conn()
               |> FileManagerController.status(%{"sessionId" => sid})
               |> json_response(200)
    end

    test "another user's session is 403 on status/keepalive/disconnect", ctx do
      %{user: user, sid: sid, host_id: id} = ctx

      user
      |> user_conn()
      |> FileManagerController.connect(%{"sessionId" => sid, "hostId" => id})
      |> json_response(200)

      {_token, other} = register_and_login("mallory", "a different strong passphrase")

      for {fun, params} <- [
            {&FileManagerController.status/2, %{"sessionId" => sid}},
            {&FileManagerController.keepalive/2, %{"sessionId" => sid}},
            {&FileManagerController.disconnect/2, %{"sessionId" => sid}}
          ] do
        assert %{"error" => "Session access denied"} =
                 other |> user_conn() |> fun.(params) |> json_response(403)
      end

      # The 403s must not have dropped the owner's session.
      assert %{"connected" => true} =
               user
               |> user_conn()
               |> FileManagerController.status(%{"sessionId" => sid})
               |> json_response(200)
    end
  end

  # --- helpers ---------------------------------------------------------------

  defp user_conn(user) do
    build_conn()
    |> Plug.Conn.assign(:current_user_id, user.id)
    |> Plug.Conn.assign(:current_user, user)
  end

  defp register_and_login(username, password) do
    conn = build_conn()
    conn |> post("/users/create", %{username: username, password: password}) |> json_response(200)
    login = post(conn, "/users/login", %{username: username, password: password})
    %{"jwt" => %{value: token}} = login.resp_cookies
    {token, Accounts.get_user_by_username(username)}
  end

  defp create_host(token, port) do
    %{"id" => id} =
      build_conn()
      |> put_req_header("authorization", "Bearer #{token}")
      |> put_req_header("content-type", "application/json")
      |> post(
        "/host/db/host",
        Jason.encode!(%{
          name: "sftp-target",
          ip: "127.0.0.1",
          port: port,
          username: "tester",
          connectionType: "ssh",
          authType: "password",
          password: "secret",
          enableFileManager: true
        })
      )
      |> json_response(200)

    id
  end

  defp daemon_port(daemon) do
    case :ssh.daemon_info(daemon) do
      {:ok, info} when is_list(info) -> :proplists.get_value(:port, info)
      {:ok, info} when is_map(info) -> Map.get(info, :port)
    end
  end

  # The pool key for the host every test in this module creates — derived by asking the REAL
  # builder, not by mirroring it here. A hand-written copy silently stopped matching the moment
  # `:owner_id` joined the key, so both pooling tests looked up a bucket nothing was ever in
  # and reported "no pooled connection" as a pass-shaped nil.
  defp pool_key(ctx) do
    ctx.host_id
    |> Hosts.get_for_user(ctx.user.id)
    |> Termelix.SSH.Credential.resolve()
    |> Pool.key_for()
  end

  # Drain `{:chunk, chunk}` messages sent by a test chunk consumer, in arrival order.
  defp collect_chunks(acc) do
    receive do
      {:chunk, chunk} -> collect_chunks([chunk | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  # Plug's test adapter accumulates a chunked response in the adapter state, not `resp_body`.
  defp chunked_body(conn) do
    {_adapter, %{chunks: chunks}} = conn.adapter
    chunks
  end

  # A file of exactly `size` bytes without materializing the content (the JSON download cap
  # is enforced from the stat size, before any read happens).
  defp write_sparse(path, size) do
    dev = File.open!(path, [:write, :raw])
    :ok = :file.pwrite(dev, size - 1, <<0>>)
    :ok = File.close(dev)
  end

  # The daemon's raw `list_dir` order (minus "."/".."), independent of `Termelix.SSH.Sftp` —
  # the ordering contract `list_directory/3` must preserve while fanning stats out in
  # parallel.
  defp raw_list_dir_order(port, path) do
    {:ok, conn} =
      :ssh.connect(
        ~c"127.0.0.1",
        port,
        [
          user: ~c"tester",
          password: ~c"secret",
          silently_accept_hosts: true,
          user_interaction: false,
          quiet_mode: true
        ],
        5_000
      )

    {:ok, chan} = :ssh_sftp.start_channel(conn, timeout: 5_000)
    {:ok, names} = :ssh_sftp.list_dir(chan, String.to_charlist(path), 5_000)
    :ssh_sftp.stop_channel(chan)
    :ssh.close(conn)

    names |> Enum.reject(&(&1 in [~c".", ~c".."])) |> Enum.map(&List.to_string/1)
  end
end
