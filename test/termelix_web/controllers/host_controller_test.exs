defmodule TermelixWeb.HostControllerTest do
  @moduledoc """
  Covers the host CRUD surface (`POST /host/db/host`, `PUT`/`DELETE /host/db/host/:id`) and
  the bulk surface (`PATCH /host/bulk-update`): camelCase request handling, JSON-blob storage,
  secret encryption at rest + stripping on the wire, partial-update secret preservation,
  ownership enforcement, and status codes.
  """
  use TermelixWeb.ConnCase

  alias Termelix.{Accounts, Hosts, Repo}
  alias Termelix.Schema.Host

  @password "correct horse battery staple"

  setup do
    {token, user} = register_and_login("alice", @password)
    %{token: token, user: user}
  end

  describe "POST /host/db/host" do
    test "creates a host, parses blobs, strips + encrypts the secret", %{token: token, user: user} do
      payload = %{
        name: "web-1",
        ip: "10.0.0.5",
        port: 22,
        username: "root",
        connectionType: "ssh",
        authType: "password",
        password: "s3cr3t",
        tags: ["prod", "web"],
        pin: true,
        enableTerminal: true,
        tunnelConnections: [%{sourcePort: 8080, endPort: 80}]
      }

      host = authed(token) |> post_json("/host/db/host", payload) |> json_response(200)

      assert host["name"] == "web-1"
      assert host["ip"] == "10.0.0.5"
      assert host["username"] == "root"
      assert host["tags"] == ["prod", "web"]
      assert host["pin"] == true
      assert host["hasPassword"] == true
      # Secrets are never returned.
      refute Map.has_key?(host, "password")
      # JSON blob stored as a string round-trips to a parsed structure.
      assert host["tunnelConnections"] == [%{"sourcePort" => 8080, "endPort" => 80}]
      # Port default from the normalizer.
      assert host["sshPort"] == 22

      # The row is encrypted at rest (an envelope, not the plaintext)...
      stored = Repo.get(Host, host["id"])
      assert String.starts_with?(stored.password, "{")
      refute stored.password == "s3cr3t"
      # ...and decrypts back to the plaintext under the owner's DEK.
      assert Hosts.get_for_user(host["id"], user.id).password == "s3cr3t"
    end

    test "derives a name from username@ip when name is omitted", %{token: token} do
      payload = %{ip: "192.168.1.1", port: 22, username: "admin", authType: "password"}
      host = authed(token) |> post_json("/host/db/host", payload) |> json_response(200)
      assert host["name"] == "admin@192.168.1.1"
    end

    test "rejects a missing ip with 400", %{token: token} do
      assert %{"error" => "Invalid SSH data"} =
               authed(token)
               |> post_json("/host/db/host", %{port: 22, username: "root"})
               |> json_response(400)
    end

    test "rejects an out-of-range port with 400", %{token: token} do
      assert %{"error" => "Invalid SSH data"} =
               authed(token)
               |> post_json("/host/db/host", %{ip: "10.0.0.9", port: 70_000})
               |> json_response(400)
    end
  end

  describe "PUT /host/db/host/:id" do
    setup %{token: token} do
      %{"id" => id} =
        authed(token)
        |> post_json("/host/db/host", %{
          name: "web-1",
          ip: "10.0.0.5",
          port: 22,
          username: "root",
          authType: "password",
          password: "s3cr3t"
        })
        |> json_response(200)

      %{host_id: id}
    end

    test "updates fields and preserves an omitted password", ctx do
      %{token: token, user: user, host_id: id} = ctx

      updated =
        authed(token)
        |> put_json("/host/db/host/#{id}", %{
          name: "web-2",
          ip: "10.0.0.5",
          port: 2222,
          username: "root",
          authType: "password"
        })
        |> json_response(200)

      assert updated["name"] == "web-2"
      assert updated["port"] == 2222
      # Password was not resent, so its ciphertext is preserved and still decrypts.
      assert updated["hasPassword"] == true
      assert Hosts.get_for_user(id, user.id).password == "s3cr3t"
    end

    test "replaces the password when a new one is supplied", ctx do
      %{token: token, user: user, host_id: id} = ctx

      authed(token)
      |> put_json("/host/db/host/#{id}", %{
        name: "web-1",
        ip: "10.0.0.5",
        port: 22,
        username: "root",
        authType: "password",
        password: "newpass"
      })
      |> json_response(200)

      assert Hosts.get_for_user(id, user.id).password == "newpass"
    end

    test "cannot update another user's host (404)", %{host_id: id} do
      {other_token, _bob} = register_and_login("bob", @password)

      assert %{"error" => "Host not found"} =
               authed(other_token)
               |> put_json("/host/db/host/#{id}", %{ip: "10.0.0.5", port: 22, username: "x"})
               |> json_response(404)
    end

    test "unknown id is a 404", %{token: token} do
      assert %{"error" => "Host not found"} =
               authed(token)
               |> put_json("/host/db/host/999999", %{ip: "10.0.0.5", port: 22, username: "x"})
               |> json_response(404)
    end

    test "invalid data is a 400", %{token: token, host_id: id} do
      assert %{"error" => "Invalid SSH data"} =
               authed(token)
               |> put_json("/host/db/host/#{id}", %{username: "x"})
               |> json_response(400)
    end
  end

  describe "the sudo password" do
    @nested "NESTED-CLEARTEXT-SUDO"

    test "is not stored at all, from either position", %{token: token, user: user} do
      # Collected for sudo auto-fill, which was removed for being a credential-reveal primitive.
      # Nothing reads it now, and a stored secret with no consumer is liability rather than a
      # dormant feature — so neither position is accepted.
      host =
        authed(token)
        |> post_json("/host/db/host", %{
          name: "sudo-1",
          ip: "10.0.0.7",
          port: 22,
          username: "root",
          authType: "password",
          password: "pw",
          sudoPassword: "TOP-LEVEL-SUDO",
          terminalConfig: %{sudoPasswordAutoFill: true, sudoPassword: @nested}
        })
        |> json_response(200)

      refute host |> Jason.encode!() |> String.contains?(@nested)
      refute host |> Jason.encode!() |> String.contains?("TOP-LEVEL-SUDO")
      refute Map.has_key?(host["terminalConfig"], "sudoPassword")
      assert host["hasSudoPassword"] == false

      stored = Repo.get(Host, host["id"])
      assert stored.sudoPassword == nil
      # And not smuggled into the unencrypted blob either.
      refute stored.terminalConfig =~ @nested
      # The rest of the blob survives — this is a scrub, not a reset.
      assert Hosts.get_for_user(host["id"], user.id).terminalConfig =~ "sudoPasswordAutoFill"
    end

    test "a blob written by an older client does not leak on READ", %{token: token, user: user} do
      # The migration clears these, but a row it could not parse — or one written by a client that
      # has not been updated — must not leak either. The normalizer strips on read regardless.
      created =
        authed(token)
        |> post_json("/host/db/host", %{
          name: "sudo-4",
          ip: "10.0.0.10",
          port: 22,
          username: "root",
          authType: "password",
          password: "pw"
        })
        |> json_response(200)

      # Write the cleartext straight into the column, behind the controller's back — and behind
      # the trigger's, since migration 20260726220000 now refuses such a write outright. Dropping
      # it for the duration is what makes this a faithful simulation: the rows this test is about
      # are the ones already in the database from BEFORE the trigger existed, which no amount of
      # write-side enforcement can retroactively clean.
      Repo.query!("DROP TRIGGER ssh_data_no_secret_in_terminal_config_update")

      Repo.get(Host, created["id"])
      |> Ecto.Changeset.change(%{
        terminalConfig: Jason.encode!(%{"sudoPassword" => @nested, "fontSize" => 14})
      })
      |> Repo.update!()

      Repo.query!("""
      CREATE TRIGGER ssh_data_no_secret_in_terminal_config_update
      BEFORE UPDATE OF terminal_config ON ssh_data
      FOR EACH ROW
      WHEN NEW.terminal_config IS NOT NULL
       AND replace(NEW.terminal_config, ' ', '') LIKE '%"sudoPassword":%'
      BEGIN
        SELECT RAISE(ABORT, 'terminal_config must not contain a sudoPassword');
      END;
      """)

      listed = authed(token) |> get("/host/db/host") |> json_response(200)
      body = Jason.encode!(listed)

      refute body =~ @nested
      host = Enum.find(listed, &(&1["id"] == created["id"]))
      refute Map.has_key?(host["terminalConfig"], "sudoPassword")
      assert host["terminalConfig"]["fontSize"] == 14
      # Sanity: the value really was in the row, so this test could have failed.
      assert Repo.get(Host, created["id"]).terminalConfig =~ @nested
      assert user.id
    end
  end

  describe "DELETE /host/db/host/:id" do
    setup %{token: token} do
      %{"id" => id} =
        authed(token)
        |> post_json("/host/db/host", %{
          ip: "10.0.0.5",
          port: 22,
          username: "root",
          authType: "password",
          password: "s3cr3t"
        })
        |> json_response(200)

      %{host_id: id}
    end

    test "deletes an owned host", %{token: token, user: user, host_id: id} do
      assert %{"message" => "SSH host deleted"} =
               authed(token) |> delete("/host/db/host/#{id}") |> json_response(200)

      assert Hosts.get_for_user(id, user.id) == nil
    end

    test "cannot delete another user's host (404), and it survives", ctx do
      %{user: user, host_id: id} = ctx
      {other_token, _bob} = register_and_login("bob", @password)

      assert %{"error" => "SSH host not found"} =
               authed(other_token) |> delete("/host/db/host/#{id}") |> json_response(404)

      assert Hosts.get_for_user(id, user.id) != nil
    end

    test "unknown id is a 404", %{token: token} do
      assert %{"error" => "SSH host not found"} =
               authed(token) |> delete("/host/db/host/424242") |> json_response(404)
    end
  end

  describe "non-numeric path ids" do
    test "show is a 404, not a 500", %{token: token} do
      assert %{"error" => "Host not found"} =
               authed(token) |> get("/host/db/host/not-a-number") |> json_response(404)
    end

    test "update is a 404, not a 500", %{token: token} do
      assert %{"error" => "Host not found"} =
               authed(token)
               |> put_json("/host/db/host/not-a-number", %{
                 ip: "10.0.0.5",
                 port: 22,
                 username: "x",
                 authType: "password"
               })
               |> json_response(404)
    end

    test "delete is a 404, not a 500", %{token: token} do
      assert %{"error" => "SSH host not found"} =
               authed(token) |> delete("/host/db/host/not-a-number") |> json_response(404)
    end
  end

  describe "PATCH /host/bulk-update" do
    setup %{token: token} do
      ids =
        for name <- ["web-1", "web-2"] do
          %{"id" => id} =
            authed(token)
            |> post_json("/host/db/host", %{
              name: name,
              ip: "10.0.0.5",
              port: 22,
              username: "root",
              authType: "password",
              password: "s3cr3t",
              folder: "old",
              statsConfig: %{cpu: true, memory: false}
            })
            |> json_response(200)

          id
        end

      %{host_ids: ids}
    end

    test "moves the hosts into a folder", ctx do
      %{token: token, user: user, host_ids: [a, b]} = ctx

      assert %{"updated" => 2, "failed" => 0, "errors" => []} =
               authed(token)
               |> patch_json("/host/bulk-update", %{hostIds: [a, b], updates: %{folder: "prod"}})
               |> json_response(200)

      assert Hosts.get_for_user(a, user.id).folder == "prod"
      assert Hosts.get_for_user(b, user.id).folder == "prod"
    end

    test "a blank folder moves the hosts back to the root", ctx do
      %{token: token, user: user, host_ids: [a, _b]} = ctx

      authed(token)
      |> patch_json("/host/bulk-update", %{hostIds: [a], updates: %{folder: ""}})
      |> json_response(200)

      assert Hosts.get_for_user(a, user.id).folder == nil
    end

    test "flips feature flags without touching stored secrets", ctx do
      %{token: token, user: user, host_ids: [a, _b]} = ctx

      authed(token)
      |> patch_json("/host/bulk-update", %{
        hostIds: [a],
        updates: %{enableFileManager: true, enableTerminal: false}
      })
      |> json_response(200)

      host = Hosts.get_for_user(a, user.id)
      assert host.enableFileManager == true
      assert host.enableTerminal == false
      # The batch write bypasses the changeset, so guard that it leaves ciphertext alone.
      assert host.password == "s3cr3t"
    end

    test "ignores fields outside the allow-list", ctx do
      %{token: token, user: user, host_ids: [a, _b]} = ctx

      authed(token)
      |> patch_json("/host/bulk-update", %{
        hostIds: [a],
        updates: %{password: "pwned", ip: "6.6.6.6", userId: "someone-else"}
      })
      |> json_response(200)

      host = Hosts.get_for_user(a, user.id)
      assert host.password == "s3cr3t"
      assert host.ip == "10.0.0.5"
      assert host.userId == user.id
    end

    test "merges statsConfig instead of replacing it", ctx do
      %{token: token, host_ids: [a, _b]} = ctx

      authed(token)
      |> patch_json("/host/bulk-update", %{
        hostIds: [a],
        updates: %{statsConfig: %{memory: true}}
      })
      |> json_response(200)

      assert Jason.decode!(Repo.get(Host, a).statsConfig) == %{"cpu" => true, "memory" => true}
    end

    test "cannot update another user's hosts (404, and they are untouched)", ctx do
      %{user: user, host_ids: [a, b]} = ctx
      {other_token, _bob} = register_and_login("bob", @password)

      assert %{"error" => "No matching hosts found"} =
               authed(other_token)
               |> patch_json("/host/bulk-update", %{hostIds: [a, b], updates: %{folder: "stolen"}})
               |> json_response(404)

      assert Hosts.get_for_user(a, user.id).folder == "old"
      assert Hosts.get_for_user(b, user.id).folder == "old"
    end

    test "updates only the owned ids and reports the rest as failed", ctx do
      %{token: token, user: user, host_ids: [a, _b]} = ctx
      {other_token, bob} = register_and_login("bob", @password)

      %{"id" => bob_id} =
        authed(other_token)
        |> post_json("/host/db/host", %{
          ip: "10.0.0.9",
          port: 22,
          username: "root",
          authType: "password",
          folder: "bob"
        })
        |> json_response(200)

      assert %{"updated" => 1, "failed" => 1, "errors" => errors} =
               authed(token)
               |> patch_json("/host/bulk-update", %{
                 hostIds: [a, bob_id],
                 updates: %{folder: "prod"}
               })
               |> json_response(200)

      assert errors == ["1 host(s) not found or not owned"]
      assert Hosts.get_for_user(a, user.id).folder == "prod"
      assert Hosts.get_for_user(bob_id, bob.id).folder == "bob"
    end

    test "non-integer ids are counted as failures, not a crash", ctx do
      %{token: token, host_ids: [a, _b]} = ctx

      assert %{"updated" => 1, "failed" => 1} =
               authed(token)
               |> patch_json("/host/bulk-update", %{
                 hostIds: [a, "not-a-number"],
                 updates: %{pin: true}
               })
               |> json_response(200)
    end

    test "missing or empty hostIds is a 400", %{token: token} do
      for body <- [%{updates: %{pin: true}}, %{hostIds: [], updates: %{pin: true}}] do
        assert %{"error" => "hostIds array is required and must not be empty"} =
                 authed(token) |> patch_json("/host/bulk-update", body) |> json_response(400)
      end
    end

    test "more than 1000 hosts is a 400", %{token: token} do
      assert %{"error" => "Maximum 1000 hosts allowed per bulk update"} =
               authed(token)
               |> patch_json("/host/bulk-update", %{
                 hostIds: Enum.to_list(1..1001),
                 updates: %{pin: true}
               })
               |> json_response(400)
    end

    test "missing or empty updates is a 400", %{token: token, host_ids: [a, _b]} do
      for body <- [%{hostIds: [a]}, %{hostIds: [a], updates: %{}}] do
        assert %{"error" => "updates object is required and must contain at least one field"} =
                 authed(token) |> patch_json("/host/bulk-update", body) |> json_response(400)
      end
    end

    test "requires authentication", %{host_ids: [a, _b]} do
      build_conn()
      |> put_req_header("content-type", "application/json")
      |> patch("/host/bulk-update", Jason.encode!(%{hostIds: [a], updates: %{pin: true}}))
      |> json_response(401)
    end
  end

  describe "changeset-level validation" do
    # The route's upfront guard only checks ip+port; these inputs pass it but fail the
    # changeset, so they are 400s now instead of the old NOT NULL 500 crash.
    # The message names the offending field rather than collapsing to "Invalid SSH data". That
    # matters most for a rejected private key, whose changeset error explains the format problem
    # and how to fix it — throwing that away left the user with a key that would not save and no
    # reason why. Ecto validation messages are templates ("can't be blank"), so no field VALUE
    # is ever echoed back.
    test "create without an authType is a 400 naming the field", %{token: token} do
      assert %{"error" => "authType: can't be blank"} =
               authed(token)
               |> post_json("/host/db/host", %{ip: "10.0.0.9", port: 22, username: "root"})
               |> json_response(400)
    end

    test "a malformed private key is rejected with an explanation, not a generic 400", ctx do
      %{"error" => message} =
        authed(ctx.token)
        |> post_json("/host/db/host", %{
          ip: "10.0.0.10",
          port: 22,
          username: "root",
          authType: "key",
          key: "not a key at all"
        })
        |> json_response(400)

      assert message =~ "key:"
      assert message =~ "private key format"
      # The rejected value must not be echoed back.
      refute message =~ "not a key at all"
    end

    test "update without an authType is a 400 and persists nothing", %{token: token, user: user} do
      %{"id" => id} =
        authed(token)
        |> post_json("/host/db/host", %{
          ip: "10.0.0.5",
          port: 22,
          username: "root",
          authType: "password",
          password: "s3cr3t"
        })
        |> json_response(200)

      assert %{"error" => "Invalid SSH data"} =
               authed(token)
               |> put_json("/host/db/host/#{id}", %{ip: "10.0.0.5", port: 2222, username: "root"})
               |> json_response(400)

      assert Hosts.get_for_user(id, user.id).port == 22
    end
  end

  describe "legacy remote-desktop rows" do
    for {type, rd_port} <- [{"rdp", 3389}, {"vnc", 5900}, {"telnet", 23}] do
      test "a legacy #{type} row is served as an ordinary SSH host on port 22", %{
        token: token,
        user: user
      } do
        %{"id" => id} =
          authed(token)
          |> post_json("/host/db/host", %{
            ip: "10.0.0.9",
            # The old editor wrote the remote-desktop port into `port` and kept the SSH port
            # in `sshPort`.
            port: unquote(rd_port),
            sshPort: 22,
            username: "admin",
            authType: "password",
            password: "s3cr3t"
          })
          |> json_response(200)

        # Simulate a row written before the remote-desktop removal: remote-desktop-only hosts
        # stored connection_type = "rdp"/"vnc"/"telnet" and enable_ssh = 0.
        Repo.get(Host, id)
        |> Ecto.Changeset.change(%{connectionType: unquote(type), enableSsh: false})
        |> Repo.update!()

        host = authed(token) |> get("/host/db/host/#{id}") |> json_response(200)

        assert host["connectionType"] == "ssh"
        assert host["enableSsh"] == true
        # The remote-desktop port must not survive the fold: every SSH consumer prefers
        # `port`, so leaving it would make the host open and silently dial #{rd_port}.
        assert host["port"] == 22
        assert host["sshPort"] == 22

        # The list endpoint normalizes identically.
        assert [listed] = authed(token) |> get("/host/db/host") |> json_response(200)
        assert listed["connectionType"] == "ssh"
        assert listed["enableSsh"] == true
        assert listed["port"] == 22
        assert listed["sshPort"] == 22

        # The connect paths read the raw struct, not the normalized JSON — they must resolve
        # the same port.
        assert Hosts.effective_ssh_port(Hosts.get_for_user(id, user.id)) == 22
      end
    end

    test "a legacy row with a custom sshPort folds onto that port", %{token: token, user: user} do
      %{"id" => id} =
        authed(token)
        |> post_json("/host/db/host", %{
          ip: "10.0.0.12",
          port: 3389,
          sshPort: 2022,
          username: "admin",
          authType: "password",
          password: "s3cr3t"
        })
        |> json_response(200)

      Repo.get(Host, id)
      |> Ecto.Changeset.change(%{connectionType: "rdp", enableSsh: false})
      |> Repo.update!()

      host = authed(token) |> get("/host/db/host/#{id}") |> json_response(200)

      assert host["port"] == 2022
      assert host["sshPort"] == 2022
      assert Hosts.effective_ssh_port(Hosts.get_for_user(id, user.id)) == 2022
    end

    test "an ssh row keeps its own enableSsh", %{token: token} do
      %{"id" => id} =
        authed(token)
        |> post_json("/host/db/host", %{
          ip: "10.0.0.10",
          port: 22,
          username: "root",
          authType: "password",
          password: "s3cr3t",
          enableSsh: false
        })
        |> json_response(200)

      host = authed(token) |> get("/host/db/host/#{id}") |> json_response(200)

      assert host["connectionType"] == "ssh"
      assert host["enableSsh"] == false
    end
  end

  describe "POST /host/db/host/:id/wake" do
    test "sends a magic packet for a host with a MAC", %{token: token} do
      %{"id" => id} =
        authed(token)
        |> post_json("/host/db/host", %{
          ip: "10.0.0.11",
          port: 22,
          username: "root",
          authType: "password",
          password: "s3cr3t",
          macAddress: "AA:BB:CC:DD:EE:FF",
          # Loopback so the test never actually broadcasts on the runner's network.
          wolBroadcastAddress: "127.0.0.1"
        })
        |> json_response(200)

      assert %{"success" => true} =
               authed(token) |> post("/host/db/host/#{id}/wake") |> json_response(200)
    end

    test "400 when the host has no valid MAC", %{token: token} do
      %{"id" => id} =
        authed(token)
        |> post_json("/host/db/host", %{
          ip: "10.0.0.12",
          port: 22,
          username: "root",
          authType: "password",
          password: "s3cr3t"
        })
        |> json_response(200)

      assert %{"error" => "No valid MAC address configured"} =
               authed(token) |> post("/host/db/host/#{id}/wake") |> json_response(400)
    end

    test "404 for a host the caller does not own", %{token: token} do
      {other_token, _other} = register_and_login("bob", @password)

      %{"id" => id} =
        authed(other_token)
        |> post_json("/host/db/host", %{
          ip: "10.0.0.13",
          port: 22,
          username: "root",
          authType: "password",
          password: "s3cr3t",
          macAddress: "AA:BB:CC:DD:EE:FF"
        })
        |> json_response(200)

      assert %{"error" => "Host not found"} =
               authed(token) |> post("/host/db/host/#{id}/wake") |> json_response(404)
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

  defp authed(token) do
    build_conn() |> put_req_header("authorization", "Bearer #{token}")
  end

  defp post_json(conn, path, payload) do
    conn
    |> put_req_header("content-type", "application/json")
    |> post(path, Jason.encode!(payload))
  end

  defp put_json(conn, path, payload) do
    conn
    |> put_req_header("content-type", "application/json")
    |> put(path, Jason.encode!(payload))
  end

  defp patch_json(conn, path, payload) do
    conn
    |> put_req_header("content-type", "application/json")
    |> patch(path, Jason.encode!(payload))
  end
end
