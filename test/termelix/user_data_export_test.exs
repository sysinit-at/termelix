defmodule Termelix.UserDataExportTest do
  @moduledoc """
  Unit tests for the `Termelix.UserDataExport` context: the `UserExportData` shape, the
  encrypted-vs-plaintext secret handling, the include-credentials switch, and the locked /
  not-found error paths.
  """
  use Termelix.DataCase

  alias Termelix.{Accounts, Hosts, UserDataExport}
  alias Termelix.Schema.User

  @password "correct horse battery staple"

  setup do
    {:ok, user} = Accounts.admin_create_user("expuser", @password)

    {:ok, host} =
      Hosts.create_host(user.id, %{
        name: "web-1",
        ip: "10.0.0.9",
        port: 22,
        username: "root",
        authType: "password",
        password: "s3cr3t"
      })

    %{user: user, host: host}
  end

  describe "export_user_data/2" do
    test "plaintext export decrypts secrets and reports the full shape", %{user: user} do
      assert {:ok, export} = UserDataExport.export_user_data(user.id, format: :plaintext)

      assert export.version == "v2.0"
      assert export.userId == user.id
      assert export.username == "expuser"
      assert is_binary(export.exportedAt)

      assert [host] = export.userData.sshHosts
      # Secret is decrypted under the user's DEK (matches the Node plaintext admin export).
      assert host.password == "s3cr3t"

      assert export.userData.fileManagerData == %{
               recent: [],
               pinned: [],
               shortcuts: [],
               transferRecent: []
             }

      assert export.userData.dismissedAlerts == []
      assert export.metadata.encrypted == false
      assert export.metadata.exportType == "user_data"
      assert export.metadata.totalRecords == 1
    end

    test "encrypted export keeps secrets as ciphertext envelopes", %{user: user} do
      assert {:ok, export} = UserDataExport.export_user_data(user.id, format: :encrypted)

      assert [host] = export.userData.sshHosts
      # Stored ciphertext (a JSON envelope), never the plaintext.
      assert String.starts_with?(host.password, "{")
      refute host.password == "s3cr3t"
      assert export.metadata.encrypted == true
    end

    test "blob columns are scrubbed, including a row that predates the guard", %{
      user: user,
      host: host
    } do
      # The export builds rows with `Map.from_struct/1`, so an unencrypted column is egress by
      # default. That is how a `sudoPassword` inside the `terminalConfig` blob reached the
      # `format: "encrypted"` export — the one documented as never exposing plaintext.
      #
      # Writing such a row is now refused by a database trigger, so the only way to reach the state
      # this guards is the one that matters: a row written before the trigger existed. The triggers
      # are dropped inside the sandbox transaction and restored when it rolls back.
      drop_terminal_config_triggers()

      for blob <- [
            ~s({"sudoPassword":"TOP-LEVEL","fontSize":14}),
            ~s({"a":{"sudoPassword":"NESTED"}}),
            ~s([{"sudoPassword":"IN-ARRAY"}]),
            ~s({"sudoPassword":"MALFORMED",})
          ] do
        Repo.query!("UPDATE ssh_data SET terminal_config = ? WHERE id = ?", [blob, host.id])

        assert {:ok, export} = UserDataExport.export_user_data(user.id, format: :encrypted)
        assert [exported] = export.userData.sshHosts

        # The malformed blob exports as nil — it cannot be edited safely and is not readable as
        # configuration, so it is dropped rather than passed through. The others keep their shape.
        exported_config = exported.terminalConfig || ""

        for marker <- ["TOP-LEVEL", "NESTED", "IN-ARRAY", "MALFORMED"] do
          refute exported_config =~ marker
        end
      end

      # Non-secret configuration survives — this scrubs a key, it does not blank the column.
      Repo.query!("UPDATE ssh_data SET terminal_config = ? WHERE id = ?", [
        ~s({"sudoPassword":"LEAK","fontSize":14}),
        host.id
      ])

      assert {:ok, export} = UserDataExport.export_user_data(user.id, format: :encrypted)
      assert [exported] = export.userData.sshHosts
      assert exported.terminalConfig =~ "fontSize"
    end

    test "include_credentials: false omits credentials", %{user: user} do
      assert {:ok, export} =
               UserDataExport.export_user_data(user.id,
                 format: :encrypted,
                 include_credentials: false
               )

      assert export.userData.sshCredentials == []
    end

    test "scope is echoed as metadata.exportType", %{user: user} do
      assert {:ok, export} = UserDataExport.export_user_data(user.id, scope: "all")
      assert export.metadata.exportType == "all"
    end

    test "a plaintext export of a user without a DEK is locked" do
      ghost = insert_dekless_user("ghost1", "ghostuser")

      assert {:error, :locked} =
               UserDataExport.export_user_data(ghost.id, format: :plaintext)

      # An encrypted export needs no key, so it still succeeds.
      assert {:ok, _} = UserDataExport.export_user_data(ghost.id, format: :encrypted)
    end

    test "an unknown user is not found" do
      assert {:error, :user_not_found} = UserDataExport.export_user_data("does-not-exist")
    end
  end

  # A user row with no wrapped DEK in the settings table — `try_get_user_dek` returns nil.
  defp drop_terminal_config_triggers do
    for suffix <- ["insert", "update"] do
      Repo.query!("DROP TRIGGER IF EXISTS ssh_data_terminal_config_must_be_json_#{suffix}")
      Repo.query!("DROP TRIGGER IF EXISTS ssh_data_no_secret_in_terminal_config_#{suffix}")
    end
  end

  defp insert_dekless_user(id, username) do
    Repo.insert!(%User{
      id: id,
      username: username,
      passwordHash: "x",
      isAdmin: false,
      isOidc: false,
      totpEnabled: false,
      donationModalDismissed: false,
      registeredAt: "2026-01-01T00:00:00.000Z"
    })
  end
end
