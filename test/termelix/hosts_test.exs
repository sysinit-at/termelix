defmodule Termelix.HostsTest do
  @moduledoc """
  Context-level coverage for `Termelix.Hosts`: changeset validation (invalid writes return an
  error changeset and persist nothing), and the `decrypt: false` listing variant, whose
  normalized wire output must be identical to the decrypted listing's.
  """
  use Termelix.DataCase, async: false

  alias Termelix.{Accounts, Hosts, Repo}
  alias Termelix.Schema.Host
  alias TermelixWeb.HostNormalizer

  @password "correct horse battery staple"

  setup do
    {:ok, user, _first?} = Accounts.register_user("alice", @password)
    %{user: user}
  end

  defp attrs(overrides \\ %{}) do
    Map.merge(
      %{
        name: "web-1",
        ip: "10.0.0.5",
        port: 22,
        username: "root",
        authType: "password",
        password: "s3cr3t",
        connectionType: "ssh"
      },
      overrides
    )
  end

  describe "create_host/2" do
    test "changeset-invalid attrs return an error changeset and insert nothing", %{user: user} do
      assert {:error, %Ecto.Changeset{}} = Hosts.create_host(user.id, attrs(%{port: 70_000}))
      assert {:error, %Ecto.Changeset{}} = Hosts.create_host(user.id, attrs(%{ip: ""}))

      assert {:error, %Ecto.Changeset{}} =
               Hosts.create_host(user.id, Map.delete(attrs(), :authType))

      assert Hosts.list_for_user(user.id) == []
    end
  end

  describe "update_host/3" do
    test "a changeset-invalid update persists nothing", %{user: user} do
      {:ok, host} = Hosts.create_host(user.id, attrs())

      assert {:error, %Ecto.Changeset{}} = Hosts.update_host(user.id, host.id, %{port: 0})
      assert Hosts.get_for_user(host.id, user.id).port == 22
    end
  end

  describe "list_for_user/2 with decrypt: false" do
    test "normalized wire output is identical to the decrypted listing", %{user: user} do
      # One host with encrypted secrets (through the context). The key has to be a real one:
      # `create_host/2` format-checks a freshly supplied private key so an unusable key is
      # rejected at save time rather than failing every connect with OTP's generic auth error.
      {:ok, _encrypted} =
        Hosts.create_host(user.id, attrs(%{key: test_private_key(), keyPassword: "kp"}))

      # ...and one legacy (imported) row with plaintext secrets, bypassing encryption.
      Repo.insert!(%Host{
        userId: user.id,
        connectionType: "ssh",
        name: "legacy",
        ip: "10.0.0.6",
        port: 23,
        username: "root",
        authType: "key",
        password: "plainpw",
        key: "  ",
        createdAt: "2024-01-01 00:00:00",
        updatedAt: "2024-01-01 00:00:00"
      })

      decrypted = user.id |> Hosts.list_for_user() |> Enum.map(&HostNormalizer.transform/1)

      raw =
        user.id |> Hosts.list_for_user(decrypt: false) |> Enum.map(&HostNormalizer.transform/1)

      assert raw == decrypted

      # Presence booleans: an encrypted envelope and non-empty legacy plaintext both count as
      # present; the whitespace-only legacy key does not (matching the decrypted read).
      [first, second] = raw
      assert first.hasPassword == true
      assert first.hasKey == true
      assert first.hasKeyPassword == true
      assert second.hasPassword == true
      assert second.hasKey == false
      refute Map.has_key?(first, :password)
      refute Map.has_key?(second, :key)
    end
  end

  describe "list_for_user/2 with a :filter" do
    test "filters BEFORE decrypting, so excluded rows never touch the DEK", %{user: user} do
      {:ok, _monitored} = Hosts.create_host(user.id, attrs(%{enableTmuxMonitor: true}))

      {:ok, _plain} =
        Hosts.create_host(
          user.id,
          attrs(%{name: "plain", ip: "10.0.0.7", enableTmuxMonitor: false})
        )

      all = Hosts.list_for_user(user.id)
      assert length(all) == 2

      filtered =
        Hosts.list_for_user(user.id, filter: &(&1.enableTmuxMonitor == true))

      assert [only] = filtered
      assert only.name == "web-1"
      # The surviving row is still decrypted as usual — the filter drops rows, not behavior.
      assert only.password == "s3cr3t"
    end
  end

  describe "effective_ssh_port/1" do
    test "an ssh row keeps its own port" do
      assert Hosts.effective_ssh_port(%Host{connectionType: "ssh", port: 2222, sshPort: 22}) ==
               2222
    end

    test "a row with no connectionType keeps its own port" do
      assert Hosts.effective_ssh_port(%Host{connectionType: nil, port: 2222}) == 2222
    end

    test "an ssh row with no port falls back to sshPort, then 22" do
      assert Hosts.effective_ssh_port(%Host{connectionType: "ssh", port: nil, sshPort: 2022}) ==
               2022

      assert Hosts.effective_ssh_port(%Host{connectionType: "ssh", port: nil, sshPort: nil}) == 22
    end

    for {type, rd_port} <- [{"rdp", 3389}, {"vnc", 5900}, {"telnet", 23}] do
      test "a legacy #{type} row ignores its remote-desktop port" do
        host = %Host{connectionType: unquote(type), port: unquote(rd_port), sshPort: 2022}
        assert Hosts.effective_ssh_port(host) == 2022
      end

      test "a legacy #{type} row with no sshPort falls back to 22, never #{rd_port}" do
        host = %Host{connectionType: unquote(type), port: unquote(rd_port), sshPort: nil}
        assert Hosts.effective_ssh_port(host) == 22
      end
    end

    test "the connectionType match is case-insensitive" do
      assert Hosts.effective_ssh_port(%Host{connectionType: "RDP", port: 3389, sshPort: 22}) == 22
    end

    test "accepts the plain map the normalizer works on" do
      assert Hosts.effective_ssh_port(%{connectionType: "rdp", port: 3389, sshPort: 22}) == 22
    end
  end

  # A genuine, throwaway private key: `Hosts.create_host/2` validates the format on write, so a
  # placeholder string is no longer a usable stand-in. Generated once per run rather than
  # checked in, so nothing here looks like a credential worth stealing.
  defp test_private_key do
    dir =
      Path.join(System.tmp_dir!(), "termelix_hosts_test_#{System.unique_integer([:positive])}")

    File.mkdir_p!(dir)
    path = Path.join(dir, "id_ed25519")
    {_, 0} = System.cmd("ssh-keygen", ["-t", "ed25519", "-N", "", "-f", path, "-q"])
    key = File.read!(path)
    File.rm_rf(dir)
    key
  end
end
