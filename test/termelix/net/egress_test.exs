defmodule Termelix.Net.EgressTest do
  @moduledoc """
  Defect 42: `POST /notification-channels` fires a request at whatever URL it is given. On a
  self-hosted box that is a request forger inside the perimeter — the docker socket, the cloud
  metadata endpoint, any RFC1918 address the host can route to — and the channel-test route
  reports the outcome, so it reads as well as writes.
  """
  use ExUnit.Case, async: false

  alias Termelix.Net.Egress

  setup do
    Application.put_env(:termelix, :alerts_allow_plaintext_egress, false)
    Application.put_env(:termelix, :alerts_egress_allow_private, false)

    on_exit(fn ->
      Application.delete_env(:termelix, :alerts_allow_plaintext_egress)
      Application.delete_env(:termelix, :alerts_egress_allow_private)
    end)
  end

  describe "the destinations defect 42 was actually about" do
    test "loopback in every spelling" do
      for url <- [
            "https://127.0.0.1:2375/containers/json",
            "https://127.1.2.3/",
            "https://[::1]/",
            # v4-mapped v6: a v4-only loopback check waves this straight through.
            "https://[::ffff:127.0.0.1]/",
            "https://localhost/"
          ] do
        assert Egress.check(url) == {:error, :host_not_allowed}, "allowed #{url}"
      end
    end

    test "the cloud metadata endpoint" do
      assert Egress.check("https://169.254.169.254/latest/meta-data/") ==
               {:error, :host_not_allowed}

      assert Egress.check("https://[fe80::1]/") == {:error, :host_not_allowed}
    end

    test "RFC1918, CGNAT and unique-local" do
      for url <- [
            "https://10.0.0.1/",
            "https://172.16.5.4/",
            "https://172.31.255.255/",
            "https://192.168.1.1/",
            "https://100.64.0.4/",
            "https://[fd00::1]/"
          ] do
        assert Egress.check(url) == {:error, :host_not_allowed}, "allowed #{url}"
      end
    end

    test "172.15 and 172.32 are NOT private — the range is 16..31, and an off-by-one here
          would either open a hole or break a legitimate destination" do
      assert Egress.check("https://172.15.0.1/") == :ok
      assert Egress.check("https://172.32.0.1/") == :ok
    end
  end

  describe "scheme" do
    test "https only by default" do
      assert Egress.check("http://example.com/hook") == {:error, :scheme_not_allowed}
      assert Egress.check("ftp://example.com/") == {:error, :scheme_not_allowed}
      assert Egress.check("https://example.com/hook") == :ok
    end

    test "plaintext is available behind the setting — a self-hosted ntfy on a LAN is real" do
      Application.put_env(:termelix, :alerts_allow_plaintext_egress, true)
      assert Egress.check("http://example.com/hook") == :ok
      # ...but the scheme setting does not also open the address rules.
      assert Egress.check("http://127.0.0.1/") == {:error, :host_not_allowed}
    end
  end

  describe "the private-range setting" do
    test "lifts RFC1918 but never loopback" do
      Application.put_env(:termelix, :alerts_egress_allow_private, true)

      assert Egress.check("https://192.168.1.10/") == :ok
      assert Egress.check("https://10.1.2.3/") == :ok

      # "Notify my LAN" and "make the server talk to itself" are different requests.
      assert Egress.check("https://127.0.0.1/") == {:error, :host_not_allowed}
      assert Egress.check("https://[::1]/") == {:error, :host_not_allowed}
      assert Egress.check("https://169.254.169.254/") == {:error, :host_not_allowed}
    end
  end

  describe "malformed input is refused, never raised" do
    test "a URL with no host, and a non-string" do
      # Refused either way; the reason names whichever rule it tripped first, and a bare string
      # has no scheme at all.
      assert Egress.check("not a url") == {:error, :scheme_not_allowed}
      assert Egress.check("") == {:error, :scheme_not_allowed}
      assert Egress.check("https://") == {:error, :host_not_allowed}
      assert Egress.check("file:///etc/passwd") == {:error, :scheme_not_allowed}
      assert Egress.check(nil) == {:error, :host_not_allowed}
      assert Egress.check(%{}) == {:error, :host_not_allowed}
    end

    test "a name that does not resolve is refused, and says why" do
      assert Egress.check("https://no-such-host.invalid/") == {:error, :unresolvable}
    end
  end

  describe "address rules, checked directly" do
    test "public addresses pass" do
      assert Egress.check_address({1, 1, 1, 1}) == :ok
      assert Egress.check_address({8, 8, 8, 8}) == :ok
      assert Egress.check_address({0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111}) == :ok
    end

    test "0.0.0.0, multicast and broadcast are refused" do
      assert Egress.check_address({0, 0, 0, 0}) == {:error, :host_not_allowed}
      assert Egress.check_address({224, 0, 0, 1}) == {:error, :host_not_allowed}
      assert Egress.check_address({255, 255, 255, 255}) == {:error, :host_not_allowed}
      assert Egress.check_address({0, 0, 0, 0, 0, 0, 0, 0}) == {:error, :host_not_allowed}
    end
  end
end
