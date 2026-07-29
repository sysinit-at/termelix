defmodule TermelixWeb.Plugs.TrustedProxyTest do
  @moduledoc """
  The trust boundary for `x-forwarded-for` / `x-forwarded-proto`.

  The cases that matter are the negative ones: an untrusted peer must not be able to dictate the
  address that lands in audit rows and rate-limit buckets, nor the scheme `Plug.SSL` acts on.
  """
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  alias TermelixWeb.Plugs.TrustedProxy

  setup do
    original = Application.get_env(:termelix, :trusted_proxies)

    on_exit(fn ->
      if original == nil,
        do: Application.delete_env(:termelix, :trusted_proxies),
        else: Application.put_env(:termelix, :trusted_proxies, original)

      TrustedProxy.reset_cache()
    end)

    :ok
  end

  defp configure(value) do
    Application.put_env(:termelix, :trusted_proxies, value)
    TrustedProxy.reset_cache()
  end

  defp run(peer, headers) do
    Enum.reduce(headers, %{conn(:get, "/") | remote_ip: peer}, fn {k, v}, conn ->
      put_req_header(conn, k, v)
    end)
    |> TrustedProxy.call([])
  end

  describe "x-forwarded-for" do
    test "an untrusted peer cannot forge the client address" do
      configure("10.0.0.0/8")
      conn = run({100, 64, 0, 9}, [{"x-forwarded-for", "1.2.3.4"}])
      assert conn.remote_ip == {100, 64, 0, 9}
    end

    test "a trusted proxy's forwarded address is adopted" do
      configure("10.0.0.0/8")
      conn = run({10, 23, 56, 5}, [{"x-forwarded-for", "203.0.113.7"}])
      assert conn.remote_ip == {203, 0, 113, 7}
    end

    test "chained proxies resolve to the right-most untrusted hop" do
      configure("10.0.0.0/8")

      conn = run({10, 23, 56, 5}, [{"x-forwarded-for", "203.0.113.7, 10.1.1.1, 10.23.56.5"}])

      assert conn.remote_ip == {203, 0, 113, 7}
    end

    # Taking the left-most entry (what the old per-controller helpers did) would return
    # 9.9.9.9 here — a value the client chose.
    test "a client-supplied prefix ahead of the real address is ignored" do
      configure("10.0.0.0/8")
      conn = run({10, 23, 56, 5}, [{"x-forwarded-for", "9.9.9.9, 203.0.113.7"}])
      assert conn.remote_ip == {203, 0, 113, 7}
    end

    test "an all-trusted chain leaves the peer in place" do
      configure("10.0.0.0/8")
      conn = run({10, 23, 56, 5}, [{"x-forwarded-for", "10.1.1.1"}])
      assert conn.remote_ip == {10, 23, 56, 5}
    end

    test "a garbage header value is ignored" do
      configure("10.0.0.0/8")
      conn = run({10, 23, 56, 5}, [{"x-forwarded-for", "not-an-ip"}])
      assert conn.remote_ip == {10, 23, 56, 5}
    end

    test "an address carrying a port still parses" do
      configure("10.0.0.0/8")
      conn = run({10, 23, 56, 5}, [{"x-forwarded-for", "203.0.113.7:41234"}])
      assert conn.remote_ip == {203, 0, 113, 7}
    end
  end

  # The endpoint binds `ip: {0,0,0,0,0,0,0,0}`, so an IPv4 client's peer address arrives
  # IPv4-mapped. Without collapsing it, no IPv4 CIDR matches, the reverse proxy is never trusted,
  # and `ForceSSL` redirects every proxied request — a redirect loop the `localhost` healthcheck
  # cannot see.
  describe "IPv4-mapped IPv6 peers (the endpoint's real socket)" do
    test "a mapped proxy address still matches an IPv4 CIDR" do
      configure("10.0.0.0/8")
      # ::ffff:10.23.56.5
      conn = run({0, 0, 0, 0, 0, 0xFFFF, 0x0A17, 0x3805}, [{"x-forwarded-for", "203.0.113.7"}])
      assert conn.remote_ip == {203, 0, 113, 7}
    end

    test "a mapped untrusted address is still refused" do
      configure("10.0.0.0/8")
      # ::ffff:100.64.0.9
      conn = run({0, 0, 0, 0, 0, 0xFFFF, 0x6440, 0x0009}, [{"x-forwarded-for", "203.0.113.7"}])
      assert conn.remote_ip == {100, 64, 0, 9}
    end

    test "the peer is normalised even when nothing is forwarded" do
      configure("none")
      conn = run({0, 0, 0, 0, 0, 0xFFFF, 0x0A17, 0x3805}, [])
      assert conn.remote_ip == {10, 23, 56, 5}
    end

    test "a mapped address inside the forwarded chain is collapsed too" do
      configure("10.0.0.0/8")
      conn = run({10, 23, 56, 5}, [{"x-forwarded-for", "::ffff:203.0.113.7"}])
      assert conn.remote_ip == {203, 0, 113, 7}
    end

    test "a real IPv6 peer is left alone" do
      configure("none")
      conn = run({0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}, [])
      assert conn.remote_ip == {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}
    end

    test "the default config trusts a mapped loopback and private peer" do
      configure("loopback,private")

      # ::ffff:127.0.0.1 — exactly what the eval probe observed on the IPv6 listener.
      assert run({0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {203, 0, 113, 7}

      assert run({0, 0, 0, 0, 0, 0xFFFF, 0x0A17, 0x3805}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {203, 0, 113, 7}
    end
  end

  describe "x-forwarded-proto" do
    test "an untrusted peer cannot claim https" do
      configure("10.0.0.0/8")
      conn = run({100, 64, 0, 9}, [{"x-forwarded-proto", "https"}])
      assert conn.scheme == :http
    end

    test "a trusted proxy's scheme is adopted" do
      configure("10.0.0.0/8")
      conn = run({10, 23, 56, 5}, [{"x-forwarded-proto", "https"}])
      assert conn.scheme == :https
    end
  end

  describe "configuration" do
    test "the default trusts loopback and RFC1918 but not CGNAT/tailnet space" do
      configure("loopback,private")

      assert run({127, 0, 0, 1}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {203, 0, 113, 7}

      assert run({192, 168, 1, 5}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {203, 0, 113, 7}

      assert run({172, 18, 0, 1}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {203, 0, 113, 7}

      # The deployment's direct-access range: must NOT be able to speak for a client.
      assert run({100, 64, 0, 9}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {100, 64, 0, 9}
    end

    test "`none` disables forwarding entirely" do
      configure("none")

      assert run({10, 23, 56, 5}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {10, 23, 56, 5}
    end

    test "a bare address is treated as a single host" do
      configure("10.23.56.5")

      assert run({10, 23, 56, 5}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {203, 0, 113, 7}

      assert run({10, 23, 56, 6}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {10, 23, 56, 6}
    end

    test "a non-byte-aligned prefix masks correctly" do
      configure("172.16.0.0/12")

      assert run({172, 31, 255, 254}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {203, 0, 113, 7}

      # 172.32.0.0 is outside a /12 that starts at 172.16.0.0.
      assert run({172, 32, 0, 1}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {172, 32, 0, 1}
    end

    test "IPv6 peers are matched against IPv6 ranges only" do
      configure("loopback,private")

      assert run({0, 0, 0, 0, 0, 0, 0, 1}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {203, 0, 113, 7}

      assert run({0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}
    end

    test "an unparseable entry is skipped rather than crashing the pipeline" do
      configure("nonsense,10.0.0.0/8")

      assert run({10, 23, 56, 5}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {203, 0, 113, 7}
    end

    # `::ffff:10.23.56.5` is exactly how that proxy looks on the wire, so naming it that way in
    # TRUSTED_PROXIES is a reasonable thing for an operator to do. It has to match the peer, which
    # the plug has already normalised to `{10,23,56,5}`.
    test "a proxy configured in IPv4-mapped form is trusted" do
      configure("::ffff:10.23.56.5")

      assert run({10, 23, 56, 5}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {203, 0, 113, 7}

      assert run({0, 0, 0, 0, 0, 0xFFFF, 0x0A17, 0x3805}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {203, 0, 113, 7}
    end

    test "a proxy configured in IPv4-mapped form does not trust other addresses" do
      configure("::ffff:10.23.56.5")

      assert run({10, 23, 56, 6}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {10, 23, 56, 6}
    end

    test "an IPv4-mapped CIDR keeps its host coverage" do
      configure("::ffff:10.0.0.0/104")

      assert run({10, 23, 56, 5}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {203, 0, 113, 7}

      assert run({11, 0, 0, 1}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip == {11, 0, 0, 1}
    end

    # `::ffff:0.0.0.0/96` collapses to an IPv4 /0 — a config that trusts everything. Every hop in
    # the chain is then a trusted proxy, so no entry can be identified as the client and the peer
    # stands. Pinned because the tempting "fix" is to fall back to the left-most hop, which is the
    # client-controlled value this plug exists to ignore.
    test "a config that trusts everything yields no forwarded client" do
      configure("::ffff:0.0.0.0/96")

      assert run({203, 0, 113, 7}, [{"x-forwarded-for", "198.51.100.4"}]).remote_ip ==
               {203, 0, 113, 7}
    end

    # Left as an IPv6 range, `::ffff:10.0.0.0/64` constrains only leading zeros: it matches
    # everything in ::/64 — letting ::1 forge x-forwarded-for — while never matching the
    # 10.0.0.0/8 it names, because peers normalise to IPv4 first. Exactly inverted, so it is
    # refused rather than interpreted.
    test "a mapped prefix shorter than /96 is refused, not reinterpreted" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          configure("::ffff:10.0.0.0/64")
          assert TrustedProxy.trusted_proxies() == []
        end)

      assert log =~ "shorter than /96"
      assert log =~ "10.0.0.0/8"

      # Neither the IPv6 addresses it would have swept in...
      assert run({0, 0, 0, 0, 0, 0, 0, 1}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {0, 0, 0, 0, 0, 0, 0, 1}

      # ...nor the IPv4 hosts it appeared to name.
      assert run({10, 0, 0, 5}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip == {10, 0, 0, 5}
    end

    # /81..95 constrains part of the 0xffff group, so ::1 (whose bit 80 is 0) is excluded. The
    # refusal stands — such a range still cannot match a normalised IPv4 peer — but claiming
    # loopback exposure here would be false, and a security warning that overstates the risk
    # teaches operators to discount the next one.
    test "the /81../95 diagnostic makes no loopback claim" do
      for bits <- [81, 88, 95] do
        log =
          ExUnit.CaptureLog.capture_log(fn ->
            configure("::ffff:10.0.0.0/#{bits}")
            assert TrustedProxy.trusted_proxies() == []
          end)

        refute log =~ "::1"
        assert log =~ "adjacent non-mapped IPv6 space"
        assert log =~ "10.0.0.0/8"
      end
    end

    test "the /80-and-shorter diagnostic does name the loopback exposure" do
      for bits <- [64, 80] do
        log =
          ExUnit.CaptureLog.capture_log(fn ->
            configure("::ffff:10.0.0.0/#{bits}")
            assert TrustedProxy.trusted_proxies() == []
          end)

        assert log =~ "::1"
        assert log =~ "degenerates to ::/#{bits}"
      end
    end

    test "a refused mapped prefix does not discard the other entries" do
      ExUnit.CaptureLog.capture_log(fn -> configure("::ffff:10.0.0.0/64,192.168.0.0/16") end)

      assert run({192, 168, 1, 5}, [{"x-forwarded-for", "203.0.113.7"}]).remote_ip ==
               {203, 0, 113, 7}
    end

    test "/96 remains the boundary that is still accepted" do
      configure("::ffff:10.0.0.0/96")
      assert TrustedProxy.trusted_proxies() == [{{10, 0, 0, 0}, 0}]
    end

    test "reset_cache/0 honours its contract on a cold cache" do
      TrustedProxy.reset_cache()
      assert TrustedProxy.reset_cache() == :ok
    end
  end
end
