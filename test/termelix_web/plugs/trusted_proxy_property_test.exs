defmodule TermelixWeb.Plugs.TrustedProxyPropertyTest do
  @moduledoc """
  Generated coverage for the trust check's address matching.

  Three rounds of point fixes on this plug each found a defect the previous round's targeted tests
  did not cover — IPv4-mapped peers, then IPv4-mapped configuration, then the coverage inversion
  below /96. The common shape was always the same: a case nobody thought to enumerate. So the
  matcher is checked here against an independent reference (integer comparison of the leading
  `bits`), across generated address/prefix pairs, rather than against more hand-picked examples.

  Generation is seeded, so a failure reproduces exactly and the suite stays deterministic; the
  failure messages carry the offending pair. `stream_data` would add shrinking, but the inputs
  here are small enough to read as-is and it is not worth a new dependency.
  """
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias TermelixWeb.Plugs.TrustedProxy

  # Every prefix length is covered by construction rather than by hoping random draws hit them
  # all — the masking code has a distinct path per partial-group boundary, so a prefix length that
  # never gets generated is a path that never gets tested.
  @prefixes 8..32
  @cases_per_prefix 3
  @peers_per_cidr 24
  @seed {19_700_101, 42, 7}

  # Two probes in different /8s: no prefix of /8 or longer can contain both, so at least one is
  # always outside the range under test and can stand in for "the real client".
  @probes [{203, 0, 113, 7}, {198, 51, 100, 4}]

  setup do
    previous = Application.get_env(:termelix, :trusted_proxies)

    on_exit(fn ->
      if previous == nil,
        do: Application.delete_env(:termelix, :trusted_proxies),
        else: Application.put_env(:termelix, :trusted_proxies, previous)

      TrustedProxy.reset_cache()
    end)

    :rand.seed(:exsss, @seed)
    :ok
  end

  # A generator that quietly stops generating turns every property below into a tautology. The
  # first version of this file did exactly that: it built "interior" addresses by truncating a
  # random address (zeroing its host bits) and then merging those zeroed host bits into the
  # network, so all eight collapsed onto the network address itself and no property ever saw a
  # random address inside a range. These assertions make that failure loud.
  describe "the generator produces what the properties assume" do
    test "every prefix length in the advertised range is generated" do
      generated = cidrs() |> Enum.map(&elem(&1, 1)) |> Enum.uniq() |> Enum.sort()
      assert generated == Enum.to_list(@prefixes)
    end

    test "the interior generator spreads across the range instead of collapsing" do
      for {net, bits} <- cidrs() do
        interior = interior_peers(net, bits)

        assert Enum.all?(interior, &reference_match?(&1, net, bits)),
               "interior peer outside #{ip_string(net)}/#{bits}: " <>
                 inspect(Enum.reject(interior, &reference_match?(&1, net, bits)))

        # Ranges of /31 and /32 hold two addresses and one; there is nothing to spread across.
        if Bitwise.bsl(1, 32 - bits) >= 4 do
          distinct = interior |> Enum.uniq() |> length()

          assert distinct >= 2,
                 "interior generator for #{ip_string(net)}/#{bits} collapsed to " <>
                   inspect(Enum.uniq(interior))
        end
      end
    end

    test "each case yields both interior and exterior peers" do
      for {net, bits} <- cidrs() do
        {inside, outside} = Enum.split_with(peers(net, bits), &reference_match?(&1, net, bits))

        assert length(outside) >= 1, "no exterior peer for #{ip_string(net)}/#{bits}"
        assert length(inside) >= 3, "too few interior peers for #{ip_string(net)}/#{bits}"
      end
    end

    test "interior addresses really are inside, exterior really are outside" do
      for {net, bits} <- cidrs() do
        assert reference_match?(merge_host(random_ipv4(), net, bits), net, bits)
        assert reference_match?(last_in_range(net, bits), net, bits)
        assert reference_match?(flip_bit(net, bits), net, bits)
        refute reference_match?(flip_bit(net, bits - 1), net, bits)
      end
    end
  end

  describe "matching agrees with an independent reference" do
    test "for IPv4 peers against IPv4 CIDRs" do
      for {net, bits} <- cidrs() do
        configure("#{ip_string(net)}/#{bits}")

        for peer <- peers(net, bits) do
          assert decide(peer) == reference(peer, net, bits),
                 "peer #{ip_string(peer)} vs #{ip_string(net)}/#{bits}"
        end
      end
    end
  end

  describe "IPv4-mapped form never changes the answer" do
    # The bug in 6d68b63: the peer arrives ::ffff:-prefixed on the endpoint's IPv6 socket.
    test "presenting the peer mapped decides identically" do
      for {net, bits} <- cidrs() do
        configure("#{ip_string(net)}/#{bits}")

        for peer <- peers(net, bits) do
          assert decide(mapped(peer)) == decide(peer),
                 "mapped peer #{ip_string(peer)} vs #{ip_string(net)}/#{bits}"
        end
      end
    end

    # The bug in 990bc6c: the operator writes the proxy the way it appears on the wire.
    test "writing the CIDR mapped decides identically" do
      for {net, bits} <- cidrs() do
        plain = "#{ip_string(net)}/#{bits}"
        as_mapped = "::ffff:#{ip_string(net)}/#{bits + 96}"

        for peer <- peers(net, bits) do
          configure(plain)
          expected = decide(peer)

          configure(as_mapped)

          assert decide(peer) == expected,
                 "#{as_mapped} disagreed with #{plain} for peer #{ip_string(peer)}"
        end
      end
    end

    test "both sides mapped decides identically" do
      for {net, bits} <- cidrs() do
        plain = "#{ip_string(net)}/#{bits}"

        for peer <- peers(net, bits) do
          configure(plain)
          expected = decide(peer)

          configure("::ffff:#{ip_string(net)}/#{bits + 96}")

          assert decide(mapped(peer)) == expected,
                 "both-mapped disagreed with #{plain} for peer #{ip_string(peer)}"
        end
      end
    end
  end

  describe "refused configurations trust nothing" do
    # The bug in d22073d: below /96 the coverage inverts, and at /80 or shorter it swept in ::1.
    test "no mapped prefix under /96 trusts IPv6 loopback or the IPv4 it names" do
      for {net, bits} <- cidrs(),
          prefix <- [bits, bits + 40, bits + 80] |> Enum.filter(&(&1 < 96)) do
        ExUnit.CaptureLog.capture_log(fn ->
          configure("::ffff:#{ip_string(net)}/#{prefix}")

          assert TrustedProxy.trusted_proxies() == [],
                 "::ffff:#{ip_string(net)}/#{prefix} was not refused"

          assert decide({0, 0, 0, 0, 0, 0, 0, 1}) == :untrusted,
                 "::1 trusted under ::ffff:#{ip_string(net)}/#{prefix}"

          assert decide(net) == :untrusted,
                 "#{ip_string(net)} trusted under ::ffff:#{ip_string(net)}/#{prefix}"
        end)
      end
    end
  end

  describe "address families stay separate" do
    test "an IPv4 CIDR never trusts a non-mapped IPv6 peer" do
      for {net, bits} <- cidrs() do
        configure("#{ip_string(net)}/#{bits}")

        for peer <- ipv6_peers() do
          assert decide(peer) == :untrusted,
                 "IPv6 #{ip_string(peer)} trusted by #{ip_string(net)}/#{bits}"
        end
      end
    end
  end

  # --- the plug, through its public path ---

  defp configure(value) do
    Application.put_env(:termelix, :trusted_proxies, value)
    TrustedProxy.reset_cache()
  end

  # Trust is observable only through its effect: a trusted peer's forwarded client replaces
  # `remote_ip`. The probe is chosen outside the range so it is never mistaken for another proxy.
  defp decide(peer) do
    probe = probe_outside()

    conn =
      %{conn(:get, "/") | remote_ip: peer}
      |> put_req_header("x-forwarded-for", ip_string(probe))
      |> TrustedProxy.call([])

    if conn.remote_ip == probe, do: :trusted, else: :untrusted
  end

  defp probe_outside do
    ranges = TrustedProxy.trusted_proxies()

    Enum.find(@probes, hd(@probes), fn probe ->
      not Enum.any?(ranges, fn {net, bits} -> reference_match?(probe, net, bits) end)
    end)
  end

  # --- independent reference: compare the leading `bits` as integers ---

  defp reference(peer, net, bits) do
    if reference_match?(normalize(peer), net, bits), do: :trusted, else: :untrusted
  end

  defp reference_match?(ip, net, bits) do
    {a, width} = to_int(ip)
    {b, net_width} = to_int(net)

    width == net_width and Bitwise.bsr(a, width - bits) == Bitwise.bsr(b, width - bits)
  end

  defp to_int(ip) when tuple_size(ip) == 4 do
    {a, b, c, d} = ip
    <<n::32>> = <<a, b, c, d>>
    {n, 32}
  end

  defp to_int(ip) when tuple_size(ip) == 8 do
    bin = for i <- 0..7, into: <<>>, do: <<elem(ip, i)::16>>
    <<n::128>> = bin
    {n, 128}
  end

  defp normalize({0, 0, 0, 0, 0, 0xFFFF, ab, cd}) do
    {Bitwise.bsr(ab, 8), Bitwise.band(ab, 0xFF), Bitwise.bsr(cd, 8), Bitwise.band(cd, 0xFF)}
  end

  defp normalize(ip), do: ip

  defp mapped({a, b, c, d}), do: {0, 0, 0, 0, 0, 0xFFFF, a * 256 + b, c * 256 + d}

  # --- generators ---

  # Prefixes from /8: shorter ones would swallow both probes, leaving no address that can stand in
  # for the client. /8../32 covers every partial-byte boundary the matcher masks on.
  defp cidrs do
    for bits <- @prefixes, _ <- 1..@cases_per_prefix do
      {truncate(random_ipv4(), bits), bits}
    end
  end

  # A mix of addresses inside the range, on its edges, and unrelated — so both branches of the
  # decision are exercised rather than whichever one random addresses happen to hit. For anything
  # wider than a /24 a random address is outside with overwhelming probability, so the interior
  # has to be constructed deliberately.
  defp peers(net, bits) do
    interior_peers(net, bits) ++
      edge_peers(net, bits) ++ for(_ <- 1..(@peers_per_cidr - 8 - 4), do: random_ipv4())
  end

  # Kept separate so the meta-test can hold *this* to account. Asserting on the combined list
  # instead would hide a collapse here, because the edges below are themselves interior and
  # distinct — which is exactly how the first version of this file passed while generating nothing.
  defp interior_peers(net, bits), do: for(_ <- 1..8, do: merge_host(random_ipv4(), net, bits))

  defp edge_peers(net, bits) do
    [
      net,
      last_in_range(net, bits),
      # Flipping the final network bit leaves the range; flipping the first host bit does not.
      flip_bit(net, bits - 1),
      flip_bit(net, bits)
    ]
  end

  defp ipv6_peers do
    fixed = [
      {0, 0, 0, 0, 0, 0, 0, 1},
      {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1},
      {0xFC00, 0, 0, 0, 0, 0, 0, 1},
      {0xFE80, 0, 0, 0, 0, 0, 0, 1}
    ]

    fixed ++ for(_ <- 1..4, do: random_ipv6())
  end

  defp random_ipv6, do: List.to_tuple(for _ <- 1..8, do: :rand.uniform(0x10000) - 1)

  defp random_ipv4, do: {rand_byte(), rand_byte(), rand_byte(), rand_byte()}

  defp rand_byte, do: :rand.uniform(256) - 1

  defp truncate(ip, bits) do
    {n, width} = to_int(ip)
    masked = Bitwise.bsl(Bitwise.bsr(n, width - bits), width - bits)
    from_int(masked)
  end

  # Keep `bits` leading bits of `net`, take the rest from `ip` — an address inside the range.
  defp merge_host(ip, net, bits) do
    {host, width} = to_int(ip)
    {network, ^width} = to_int(net)
    keep = Bitwise.bsl(Bitwise.bsr(network, width - bits), width - bits)
    host_mask = Bitwise.bnot(Bitwise.bsl(Bitwise.bsr(-1, width - bits), width - bits))
    from_int(Bitwise.band(Bitwise.bor(keep, Bitwise.band(host, host_mask)), 0xFFFFFFFF))
  end

  defp flip_bit(ip, index) when index in 0..31 do
    {n, width} = to_int(ip)
    from_int(Bitwise.bxor(n, Bitwise.bsl(1, width - 1 - index)))
  end

  defp flip_bit(ip, _index), do: ip

  defp last_in_range(net, bits) do
    {n, width} = to_int(net)
    host_bits = width - bits
    from_int(Bitwise.bor(n, Bitwise.bsl(1, host_bits) - 1))
  end

  defp from_int(n) do
    <<a, b, c, d>> = <<n::32>>
    {a, b, c, d}
  end

  defp ip_string(ip), do: ip |> :inet.ntoa() |> to_string()
end
