defmodule TermelixWeb.Plugs.TrustedProxy do
  @moduledoc """
  Normalises `conn.remote_ip` (and the forwarded scheme) from `x-forwarded-*` headers, but only
  when the *direct peer* is a configured trusted proxy.

  Before this plug existed the codebase disagreed with itself: `user_session_controller`,
  `admin_controller` and `tmux_controller` each carried a private `client_ip/1` that took the
  first `x-forwarded-for` value with no trust check and wrote it to session and audit rows, while
  `user_controller` deliberately used the peer address only, because a spoofable header would let
  an attacker reset their own rate-limit budget. Both halves were wrong for this deployment:

    * trusting the header unconditionally let anyone who can reach the app port directly (here,
      any tailnet peer on `:8080`) forge the IP in the audit trail;
    * refusing it unconditionally meant that behind a reverse proxy *every* request carried the
      proxy's address, so `{:login, ip, username}` buckets collapsed onto one IP — an attacker
      could burn any known user's failed-login budget and lock them out — and `{:register, ip}`
      became a single global 10-per-hour bucket for all clients.

  Resolving once, here, fixes both: downstream code reads `conn.remote_ip` and gets the real
  client when a trusted proxy forwarded it, or the honest peer address otherwise. Nothing needs
  a helper, so no future call site can forget the check.

  ## Configuration

  `TRUSTED_PROXIES` is a comma-separated list of CIDRs, bare addresses, or the tokens
  `loopback`, `private` and `none`. It defaults to `loopback,private` — loopback plus the RFC1918
  ranges — which covers the usual "reverse proxy on the same host or docker network" topology
  without trusting anything routable. Note that CGNAT/tailnet space (`100.64.0.0/10`) is
  deliberately *not* trusted by default: on this deployment that is exactly the range direct
  clients arrive from, and the proxy itself sits in `10.0.0.0/8`. A proxy reached over a tailnet
  address must therefore be listed explicitly.

  The default's residual exposure is worth stating plainly: on a deployment whose app port is
  reachable from a flat LAN, every LAN peer sits inside `private` and can therefore assert its own
  `x-forwarded-for`. That is the price of working out of the box for the compose/docker majority;
  an installation that exposes the port to untrusted peers should set `TRUSTED_PROXIES` to its
  proxy's exact address, or to `none` when there is no proxy at all.

  ## Forwarded scheme

  The same trust decision governs `x-forwarded-proto`. `config/prod.exs` previously handed this
  to `Plug.SSL`'s `rewrite_on:`, which performs no trust check of its own; since `Plug.SSL` is
  installed by Phoenix ahead of every endpoint plug, the rewrite is done here and `rewrite_on` is
  dropped, so the scheme `Plug.SSL` sees has already been vetted.
  """

  @behaviour Plug

  import Plug.Conn

  @loopback [{{127, 0, 0, 0}, 8}, {{0, 0, 0, 0, 0, 0, 0, 1}, 128}]
  @private [
    {{10, 0, 0, 0}, 8},
    {{172, 16, 0, 0}, 12},
    {{192, 168, 0, 0}, 16},
    {{0xFC00, 0, 0, 0, 0, 0, 0, 0}, 7}
  ]

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    conn = %{conn | remote_ip: normalize(conn.remote_ip)}

    if trusted?(conn.remote_ip, trusted_proxies()) do
      conn |> rewrite_remote_ip() |> rewrite_scheme()
    else
      conn
    end
  end

  # An IPv4 client reaching the endpoint's IPv6 socket (`ip: {0,0,0,0,0,0,0,0}` in
  # `config/runtime.exs`) has an IPv4-mapped peer address — `::ffff:10.23.56.5` as an 8-tuple, not
  # `{10,23,56,5}`. Collapsing it first is load-bearing, not cosmetic: without it no IPv4 CIDR ever
  # matches, so the reverse proxy is never trusted, `x-forwarded-proto` is ignored, and every
  # proxied request is redirected to https — a redirect loop that the container healthcheck cannot
  # see, because it uses the `localhost` host that `ForceSSL` excludes. Normalising `conn.remote_ip`
  # itself (not just the comparison) also keeps audit rows and rate-limit buckets on the readable
  # dotted form instead of `::ffff:`-prefixed duplicates of the same client.
  defp normalize({0, 0, 0, 0, 0, 0xFFFF, ab, cd}) do
    {Bitwise.bsr(ab, 8), Bitwise.band(ab, 0xFF), Bitwise.bsr(cd, 8), Bitwise.band(cd, 0xFF)}
  end

  defp normalize(ip), do: ip

  # Walk `x-forwarded-for` right to left, discarding hops that are themselves trusted proxies;
  # the first untrusted address is the client. Taking the *left*-most entry instead (as the old
  # per-controller helpers did) reads whatever the original client chose to send.
  defp rewrite_remote_ip(conn) do
    trusted = trusted_proxies()

    forwarded =
      conn
      |> get_req_header("x-forwarded-for")
      |> Enum.flat_map(&String.split(&1, ","))
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))

    case Enum.reverse(forwarded) |> Enum.find_value(&client_address(&1, trusted)) do
      nil -> conn
      ip -> %{conn | remote_ip: ip}
    end
  end

  defp client_address(candidate, trusted) do
    with {:ok, parsed} <- parse_address(candidate),
         ip = normalize(parsed),
         false <- trusted?(ip, trusted) do
      ip
    else
      _ -> nil
    end
  end

  defp rewrite_scheme(conn) do
    case conn |> get_req_header("x-forwarded-proto") |> List.first() do
      nil -> conn
      value -> apply_scheme(conn, value |> String.trim() |> String.downcase())
    end
  end

  defp apply_scheme(conn, "https"), do: %{conn | scheme: :https}
  defp apply_scheme(conn, "http"), do: %{conn | scheme: :http}
  defp apply_scheme(conn, _other), do: conn

  defp trusted?(_ip, []), do: false

  defp trusted?(ip, ranges), do: Enum.any?(ranges, fn {net, bits} -> in_range?(ip, net, bits) end)

  # Same-family comparison of the first `bits` of the address, tuple element by tuple element.
  defp in_range?(ip, net, bits)
       when tuple_size(ip) == tuple_size(net) do
    unit = if tuple_size(ip) == 4, do: 8, else: 16

    Enum.reduce_while(0..(tuple_size(ip) - 1), true, fn index, _acc ->
      remaining = bits - index * unit

      cond do
        remaining <= 0 -> {:halt, true}
        remaining >= unit -> compare_full(ip, net, index)
        true -> {:halt, compare_partial(ip, net, index, remaining, unit)}
      end
    end)
  end

  defp in_range?(_ip, _net, _bits), do: false

  defp compare_full(ip, net, index) do
    if elem(ip, index) == elem(net, index), do: {:cont, true}, else: {:halt, false}
  end

  defp compare_partial(ip, net, index, remaining, unit) do
    mask = Bitwise.bsl(Bitwise.bsr(0xFFFF, 16 - unit), unit - remaining)
    Bitwise.band(elem(ip, index), mask) == Bitwise.band(elem(net, index), mask)
  end

  defp parse_address(value) do
    # Strip a port and/or the brackets an IPv6 authority carries ("[::1]:443", "1.2.3.4:443").
    value
    |> String.replace(~r/^\[(.+)\](?::\d+)?$/, "\\1")
    |> String.replace(~r/^(\d+\.\d+\.\d+\.\d+):\d+$/, "\\1")
    |> String.to_charlist()
    |> :inet.parse_address()
  end

  @doc """
  The configured trusted-proxy ranges, as `{address_tuple, prefix_bits}`.

  Parsed on demand from `:termelix, :trusted_proxies` (populated from `TRUSTED_PROXIES` in
  `config/runtime.exs`) and memoised in `:persistent_term`, since it is read on every request
  and never changes at runtime.
  """
  @spec trusted_proxies() :: [{tuple(), non_neg_integer()}]
  def trusted_proxies do
    case :persistent_term.get({__MODULE__, :ranges}, :unset) do
      :unset ->
        ranges =
          parse_config(Application.get_env(:termelix, :trusted_proxies, "loopback,private"))

        :persistent_term.put({__MODULE__, :ranges}, ranges)
        ranges

      ranges ->
        ranges
    end
  end

  @doc false
  # Test hook: re-read the configuration instead of the memoised copy.
  @spec reset_cache() :: :ok
  def reset_cache do
    _ = :persistent_term.erase({__MODULE__, :ranges})
    :ok
  end

  defp parse_config(value) when is_binary(value) do
    value
    |> String.split(",", trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.flat_map(&parse_entry/1)
  end

  defp parse_config(value) when is_list(value), do: Enum.flat_map(value, &parse_entry/1)
  defp parse_config(_value), do: []

  defp parse_entry("loopback"), do: @loopback
  defp parse_entry("private"), do: @private
  defp parse_entry("none"), do: []

  defp parse_entry(entry) do
    case String.split(entry, "/", parts: 2) do
      [address, bits] -> parse_cidr(address, bits)
      [address] -> parse_host(address)
    end
  end

  defp parse_cidr(address, bits) do
    with {:ok, ip} <- parse_address(address),
         {parsed, ""} <- Integer.parse(bits),
         true <- parsed >= 0 and parsed <= max_bits(ip) do
      normalize_range({ip, parsed}, "#{address}/#{bits}")
    else
      _ -> warn_invalid("#{address}/#{bits}")
    end
  end

  defp parse_host(address) do
    case parse_address(address) do
      {:ok, ip} -> normalize_range({ip, max_bits(ip)}, address)
      _ -> warn_invalid(address)
    end
  end

  # Configured ranges get the same collapse as peers do, or a deployment that names its proxy in
  # IPv4-mapped form — `TRUSTED_PROXIES="::ffff:10.23.56.5"`, which is exactly how that peer looks
  # on the wire — would parse to an 8-tuple and never match the normalised 4-tuple it is meant to
  # describe. The prefix shifts with the address: the mapped space is `::ffff:0:0/96`, so a /104
  # covers the same hosts as an IPv4 /8.
  defp normalize_range({{0, 0, 0, 0, 0, 0xFFFF, _, _} = ip, bits}, _entry) when bits >= 96 do
    [{normalize(ip), bits - 96}]
  end

  # A mapped prefix shorter than /96 reaches outside the mapped block and is refused, but the two
  # bands below fail differently and the diagnostic has to say which — a security warning that
  # overstates the exposure teaches operators to discount the next one.
  #
  # At /80 or shorter the prefix constrains only the leading zero groups, so the range degenerates
  # to `::/bits` and takes in IPv6 loopback: `::1` would be trusted to assert its own client IP.
  defp normalize_range({{0, 0, 0, 0, 0, 0xFFFF, _, _}, bits}, entry) when bits <= 80 do
    refuse(
      entry,
      bits,
      "it degenerates to ::/#{bits}, matching unrelated IPv6 addresses including ::1 — which " <>
        "would then be trusted to assert its own x-forwarded-for"
    )
  end

  # Between /81 and /95 the prefix bites into the 0xffff group, so `::1` is *excluded*; the range
  # is the mapped block plus adjacent non-mapped IPv6 space. Still refused — it cannot match an
  # IPv4 peer, since peers are normalised before the comparison — but the loopback claim above
  # would be false here.
  defp normalize_range({{0, 0, 0, 0, 0, 0xFFFF, _, _}, bits}, entry) do
    refuse(
      entry,
      bits,
      "it spans the mapped block plus adjacent non-mapped IPv6 space, while never matching the " <>
        "IPv4 hosts it names, because peers are normalised to IPv4 before the comparison"
    )
  end

  defp normalize_range(range, _entry), do: [range]

  defp refuse(entry, bits, why) do
    require Logger

    Logger.warning(
      "TRUSTED_PROXIES: ignoring #{inspect(entry)} — an IPv4-mapped prefix shorter than /96 " <>
        "reaches outside the ::ffff:0:0/96 block. At /#{bits}, #{why}. Write the IPv4 range " <>
        "directly (e.g. 10.0.0.0/8), or a plain IPv6 CIDR if IPv6 was intended."
    )

    []
  end

  defp max_bits(ip) when tuple_size(ip) == 4, do: 32
  defp max_bits(_ip), do: 128

  defp warn_invalid(entry) do
    require Logger

    Logger.warning(
      "TRUSTED_PROXIES: ignoring unparseable entry #{inspect(entry)} " <>
        "(expected an IP, a CIDR, or one of loopback/private/none)"
    )

    []
  end
end
