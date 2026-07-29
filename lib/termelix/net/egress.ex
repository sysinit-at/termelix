defmodule Termelix.Net.Egress do
  @moduledoc """
  May the server make this outbound HTTP request? — defect 42's allowlist.

  `POST /notification-channels` and `/:id/test` fire a request at whatever `config["url"]`
  says, with no scheme or host check. On a self-hosted box that is a request forger sitting
  inside the network perimeter: `http://127.0.0.1:2375/containers/json`, the cloud metadata
  endpoint at `169.254.169.254`, or any RFC1918 address the host can route to — and the
  channel-test route reports the outcome, so it reads as well as writes.

  It has been dormant only because the alert engine has no evaluator. P6 gives it one, which
  is why this ships first rather than alongside.

  ## The rule

  A destination must clear three checks, in this order:

    1. **Scheme.** `https` only by default. `http` is available behind
       `alerts_allow_plaintext_egress`, because a self-hosted ntfy on a LAN is a real
       deployment and refusing it outright would be moralising rather than protecting.
    2. **Literal-address form.** A host that parses as an IP is checked directly.
    3. **Resolution.** A hostname is resolved and *every* address it answers with is checked.
       Not the first — all of them, because a name that returns one public and one private
       address is the ordinary shape of a DNS rebinding attempt, and picking the convenient
       one is exactly the bug.

  ## What is denied

  Loopback, link-local (including `169.254.169.254`), RFC1918, carrier-grade NAT, multicast,
  broadcast, unspecified and reserved ranges — v4 and v6, including v4-mapped v6 addresses,
  which are otherwise a trivial way to smuggle `127.0.0.1` past a v4-only check.

  `alerts_egress_allow_private` lifts the private-range denial for an operator who genuinely
  wants to notify a box on their own LAN. It is a deliberate, admin-only choice and it does
  NOT lift loopback: "notify my LAN" and "make the server talk to itself" are different
  requests, and only one of them is ever what someone meant.

  ## What this is not

  Not a defence against a *compromised* server, and not TOCTOU-free: the address is checked
  before the request, and a name could resolve differently by the time `Req` dials it. Closing
  that needs the connection pinned to the checked address, which `Req`/`Finch` does not expose
  cleanly. Stated rather than implied — this raises the cost of the attack from "paste a URL"
  to "win a DNS race", and that is the honest claim.
  """

  @type verdict :: :ok | {:error, :scheme_not_allowed | :host_not_allowed | :unresolvable}

  @doc """
  Check `url`. `:ok`, or `{:error, reason}` naming which rule refused it.

  Never raises: this sits in front of a delivery path, and an unparseable URL is a refusal,
  not a crash.
  """
  @spec check(term()) :: verdict()
  def check(url) when is_binary(url) do
    %URI{scheme: scheme, host: host} = URI.parse(url)

    # Scheme first, so the refusal names the rule that actually applies: `file:///etc/passwd`
    # has no host, and reporting that as "host not allowed" would send whoever is reading the
    # log looking for the wrong thing.
    with :ok <- check_scheme(scheme),
         true <- is_binary(host) and host != "" do
      check_host(host)
    else
      false -> {:error, :host_not_allowed}
      {:error, _reason} = error -> error
    end
  end

  def check(_url), do: {:error, :host_not_allowed}

  @doc "Whether a plaintext (`http`) destination is permitted. Off by default."
  @spec allow_plaintext?() :: boolean()
  def allow_plaintext?, do: setting_enabled?(:alerts_allow_plaintext_egress)

  @doc "Whether private/LAN destinations are permitted. Off by default; never lifts loopback."
  @spec allow_private?() :: boolean()
  def allow_private?, do: setting_enabled?(:alerts_egress_allow_private)

  defp check_scheme(scheme) when scheme in ["https"], do: :ok

  defp check_scheme("http"),
    do: if(allow_plaintext?(), do: :ok, else: {:error, :scheme_not_allowed})

  defp check_scheme(_other), do: {:error, :scheme_not_allowed}

  defp check_host(host) do
    case parse_address(host) do
      {:ok, address} -> check_address(address)
      :not_an_address -> check_resolved(host)
    end
  end

  # A bracketed v6 literal arrives from `URI.parse/1` without its brackets.
  defp parse_address(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, address} -> {:ok, address}
      {:error, _} -> :not_an_address
    end
  end

  defp check_resolved(host) do
    charlist = String.to_charlist(host)

    addresses =
      Enum.flat_map([:inet, :inet6], fn family ->
        case :inet.getaddrs(charlist, family) do
          {:ok, list} -> list
          {:error, _} -> []
        end
      end)

    cond do
      addresses == [] ->
        {:error, :unresolvable}

      # EVERY answer must pass. A name resolving to one public and one private address is the
      # ordinary shape of a rebinding attempt, and accepting it because the first answer looked
      # fine is the whole bug.
      Enum.all?(addresses, &(check_address(&1) == :ok)) ->
        :ok

      true ->
        {:error, :host_not_allowed}
    end
  end

  @doc """
  Whether one resolved address may be dialed. Public because the rule is worth testing
  directly, address by address, rather than only through a URL.
  """
  @spec check_address(:inet.ip_address()) :: verdict()
  def check_address(address) do
    cond do
      # Never lifted by any setting.
      loopback?(address) -> {:error, :host_not_allowed}
      unroutable?(address) -> {:error, :host_not_allowed}
      private?(address) -> if allow_private?(), do: :ok, else: {:error, :host_not_allowed}
      true -> :ok
    end
  end

  # --- address classification -------------------------------------------------

  # v4-mapped and v4-compatible v6 addresses are classified as the v4 address they carry.
  # Without this `::ffff:127.0.0.1` walks straight through a v4-only loopback check.
  defp normalize({0, 0, 0, 0, 0, 0xFFFF, ab, cd}), do: v4_from(ab, cd)
  defp normalize({0, 0, 0, 0, 0, 0, ab, cd}) when {ab, cd} != {0, 0}, do: v4_from(ab, cd)
  defp normalize(address), do: address

  defp v4_from(ab, cd),
    do: {Bitwise.bsr(ab, 8), Bitwise.band(ab, 0xFF), Bitwise.bsr(cd, 8), Bitwise.band(cd, 0xFF)}

  defp loopback?(address) do
    case normalize(address) do
      {127, _, _, _} -> true
      {0, 0, 0, 0, 0, 0, 0, 1} -> true
      _ -> false
    end
  end

  defp private?(address) do
    case normalize(address) do
      {10, _, _, _} -> true
      {172, b, _, _} when b >= 16 and b <= 31 -> true
      {192, 168, _, _} -> true
      # Carrier-grade NAT (RFC 6598) — routable-looking, and reachable on plenty of networks.
      {100, b, _, _} when b >= 64 and b <= 127 -> true
      # Unique local addresses, fc00::/7.
      {a, _, _, _, _, _, _, _} when Bitwise.band(a, 0xFE00) == 0xFC00 -> true
      _ -> false
    end
  end

  # Ranges that are never a legitimate notification destination, private setting or not.
  defp unroutable?(address) do
    case normalize(address) do
      {0, _, _, _} -> true
      # Link-local, which is where 169.254.169.254 (cloud metadata) lives.
      {169, 254, _, _} -> true
      # Multicast and the reserved/broadcast top of the space.
      {a, _, _, _} when a >= 224 -> true
      # Documentation/benchmark ranges — no reason to dial them, and cheap to refuse.
      {192, 0, 2, _} -> true
      {198, 18, _, _} -> true
      {198, 51, 100, _} -> true
      {203, 0, 113, _} -> true
      {0, 0, 0, 0, 0, 0, 0, 0} -> true
      # fe80::/10 link-local, ff00::/8 multicast.
      {a, _, _, _, _, _, _, _} when Bitwise.band(a, 0xFFC0) == 0xFE80 -> true
      {a, _, _, _, _, _, _, _} when Bitwise.band(a, 0xFF00) == 0xFF00 -> true
      _ -> false
    end
  end

  defp setting_enabled?(key) do
    case Application.get_env(:termelix, key) do
      value when value in [true, "true"] -> true
      value when value in [false, "false"] -> false
      _ -> setting_from_db(key)
    end
  end

  defp setting_from_db(key) do
    Termelix.Settings.get_value(to_string(key)) == "true"
  rescue
    # The settings table being unreadable must not open egress.
    _ -> false
  end
end
