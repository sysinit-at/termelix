defmodule Termelix.SSH.Socks5 do
  @moduledoc """
  A minimal SOCKS5 client dialer (RFC 1928 + RFC 1929), the port of the single-proxy branch of
  the Node `utils/proxy-helper.ts` (`createSingleProxyConnection`, which delegated to the `socks`
  npm package). Given a proxy and a final target, it opens a plain `:gen_tcp` socket to the proxy,
  performs the SOCKS5 method negotiation (no-auth or username/password) and a `CONNECT` request,
  and returns the **connected, passive** `:gen_tcp` socket already tunneled to the target.

  The returned socket is the raw transport primitive. OTP `:ssh.connect/2,3` *documents* an
  already-open-socket form (`open_socket()`) — the mechanism Node used to feed the `socks` socket
  into `ssh2` via `connectConfig.sock` — and the socket is returned in `{active, false}` mode as
  `:ssh`'s `valid_socket_to_use/2` requires. **However, in OTP 29 / ssh 6.0.2 that socket-takeover
  form stalls during version exchange** (`:ssh.connect(socket, …)` returns `{:error, :timeout}`
  even for a plain, readable socket), so to actually layer SSH on top `Termelix.SSH.JumpChain` bridges
  this socket to a loopback listener and dials that instead — see its moduledoc for the exact
  bridge. This module stays a pure dialer; the socket is equally usable for any raw byte stream.

  DEFERRED (documented, not ported here): SOCKS4, HTTP `CONNECT` proxies, and mixed/multi-hop
  proxy *chains* (`createMixedProxyChainConnection` / `createHopByHopConnection`). This dialer
  covers exactly one SOCKS5 proxy, which is what jump-host first-hop dialing needs. The IPv4/IPv6
  address blocklist (`isBlockedAddress`) belonged to the connectivity-test surface and is not part
  of the transport dialer.
  """

  @default_timeout 15_000

  @ver 0x05
  # method negotiation
  @auth_none 0x00
  @auth_userpass 0x02
  @auth_none_acceptable 0xFF
  # username/password sub-negotiation (RFC 1929) uses its own version byte
  @userpass_ver 0x01
  @userpass_ok 0x00
  # request
  @cmd_connect 0x01
  @rsv 0x00
  @atyp_ipv4 0x01
  @atyp_domain 0x03
  @atyp_ipv6 0x04
  @rep_success 0x00

  @type proxy :: %{
          required(:host) => String.t(),
          required(:port) => pos_integer(),
          optional(:username) => String.t() | nil,
          optional(:password) => String.t() | nil
        }

  @doc """
  Dial `target_host:target_port` through the SOCKS5 `proxy`. Returns `{:ok, socket}` with a
  connected `:gen_tcp` socket in passive (`{active, false}`) mode, ready to be used as a raw
  transport (e.g. handed to `:ssh.connect/3`), or `{:error, reason}`. On any post-connect failure
  the underlying socket is closed before returning.

  `target_host` may be an IPv4/IPv6 literal (sent as an `ATYP` address) or a hostname (sent as a
  domain name for the proxy to resolve — the standard SOCKS5 remote-DNS behaviour).
  """
  @spec connect(proxy(), String.t(), pos_integer(), timeout()) :: {:ok, port()} | {:error, term()}
  def connect(proxy, target_host, target_port, timeout \\ @default_timeout) do
    case open(proxy, timeout) do
      {:ok, sock} ->
        case handshake(sock, proxy, target_host, target_port, timeout) do
          :ok ->
            {:ok, sock}

          {:error, reason} ->
            safe_close(sock)
            {:error, reason}
        end

      {:error, reason} ->
        {:error, {:proxy_unreachable, reason}}
    end
  end

  # --- transport ------------------------------------------------------------

  defp open(proxy, timeout) do
    :gen_tcp.connect(
      String.to_charlist(proxy.host),
      proxy.port,
      [:binary, {:active, false}, {:packet, 0}],
      timeout
    )
  end

  defp handshake(sock, proxy, target_host, target_port, timeout) do
    with :ok <- negotiate_auth(sock, proxy, timeout),
         :ok <- send_connect(sock, target_host, target_port, timeout) do
      read_connect_reply(sock, timeout)
    end
  end

  # --- method negotiation ---------------------------------------------------

  defp negotiate_auth(sock, proxy, timeout) do
    methods = if creds?(proxy), do: <<@auth_none, @auth_userpass>>, else: <<@auth_none>>
    greeting = <<@ver, byte_size(methods)::8, methods::binary>>

    with :ok <- :gen_tcp.send(sock, greeting),
         {:ok, <<@ver, method>>} <- :gen_tcp.recv(sock, 2, timeout) do
      case method do
        @auth_none -> :ok
        @auth_userpass -> userpass_auth(sock, proxy, timeout)
        @auth_none_acceptable -> {:error, :no_acceptable_auth_methods}
        other -> {:error, {:unsupported_auth_method, other}}
      end
    else
      {:ok, other} -> {:error, {:bad_greeting_reply, other}}
      {:error, reason} -> {:error, {:socks_recv_failed, reason}}
    end
  end

  # RFC 1929 username/password sub-negotiation (version byte is 0x01, distinct from the SOCKS
  # version). Both fields are length-prefixed with a single byte, so each caps at 255 bytes.
  defp userpass_auth(sock, proxy, timeout) do
    user = to_string(proxy[:username] || "")
    pass = to_string(proxy[:password] || "")

    cond do
      byte_size(user) > 255 -> {:error, :username_too_long}
      byte_size(pass) > 255 -> {:error, :password_too_long}
      true -> send_userpass(sock, user, pass, timeout)
    end
  end

  defp send_userpass(sock, user, pass, timeout) do
    msg = <<@userpass_ver, byte_size(user)::8, user::binary, byte_size(pass)::8, pass::binary>>

    with :ok <- :gen_tcp.send(sock, msg),
         {:ok, <<@userpass_ver, status>>} <- :gen_tcp.recv(sock, 2, timeout) do
      if status == @userpass_ok, do: :ok, else: {:error, :proxy_auth_failed}
    else
      {:ok, other} -> {:error, {:bad_auth_reply, other}}
      {:error, reason} -> {:error, {:socks_recv_failed, reason}}
    end
  end

  # --- CONNECT request/reply ------------------------------------------------

  defp send_connect(sock, target_host, target_port, _timeout) do
    case encode_address(target_host) do
      {:ok, atyp, addr} ->
        req = <<@ver, @cmd_connect, @rsv, atyp, addr::binary, target_port::16>>

        case :gen_tcp.send(sock, req) do
          :ok -> :ok
          {:error, reason} -> {:error, {:socks_send_failed, reason}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp read_connect_reply(sock, timeout) do
    case :gen_tcp.recv(sock, 4, timeout) do
      {:ok, <<@ver, @rep_success, _rsv, atyp>>} ->
        consume_bound_address(sock, atyp, timeout)

      {:ok, <<@ver, rep, _rsv, _atyp>>} ->
        {:error, {:socks_connect_rejected, reply_error(rep)}}

      {:ok, other} ->
        {:error, {:bad_connect_reply, other}}

      {:error, reason} ->
        {:error, {:socks_recv_failed, reason}}
    end
  end

  # The CONNECT reply echoes a bound address whose length depends on ATYP; read and discard it so
  # the socket is left positioned at the start of the tunneled byte stream.
  defp consume_bound_address(sock, @atyp_ipv4, timeout), do: discard(sock, 4 + 2, timeout)
  defp consume_bound_address(sock, @atyp_ipv6, timeout), do: discard(sock, 16 + 2, timeout)

  defp consume_bound_address(sock, @atyp_domain, timeout) do
    case :gen_tcp.recv(sock, 1, timeout) do
      {:ok, <<n>>} -> discard(sock, n + 2, timeout)
      {:error, reason} -> {:error, {:socks_recv_failed, reason}}
    end
  end

  defp consume_bound_address(_sock, atyp, _timeout), do: {:error, {:unknown_bound_atyp, atyp}}

  defp discard(_sock, 0, _timeout), do: :ok

  defp discard(sock, n, timeout) do
    case :gen_tcp.recv(sock, n, timeout) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, {:socks_recv_failed, reason}}
    end
  end

  # --- helpers --------------------------------------------------------------

  # IPv4/IPv6 literals become numeric ATYP addresses; anything else is a domain name (ATYP 0x03,
  # length-prefixed) for the proxy to resolve.
  defp encode_address(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, {a, b, c, d}} ->
        {:ok, @atyp_ipv4, <<a, b, c, d>>}

      {:ok, {a, b, c, d, e, f, g, h}} ->
        {:ok, @atyp_ipv6, <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>}

      {:error, _} ->
        bytes = :erlang.iolist_to_binary(host)

        if byte_size(bytes) > 255 do
          {:error, :hostname_too_long}
        else
          {:ok, @atyp_domain, <<byte_size(bytes)::8, bytes::binary>>}
        end
    end
  end

  # SOCKS5 reply codes (RFC 1928 §6) → readable atoms.
  defp reply_error(0x01), do: :general_failure
  defp reply_error(0x02), do: :connection_not_allowed
  defp reply_error(0x03), do: :network_unreachable
  defp reply_error(0x04), do: :host_unreachable
  defp reply_error(0x05), do: :connection_refused
  defp reply_error(0x06), do: :ttl_expired
  defp reply_error(0x07), do: :command_not_supported
  defp reply_error(0x08), do: :address_type_not_supported
  defp reply_error(other), do: {:unknown_reply_code, other}

  # Offer username/password auth only when a username is configured (RFC 1929 allows an empty
  # password); the server still gets to pick no-auth if it prefers.
  defp creds?(proxy), do: present?(proxy[:username])

  defp safe_close(sock) do
    :gen_tcp.close(sock)
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  defp present?(v) when is_binary(v), do: String.trim(v) != ""
  defp present?(_), do: false
end
