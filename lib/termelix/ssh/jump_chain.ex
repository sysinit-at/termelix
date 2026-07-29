defmodule Termelix.SSH.JumpChain do
  @moduledoc """
  Jump-host chaining for OTP `:ssh`, the port of Node `hosts/jump-host-chain.ts`
  (`createJumpHostChain`). Given an ordered list of jump-host connect options and a final target,
  it stands up the chain hop by hop and returns the final connection reference, optionally routing
  the *first* TCP hop through a SOCKS5 proxy (`Termelix.SSH.Socks5`, the port of
  `getJumpHostSocks5Config` + `createSocks5Connection`).

  ## How each hop is bridged

  Node used `ssh2`'s `currentClient.forwardOut(...)` to open a `direct-tcpip` channel to the next
  hop and fed the resulting stream to the next client as `connectConfig.sock`. OTP 29 / ssh 6.0.2
  exposes **no** client-side `direct-tcpip` channel primitive on `:ssh_connection` (it has session,
  exec, shell and subsystem channels only). The supported forward primitive is
  `:ssh.tcpip_tunnel_to_server/6` — the same one `Termelix.Tunnels.Tunnel` uses. It opens the
  `direct-tcpip` channel internally and binds a **local** listener that forwards each accepted TCP
  connection through the current SSH connection to `next_host:next_port`. So to add a hop we:

    1. ask the current connection to forward `127.0.0.1:0 -> next_host:next_port`
       (`tcpip_tunnel_to_server` returns the OS-picked local port);
    2. `:ssh.connect/3` the next hop at `127.0.0.1:<local_port>` — its SSH negotiation now travels
       through the previous hop's `direct-tcpip` channel to the real next-hop `sshd`.

  This requires each intermediate hop's daemon to permit local forwarding (`AllowTcpForwarding
  yes`, the OpenSSH default; the in-VM test daemon sets `tcpip_tunnel_in: true`). The first hop is
  reached directly, or — when `socks5_opts` is given — through a socket `Termelix.SSH.Socks5` dials.

  ## Feeding a SOCKS5 socket to `:ssh` (the "exact bridging needed")

  OTP `:ssh.connect/2,3` documents an already-open-socket form (`open_socket()`), which is how Node
  fed the `socks` socket to `ssh2`. In OTP 29 / ssh 6.0.2, however, that socket-takeover path
  **stalls during version exchange** — `:ssh.connect(socket, opts, timeout)` returns
  `{:error, :timeout}` even for a plainly-connected, passive socket whose server banner is readable
  by hand (verified empirically). So rather than hand the SOCKS5-dialed socket to `:ssh` directly,
  we **bridge** it: a loopback listener is opened, a relay process splices the dialed socket to
  each accepted local connection, and `:ssh.connect/3` dials `127.0.0.1:<local_port>` normally
  (the ordinary host/port path, which works). This is the same shape as the hop bridge above, but
  hand-rolled with `:gen_tcp` for the one socket SOCKS5 produces (there is no OTP primitive that
  wraps a caller-supplied socket into a listener). `Termelix.SSH.Socks5` still returns the raw
  socket — the correct low-level primitive — and the bridge lives here where SSH is layered on top.

  ## Lifetime

  `connect/3` returns only the **final** `ConnRef` (Node parity: `createJumpHostChain` returns just
  the last client). The intermediate connections and their forward listeners stay up — they carry
  the tunnel — but their handles are dropped. Callers that must tear the whole chain down should
  use `connect_chain/3`, which returns every `ConnRef` in order (`[hop0, …, final]`), and
  `close_chain/1`. Closing only the final ref leaves the intermediates running until their owning
  process exits, so prefer `connect_chain/3` for anything long-lived.

  This is a standalone primitive — `Termelix.SSH.Client` / `Termelix.SSH.Exec` are intentionally left
  unwired; they can opt into it later.
  """

  require Logger

  alias Termelix.SSH.ConnectOpts
  alias Termelix.SSH.Socks5

  @connect_timeout 15_000
  @forward_timeout 15_000

  # How many times a tunnelled hop may re-establish its forward — see `connect_via/3`.
  @forward_attempts 3
  @bind_host ~c"127.0.0.1"

  @type conn_opts :: %{
          required(:host) => String.t(),
          required(:port) => pos_integer(),
          required(:username) => String.t(),
          optional(:password) => String.t() | nil,
          optional(:private_key) => String.t() | nil,
          optional(:key_password) => String.t() | nil
        }

  @type socks5_opts :: Socks5.proxy() | nil

  # --- public API -----------------------------------------------------------

  @doc """
  Establish the chain and return the **final** connection reference. `jump_hops` is ordered from
  the closest hop (reached first, directly or via SOCKS5) to the last hop before the target; an
  empty list connects straight to `final_conn_opts` (still honouring `socks5_opts`). Returns
  `{:ok, conn}` or `{:error, reason}`; on failure every connection opened so far is torn down.
  """
  @spec connect(conn_opts(), [conn_opts()], socks5_opts()) :: {:ok, term()} | {:error, term()}
  def connect(final_conn_opts, jump_hops \\ [], socks5_opts \\ nil) do
    case connect_chain(final_conn_opts, jump_hops, socks5_opts) do
      {:ok, refs} -> {:ok, List.last(refs)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Like `connect/3` but returns **all** connection references in hop order
  (`{:ok, [hop0, …, final]}`), so the caller can tear the whole chain down with `close_chain/1`.
  """
  @spec connect_chain(conn_opts(), [conn_opts()], socks5_opts()) ::
          {:ok, [term()]} | {:error, term()}
  def connect_chain(final_conn_opts, jump_hops \\ [], socks5_opts \\ nil) do
    targets = jump_hops ++ [final_conn_opts]
    build_chain(targets, normalize_socks5(socks5_opts), [])
  end

  @doc "Close every connection reference in a chain (in reverse order). Always returns `:ok`."
  @spec close_chain([term()]) :: :ok
  def close_chain(refs) when is_list(refs) do
    refs |> Enum.reverse() |> Enum.each(&safe_close/1)
    :ok
  end

  @doc """
  Build a `Termelix.SSH.Socks5` proxy map from a host row's `socks5*` fields, or `nil` when the host
  does not use SOCKS5. Mirrors `getJumpHostSocks5Config`'s single-proxy branch (the
  `socks5ProxyChain` / mixed-chain branch is deferred — see `Termelix.SSH.Socks5`).
  """
  @spec socks5_from_host(map()) :: Socks5.proxy() | nil
  def socks5_from_host(host) when is_map(host) do
    use? = get(host, :useSocks5, "useSocks5")
    proxy_host = get(host, :socks5Host, "socks5Host")

    if truthy?(use?) and present?(proxy_host) do
      %{
        host: proxy_host,
        port: get(host, :socks5Port, "socks5Port") || 1080,
        username: get(host, :socks5Username, "socks5Username"),
        password: get(host, :socks5Password, "socks5Password")
      }
    else
      nil
    end
  end

  def socks5_from_host(_), do: nil

  # --- chain construction ---------------------------------------------------

  # First hop: reached directly over TCP, or through a SOCKS5-dialed socket.
  defp build_chain([first | rest], socks5, []) do
    case connect_first(first, socks5) do
      {:ok, conn} -> build_chain(rest, socks5, [conn])
      {:error, reason} -> {:error, reason}
    end
  end

  # Subsequent hop: forward through the previous connection, then SSH over that forward.
  defp build_chain([next | rest], socks5, [prev | _] = acc) do
    case connect_via(prev, next) do
      {:ok, conn} ->
        build_chain(rest, socks5, [conn | acc])

      {:error, reason} ->
        close_chain(acc)
        {:error, reason}
    end
  end

  defp build_chain([], _socks5, acc), do: {:ok, Enum.reverse(acc)}

  defp connect_first(opts, nil), do: ssh_connect_host(opts)

  defp connect_first(opts, %{} = socks5) do
    case Socks5.connect(socks5, opts.host, opts.port, @connect_timeout) do
      {:ok, sock} -> connect_over_socket(sock, opts)
      {:error, reason} -> {:error, {:socks5_failed, reason}}
    end
  end

  # SSH over a caller-supplied socket. OTP's socket-takeover form stalls (see moduledoc), so we
  # bridge the socket to a loopback listener and let `:ssh` dial that with the ordinary path.
  defp connect_over_socket(sock, opts) do
    case bridge(sock) do
      {:ok, listen_port} ->
        case :ssh.connect(@bind_host, listen_port, ssh_opts(opts), @connect_timeout) do
          {:ok, conn} -> {:ok, conn}
          {:error, reason} -> {:error, {:connect_failed, reason}}
        end

      {:error, reason} ->
        safe_close_socket(sock)
        {:error, {:bridge_failed, reason}}
    end
  end

  # Bridge to `next` through `prev`: open a local `direct-tcpip` forward on the previous hop, then
  # SSH-connect the next hop at the forward's local endpoint.
  defp connect_via(prev_conn, next, attempts_left \\ @forward_attempts) do
    case :ssh.tcpip_tunnel_to_server(
           prev_conn,
           @bind_host,
           0,
           String.to_charlist(next.host),
           next.port,
           @forward_timeout
         ) do
      {:ok, listen_port} ->
        case :ssh.connect(@bind_host, listen_port, ssh_opts(next), @connect_timeout) do
          {:ok, conn} ->
            {:ok, conn}

          # A forward that reports itself up but never carries the connection. OTP's
          # `tcpip_tunnel_to_server/6` returns as soon as the local listener exists; the
          # `direct-tcpip` channel to the server is only opened when something connects to it,
          # and if THAT loses a race the client's TCP connect still succeeds — it is the
          # backlog — and then nothing ever answers. The symptom is not an error but silence:
          # `:ssh.connect/4` waits for a version banner until its own timeout, so the failure
          # takes exactly as long as the budget you give it, whatever that budget is.
          #
          # Retrying establishes a NEW forward, which is the only thing that can help: the old
          # listener is wedged, and no amount of waiting on it changes that. Bounded, and only
          # for `:timeout` — a refused connection or a rejected credential is an answer, and
          # answers are not retried.
          {:error, :timeout} when attempts_left > 1 ->
            Logger.warning(
              "jump forward to #{next.host}:#{next.port} did not carry the connection; " <>
                "re-establishing (#{attempts_left - 1} attempt(s) left)"
            )

            connect_via(prev_conn, next, attempts_left - 1)

          {:error, reason} ->
            {:error, {:connect_failed, reason}}
        end

      {:error, reason} ->
        {:error, {:forward_failed, reason}}
    end
  end

  defp ssh_connect_host(opts) do
    case :ssh.connect(String.to_charlist(opts.host), opts.port, ssh_opts(opts), @connect_timeout) do
      {:ok, conn} -> {:ok, conn}
      {:error, reason} -> {:error, {:connect_failed, reason}}
    end
  end

  # The `:hop` profile: the shared auth/trust base with neither the pooled `idle_time` backstop
  # (a hop carrying only forwards idles channel-less by design) nor interactive keepalive.
  defp ssh_opts(opts), do: ConnectOpts.build(opts, :hop)

  # --- socket bridge (SOCKS5 socket -> local listener for :ssh) --------------

  # Splice `sock` to a fresh loopback listener; return the OS-picked local port. A relay process
  # owns both the listener and `sock`, accepts one local connection (the one `:ssh` will make), and
  # copies bytes in both directions until either side closes. Ownership of `sock` (and the
  # listener) is transferred to the relay before it runs, so this process must not touch `sock`
  # afterwards.
  defp bridge(sock) do
    case :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}, {:ip, {127, 0, 0, 1}}]) do
      {:ok, lsock} ->
        {:ok, {_ip, port}} = :inet.sockname(lsock)
        parent = self()

        pid =
          spawn(fn ->
            receive do
              {:start, ^parent} -> bridge_accept(lsock, sock)
            after
              @connect_timeout -> :ok
            end
          end)

        with :ok <- :gen_tcp.controlling_process(lsock, pid),
             :ok <- :gen_tcp.controlling_process(sock, pid) do
          send(pid, {:start, parent})
          {:ok, port}
        else
          {:error, reason} ->
            Process.exit(pid, :kill)
            safe_close_socket(lsock)
            # `sock` was leaked here: ownership may or may not have moved, and either way the
            # SOCKS5 connection to the proxy stayed open with nobody left to close it.
            safe_close_socket(sock)
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp bridge_accept(lsock, up) do
    case :gen_tcp.accept(lsock, @connect_timeout) do
      {:ok, down} ->
        # One connection is all `:ssh` makes; stop listening.
        :gen_tcp.close(lsock)
        splice(down, up)

      _ ->
        safe_close_socket(lsock)
        safe_close_socket(up)
    end
  end

  # Copy bytes both ways until either side closes.
  #
  # ONE process owns BOTH sockets. The previous shape — a second process spawned to
  # `:gen_tcp.recv/3` the accepted socket while this one recv'd the upstream — had that second
  # process reading a socket it did not own. `inet` does not promise that: depending on backend
  # and timing the read never completes, and because the SSH client has by then finished its TCP
  # connect and is waiting for the server's version banner, the symptom is not an error but a
  # HANG — `:ssh.connect/4` sitting out whatever timeout it was given.
  #
  # `{:active, :once}`, re-armed one message at a time, NOT `active: true`. Unlimited active
  # mode hands the socket's flow control to the VM: the kernel drains its receive buffer into
  # this mailbox as fast as the peer can send, the TCP window never closes, and a peer that
  # sends faster than the other side accepts (a `cat` of a large file down a slow forward — the
  # ordinary case this code exists for) grows the mailbox without bound until the node dies.
  # `:once` keeps the backpressure where TCP already implements it: one message is delivered,
  # nothing more is read until this process has finished forwarding it, and a blocked
  # `:gen_tcp.send/2` on the far side stalls the near side's window exactly as it should.
  defp splice(down, up) do
    with :ok <- :inet.setopts(down, active: :once),
         :ok <- :inet.setopts(up, active: :once) do
      splice_loop(down, up)
    else
      _ -> close_both(down, up)
    end
  end

  defp splice_loop(down, up) do
    receive do
      {:tcp, ^down, data} ->
        # Send first, re-arm second: nothing more is read from `down` until this chunk has
        # reached `up`, which is what keeps the TCP window doing the throttling.
        with :ok <- :gen_tcp.send(up, data),
             :ok <- :inet.setopts(down, active: :once) do
          splice_loop(down, up)
        else
          _ -> close_both(down, up)
        end

      {:tcp, ^up, data} ->
        with :ok <- :gen_tcp.send(down, data),
             :ok <- :inet.setopts(up, active: :once) do
          splice_loop(down, up)
        else
          _ -> close_both(down, up)
        end

      {:tcp_closed, _sock} ->
        close_both(down, up)

      {:tcp_error, _sock, _reason} ->
        close_both(down, up)
    end
  end

  defp close_both(a, b) do
    safe_close_socket(a)
    safe_close_socket(b)
  end

  # --- socks5 config normalization ------------------------------------------

  defp normalize_socks5(nil), do: nil

  defp normalize_socks5(%{host: host} = m) when is_binary(host) do
    if present?(host) do
      %{host: host, port: m[:port] || 1080, username: m[:username], password: m[:password]}
    else
      nil
    end
  end

  # Tolerate being handed a raw host row / SOCKS5Config-shaped map.
  defp normalize_socks5(%{} = m), do: socks5_from_host(m)

  # --- helpers --------------------------------------------------------------

  defp get(map, atom_key, string_key) do
    case Map.get(map, atom_key) do
      nil -> Map.get(map, string_key)
      v -> v
    end
  end

  defp truthy?(true), do: true
  defp truthy?(1), do: true
  defp truthy?("1"), do: true
  defp truthy?("true"), do: true
  defp truthy?(_), do: false

  defp safe_close(conn) do
    :ssh.close(conn)
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  defp safe_close_socket(sock) do
    :gen_tcp.close(sock)
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  defp present?(v) when is_binary(v), do: String.trim(v) != ""
  defp present?(_), do: false
end
