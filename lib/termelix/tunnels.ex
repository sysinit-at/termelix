defmodule Termelix.Tunnels do
  @moduledoc """
  The tunnel control plane: create, look up, list, and tear down SSH local port forwards,
  ported from the Node `hosts/tunnel/manager.ts` + `routes.ts` glue. Mirrors the
  `Termelix.Terminal.SessionManager` shape — a thin context over a `Registry` +
  `DynamicSupervisor` pair — but each managed process is a `Termelix.Tunnels.Tunnel`.

  Where Node kept a dozen global `Map`/`Set`s (activeTunnels, connectionStatus, retryCounters,
  manualDisconnects, …) keyed by tunnel name, OTP folds all of that per-tunnel state into the
  `Tunnel` GenServer and its Registry value. Status is therefore read straight from the
  Registry (no cross-process call), and "connected/connecting/failed" is whatever the live
  process last published.

  Source credentials are resolved **server-side** from the host row via
  `Termelix.Hosts.get_for_user/2` (ownership + DEK decryption enforced) — a body-supplied
  `sourcePassword`/`sourceSSHKey` is never trusted, and an unresolvable source host reads as
  "no access". This resolution runs in the caller's process (which holds the DB connection),
  and only the decrypted `conn_opts` are handed to the tunnel process.

  DEVIATIONS from Node, all intentional for this port:
  - Statuses are **scoped to the requesting user** (Node exposed one global map). The frontend
    only ever looks up its own tunnel names, so this is transparent and strictly safer.
  - Registry keys are `{user_id, name}`: the raw user-chosen name is only unique per user, so
    two users can run same-named tunnels simultaneously (previously a second same-named
    tunnel — even another user's — failed with a confusing `{:stop, :name_taken}` → 500).
    Same-user duplicate names keep the Node reconnect semantics below: the old tunnel is
    stopped and replaced.
  - A manual disconnect **stops** the process (the status map then omits it); the frontend
    renders a missing entry as `DISCONNECTED`, so the UX matches Node's explicit
    `{status: disconnected, manualDisconnect: true}` broadcast.
  - Reverse (`-R`) and dynamic (SOCKS) forwarding are deferred to `Tunnel` (immediate `failed`).
  - `bindHost` is **constrained to loopback** unless an admin enables the
    `tunnel_allow_public_bind` setting. The forwarded listener carries no authentication of
    its own, so a body-supplied `0.0.0.0` would turn this app into an open TCP relay into the
    remote network for anyone who can reach the container's port.

  The `Registry` (`Termelix.Tunnels.Registry`) and `DynamicSupervisor`
  (`Termelix.Tunnels.TunnelSupervisor`) must be started in the supervision tree — see the child
  specs returned to the integrator; `application.ex` is not edited here.
  """
  alias Termelix.SSH.Credential
  alias Termelix.Tunnels.Tunnel
  alias Termelix.Hosts
  alias Termelix.Settings

  @registry Termelix.Tunnels.Registry
  @supervisor Termelix.Tunnels.TunnelSupervisor
  @topic "tunnels:status"

  @default_bind_host "127.0.0.1"
  @public_bind_setting "tunnel_allow_public_bind"

  @doc """
  Start (or restart) a local port forward from a connect request. `params` is the raw
  `TunnelConfig` body the frontend posts. Returns `{:ok, tunnel_name}`, `{:error,
  :access_denied}` when the source host is not owned/resolvable, `{:error,
  :bind_host_not_allowed}` when `bindHost` leaves loopback without the admin opt-in, or
  `{:error, reason}`.
  """
  @spec connect(String.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def connect(user_id, params) do
    name = params["name"]

    with {:ok, config} <- build_config(user_id, name, params) do
      # Reconnect semantics: replace any existing tunnel with this name (Node
      # cleanupTunnelResources before connectSSHTunnel).
      case lookup(name, user_id) do
        nil -> :ok
        pid -> Tunnel.stop(pid)
      end

      case DynamicSupervisor.start_child(@supervisor, {Tunnel, config}) do
        {:ok, _pid} -> {:ok, name}
        {:error, {:already_started, _pid}} -> {:ok, name}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  @doc "Disconnect (stop) a user's tunnel by name. Idempotent — a missing tunnel is a no-op."
  @spec disconnect(String.t(), String.t()) :: :ok
  def disconnect(user_id, name) do
    case lookup(name, user_id) do
      nil -> :ok
      pid -> Tunnel.stop(pid)
    end

    # Nudge SSE subscribers to recompute now that the entry is gone.
    Phoenix.PubSub.broadcast(Termelix.PubSub, @topic, {:tunnel_status, name, :disconnected})
    :ok
  end

  @doc """
  Stop every tunnel belonging to `user_id`, returning how many were stopped.

  The data-plane half of revocation. A tunnel outliving its owner's access is worse than a
  stale terminal: it is a listening socket on this node forwarding into their network, with no
  authentication of its own once it is up.
  """
  @spec stop_user_tunnels(String.t()) :: non_neg_integer()
  def stop_user_tunnels(user_id) do
    names = Registry.select(@registry, [{{{user_id, :"$1"}, :_, :_}, [], [:"$1"]}])
    Enum.each(names, &disconnect(user_id, &1))
    length(names)
  end

  @doc "Look up a tunnel pid by name, ownership-checked. Returns the pid or nil."
  @spec lookup(String.t(), String.t()) :: pid() | nil
  def lookup(name, user_id) do
    case Registry.lookup(@registry, {user_id, name}) do
      [{pid, _meta}] -> pid
      _ -> nil
    end
  end

  @doc """
  Every live tunnel of a user as a `%{name => TunnelStatus}` map (the `GET /ssh/tunnel/status`
  body and each SSE `statuses` frame).
  """
  @spec statuses_for_user(String.t()) :: %{optional(String.t()) => map()}
  def statuses_for_user(user_id) do
    @registry
    |> Registry.select([{{{user_id, :"$1"}, :_, :"$2"}, [], [{{:"$1", :"$2"}}]}])
    |> Map.new(fn {name, meta} -> {name, meta.status} end)
  end

  @doc "The status of a single named tunnel owned by the user, or nil if absent."
  @spec status_for(String.t(), String.t()) :: map() | nil
  def status_for(user_id, name) do
    case Registry.lookup(@registry, {user_id, name}) do
      [{_pid, %{status: status}}] -> status
      _ -> nil
    end
  end

  # --- config building ------------------------------------------------------

  defp build_config(_user_id, nil, _params), do: {:error, :invalid}
  defp build_config(_user_id, "", _params), do: {:error, :invalid}

  defp build_config(user_id, name, params) do
    with {:ok, bind_host} <- bind_host(params),
         {:ok, conn_opts, host_id} <- resolve_source(user_id, params) do
      {:ok,
       %{
         name: name,
         user_id: user_id,
         host_id: host_id,
         mode: mode(params),
         bind_host: bind_host,
         source_port: to_int(params["sourcePort"]) || 0,
         connect_to_host: connect_to_host(params),
         connect_to_port: to_int(params["endpointPort"]) || 0,
         max_retries: to_int(params["maxRetries"]) || 3,
         retry_interval: to_int(params["retryInterval"]) || 5000,
         conn_opts: conn_opts
       }}
    end
  end

  # The listener `Tunnel` opens (`tunnel.ex:301`) is unauthenticated: whoever reaches
  # `bind_host:source_port` is forwarded into the remote network. Loopback keeps that reachable
  # only from inside the container; anything wider is an explicit admin decision. Rejected
  # rather than rewritten — a caller who asked for `0.0.0.0` and silently got `127.0.0.1` would
  # report the tunnel as broken instead of learning it was refused.
  defp bind_host(params) do
    case nonblank(params["bindHost"]) do
      nil ->
        {:ok, @default_bind_host}

      host ->
        if loopback?(host) or public_bind_allowed?() do
          {:ok, host}
        else
          {:error, :bind_host_not_allowed}
        end
    end
  end

  # Any 127.0.0.0/8 address (including the shorthand `127.1` Erlang accepts), the IPv6 `::1`
  # in either bracketed or bare form, and the `localhost` name.
  defp loopback?(host) do
    trimmed = host |> String.trim() |> String.trim_leading("[") |> String.trim_trailing("]")

    case :inet.parse_address(String.to_charlist(trimmed)) do
      {:ok, {127, _, _, _}} -> true
      {:ok, {0, 0, 0, 0, 0, 0, 0, 1}} -> true
      {:ok, _other} -> false
      {:error, _} -> String.downcase(trimmed) == "localhost"
    end
  end

  # Same `getBoolean(key, default)` shape as the other admin toggles (see
  # `history_controller.ex:184`): a missing row means off, and only "true"/"1" turn it on.
  defp public_bind_allowed? do
    case Settings.get_value(@public_bind_setting) do
      nil -> false
      value -> value == "true" or value == "1"
    end
  end

  # Source credentials come from the owned host row, never the request body.
  defp resolve_source(user_id, params) do
    case to_int(params["sourceHostId"]) do
      nil ->
        {:error, :access_denied}

      host_id ->
        # `fetch_for_connect/2`, not `get_for_user/2`: this map goes to `:ssh`, and a locked
        # vault would otherwise put a ciphertext envelope in `password` (defect 40).
        case Hosts.fetch_for_connect(host_id, user_id) do
          {:ok, host} -> {:ok, conn_opts(host), host_id}
          {:error, :locked} -> {:error, :data_locked}
          {:error, :not_found} -> {:error, :access_denied}
        end
    end
  end

  # Public only so `test/termelix/ssh/host_key_coverage_test.exs` can assert on the REAL map
  # this subsystem hands to `:ssh`. A test that mirrors the shape instead proves nothing about
  # this function — which is precisely how the missing host-key pin survived here.
  @doc false
  def conn_opts(host) do
    %{
      host: host.ip,
      port: Hosts.effective_ssh_port(host),
      username: host.username,
      password: host.password,
      private_key: host.key,
      key_password: host.keyPassword,
      host_id: host.id,
      owner_id: Map.get(host, :userId),
      # The pin travels WITH the conn_opts: this map is built by hand rather than through
      # `Credential.resolve/2`'s host-row path, and omitting it meant `HostKeyPolicy` saw first
      # contact on every connect — i.e. this path was never actually verified.
      host_key: Credential.host_key(host)
    }
  end

  # Node getTunnelMode: mode ?? tunnelType ?? "remote". The frontend defaults new tunnels to
  # "local"; we default a missing mode to :local (the only forward direction ported).
  defp mode(params) do
    case nonblank(params["mode"]) || nonblank(params["tunnelType"]) do
      "remote" -> :remote
      "dynamic" -> :dynamic
      _ -> :local
    end
  end

  # Node establishDirectTunnel local branch: targetHost || endpointHost || "127.0.0.1".
  defp connect_to_host(params) do
    nonblank(params["targetHost"]) || nonblank(params["endpointHost"]) || "127.0.0.1"
  end

  defp to_int(v) when is_integer(v), do: v

  defp to_int(v) when is_binary(v) do
    case Integer.parse(v) do
      {n, _} -> n
      :error -> nil
    end
  end

  defp to_int(_), do: nil

  defp nonblank(v) when is_binary(v), do: if(String.trim(v) == "", do: nil, else: v)
  defp nonblank(_), do: nil
end
