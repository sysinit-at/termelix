defmodule Termelix.Metrics do
  @moduledoc """
  Host reachability — what powers the sidebar's per-host online/offline indicators.

  `ping/2` and `ping_all/1` do a short TCP connect to a host's service port (mirroring
  Node's `tcpPing`); a successful connect means online. Only reachability lives here now:
  the former CPU/mem/disk metrics collection (the Host Metrics dashboard) was removed as
  low-value for the SRE/sysadmin audience.
  """
  alias Termelix.Hosts

  @ping_timeout 5_000

  @doc """
  TCP reachability of a host the user owns. Returns `{:ok, :online | :offline}` or
  `{:error, :not_found}`.
  """
  @spec ping(integer() | String.t(), String.t()) ::
          {:ok, :online | :offline} | {:error, :not_found}
  def ping(host_id, user_id) do
    case Hosts.get_for_user(host_id, user_id) do
      nil -> {:error, :not_found}
      host -> {:ok, if(tcp_ping(host.ip, ping_port(host)), do: :online, else: :offline)}
    end
  end

  @doc "Reachability of every host the user owns, as `%{host_id => :online | :offline}`."
  @spec ping_all(String.t()) :: %{optional(integer()) => :online | :offline}
  def ping_all(user_id) do
    user_id
    # Only ip/port are needed here — neither is a secret field, so skip the
    # per-host DEK decryption entirely.
    |> Hosts.list_for_user(decrypt: false)
    |> Task.async_stream(
      fn host ->
        {host.id, if(tcp_ping(host.ip, ping_port(host)), do: :online, else: :offline)}
      end,
      max_concurrency: 16,
      timeout: @ping_timeout + 1_000,
      on_timeout: :kill_task,
      ordered: false
    )
    |> Enum.reduce(%{}, fn
      {:ok, {id, status}}, acc -> Map.put(acc, id, status)
      {:exit, _}, acc -> acc
    end)
  end

  defp ping_port(host), do: Hosts.effective_ssh_port(host)

  defp tcp_ping(nil, _port), do: false

  defp tcp_ping(ip, port) do
    host = ip |> strip_brackets() |> String.to_charlist()

    case :gen_tcp.connect(host, port, [:binary, active: false], @ping_timeout) do
      {:ok, socket} ->
        :gen_tcp.close(socket)
        true

      {:error, _} ->
        false
    end
  end

  defp strip_brackets(ip), do: String.trim(ip, "[") |> String.trim("]")
end
