defmodule TermelixWeb.HostNormalizer do
  @moduledoc """
  Shapes a `Host` struct into the camelCase JSON the frontend expects, mirroring
  `host-normalizers.ts` (`transformHostResponse` + `stripSensitiveFields`).

  Secret fields are removed entirely and replaced by presence booleans; comma-string tags
  become arrays; JSON config blobs are parsed; the SSH port gets its default; and rows left
  behind by the removed remote-desktop feature are folded onto SSH (see
  `normalize_legacy_protocol/1`).
  """

  alias Termelix.Hosts

  # Secrets never sent to the browser (stripSensitiveFields).
  @secret_fields ~w(key keyPassword autostartKey autostartKeyPassword password sudoPassword
                    socks5Password autostartPassword)a

  # Secrets that a JSON blob must never carry either.
  #
  # `@secret_fields` is a `Map.drop` over TOP-LEVEL keys, so it cannot see inside
  # `terminalConfig`. The old editor wrote the sudo password in there — a plain, unencrypted
  # column — which meant the same secret was stored twice: once field-encrypted under
  # `sudo_password`, and once in cleartext inside a blob that was handed back verbatim in every
  # host list. Stripped here as well as on write, because a row saved by an older client still
  # has it and must not leak on read.
  @blob_secret_keys ~w(sudoPassword password keyPassword)

  # JSON blob fields → parsed; value is the fallback when null/blank/invalid.
  @json_array_fields ~w(tunnelConnections jumpHosts quickActions socks5ProxyChain portKnockSequence)a
  @json_object_fields ~w(statsConfig terminalConfig)a

  @doc "Transform a decrypted `Host` struct into a JSON-ready map."
  @spec transform(map()) :: map()
  def transform(host) do
    base = Map.from_struct(host) |> Map.drop([:__meta__])

    base
    |> add_presence_booleans()
    |> Map.drop(@secret_fields)
    |> normalize_tags()
    |> parse_json_blobs()
    |> scrub_blob_secrets()
    |> normalize_legacy_protocol()
    |> apply_ssh_port_default()
  end

  # SSH is the only protocol the server serves, so `connectionType` is pinned on read as well
  # as on write — rows created before the remote-desktop removal still carry
  # `connection_type` in ("rdp", "vnc", "telnet") and the frontend treats anything but "ssh"
  # as a foreign host. Those same rows were saved with `enable_ssh = 0` (the old editor
  # derived `connectionType` from the protocol toggles), which would leave them listed but
  # unopenable with no way back, so SSH is switched on for them too. A host that stored
  # `connection_type = "ssh"` keeps whatever `enableSsh` it has — that toggle stays honest.
  #
  # `port` is folded with them: those rows put the remote-desktop port (3389/5900/23) in
  # `port` and the SSH port in `ssh_port`, and every consumer prefers `port`, so leaving it
  # would make the folded host open and silently dial RDP/VNC/Telnet. Runs before
  # `apply_ssh_port_default/1` so `sshPort` derives from the already-corrected `port`.
  defp normalize_legacy_protocol(map) do
    enable_ssh =
      case map[:connectionType] do
        nil -> map[:enableSsh]
        "ssh" -> map[:enableSsh]
        _legacy -> true
      end

    map
    |> Map.put(:port, Hosts.effective_ssh_port(map))
    |> Map.put(:connectionType, "ssh")
    |> Map.put(:enableSsh, enable_ssh)
  end

  defp add_presence_booleans(map) do
    map
    |> Map.put(:hasKey, present?(map[:key]))
    |> Map.put(:hasKeyPassword, present?(map[:keyPassword]))
    |> Map.put(:hasPassword, present?(map[:password]))
    |> Map.put(:hasSudoPassword, present?(map[:sudoPassword]))
  end

  # Runs AFTER `parse_json_blobs/1`, so the blobs are decoded by now.
  #
  # RECURSIVE, and that is not defensiveness. The first version dropped only top-level keys of a
  # map, so two shapes walked straight past it and came back to the browser in cleartext: a blob
  # that is a LIST rather than a map (`[{"sudoPassword":"x"}]` — the `is_map` guard skipped it
  # entirely) and a key nested one level down (`{"a":{"sudoPassword":"x"}}`). Both were confirmed
  # against a running server. The application never READS either of them, which is exactly why the
  # gap was easy to argue away — but "the API never returns a secret" is the rule, and a secret it
  # does not happen to use is still a secret it handed over.
  #
  # Both string and atom keys are dropped: `parse_json/2` decodes with string keys, but a caller
  # that built the structure itself (tests, a future internal writer) would use atoms, and a
  # scrubber handling only one of the two passes its tests and leaks in production.
  defp scrub_blob_secrets(map) do
    Enum.reduce(@json_object_fields, map, fn field, acc ->
      Map.put(acc, field, drop_secret_keys(acc[field]))
    end)
  end

  defp drop_secret_keys(blob) when is_map(blob) do
    blob
    |> Enum.reject(fn {key, _value} -> secret_key?(key) end)
    |> Map.new(fn {key, value} -> {key, drop_secret_keys(value)} end)
  end

  defp drop_secret_keys(blob) when is_list(blob), do: Enum.map(blob, &drop_secret_keys/1)

  defp drop_secret_keys(blob), do: blob

  defp secret_key?(key) when is_atom(key), do: secret_key?(Atom.to_string(key))
  defp secret_key?(key) when is_binary(key), do: key in @blob_secret_keys
  defp secret_key?(_key), do: false

  defp normalize_tags(map) do
    tags =
      case map[:tags] do
        t when is_binary(t) and t != "" ->
          t |> String.split(",") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))

        _ ->
          []
      end

    Map.put(map, :tags, tags)
  end

  defp parse_json_blobs(map) do
    map =
      Enum.reduce(@json_array_fields, map, fn field, acc ->
        Map.put(acc, field, parse_json(acc[field], []))
      end)

    Enum.reduce(@json_object_fields, map, fn field, acc ->
      Map.put(acc, field, parse_json(acc[field], nil))
    end)
  end

  defp apply_ssh_port_default(map) do
    Map.put(map, :sshPort, map[:sshPort] || map[:port] || 22)
  end

  defp parse_json(value, fallback) when is_binary(value) and value != "" do
    case Jason.decode(value) do
      {:ok, decoded} -> decoded
      {:error, _} -> fallback
    end
  end

  defp parse_json(_value, fallback), do: fallback

  defp present?(v) when is_binary(v), do: String.trim(v) != ""
  defp present?(_), do: false
end
