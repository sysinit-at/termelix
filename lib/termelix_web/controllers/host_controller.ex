defmodule TermelixWeb.HostController do
  @moduledoc "Ports the `/host` surface (owned-host listing + CRUD) the frontend uses."
  use Phoenix.Controller, formats: [:json]

  import TermelixWeb.ControllerHelpers

  alias Termelix.{Hosts, WakeOnLan}
  alias TermelixWeb.HostNormalizer

  # Caps the batch so one request cannot rewrite an entire host table (same limit as Node).
  @bulk_limit 1000

  # GET /host/db/host
  def index(conn, _params) do
    user_id = conn.assigns.current_user_id

    hosts =
      user_id
      # The normalizer only reads non-secret fields plus secret *presence* (computable
      # from the stored values), so the DEK decryption pass is skipped here.
      |> Hosts.list_for_user(decrypt: false)
      |> Enum.map(&HostNormalizer.transform/1)

    json(conn, hosts)
  end

  # GET /host/db/host/:id
  def show(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    # An unparsable id was never a valid host id — answer like a nonexistent one (404),
    # so probing can't distinguish the two.
    with {:ok, host_id} <- parse_id(id),
         %{} = host <- Hosts.get_for_user(host_id, user_id) do
      json(conn, HostNormalizer.transform(host))
    else
      _ -> error(conn, 404, "Host not found")
    end
  end

  # POST /host/db/host
  def create(conn, params) do
    user_id = conn.assigns.current_user_id

    with :ok <- validate(params),
         {:ok, host} <- Hosts.create_host(user_id, build_create_attrs(params, user_id)) do
      json(conn, HostNormalizer.transform(host))
    else
      {:error, :invalid} -> error(conn, 400, "Invalid SSH data")
      {:error, %Ecto.Changeset{} = cs} -> error(conn, 400, changeset_message(cs))
      {:error, _} -> error(conn, 500, "Failed to save SSH data")
    end
  end

  # PUT /host/db/host/:id
  def update(conn, %{"id" => id} = params) do
    user_id = conn.assigns.current_user_id

    with :ok <- validate(params),
         {:ok, host_id} <- parse_id(id),
         {:ok, host} <- Hosts.update_host(user_id, host_id, build_update_attrs(params)) do
      json(conn, HostNormalizer.transform(host))
    else
      {:error, :invalid} -> error(conn, 400, "Invalid SSH data")
      :error -> error(conn, 404, "Host not found")
      {:error, :not_found} -> error(conn, 404, "Host not found")
      {:error, %Ecto.Changeset{}} -> error(conn, 400, "Invalid SSH data")
      {:error, _} -> error(conn, 500, "Failed to update SSH data")
    end
  end

  # PATCH /host/bulk-update
  def bulk_update(conn, params) do
    host_ids = params["hostIds"]
    updates = params["updates"]

    cond do
      not is_list(host_ids) or host_ids == [] ->
        error(conn, 400, "hostIds array is required and must not be empty")

      length(host_ids) > @bulk_limit ->
        error(conn, 400, "Maximum #{@bulk_limit} hosts allowed per bulk update")

      not is_map(updates) or updates == %{} ->
        error(conn, 400, "updates object is required and must contain at least one field")

      true ->
        case Hosts.bulk_update_hosts(conn.assigns.current_user_id, host_ids, updates) do
          {:ok, result} -> json(conn, result)
          {:error, :none_owned} -> error(conn, 404, "No matching hosts found")
        end
    end
  end

  # DELETE /host/db/host/:id
  def delete(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    with {:ok, host_id} <- parse_id(id),
         {:ok, _host} <- Hosts.delete_host(user_id, host_id) do
      json(conn, %{message: "SSH host deleted"})
    else
      _ -> error(conn, 404, "SSH host not found")
    end
  end

  # POST /host/db/host/:id/wake
  #
  # Broadcasts a Wake-on-LAN magic packet for the host's stored MAC (set in the host editor's
  # General tab). Mirrors the Node route: 404 for a host the caller does not own, 400 when no
  # valid MAC is configured, 500 when the datagram cannot be sent.
  def wake(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    with {:ok, host_id} <- parse_id(id),
         %{} = host <- Hosts.get_for_user(host_id, user_id) do
      cond do
        not WakeOnLan.valid_mac?(host.macAddress) ->
          error(conn, 400, "No valid MAC address configured")

        WakeOnLan.send(host.macAddress, host.wolBroadcastAddress) == :ok ->
          json(conn, %{success: true})

        true ->
          error(conn, 500, "Failed to send WoL packet")
      end
    else
      _ -> error(conn, 404, "Host not found")
    end
  end

  # --- request validation -----------------------------------------------------

  # Mirrors the Node guard: userId (from the token, always present) + a non-empty ip +
  # a valid numeric port. SSH-key content validation (parseSSHKey) is deferred with the
  # rest of the SSH-key handling breadth work.
  defp validate(params) do
    if non_empty_string?(params["ip"]) and valid_port?(params["port"]) do
      :ok
    else
      {:error, :invalid}
    end
  end

  # --- attrs builders (port of the `sshDataObj` construction in host.ts) -------

  # SSH is the only protocol the server serves, so `connectionType` is pinned rather than
  # taken from the request — the API must not mint hosts no subsystem can reach.
  @connection_type "ssh"

  defp build_create_attrs(params, user_id) do
    auth = first_truthy([params["authType"], params["authMethod"]])
    username = effective_username(params)
    name = effective_name(params["name"], username, params["ip"])

    params
    |> base_attrs(auth, username, name)
    |> Map.put(:userId, user_id)
    |> Map.put(:folder, nilify(params["folder"]))
    |> put_create_secrets(params, auth)
  end

  defp build_update_attrs(params) do
    auth = first_truthy([params["authType"], params["authMethod"]])
    username = effective_username(params)
    name = effective_name(params["name"], username, params["ip"])

    params
    |> base_attrs(auth, username, name)
    |> Map.put(:folder, params["folder"])
    |> put_update_secrets(params, auth)
  end

  # Fields set identically on create and update (folder, userId and the auth-conditional
  # secrets differ and are layered on by the callers above). `socks5Password` is always
  # (re)written here, matching the Node routes. `sudoPassword` is not written at all any more —
  # see the note above `scrub_terminal_config/1`.
  defp base_attrs(params, auth, username, name) do
    %{
      connectionType: @connection_type,
      name: name,
      tags: tags_to_string(params["tags"]),
      ip: params["ip"],
      port: params["port"],
      username: username,
      authType: auth,
      useWarpgate: truthy?(params["useWarpgate"]),
      credentialId: nilify(params["credentialId"]),
      vaultProfileId: nilify(params["vaultProfileId"]),
      overrideCredentialUsername: truthy?(params["overrideCredentialUsername"]),
      pin: truthy?(params["pin"]),
      enableTerminal: truthy?(params["enableTerminal"]),
      enableTunnel: truthy?(params["enableTunnel"]),
      tunnelConnections: json_array(params["tunnelConnections"]),
      jumpHosts: json_array(params["jumpHosts"]),
      quickActions: json_array(params["quickActions"]),
      enableFileManager: truthy?(params["enableFileManager"]),
      scpLegacy: truthy?(params["scpLegacy"]),
      enableTmuxMonitor: truthy?(params["enableTmuxMonitor"]),
      # NOT `truthy?/1`. `enableTmuxShell` is tri-state — nil means "not decided, detect tmux
      # and use it if present", which is the default-on behaviour. `truthy?/1` collapses both
      # nil and an absent key to `false`, which would permanently opt every existing host OUT
      # of tmux the first time anything saved it.
      enableTmuxShell: tristate(params["enableTmuxShell"]),
      showTerminalInSidebar: truthy?(params["showTerminalInSidebar"]),
      showFileManagerInSidebar: truthy?(params["showFileManagerInSidebar"]),
      showTunnelInSidebar: truthy?(params["showTunnelInSidebar"]),
      showServerStatsInSidebar: truthy?(params["showServerStatsInSidebar"]),
      defaultPath: nilify(params["defaultPath"]),
      statsConfig: json_config(params["statsConfig"]),
      # Scrubbed, because the editor used to write the sudo password in here and this column is
      # not encrypted. See `scrub_terminal_config/1`.
      terminalConfig: json_config(scrub_terminal_config(params["terminalConfig"])),
      forceKeyboardInteractive:
        if(truthy?(params["forceKeyboardInteractive"]), do: "true", else: "false"),
      notes: nilify(params["notes"]),
      useSocks5: truthy?(params["useSocks5"]),
      socks5Host: nilify(params["socks5Host"]),
      socks5Port: nilify(params["socks5Port"]),
      socks5Username: nilify(params["socks5Username"]),
      socks5Password: nilify(params["socks5Password"]),
      socks5ProxyChain: json_blob(params["socks5ProxyChain"]),
      macAddress: nilify(params["macAddress"]),
      wolBroadcastAddress: nilify(params["wolBroadcastAddress"]),
      portKnockSequence: json_blob(params["portKnockSequence"]),
      enableSsh: truthy?(params["enableSsh"]),
      sshPort: params["sshPort"] || params["port"] || 22
    }
  end

  # On create the auth-type block always writes password/key/keyPassword/keyType.
  defp put_create_secrets(attrs, params, auth) do
    secrets =
      cond do
        auth == "password" ->
          %{password: nilify(params["password"]), key: nil, keyPassword: nil, keyType: nil}

        auth == "key" ->
          %{
            key: nilify(params["key"]),
            keyPassword: nilify(params["keyPassword"]),
            keyType: params["keyType"],
            password: nilify(params["password"])
          }

        auth == "credential" ->
          %{password: nilify(params["password"]), key: nil, keyPassword: nil, keyType: nil}

        true ->
          # "agent" and any unknown type
          %{password: nil, key: nil, keyPassword: nil, keyType: nil}
      end

    Map.merge(attrs, secrets)
  end

  # On update the auth-type block preserves stored secrets unless a new value is supplied:
  # password/key/keyType are only written when truthy, so an omitted secret keeps its
  # ciphertext.
  defp put_update_secrets(attrs, params, auth) do
    cond do
      auth == "password" ->
        attrs
        |> put_if_truthy(:password, params["password"])
        |> Map.merge(%{key: nil, keyPassword: nil, keyType: nil})

      auth == "key" ->
        attrs
        |> put_if_truthy(:key, params["key"])
        |> put_if_present(:keyPassword, params, "keyPassword")
        |> put_if_truthy(:keyType, params["keyType"])
        |> Map.put(:password, nilify(params["password"]))

      auth == "credential" ->
        Map.merge(attrs, %{
          password: nilify(params["password"]),
          key: nil,
          keyPassword: nil,
          keyType: nil
        })

      true ->
        # "agent" and any unknown type
        Map.merge(attrs, %{password: nil, key: nil, keyPassword: nil, keyType: nil})
    end
  end

  # --- small value helpers ----------------------------------------------------

  # The `ssh_data.username` column is NOT NULL, so an absent username stores "".
  defp effective_username(params), do: nilify(params["username"]) || ""

  defp effective_name(name, username, ip) do
    cond do
      truthy?(name) -> name
      truthy?(username) -> "#{username}@#{ip}"
      true -> to_string(ip)
    end
  end

  defp put_if_truthy(map, key, value) do
    if truthy?(value), do: Map.put(map, key, value), else: map
  end

  # Sets `key` (to value-or-nil) only when the caller included `param_key` in the body,
  # matching Node's `if (keyPassword !== undefined) ...`.
  defp put_if_present(map, key, params, param_key) do
    if Map.has_key?(params, param_key),
      do: Map.put(map, key, nilify(params[param_key])),
      else: map
  end

  defp tags_to_string(tags) when is_list(tags), do: Enum.join(tags, ",")
  defp tags_to_string(tags) when is_binary(tags), do: tags
  defp tags_to_string(_), do: ""

  # Array.isArray(x) ? JSON.stringify(x) : null
  defp json_array(x) when is_list(x), do: Jason.encode!(x)
  defp json_array(_), do: nil

  # x ? (typeof x === "string" ? x : JSON.stringify(x)) : null
  # --- the sudo password ---------------------------------------------------
  #
  # No longer accepted or stored, and the editor no longer asks for one.
  #
  # It existed for sudo auto-fill, where the server typed it into the PTY at a password prompt.
  # That is a credential-reveal primitive however it is gated — writing into the PTY is
  # indistinguishable from the user typing, so whether it comes back echoed is decided by the
  # REMOTE's terminal settings, which this server cannot see — so the feature was removed. Nothing
  # reads the value now, and a stored secret with no consumer is liability rather than a feature:
  # it can leak and it cannot help.
  #
  # `terminalConfig` is still scrubbed on write, because that is where the old editor put it, that
  # column is unencrypted, and a client that has not been updated is still sending it there.
  #
  # `@secret_fields` still lists `sudoPassword`, so anything left in the column stays redacted and
  # encrypted; migration 20260726210000 nulls it.
  # Never store a secret in this blob. Handles both the map the SPA sends and a pre-encoded
  # string, because both reach `json_config/1`.
  # RECURSIVE, for the same reason the normalizer's is: dropping only a top-level map key let
  # `[{"sudoPassword":"x"}]` and `{"a":{"sudoPassword":"x"}}` through to storage in cleartext.
  defp scrub_terminal_config(config) when is_map(config) do
    config
    |> Enum.reject(fn {key, _value} -> key in ["sudoPassword", :sudoPassword] end)
    |> Map.new(fn {key, value} -> {key, scrub_terminal_config(value)} end)
  end

  defp scrub_terminal_config(config) when is_list(config),
    do: Enum.map(config, &scrub_terminal_config/1)

  defp scrub_terminal_config(config) when is_binary(config) do
    case Jason.decode(config) do
      # Decoded and scrubbed whatever the shape — a list is as capable of carrying the key as a
      # map, and an earlier `when is_map(decoded)` guard simply returned those unchanged.
      {:ok, decoded} ->
        scrub_terminal_config(decoded)

      _undecodable ->
        # DROPPED, not stored verbatim. This clause used to return the string unchanged, which
        # meant a blob that merely fails to parse carried whatever it liked into an unencrypted
        # column — the trigger skips invalid JSON and the read path returns nil for it, so it was
        # invisible from the API and still sat there in the clear. It surfaced in the ENCRYPTED
        # data export, which is documented as never exposing plaintext.
        #
        # Nothing is lost: `HostNormalizer.parse_json/2` already resolves an undecodable blob to
        # nil, so this was never readable as configuration by anyone.
        nil
    end
  end

  defp scrub_terminal_config(config), do: config

  defp json_config(x) when is_binary(x), do: if(x == "", do: nil, else: x)
  defp json_config(x) when x in [nil, false, 0, 0.0], do: nil
  defp json_config(x), do: Jason.encode!(x)

  # x ? JSON.stringify(x) : null
  defp json_blob(x) when x in [nil, false, 0, 0.0, ""], do: nil
  defp json_blob(x), do: Jason.encode!(x)

  # JS `||` chain — first value that is not JS-falsy, else `default`.
  defp first_truthy(values, default \\ nil), do: Enum.find(values, default, &truthy?/1)

  # JS truthiness for the values the frontend actually sends (booleans/strings/numbers).
  defp truthy?(value), do: value not in [nil, false, 0, 0.0, ""]

  # A boolean that is allowed to be undecided. JSON `null` and an absent key both mean "leave it
  # to detection"; anything else is coerced the way the rest of this controller coerces booleans.
  defp tristate(nil), do: nil
  defp tristate(true), do: true
  defp tristate(false), do: false
  defp tristate("true"), do: true
  defp tristate("false"), do: false
  defp tristate(""), do: nil
  defp tristate(other), do: truthy?(other)

  # JS `x || null` for scalars.
  defp nilify(value), do: if(truthy?(value), do: value, else: nil)

  defp non_empty_string?(v), do: is_binary(v) and String.trim(v) != ""

  defp valid_port?(p), do: is_integer(p) and p > 0 and p <= 65_535
  # A rejected private key already carries an operator-facing explanation naming the format
  # problem (`Termelix.SSH.KeyDecode.message/1` via `Hosts.validate_key_formats/1`). Collapsing
  # every changeset into "Invalid SSH data" threw that away and left the user with a key that
  # will not save and no reason — which is the failure mode the write-time check exists to
  # prevent. Only the message is surfaced; no field value ever is.
  defp changeset_message(%Ecto.Changeset{} = changeset) do
    changeset
    |> Ecto.Changeset.traverse_errors(fn {message, opts} ->
      Regex.replace(~r/%\{(\w+)\}/, message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), "") |> to_string()
      end)
    end)
    |> Enum.flat_map(fn {field, messages} -> Enum.map(messages, &"#{field}: #{&1}") end)
    |> case do
      [] -> "Invalid SSH data"
      messages -> Enum.join(messages, "; ")
    end
  end
end
