defmodule TermelixWeb.CredentialController do
  @moduledoc """
  Ports the `/credentials` surface: CRUD, folders, and the credential-usage endpoints the
  frontend calls (`credentials.ts` / `credentials-api.ts`).

  Secret fields (`password`, `key`, `privateKey`, `keyPassword`, `publicKey`) are encrypted at
  rest under the owning user's DEK. They are stripped from list/create responses (only presence
  is implied by the shape); the single-credential fetch deliberately returns `password` /
  `keyPassword` / `publicKey` for editing, plus `hasKey` / `hasKeyPassword` booleans — matching
  the Node route. `privateKey`/`key` material is never returned. Ownership is enforced by the
  context (every query is scoped to `current_user_id`).

  Note: the Node create/update paths run SSH keys through `parseSSHKey` to derive `publicKey` /
  `detectedKeyType` and to reject malformed keys. That parser is a separate deferred subsystem
  (`ssh-key-utils.ts` + `credential-key-routes.ts`); here `privateKey` falls back to the raw key
  (as the Node fallback does) and `publicKey`/`detectedKeyType` are left unset on write.
  """
  use Phoenix.Controller, formats: [:json]

  import TermelixWeb.ControllerHelpers

  alias Termelix.Credentials
  alias Termelix.Hosts

  # POST /credentials
  def create(conn, params) do
    user_id = conn.assigns.current_user_id
    name = params["name"]
    auth_type = params["authType"]

    cond do
      not nonblank?(name) ->
        error(conn, 400, "Name is required")

      auth_type not in ["password", "key"] ->
        error(conn, 400, ~s(Auth type must be "password" or "key"))

      auth_type == "password" and not present?(params["password"]) ->
        error(conn, 400, "Password is required for password authentication")

      auth_type == "key" and not present?(params["key"]) ->
        error(conn, 400, "SSH key is required for key authentication")

      true ->
        case Credentials.create_credential(user_id, build_create_attrs(params, auth_type)) do
          {:ok, cred} -> conn |> put_status(201) |> json(format_credential_output(cred))
          {:error, _} -> error(conn, 500, "Failed to create credential")
        end
    end
  end

  # GET /credentials
  def index(conn, _params) do
    # The list output carries no decrypted secrets (publicKey is still decrypted inside
    # the context — it is part of the wire shape), so skip the full decryption pass.
    creds = Credentials.list_for_user(conn.assigns.current_user_id, decrypt: false)
    json(conn, Enum.map(creds, &format_credential_output/1))
  end

  # GET /credentials/folders
  def folders(conn, _params) do
    json(conn, Credentials.list_folders(conn.assigns.current_user_id))
  end

  # PUT /credentials/folders/rename
  def rename_folder(conn, params) do
    user_id = conn.assigns.current_user_id
    old_name = params["oldName"]
    new_name = params["newName"]

    cond do
      not nonblank?(old_name) or not nonblank?(new_name) ->
        error(conn, 400, "Both oldName and newName are required")

      old_name == new_name ->
        error(conn, 400, "Old name and new name cannot be the same")

      true ->
        Credentials.rename_folder(user_id, old_name, new_name)
        json(conn, %{success: true, message: "Folder renamed successfully"})
    end
  end

  # GET /credentials/:id
  def show(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    case Credentials.get_for_user(to_int(id), user_id) do
      nil ->
        error(conn, 404, "Credential not found")

      cred ->
        # Write-only secret store: the stored password / key / keyPassword are NEVER
        # returned — only presence booleans, so the editor can show "set, leave blank to
        # keep" without ever retrieving the secret. `publicKey` / `certPublicKey` are
        # public key material and safe to expose.
        output =
          cred
          |> format_credential_output()
          |> Map.put(:hasPassword, present?(cred.password))
          |> Map.put(:hasKey, present?(cred.key))
          |> Map.put(:hasKeyPassword, present?(cred.keyPassword))
          |> maybe_put(:certPublicKey, present?(cred.certPublicKey), cred.certPublicKey)

        json(conn, output)
    end
  end

  # PUT /credentials/:id
  def update(conn, %{"id" => id} = params) do
    user_id = conn.assigns.current_user_id
    cred_id = to_int(id)

    case Credentials.get_for_user(cred_id, user_id) do
      nil ->
        error(conn, 404, "Credential not found")

      existing ->
        fields = build_update_fields(params, existing)

        if map_size(fields) == 0 do
          json(conn, format_credential_output(existing))
        else
          case Credentials.update_credential(user_id, cred_id, fields) do
            {:ok, cred} -> json(conn, format_credential_output(cred))
            {:error, :not_found} -> error(conn, 404, "Credential not found")
            {:error, %Ecto.Changeset{}} -> error(conn, 500, "Failed to update credential")
          end
        end
    end
  end

  # DELETE /credentials/:id
  def delete(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id
    cred_id = to_int(id)

    case Credentials.get_for_user(cred_id, user_id) do
      nil ->
        error(conn, 404, "Credential not found")

      _cred ->
        Credentials.delete_credential(user_id, cred_id)
        json(conn, %{message: "Credential deleted successfully"})
    end
  end

  # POST /credentials/:id/apply-to-host/:hostId
  def apply_to_host(conn, %{"id" => id, "hostId" => host_id}) do
    user_id = conn.assigns.current_user_id

    with %{} = cred <- Credentials.get_for_user(to_int(id), user_id),
         {:ok, host_id} <- parse_id(host_id) do
      Credentials.apply_to_host(user_id, cred, host_id)
      json(conn, %{message: "Credential applied to host successfully"})
    else
      # An unparsable hostId was never a valid host id — answer like a nonexistent one.
      :error -> error(conn, 404, "Host not found")
      nil -> error(conn, 404, "Credential not found")
    end
  end

  # GET /credentials/:id/hosts
  def hosts(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    case to_int(id) do
      nil ->
        json(conn, [])

      cred_id ->
        hosts = Credentials.list_hosts_using_credential(user_id, cred_id)
        json(conn, Enum.map(hosts, &format_ssh_host_output/1))
    end
  end

  # --- request shaping ------------------------------------------------------

  defp build_create_attrs(params, auth_type) do
    key = params["key"]
    password = params["password"]
    key_password = params["keyPassword"]

    plain_password = if auth_type == "password" and present?(password), do: password
    plain_key = if auth_type == "key" and present?(key), do: key
    plain_key_password = if auth_type == "key" and present?(key_password), do: key_password

    %{
      name: String.trim(params["name"]),
      description: trim_or_nil(params["description"]),
      folder: trim_or_nil(params["folder"]),
      tags: tags_to_string(params["tags"]),
      authType: auth_type,
      username: trim_or_nil(params["username"]),
      password: plain_password,
      key: plain_key,
      # parseSSHKey deferred: privateKey falls back to the raw key, publicKey/detectedKeyType unset.
      privateKey: plain_key,
      publicKey: nil,
      keyPassword: plain_key_password,
      keyType: presence(params["keyType"]),
      detectedKeyType: nil,
      certPublicKey:
        if(auth_type == "key" and present?(params["certPublicKey"]),
          do: String.trim(params["certPublicKey"])
        ),
      usageCount: 0,
      lastUsed: nil
    }
  end

  # Only fields explicitly present in the body are updated (Node's `!== undefined` checks).
  defp build_update_fields(params, existing) do
    %{}
    |> put_if(params, "name", :name, &safe_trim/1)
    |> put_if(params, "description", :description, &trim_or_nil/1)
    |> put_if(params, "folder", :folder, &trim_or_nil/1)
    |> put_if(params, "tags", :tags, &tags_to_string/1)
    |> put_if(params, "username", :username, &trim_or_nil/1)
    |> put_if(params, "authType", :authType, & &1)
    |> put_if(params, "keyType", :keyType, & &1)
    # Secrets are replace-only: a blank/absent value keeps the stored secret rather than
    # wiping it, so the write-only editor (which can no longer prefill the old value)
    # never destroys a credential by saving with the field left empty. To remove a
    # secret, delete the credential.
    |> put_secret_if_present(params, "password", :password)
    |> put_key(params, existing)
    |> put_secret_if_present(params, "keyPassword", :keyPassword)
    |> put_if(params, "certPublicKey", :certPublicKey, &trim_or_nil/1)
  end

  # Only write the secret field when a non-blank replacement was actually provided.
  defp put_secret_if_present(map, params, param_key, field) do
    case params[param_key] do
      v when is_binary(v) -> if present?(v), do: Map.put(map, field, v), else: map
      _ -> map
    end
  end

  defp put_key(fields, params, existing) do
    key = params["key"]

    # Replace-only, like the other secrets: a blank/absent key keeps the stored one.
    if is_binary(key) and present?(key) do
      fields = Map.put(fields, :key, key)

      # parseSSHKey deferred: keep privateKey in sync with the raw key on a key-auth credential.
      if existing.authType == "key",
        do: Map.put(fields, :privateKey, key),
        else: fields
    else
      fields
    end
  end

  defp put_if(map, params, param_key, field, fun) do
    if Map.has_key?(params, param_key) do
      Map.put(map, field, fun.(params[param_key]))
    else
      map
    end
  end

  # --- response shaping -----------------------------------------------------

  defp format_credential_output(cred) do
    %{
      id: cred.id,
      name: cred.name,
      description: cred.description,
      folder: cred.folder,
      tags: parse_tags(cred.tags),
      authType: cred.authType,
      username: presence(cred.username),
      publicKey: cred.publicKey,
      hasCertPublicKey: present?(cred.certPublicKey),
      keyType: cred.keyType,
      detectedKeyType: cred.detectedKeyType,
      usageCount: cred.usageCount || 0,
      lastUsed: cred.lastUsed,
      createdAt: cred.createdAt,
      updatedAt: cred.updatedAt
    }
  end

  defp format_ssh_host_output(host) do
    %{
      id: host.id,
      userId: host.userId,
      name: host.name,
      ip: host.ip,
      port: Hosts.effective_ssh_port(host),
      username: host.username,
      folder: host.folder,
      tags: parse_tags(host.tags),
      pin: truthy(host.pin),
      authType: host.authType,
      enableTerminal: truthy(host.enableTerminal),
      enableTunnel: truthy(host.enableTunnel),
      tunnelConnections: parse_json_array(host.tunnelConnections),
      enableFileManager: host.enableFileManager != false,
      defaultPath: host.defaultPath,
      createdAt: host.createdAt,
      updatedAt: host.updatedAt
    }
  end

  # --- helpers --------------------------------------------------------------

  defp parse_tags(tags) when is_binary(tags) and tags != "" do
    tags |> String.split(",") |> Enum.reject(&(&1 == ""))
  end

  defp parse_tags(_), do: []

  defp parse_json_array(v) when is_binary(v) and v != "" do
    case Jason.decode(v) do
      {:ok, decoded} -> decoded
      _ -> []
    end
  end

  defp parse_json_array(_), do: []

  defp tags_to_string(tags) when is_list(tags), do: Enum.join(tags, ",")
  defp tags_to_string(tags) when is_binary(tags), do: tags
  defp tags_to_string(_), do: ""

  defp trim_or_nil(v) when is_binary(v) do
    case String.trim(v) do
      "" -> nil
      t -> t
    end
  end

  defp trim_or_nil(_), do: nil

  defp safe_trim(v) when is_binary(v), do: String.trim(v)
  defp safe_trim(v), do: v

  defp presence(v), do: if(present?(v), do: v)

  defp to_int(id) when is_integer(id), do: id

  defp to_int(id) when is_binary(id) do
    case Integer.parse(id) do
      {n, _} -> n
      :error -> nil
    end
  end

  defp to_int(_), do: nil

  defp maybe_put(map, _key, false, _value), do: map
  defp maybe_put(map, key, true, value), do: Map.put(map, key, value)

  # JS `!!string`: non-nil, non-empty (whitespace counts as present, matching the Node route).
  defp present?(v) when is_binary(v), do: v != ""
  defp present?(_), do: false

  # isNonEmptyString: non-empty after trimming.
  defp nonblank?(v) when is_binary(v), do: String.trim(v) != ""
  defp nonblank?(_), do: false

  defp truthy(nil), do: false
  defp truthy(false), do: false
  defp truthy(_), do: true
end
