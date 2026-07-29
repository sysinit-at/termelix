defmodule Termelix.Credentials do
  @moduledoc """
  SSH credential (`ssh_credentials`) access for a user, with DEK-based encryption of secret
  fields. Ports `credentials.ts` + `credential-repository.ts`.

  Listing/reads decrypt secrets in-memory (skipped gracefully if the DEK is locked); the
  controller then strips them for the wire. Writes encrypt the secret fields under the owning
  user's DEK — for a fresh row in a second pass once the autoincrement id is known, so the
  field-crypto record-id context matches the row (as in `Termelix.Hosts.create_host`). All
  reads/writes are scoped to the owning `userId` to enforce ownership.
  """
  import Ecto.Query, only: [from: 2]

  require Logger

  alias Termelix.Repo
  alias Termelix.Schema.{SshCredential, SshCredentialUsage, Host}
  alias Termelix.Crypto.{UserKeyManager, DataCrypto, FieldCrypto}

  # Encrypted-at-rest fields for ssh_credentials (see FieldCrypto.@encrypted_fields).
  @secret_fields ~w(password privateKey keyPassword key publicKey)a

  @doc """
  All of a user's credentials (newest-updated first). With `decrypt: true` (default) secrets
  are decrypted in-memory (skipped gracefully if the DEK is locked). With `decrypt: false`
  the per-row secret decryption is skipped; only `publicKey` is still decrypted, because it
  is the one encrypted field that reaches the list wire shape (`format_credential_output`)
  — every other secret is stripped there, so the list response is identical either way.
  """
  @spec list_for_user(String.t(), keyword()) :: [SshCredential.t()]
  def list_for_user(user_id, opts \\ []) do
    creds =
      Repo.all(
        from c in SshCredential, where: c.userId == ^user_id, order_by: [desc: c.updatedAt]
      )

    case {Keyword.get(opts, :decrypt, true), UserKeyManager.try_get_user_dek(user_id)} do
      {true, dek} when is_binary(dek) ->
        Enum.map(creds, &DataCrypto.decrypt_record("ssh_credentials", &1, dek))

      {false, dek} when is_binary(dek) ->
        Enum.map(creds, &decrypt_public_key(&1, dek))

      {_, nil} ->
        creds
    end
  end

  @doc "A single credential owned by the user, secrets decrypted. Returns nil if not found/owned."
  @spec get_for_user(integer() | nil, String.t()) :: SshCredential.t() | nil
  def get_for_user(id, user_id) do
    case Repo.get_by(SshCredential, id: id, userId: user_id) do
      nil -> nil
      %SshCredential{} = cred -> decrypt(cred, user_id)
    end
  end

  @doc """
  Create a credential for a user. Secret fields in `attrs` are stored encrypted under the
  user's DEK (encrypted in a second pass once the autoincrement id is known). Both writes
  run in one transaction, so a failure in the encryption pass rolls the row back instead of
  leaving unencrypted secrets behind. Returns the credential struct with plaintext secrets
  (the controller strips them for the wire).
  """
  @spec create_credential(String.t(), map()) :: {:ok, SshCredential.t()} | {:error, term()}
  def create_credential(user_id, attrs) do
    now = DateTime.utc_now() |> DateTime.to_iso8601()

    attrs =
      attrs
      |> Map.put(:userId, user_id)
      |> Map.put_new(:createdAt, now)
      |> Map.put_new(:updatedAt, now)

    Repo.transaction(fn ->
      case Repo.insert(SshCredential.changeset(%SshCredential{}, attrs)) do
        {:ok, cred} -> encrypt_secrets_in_place(cred, user_id)
        {:error, changeset} -> Repo.rollback(changeset)
      end
    end)
  end

  @doc """
  Update a user's credential with the already-normalized `fields`. Any secret fields present
  are re-encrypted under the user's DEK with the row id. Returns the decrypted credential, or
  `{:error, :not_found}` if it is not owned by the user.
  """
  @spec update_credential(String.t(), integer() | nil, map()) ::
          {:ok, SshCredential.t()} | {:error, :not_found}
  def update_credential(user_id, id, fields) do
    case Repo.get_by(SshCredential, id: id, userId: user_id) do
      nil ->
        {:error, :not_found}

      %SshCredential{id: real_id} = cred ->
        dek = UserKeyManager.get_user_dek(user_id)
        encrypted = encrypt_present_secrets(fields, real_id, dek)

        with {:ok, updated} <- cred |> SshCredential.update_changeset(encrypted) |> Repo.update() do
          {:ok, decrypt(updated, user_id)}
        end
    end
  end

  @doc """
  Delete a user's credential. Hosts referencing it are decoupled first (credential link and
  its secret copies cleared, auth reset to password), mirroring the Node route.
  """
  @spec delete_credential(String.t(), integer()) :: :ok
  def delete_credential(user_id, credential_id) do
    from(h in Host, where: h.userId == ^user_id and h.credentialId == ^credential_id)
    |> Repo.update_all(
      set: [credentialId: nil, password: nil, key: nil, keyPassword: nil, authType: "password"]
    )

    Repo.delete_all(
      from c in SshCredential, where: c.id == ^credential_id and c.userId == ^user_id
    )

    :ok
  end

  @doc "Distinct, non-empty credential folder names for a user, sorted ascending."
  @spec list_folders(String.t()) :: [String.t()]
  def list_folders(user_id) do
    Repo.all(from c in SshCredential, where: c.userId == ^user_id, select: c.folder)
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    |> Enum.uniq()
    |> Enum.sort()
  end

  @doc "Rename a credential folder for a user. Returns the number of rows moved."
  @spec rename_folder(String.t(), String.t(), String.t()) :: non_neg_integer()
  def rename_folder(user_id, old_name, new_name) do
    {count, _} =
      from(c in SshCredential, where: c.userId == ^user_id and c.folder == ^old_name)
      |> Repo.update_all(set: [folder: new_name])

    count
  end

  @doc "Hosts owned by the user that link to the given credential, secrets decrypted."
  @spec list_hosts_using_credential(String.t(), integer()) :: [Host.t()]
  def list_hosts_using_credential(user_id, credential_id) do
    hosts =
      Repo.all(from h in Host, where: h.userId == ^user_id and h.credentialId == ^credential_id)

    case UserKeyManager.try_get_user_dek(user_id) do
      nil -> hosts
      dek -> Enum.map(hosts, &DataCrypto.decrypt_record("ssh_data", &1, dek))
    end
  end

  @doc """
  Apply a (decrypted) credential to one of the user's hosts: link the credential, adopt its
  username/authType, clear the host's inline secrets, and record the usage.
  """
  @spec apply_to_host(String.t(), SshCredential.t(), integer()) :: :ok
  def apply_to_host(user_id, %SshCredential{} = cred, host_id) do
    now = DateTime.utc_now() |> DateTime.to_iso8601()

    from(h in Host, where: h.id == ^host_id and h.userId == ^user_id)
    |> Repo.update_all(
      set: [
        credentialId: cred.id,
        username: cred.username || "",
        authType: cred.authType,
        password: nil,
        key: nil,
        keyPassword: nil,
        keyType: nil,
        updatedAt: now
      ]
    )

    record_usage(user_id, cred.id, host_id, now)
    :ok
  end

  @doc "Record a credential-on-host use and bump the credential's usage count / last-used."
  @spec record_usage(String.t(), integer(), integer(), String.t() | nil) :: :ok
  def record_usage(user_id, credential_id, host_id, used_at \\ nil) do
    used_at = used_at || DateTime.to_iso8601(DateTime.utc_now())

    Repo.insert!(%SshCredentialUsage{
      credentialId: credential_id,
      hostId: host_id,
      userId: user_id,
      usedAt: used_at
    })

    from(c in SshCredential, where: c.id == ^credential_id and c.userId == ^user_id)
    |> Repo.update_all(set: [lastUsed: used_at], inc: [usageCount: 1])

    :ok
  end

  # --- internals ------------------------------------------------------------

  # Decrypt only the `publicKey` field (the decrypt:false list path), with the same
  # lazy/graceful semantics as `DataCrypto.safe_decrypt`: non-envelope values pass through
  # unchanged and a failed decrypt keeps the stored value.
  defp decrypt_public_key(%SshCredential{publicKey: value} = cred, dek)
       when is_binary(value) and value != "" do
    if String.starts_with?(value, "{") do
      try do
        %{cred | publicKey: FieldCrypto.decrypt_field(value, dek, cred.id, "publicKey")}
      rescue
        error ->
          Logger.warning("Field decrypt failed for publicKey: #{Exception.message(error)}")
          cred
      end
    else
      cred
    end
  end

  defp decrypt_public_key(%SshCredential{} = cred, _dek), do: cred

  defp decrypt(cred, user_id) do
    case UserKeyManager.try_get_user_dek(user_id) do
      nil -> cred
      dek -> DataCrypto.decrypt_record("ssh_credentials", cred, dek)
    end
  end

  # Encrypt any present secret fields with the real row id, persist, and return the struct
  # with plaintext secrets (callers expect a usable credential).
  defp encrypt_secrets_in_place(%SshCredential{id: id} = cred, user_id) do
    dek = UserKeyManager.get_user_dek(user_id)

    encrypted =
      Enum.reduce(@secret_fields, %{}, fn field, acc ->
        case Map.get(cred, field) do
          v when is_binary(v) and v != "" ->
            Map.put(acc, field, FieldCrypto.encrypt_field(v, dek, id, field))

          _ ->
            acc
        end
      end)

    if map_size(encrypted) > 0 do
      cred |> Ecto.Changeset.change(encrypted) |> Repo.update!()
    end

    cred
  end

  defp encrypt_present_secrets(attrs, record_id, dek) do
    Enum.reduce(@secret_fields, attrs, fn field, acc ->
      case Map.get(acc, field) do
        v when is_binary(v) and v != "" ->
          Map.put(acc, field, FieldCrypto.encrypt_field(v, dek, record_id, field))

        _ ->
          acc
      end
    end)
  end
end
