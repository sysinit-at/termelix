defmodule Termelix.Hosts do
  @moduledoc """
  Host (`ssh_data`) access for a user, including DEK-based decryption of secret fields.

  Listing returns owned hosts with their secrets decrypted in-memory (the controller then
  strips them for the wire); `list_for_user/2` accepts `decrypt: false` to skip decryption
  for callers that only need non-secret columns or secret *presence*. RBAC-shared hosts are
  not yet ported — noted for the breadth phase.
  """
  import Ecto.Query, only: [from: 2]

  require Logger

  alias Termelix.Repo
  alias Termelix.Schema.Host
  alias Termelix.Crypto.{UserKeyManager, DataCrypto, FieldCrypto}
  alias Termelix.SSH.KeyDecode

  @secret_fields ~w(password key keyPassword sudoPassword autostartPassword autostartKey
                    autostartKeyPassword socks5Password)a

  # Columns holding a private key. Both are format-checked on write — see
  # `validate_key_formats/1`.
  @key_fields ~w(key autostartKey)a

  # Boolean columns `bulk_update_hosts/3` may write. `folder` and `statsConfig` are allowed
  # too but are not plain flag flips — see the function.
  @bulk_fields ~w(pin enableTerminal enableTunnel enableFileManager enableTmuxMonitor)a

  @doc """
  All of a user's hosts. With `decrypt: true` (default) secrets are decrypted in-memory
  (skipped gracefully if the DEK is locked); with `decrypt: false` the DEK is never touched
  and secret fields stay as stored (ciphertext envelopes or legacy plaintext) — enough for
  callers that only read non-secret columns or compute secret *presence*: an encrypted
  envelope is always non-empty, and `DataCrypto.safe_decrypt` returns a non-envelope value
  unchanged, so presence booleans computed from the raw stored value match the decrypted
  ones exactly.
  """
  @spec list_for_user(String.t(), keyword()) :: [Host.t()]
  def list_for_user(user_id, opts \\ []) do
    hosts = Repo.all(from h in Host, where: h.userId == ^user_id, order_by: [asc: h.id])

    # Optional pre-decryption filter. Decryption touches the DEK and every secret
    # field per row, so a caller that only wants a subset (the tmux fleet probe on
    # the SPA startup path filters to `enableTmuxMonitor`) filters first rather than
    # materializing plaintext secrets it is about to discard.
    hosts =
      case Keyword.get(opts, :filter) do
        nil -> hosts
        fun when is_function(fun, 1) -> Enum.filter(hosts, fun)
      end

    if Keyword.get(opts, :decrypt, true) do
      case UserKeyManager.try_get_user_dek(user_id) do
        nil -> hosts
        dek -> Enum.map(hosts, &DataCrypto.decrypt_record("ssh_data", &1, dek))
      end
    else
      hosts
    end
  end

  @doc """
  A host ready to be *connected to*, or a typed refusal. Use this — not `get_for_user/2` —
  anywhere the row is about to be handed to `:ssh`.

  `get_for_user/2` decrypts "gracefully": if the DEK cannot be unwrapped it returns the row
  with its secret columns still holding ciphertext, and `DataCrypto.safe_decrypt/4` hands back
  anything it fails to open. That is right for display (the controllers strip secrets anyway,
  and you should still be able to *see* your hosts) and wrong for connecting: every SSH caller
  read `host.password` and passed it straight to `:ssh`, so a locked vault meant a JSON
  envelope was offered to a real sshd as a password — a failed login on someone else's machine,
  with our ciphertext in their auth log. That is defect 40, and this is the `DATA_LOCKED` gate
  from `docs/AUTH_HOST_CONTRACT.md`.

  `{:error, :locked}` only when a secret is *actually* still sealed. A host that keeps no
  secrets here (agent forwarding, a credential the user has not attached) has nothing to leak,
  so it connects normally rather than being taken down with the vault.
  """
  @spec fetch_for_connect(integer() | String.t(), String.t()) ::
          {:ok, Host.t()} | {:error, :not_found | :locked}
  def fetch_for_connect(id, user_id) do
    case get_for_user(id, user_id) do
      nil -> {:error, :not_found}
      %Host{} = host -> if sealed?(host), do: {:error, :locked}, else: {:ok, host}
    end
  end

  # Any encrypted column of `ssh_data` still holding an envelope after the decryption pass.
  defp sealed?(host) do
    "ssh_data"
    |> FieldCrypto.encrypted_fields()
    |> Enum.any?(fn field ->
      case Map.fetch(host, String.to_existing_atom(field)) do
        {:ok, value} -> FieldCrypto.envelope?(value)
        :error -> false
      end
    end)
  rescue
    # An encrypted-field name with no matching struct key is a mapping bug, not a verdict about
    # this host — but the safe reading of "we cannot tell" is still "do not connect".
    ArgumentError -> true
  end

  @doc """
  A single host owned by the user, secrets decrypted where the DEK allows. Returns nil if not
  found/owned.

  **Secret fields may still hold ciphertext** when the DEK is unavailable — see
  `fetch_for_connect/2`, which every SSH-bound caller uses instead.
  """
  @spec get_for_user(integer() | String.t(), String.t()) :: Host.t() | nil
  def get_for_user(id, user_id) do
    case Repo.get_by(Host, id: id, userId: user_id) do
      nil ->
        nil

      %Host{} = host ->
        case UserKeyManager.try_get_user_dek(user_id) do
          nil -> host
          dek -> DataCrypto.decrypt_record("ssh_data", host, dek)
        end
    end
  end

  # Values `connection_type` could hold before the remote-desktop removal. Rows carrying one
  # of these stored the *remote-desktop* port in `port` (3389/5900/23) and the real SSH port
  # in `ssh_port` — see `effective_ssh_port/1`.
  @legacy_remote_desktop_types ~w(rdp vnc telnet)

  @doc """
  The TCP port an SSH connection to `host` must use.

  For an ordinary SSH row this is `port`, falling back to `sshPort` then 22 — the port
  ordering every connect path uses. Rows left behind by the removed remote-desktop feature
  are the exception: their `port` holds the RDP/VNC/Telnet port the old editor wrote there
  (`connection_type` in `("rdp","vnc","telnet")`), while the SSH port sits in `ssh_port`.
  `TermelixWeb.HostNormalizer` folds those rows onto SSH, so they are listed and openable;
  without ignoring their `port` here they would open and silently dial 3389/5900/23.

  Accepts a `Host` struct or the plain map the normalizer works on.
  """
  @spec effective_ssh_port(map()) :: pos_integer()
  def effective_ssh_port(host) do
    if legacy_remote_desktop?(host) do
      Map.get(host, :sshPort) || 22
    else
      Map.get(host, :port) || Map.get(host, :sshPort) || 22
    end
  end

  defp legacy_remote_desktop?(host) do
    case Map.get(host, :connectionType) do
      type when is_binary(type) -> String.downcase(type) in @legacy_remote_desktop_types
      _ -> false
    end
  end

  @doc """
  Create a host for a user. Secret fields in `attrs` are stored encrypted under the user's
  DEK (encrypted in a second pass once the autoincrement id is known, so the field-crypto
  record-id context matches the row). Both writes run in one transaction, so a failure in
  the encryption pass rolls the row back instead of leaving unencrypted secrets behind.
  Returns the decrypted `Host`.

  A private key that cannot ever work is rejected here rather than at connect time — see
  `validate_key_formats/1`.
  """
  @spec create_host(String.t(), map()) :: {:ok, Host.t()} | {:error, term()}
  def create_host(user_id, attrs) do
    now = DateTime.utc_now() |> DateTime.to_iso8601()

    attrs =
      attrs
      |> Map.put(:userId, user_id)
      |> Map.put_new(:createdAt, now)
      |> Map.put_new(:updatedAt, now)

    changeset = %Host{} |> Host.changeset(attrs) |> validate_key_formats()

    Repo.transaction(fn ->
      case Repo.insert(changeset) do
        {:ok, host} -> encrypt_secrets_in_place(host, user_id)
        {:error, changeset} -> Repo.rollback(changeset)
      end
    end)
  end

  @doc """
  Update an owned host. Only fields present in `attrs` change, so secrets the caller does
  not resend keep their stored ciphertext. Any secret fields that *are* present are
  re-encrypted under the user's DEK using the real row id (same second-pass pattern as
  `create_host`), and the update + encryption pass run in one transaction. A private key
  present in `attrs` is format-checked exactly as on create (`validate_key_formats/1`);
  one that is absent is not re-checked, since what is stored is ciphertext. Returns the
  decrypted `Host`, or `{:error, :not_found}` when the host is not owned by the user
  (ownership enforced; a body `userId` is never trusted).
  """
  @spec update_host(String.t(), integer() | String.t(), map()) ::
          {:ok, Host.t()} | {:error, :not_found | term()}
  def update_host(user_id, id, attrs) do
    Repo.transaction(fn ->
      case Repo.get_by(Host, id: id, userId: user_id) do
        nil ->
          Repo.rollback(:not_found)

        %Host{} = host ->
          now = DateTime.utc_now() |> DateTime.to_iso8601()
          attrs = Map.put(attrs, :updatedAt, now)
          provided_secrets = Enum.filter(@secret_fields, &Map.has_key?(attrs, &1))
          changeset = host |> Host.changeset(attrs) |> validate_key_formats()

          case Repo.update(changeset) do
            {:ok, host} -> encrypt_secrets_in_place(host, user_id, provided_secrets)
            {:error, changeset} -> Repo.rollback(changeset)
          end
      end
    end)
  end

  @doc """
  Delete an owned host. Returns `{:ok, host}` or `{:error, :not_found}` when the host is not
  owned by the user (ownership enforced).
  """
  @spec delete_host(String.t(), integer() | String.t()) ::
          {:ok, Host.t()} | {:error, :not_found}
  def delete_host(user_id, id) do
    case Repo.get_by(Host, id: id, userId: user_id) do
      nil -> {:error, :not_found}
      %Host{} = host -> Repo.delete(host)
    end
  end

  @doc """
  Apply `updates` to the hosts among `host_ids` that the user owns (`PATCH /host/bulk-update`).

  Ids the user does not own are counted as `failed` and summarised in `errors` instead of
  failing the whole request; `{:error, :none_owned}` is returned only when none of them are
  owned. Keys outside the allow-list (`@bulk_fields` plus `folder` and `statsConfig`) are
  ignored — a bulk write must never become a way to set arbitrary columns (secrets included)
  on many rows at once, so the allow-list is the security boundary here, not the caller's key
  set. Because every allowed field is non-secret, the rows are written with `update_all` and
  stored ciphertext is untouched.

  One field needs per-host handling: `statsConfig` is merged into each host's stored config,
  so a bulk change to one probe leaves the rest of a host's settings alone.
  """
  @spec bulk_update_hosts(String.t(), [term()], map()) ::
          {:ok, %{updated: non_neg_integer(), failed: non_neg_integer(), errors: [String.t()]}}
          | {:error, :none_owned}
  def bulk_update_hosts(user_id, host_ids, updates) do
    # Non-integer ids can never match a row and would raise on cast, so they are dropped
    # before the query — they still count as failures below.
    ids = Enum.filter(host_ids, &is_integer/1)

    owned =
      Repo.all(
        from h in Host,
          where: h.userId == ^user_id and h.id in ^ids,
          select: %{id: h.id, statsConfig: h.statsConfig}
      )

    owned_ids = Enum.map(owned, & &1.id)
    unowned = Enum.reject(host_ids, &(&1 in owned_ids))

    if owned_ids == [] do
      {:error, :none_owned}
    else
      apply_bulk_fields(user_id, owned_ids, updates)

      errors = unowned_error(unowned) ++ merge_stats_config(user_id, owned, updates)

      {:ok, %{updated: length(owned_ids), failed: length(unowned), errors: errors}}
    end
  end

  defp unowned_error([]), do: []
  defp unowned_error(unowned), do: ["#{length(unowned)} host(s) not found or not owned"]

  # One statement for the fields that are the same for every host in the batch.
  defp apply_bulk_fields(user_id, owned_ids, updates) do
    changes =
      @bulk_fields
      |> Enum.reduce([], fn field, acc ->
        case Map.get(updates, Atom.to_string(field)) do
          value when is_boolean(value) -> [{field, value} | acc]
          _ -> acc
        end
      end)
      |> put_folder(updates)

    if changes != [] do
      from(h in Host, where: h.userId == ^user_id and h.id in ^owned_ids)
      |> Repo.update_all(set: [{:updatedAt, iso_now()} | changes])
    end
  end

  # A blank folder clears it — that is the SPA's "move to root" (`updates.folder || null`).
  defp put_folder(changes, %{"folder" => folder}) when is_binary(folder) do
    [{:folder, if(folder == "", do: nil, else: folder)} | changes]
  end

  defp put_folder(changes, _updates), do: changes

  defp merge_stats_config(user_id, owned, %{"statsConfig" => patch}) when is_map(patch) do
    Enum.flat_map(owned, fn host ->
      case decode_config(host.statsConfig) do
        {:ok, existing} ->
          write_host_config(user_id, host.id,
            statsConfig: Jason.encode!(Map.merge(existing, patch))
          )

          []

        :error ->
          ["Failed to update statsConfig for host #{host.id}"]
      end
    end)
  end

  defp merge_stats_config(_user_id, _owned, _updates), do: []

  # Ownership is re-stated in the per-host statement so the write can never widen beyond the
  # rows the batch query already proved are the caller's.
  defp write_host_config(user_id, host_id, changes) do
    from(h in Host, where: h.userId == ^user_id and h.id == ^host_id)
    |> Repo.update_all(set: [{:updatedAt, iso_now()} | changes])
  end

  defp decode_config(json) when json in [nil, ""], do: {:ok, %{}}

  defp decode_config(json) when is_binary(json) do
    case Jason.decode(json) do
      {:ok, config} when is_map(config) -> {:ok, config}
      _ -> :error
    end
  end

  defp iso_now, do: DateTime.utc_now() |> DateTime.to_iso8601()

  @doc """
  Reject private keys we can prove will never authenticate, naming the reason.

  A key that saves cleanly and then fails every connect with OTP's generic auth error is the
  worst outcome available: it reads as a server fault and pushes the operator onto password
  auth — the path with no host-key checking. The two cases that motivate this are a pasted
  `.pub` file and a passphrase-protected `BEGIN OPENSSH PRIVATE KEY`, which OTP cannot
  decrypt at all (`Termelix.SSH.KeyDecode` moduledoc).

  Only *format* defects reject. A passphrase-protected PEM key passes even when this write
  carries no passphrase: on update an absent `keyPassword` keeps the stored one, so judging
  it here would reject valid edits. `KeyDecode.check_format/1` takes no passphrase for that
  reason, which also keeps passphrases off this path entirely.

  Rollback: `config :termelix, :host_key_format_validation, :warn` logs every rejection and
  saves anyway; `:off` skips the check. Default `:reject`.
  """
  @spec validate_key_formats(Ecto.Changeset.t()) :: Ecto.Changeset.t()
  def validate_key_formats(changeset) do
    Enum.reduce(@key_fields, changeset, &validate_key_format(&2, &1))
  end

  defp validate_key_format(changeset, field) do
    mode = key_format_validation()
    value = Ecto.Changeset.get_change(changeset, field)

    # Only a freshly-supplied, non-blank key is checked: `nil` means the field is untouched
    # (its stored ciphertext stands) and `""` means the caller is clearing it.
    if mode == :off or not is_binary(value) or String.trim(value) == "" do
      changeset
    else
      case KeyDecode.check_format(value) do
        :ok -> changeset
        {:error, reason} -> record_key_format_error(changeset, field, reason, mode)
      end
    end
  end

  defp record_key_format_error(changeset, field, reason, :warn) do
    Logger.warning(
      "host #{field} failed the private-key format check (#{reason}); saved anyway because " <>
        ":host_key_format_validation is :warn"
    )

    changeset
  end

  defp record_key_format_error(changeset, field, reason, _reject) do
    Ecto.Changeset.add_error(changeset, field, KeyDecode.message(reason),
      validation: :key_format,
      reason: reason
    )
  end

  defp key_format_validation,
    do: Application.get_env(:termelix, :host_key_format_validation, :reject)

  # Encrypt the present secret fields (default: all of them) with the real row id, persist,
  # and return the struct with plaintext secrets (as callers expect a usable host). On update
  # only the freshly-provided secrets are passed, so already-encrypted stored values are not
  # re-wrapped.
  defp encrypt_secrets_in_place(host, user_id, fields \\ @secret_fields) do
    dek = UserKeyManager.get_user_dek(user_id)

    encrypted =
      Enum.reduce(fields, %{}, fn field, acc ->
        case Map.get(host, field) do
          v when is_binary(v) and v != "" ->
            Map.put(acc, field, Termelix.Crypto.FieldCrypto.encrypt_field(v, dek, host.id, field))

          _ ->
            acc
        end
      end)

    if map_size(encrypted) > 0 do
      host |> Ecto.Changeset.change(encrypted) |> Repo.update!()
    end

    host
  end
end
