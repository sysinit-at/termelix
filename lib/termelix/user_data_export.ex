defmodule Termelix.UserDataExport do
  @moduledoc """
  User data export — the Elixir port of `utils/user-data-export.ts` (`UserDataExport`).

  Produces the `UserExportData` JSON shape (version `v2.0`) the frontend's
  `adminExportUserData` downloads: the user's hosts, credentials, file-manager bookmarks
  (recent/pinned/shortcuts/transfer-recent) and dismissed alerts, plus `metadata`.

  ## Deviation from Node (noted deliberately)

  Node also ships a *full SQLite* self-export (`POST /database/export`) that materialises a new
  `.termelix-export.sqlite` with the secrets DEK-decrypted and re-inserted. Rebuilding a byte-
  compatible SQLite file in Elixir is impractical and out of scope, so the port exposes only the
  **JSON** shape (the same one Node's admin export and export-preview already use). The task
  explicitly allows this.

  ## Secret handling

  * `format: "encrypted"` (default) leaves secret fields as their stored ciphertext envelopes —
    a safe backup that never exposes plaintext.
  * `format: "plaintext"` decrypts hosts and credentials with the user's DEK (which must be
    unlocked). This mirrors the Node admin export (`format: "plaintext"`).

  A plaintext export is the one place the whole secret set leaves the server in the clear, so
  `:plaintext` is never implied: every caller must ask for it, and
  `TermelixWeb.UserDataExportController` — the only caller — additionally rate-limits both
  routes and requires a password re-auth before an admin may take another user's secrets.
  Use `parse_format/1` to map a request parameter onto the atom; never `String.to_atom/1`.
  """
  import Ecto.Query, only: [from: 2]

  alias Termelix.Repo
  alias Termelix.Crypto.{DataCrypto, UserKeyManager}

  alias Termelix.Schema.{
    DismissedAlert,
    FileManagerPinned,
    FileManagerRecent,
    FileManagerShortcut,
    Host,
    SshCredential,
    User
  }

  @export_version "v2.0"

  @type format :: :encrypted | :plaintext
  @type opts :: [format: format(), scope: String.t(), include_credentials: boolean()]

  @doc """
  Build the `UserExportData` map for `user_id`.

  Options (all optional):

    * `:format` — `:encrypted` (default) keeps ciphertext; `:plaintext` decrypts secrets.
    * `:scope` — echoed as `metadata.exportType` (`"user_data"` default, or `"all"`).
    * `:include_credentials` — include `ssh_credentials` (default `true`).

  Returns `{:ok, export_map}`, `{:error, :user_not_found}`, or `{:error, :locked}` when a
  plaintext export is requested but the user's DEK is not unlocked (matching Node's
  "User data not unlocked - password required for plaintext export").
  """
  @spec export_user_data(String.t(), opts()) ::
          {:ok, map()} | {:error, :user_not_found | :locked}
  def export_user_data(user_id, opts \\ []) do
    format = Keyword.get(opts, :format, :encrypted)
    scope = Keyword.get(opts, :scope, "user_data")
    include_credentials = Keyword.get(opts, :include_credentials, true)

    case Repo.get(User, user_id) do
      nil ->
        {:error, :user_not_found}

      %User{} = user ->
        with {:ok, dek} <- resolve_dek(user_id, format) do
          {:ok, build_export(user, dek, format, scope, include_credentials)}
        end
    end
  end

  @doc """
  Map a request-supplied format onto the `t:format/0` atom. `nil` (absent) is `:encrypted`,
  the safe default — plaintext only ever happens when the caller spelled it out. Anything
  else is `:error`, so an unknown value is refused instead of silently downgrading (and no
  user-controlled string ever reaches `String.to_atom/1`).
  """
  @spec parse_format(term()) :: {:ok, format()} | :error
  def parse_format(nil), do: {:ok, :encrypted}
  def parse_format("encrypted"), do: {:ok, :encrypted}
  def parse_format("plaintext"), do: {:ok, :plaintext}
  def parse_format(_other), do: :error

  # A plaintext export needs the unlocked DEK; an encrypted export needs no key.
  defp resolve_dek(_user_id, :encrypted), do: {:ok, nil}

  defp resolve_dek(user_id, :plaintext) do
    case UserKeyManager.try_get_user_dek(user_id) do
      nil -> {:error, :locked}
      dek -> {:ok, dek}
    end
  end

  defp build_export(user, dek, format, scope, include_credentials) do
    hosts = user.id |> list_hosts() |> maybe_decrypt("ssh_data", dek)

    credentials =
      if include_credentials do
        user.id |> list_credentials() |> maybe_decrypt("ssh_credentials", dek)
      else
        []
      end

    recent = user.id |> list_plain(FileManagerRecent)
    pinned = user.id |> list_plain(FileManagerPinned)
    shortcuts = user.id |> list_plain(FileManagerShortcut)
    transfer_recent = list_transfer_recent(user.id)
    dismissed = user.id |> list_plain(DismissedAlert)

    total =
      length(hosts) + length(credentials) + length(recent) + length(pinned) +
        length(shortcuts) + length(transfer_recent) + length(dismissed)

    %{
      version: @export_version,
      exportedAt: iso_now(),
      userId: user.id,
      username: user.username,
      userData: %{
        sshHosts: hosts,
        sshCredentials: credentials,
        fileManagerData: %{
          recent: recent,
          pinned: pinned,
          shortcuts: shortcuts,
          transferRecent: transfer_recent
        },
        dismissedAlerts: dismissed
      },
      metadata: %{
        totalRecords: total,
        encrypted: format == :encrypted,
        exportType: scope
      }
    }
  end

  # --- per-table reads (owned rows only) ------------------------------------

  defp list_hosts(user_id),
    do: Repo.all(from h in Host, where: h.userId == ^user_id, order_by: [asc: h.id])

  defp list_credentials(user_id),
    do: Repo.all(from c in SshCredential, where: c.userId == ^user_id, order_by: [asc: c.id])

  defp list_plain(user_id, schema) do
    Repo.all(from r in schema, where: r.userId == ^user_id, order_by: [asc: r.id])
    |> Enum.map(&to_map/1)
  end

  # `transfer_recent` has no Ecto schema module in the port; query it schemaless into the
  # camelCase map shape the export expects.
  defp list_transfer_recent(user_id) do
    Repo.all(
      from t in "transfer_recent",
        where: t.user_id == type(^user_id, :string),
        order_by: [asc: t.id],
        select: %{
          id: t.id,
          userId: t.user_id,
          sourceHostId: t.source_host_id,
          destHostId: t.dest_host_id,
          destPath: t.dest_path,
          destPathLabel: t.dest_path_label,
          lastUsed: t.last_used
        }
    )
  end

  # For a plaintext export, decrypt each record's secret fields under the user's DEK; for an
  # encrypted export leave the stored ciphertext untouched. Either way, emit plain maps.
  defp maybe_decrypt(records, _table, nil), do: Enum.map(records, &to_map/1)

  defp maybe_decrypt(records, table, dek) do
    Enum.map(records, fn record ->
      table |> DataCrypto.decrypt_record(record, dek) |> to_map()
    end)
  end

  # `Map.from_struct/1` emits every column verbatim, which is the point for an export — and also
  # means any UNENCRYPTED column is egress by default, whatever ends up in it. That is not
  # hypothetical: the host editor once wrote the sudo password into the `terminalConfig` JSON blob,
  # a plain TEXT column, and a malformed one carried it into the `format: "encrypted"` export —
  # the one documented as never exposing plaintext.
  #
  # The blob is now guarded on write, on read and by a database trigger, so this is the fourth
  # layer rather than the first. It is here because this function's contract is "every field", and
  # the next plain column to acquire a secret would arrive in exports with nobody having decided
  # that it should.
  @blob_fields ~w(terminalConfig statsConfig)a
  @blob_secret_keys ~w(sudoPassword password keyPassword)

  defp to_map(struct) do
    struct
    |> Map.from_struct()
    |> Map.delete(:__meta__)
    |> scrub_blobs()
  end

  defp scrub_blobs(map) do
    Enum.reduce(@blob_fields, map, fn field, acc ->
      case Map.fetch(acc, field) do
        {:ok, blob} when is_binary(blob) -> Map.put(acc, field, scrub_encoded(blob))
        _absent_or_not_text -> acc
      end
    end)
  end

  defp scrub_encoded(blob) do
    case Jason.decode(blob) do
      {:ok, decoded} -> decoded |> drop_secret_keys() |> Jason.encode!()
      # Unparseable, so it cannot be edited safely — and cannot be read as configuration either.
      # Dropped rather than passed through: this is precisely the shape that leaked.
      _ -> nil
    end
  end

  defp drop_secret_keys(value) when is_map(value) do
    value
    |> Enum.reject(fn {key, _} -> key in @blob_secret_keys end)
    |> Map.new(fn {key, nested} -> {key, drop_secret_keys(nested)} end)
  end

  defp drop_secret_keys(value) when is_list(value), do: Enum.map(value, &drop_secret_keys/1)
  defp drop_secret_keys(value), do: value

  # Millisecond-precision ISO-8601, matching JS `new Date().toISOString()`.
  defp iso_now, do: DateTime.utc_now() |> DateTime.truncate(:millisecond) |> DateTime.to_iso8601()
end
