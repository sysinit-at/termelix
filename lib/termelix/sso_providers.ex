defmodule Termelix.SsoProviders do
  @moduledoc """
  CRUD + config-codec for the `sso_providers` table — the Elixir port of
  `sso-provider-repository.ts` and the config (de)serialization in `sso-provider-routes.ts`.

  Provider `config` is persisted as a JSON string. Its secret fields (`client_secret`,
  `bindPassword`) are sealed under the instance key (`Termelix.Crypto.SystemSecrets`) — the
  Node backend's `encoded:` base64 wrap, reversible by anyone holding the database file, is
  NOT carried over. Reads remain backward compatible with `encoded:`/`encrypted:` base64 and
  plaintext values; writes only produce the sealed form. The admin/create/update responses
  hand back the opened (plaintext-secret) config object, which the controller then reduces to
  presence booleans.
  """
  import Ecto.Query, only: [from: 2]
  alias Termelix.Repo
  alias Termelix.Crypto.SystemSecrets
  alias Termelix.Schema.{SsoProvider, User}

  @oidc_like ~w(oidc github google)

  # --- reads ----------------------------------------------------------------

  @doc "Public projection (`id, name, type, displayOrder`) of every enabled provider."
  @spec list_enabled_public() :: [map()]
  def list_enabled_public do
    from(p in SsoProvider,
      where: p.enabled == true,
      order_by: [asc: p.displayOrder, asc: p.id],
      select: %{id: p.id, name: p.name, type: p.type, displayOrder: p.displayOrder}
    )
    |> Repo.all()
  end

  @doc "Every enabled provider row (ordered)."
  @spec list_enabled() :: [SsoProvider.t()]
  def list_enabled do
    Repo.all(
      from(p in SsoProvider, where: p.enabled == true, order_by: [asc: p.displayOrder, asc: p.id])
    )
  end

  @doc "Every provider row (ordered)."
  @spec list_all() :: [SsoProvider.t()]
  def list_all do
    Repo.all(from(p in SsoProvider, order_by: [asc: p.displayOrder, asc: p.id]))
  end

  @spec find_by_id(integer() | nil) :: SsoProvider.t() | nil
  def find_by_id(nil), do: nil
  def find_by_id(id), do: Repo.get(SsoProvider, id)

  @doc "First enabled provider whose type is oidc/github/google (the env/legacy fallback path)."
  @spec find_first_enabled_oidc_like() :: SsoProvider.t() | nil
  def find_first_enabled_oidc_like do
    list_enabled() |> Enum.find(fn p -> p.type in @oidc_like end)
  end

  @doc "How many users are bound to this provider (delete-guard)."
  @spec count_users_by_provider_id(integer()) :: non_neg_integer()
  def count_users_by_provider_id(provider_id) do
    Repo.aggregate(from(u in User, where: u.ssoProviderId == ^provider_id), :count, :id)
  end

  # --- writes ---------------------------------------------------------------

  @doc "Insert a provider from already-encrypted `attrs` (name/type/enabled/displayOrder/config)."
  @spec create(map()) :: SsoProvider.t()
  def create(attrs) do
    now = iso_now()

    Repo.insert!(%SsoProvider{
      name: attrs.name,
      type: attrs.type,
      enabled: Map.get(attrs, :enabled, true),
      displayOrder: Map.get(attrs, :displayOrder, 0),
      config: attrs.config,
      createdAt: now,
      updatedAt: now
    })
  end

  @doc "Apply the already-shaped `updates` (camelCase field atoms) to a provider row."
  @spec update(integer(), map()) :: SsoProvider.t() | nil
  def update(id, updates) do
    case Repo.get(SsoProvider, id) do
      nil -> nil
      row -> Repo.update!(Ecto.Changeset.change(row, updates))
    end
  end

  @spec delete(integer()) :: boolean()
  def delete(id) do
    {count, _} = Repo.delete_all(from(p in SsoProvider, where: p.id == ^id))
    count > 0
  end

  # --- config codec (mirrors sso-provider-routes.ts) ------------------------

  @doc """
  Decode a stored config JSON string into a map with plaintext secrets. An unparseable
  string yields `%{}`; an `encoded:` secret that fails base64 decode becomes
  `"[ENCODING ERROR]"`, matching `decryptProviderConfig`. Sealed secrets
  (`Termelix.Crypto.SystemSecrets`) are opened with the instance key; one that will not open
  (wrong key, tampered) also reads back as `"[ENCODING ERROR]"` rather than leaking the
  ciphertext.
  """
  @spec decrypt_provider_config(String.t() | nil) :: map()
  def decrypt_provider_config(config_json) do
    map = safe_decode(config_json)
    Enum.reduce(~w(client_secret bindPassword), map, &decode_secret_field/2)
  end

  @doc """
  Encode a config map into a JSON string, sealing `client_secret` / `bindPassword` under the
  instance key (see `Termelix.Crypto.SystemSecrets`) unless already wrapped — the inverse of
  `decrypt_provider_config/1`.
  """
  @spec encrypt_provider_config(map()) :: String.t()
  def encrypt_provider_config(config) when is_map(config) do
    config
    |> encode_secret_field("client_secret")
    |> encode_secret_field("bindPassword")
    |> Jason.encode!()
  end

  # --- provider defaults (create-time, mirrors sso-provider-routes.ts) ------

  @github_create_defaults %{
    "authorization_url" => "https://github.com/login/oauth/authorize",
    "token_url" => "https://github.com/login/oauth/access_token",
    "issuer_url" => "https://github.com",
    "identifier_path" => "id",
    "name_path" => "name",
    "scopes" => "read:user user:email",
    "userinfo_url" => "https://api.github.com/user"
  }

  @google_create_defaults %{
    "authorization_url" => "https://accounts.google.com/o/oauth2/v2/auth",
    "token_url" => "https://oauth2.googleapis.com/token",
    "issuer_url" => "https://accounts.google.com",
    "identifier_path" => "sub",
    "name_path" => "name",
    "scopes" => "openid email profile"
  }

  @doc "Fill in github/google authorization endpoints before validation, keeping caller overrides."
  @spec apply_create_defaults(String.t(), map()) :: map()
  def apply_create_defaults("github", config), do: Map.merge(@github_create_defaults, config)
  def apply_create_defaults("google", config), do: Map.merge(@google_create_defaults, config)
  def apply_create_defaults(_type, config), do: config

  # --- helpers --------------------------------------------------------------

  defp decode_secret_field(field, map) do
    case Map.get(map, field) do
      "encoded:" <> b64 ->
        case Base.decode64(b64) do
          {:ok, plain} -> Map.put(map, field, plain)
          :error -> Map.put(map, field, "[ENCODING ERROR]")
        end

      "encrypted:" <> _ = value ->
        Map.put(map, field, SystemSecrets.open(value, field))

      value when is_binary(value) ->
        if SystemSecrets.sealed?(value) do
          Map.put(map, field, open_sealed(value, field))
        else
          map
        end

      _ ->
        map
    end
  end

  # A sealed value that will not open (wrong instance key, tampered ciphertext) reads back
  # with the same marker an undecodable legacy wrapper gets — the admin API never surfaces
  # raw ciphertext, and the presence boolean still reports that a value is stored.
  defp open_sealed(value, field) do
    SystemSecrets.open(value, field)
  rescue
    _error -> "[ENCODING ERROR]"
  end

  defp encode_secret_field(map, field) do
    case Map.get(map, field) do
      value when is_binary(value) and value != "" ->
        if wrapped?(value) do
          map
        else
          Map.put(map, field, SystemSecrets.seal(value, field))
        end

      _ ->
        map
    end
  end

  # Already-stored forms pass through unchanged — re-wrapping a legacy base64 value or a
  # sealed envelope on a config round-trip would corrupt the secret.
  defp wrapped?(value) do
    String.starts_with?(value, "encoded:") or String.starts_with?(value, "encrypted:") or
      SystemSecrets.sealed?(value)
  end

  defp safe_decode(nil), do: %{}

  defp safe_decode(json) when is_binary(json) do
    case Jason.decode(json) do
      {:ok, map} when is_map(map) -> map
      _ -> %{}
    end
  end

  defp iso_now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
