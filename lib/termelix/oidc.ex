defmodule Termelix.Oidc do
  @moduledoc """
  OIDC / SSO authorization-code flow — the Elixir port of the `/users/oidc/*` handlers in
  `users.ts` plus `user-oidc-utils.ts`.

  Config resolution (`load_provider_config/1`) walks the same fallbacks as the Node
  `loadProviderConfig`: an explicit `sso_providers` row, then env vars, then the first
  enabled OIDC-like row, then the legacy `oidc_config` settings blob. Provider configs are
  plain maps with the snake_case string keys the frontend sends (`client_id`, `issuer_url`,
  `authorization_url`, `token_url`, `userinfo_url`, `identifier_path`, `name_path`, `scopes`,
  `allowed_users`, `admin_group`, `group_claim`, `ca_cert`).

  Outbound HTTP (token exchange, userinfo, discovery, JWKS) goes through `Req` with the
  `:req_options` app-env injection so tests stub it via `Req.Test`. The `id_token` signature
  and issuer/audience/exp claims are verified against the provider JWKS with JOSE, matching
  `verifyOIDCToken`.

  New OIDC users get a fresh DEK (`UserKeyManager.create_user_dek`); their `oidcIdentifier`
  is stored **plaintext** so `find_by_oidc_identifier/1` can match it by column — the same as
  the Node insert + `findByOidcIdentifier(eq(...))` lookup (it is never migrated to the
  encrypted-at-rest set, only classified as sensitive for graceful-decrypt on read).
  """
  require Logger

  alias Termelix.{Id, Repo, Rbac, Settings, SsoProviders}
  alias Termelix.Schema.User
  alias Termelix.Crypto.UserKeyManager

  @default_scopes "openid email profile"

  # --- provider config resolution -------------------------------------------

  @doc """
  Resolve a provider config. Returns `{:ok, %{config: map, provider_type: String, provider_db_id: integer | nil}}`
  or `nil` when nothing is configured. `provider_id` may be nil.
  """
  @spec load_provider_config(integer() | nil) ::
          {:ok, %{config: map(), provider_type: String.t(), provider_db_id: integer() | nil}}
          | nil
  def load_provider_config(provider_id) do
    with nil <- from_provider_row(provider_id),
         nil <- from_env(),
         nil <- from_first_enabled(),
         nil <- from_legacy_settings() do
      nil
    end
  end

  defp from_provider_row(nil), do: nil

  defp from_provider_row(provider_id) do
    case SsoProviders.find_by_id(provider_id) do
      nil ->
        nil

      row ->
        config =
          row.config
          |> SsoProviders.decrypt_provider_config()
          |> apply_provider_defaults(row.type)

        {:ok, %{config: config, provider_type: row.type, provider_db_id: row.id}}
    end
  end

  defp from_env do
    case get_oidc_config_from_env() do
      nil -> nil
      config -> {:ok, %{config: config, provider_type: "oidc", provider_db_id: nil}}
    end
  end

  defp from_first_enabled do
    case SsoProviders.find_first_enabled_oidc_like() do
      nil ->
        nil

      row ->
        config =
          row.config
          |> SsoProviders.decrypt_provider_config()
          |> apply_provider_defaults(row.type)

        {:ok, %{config: config, provider_type: row.type, provider_db_id: row.id}}
    end
  end

  defp from_legacy_settings do
    case Settings.get_value("oidc_config") do
      nil ->
        nil

      raw ->
        case Jason.decode(raw) do
          {:ok, config} when is_map(config) ->
            {:ok,
             %{
               config: SsoProviders.decrypt_provider_config(raw),
               provider_type: "oidc",
               provider_db_id: nil
             }}

          _ ->
            nil
        end
    end
  end

  @doc "Build an OIDC config map from `OIDC_*` env vars, or nil if the required ones are unset."
  @spec get_oidc_config_from_env() :: map() | nil
  def get_oidc_config_from_env do
    client_id = System.get_env("OIDC_CLIENT_ID")
    client_secret = System.get_env("OIDC_CLIENT_SECRET")
    issuer_url = System.get_env("OIDC_ISSUER_URL")
    authorization_url = System.get_env("OIDC_AUTHORIZATION_URL")
    token_url = System.get_env("OIDC_TOKEN_URL")

    if blank?(client_id) or blank?(client_secret) or blank?(issuer_url) or
         blank?(authorization_url) or blank?(token_url) do
      nil
    else
      %{
        "client_id" => client_id,
        "client_secret" => client_secret,
        "issuer_url" => issuer_url,
        "authorization_url" => authorization_url,
        "token_url" => token_url,
        "userinfo_url" => System.get_env("OIDC_USERINFO_URL") || "",
        "identifier_path" => System.get_env("OIDC_IDENTIFIER_PATH") || "sub",
        "name_path" => System.get_env("OIDC_NAME_PATH") || "name",
        "scopes" => System.get_env("OIDC_SCOPES") || @default_scopes,
        "allowed_users" => System.get_env("OIDC_ALLOWED_USERS") || "",
        "admin_group" => System.get_env("OIDC_ADMIN_GROUP") || "",
        "group_claim" => System.get_env("OIDC_GROUP_CLAIM") || ""
      }
    end
  end

  # Load-time provider defaults (mirrors user-oidc-utils.applyProviderDefaults — note these
  # differ from the create-time github issuer in SsoProviders).
  @google_defaults %{
    "issuer_url" => "https://accounts.google.com",
    "authorization_url" => "https://accounts.google.com/o/oauth2/v2/auth",
    "token_url" => "https://oauth2.googleapis.com/token",
    "userinfo_url" => "https://openidconnect.googleapis.com/v1/userinfo",
    "identifier_path" => "sub",
    "name_path" => "name",
    "scopes" => @default_scopes
  }

  @github_defaults %{
    "issuer_url" => "https://token.actions.githubusercontent.com",
    "authorization_url" => "https://github.com/login/oauth/authorize",
    "token_url" => "https://github.com/login/oauth/access_token",
    "userinfo_url" => "https://api.github.com/user",
    "identifier_path" => "id",
    "name_path" => "name",
    "scopes" => "read:user user:email"
  }

  @doc "Fill in provider defaults for google/github, keeping any non-empty config value."
  @spec apply_provider_defaults(map(), String.t()) :: map()
  def apply_provider_defaults(config, "google"), do: merge_defaults(config, @google_defaults)
  def apply_provider_defaults(config, "github"), do: merge_defaults(config, @github_defaults)
  def apply_provider_defaults(config, _type), do: config

  defp merge_defaults(config, defaults) do
    Enum.reduce(defaults, config, fn {k, v}, acc ->
      case Map.get(acc, k) do
        val when is_binary(val) and val != "" -> acc
        _ -> Map.put(acc, k, v)
      end
    end)
  end

  # --- authorize ------------------------------------------------------------

  @doc """
  Build the provider authorization URL for an already-stored `state`/`nonce` pair (see
  `store_state/2`). Returns the fully-qualified `auth_url` string.
  """
  @spec build_authorize_url(map(), String.t(), String.t(), String.t()) :: String.t()
  def build_authorize_url(config, backend_callback_uri, state, nonce) do
    query =
      URI.encode_query(%{
        "client_id" => config["client_id"],
        "redirect_uri" => backend_callback_uri,
        "response_type" => "code",
        "scope" => config["scopes"] || @default_scopes,
        "state" => state,
        "nonce" => nonce
      })

    base = config["authorization_url"]
    sep = if String.contains?(base, "?"), do: "&", else: "?"
    base <> sep <> query
  end

  # --- flow state (TTL'd ETS, swept by Termelix.EtsOwner) -------------------

  @state_table :termelix_oidc_flow_state
  @state_ttl_ms 10 * 60 * 1000
  @max_states 10_000

  @doc """
  Create the flow-state ETS table if it does not exist yet. Idempotent: the
  `ArgumentError` raised when the named table already exists means the owner
  (`Termelix.EtsOwner`) or another caller beat us to it.
  """
  @spec ensure_table() :: :ok
  def ensure_table do
    try do
      :ets.new(@state_table, [
        :named_table,
        :public,
        :set,
        read_concurrency: true,
        write_concurrency: true
      ])

      :ok
    rescue
      ArgumentError -> :ok
    end
  end

  @doc """
  Store the per-state flow context the callback reads back, expiring after 10 minutes.

  `GET /users/oidc/authorize` is unauthenticated, so every caller can mint a row here. It
  used to write five rows into the `settings` table — permanent, unswept, and sharing that
  table with the wrapped per-user DEKs — so one unauthenticated request grew the DEK store
  and busted the global settings cache. The context now lives in a TTL'd public ETS table
  owned for the node's lifetime by `Termelix.EtsOwner`, which sweeps it via
  `sweep_expired/1` every 60s; `@max_states` caps the footprint between sweeps.
  """
  @spec store_state(String.t(), keyword()) :: :ok
  def store_state(state, opts) do
    ensure_table()

    context = %{
      nonce: Keyword.fetch!(opts, :nonce),
      backend_callback: Keyword.fetch!(opts, :backend_callback),
      frontend_origin: Keyword.fetch!(opts, :frontend_origin),
      remember_me: if(opts[:remember_me], do: true, else: false),
      provider_db_id: opts[:provider_db_id]
    }

    enforce_cap(state)
    expires_at = System.monotonic_time(:millisecond) + @state_ttl_ms
    :ets.insert(@state_table, {state, context, expires_at})
    :ok
  end

  @doc """
  Read back the flow context stored for `state`: `{:ok, %{nonce:, backend_callback:,
  frontend_origin:, remember_me:, provider_db_id:}}`, or `:error` when `state` is unknown
  or its TTL lapsed (a lapsed row reads as absent even before the sweep removes it).
  """
  @spec fetch_state(String.t()) :: {:ok, map()} | :error
  def fetch_state(state) when is_binary(state) do
    ensure_table()

    case :ets.lookup(@state_table, state) do
      [{_, context, expires_at}] ->
        if System.monotonic_time(:millisecond) < expires_at, do: {:ok, context}, else: :error

      [] ->
        :error
    end
  end

  def fetch_state(_state), do: :error

  @doc "Forget the provider id for `state`, keeping the rest of the flow context."
  @spec delete_provider(String.t()) :: :ok
  def delete_provider(state) do
    ensure_table()

    case :ets.lookup(@state_table, state) do
      [{_, context, expires_at}] ->
        :ets.insert(@state_table, {state, %{context | provider_db_id: nil}, expires_at})

      [] ->
        :ok
    end

    :ok
  end

  @doc "Drop the whole flow context for `state` (mirrors deleteOIDCStateSettings)."
  @spec delete_state(String.t()) :: :ok
  def delete_state(state) do
    ensure_table()
    :ets.delete(@state_table, state)
    :ok
  end

  @doc """
  Delete every flow state whose TTL has lapsed as of `now_ms`, returning the number
  removed. Driven every 60s by `Termelix.EtsOwner`.
  """
  @spec sweep_expired(integer()) :: non_neg_integer()
  def sweep_expired(now_ms \\ System.monotonic_time(:millisecond)) do
    ensure_table()
    spec = [{{:_, :_, :"$1"}, [{:"=<", :"$1", now_ms}], [true]}]
    :ets.select_delete(@state_table, spec)
  end

  # Keep the table under @max_states: a fresh state (a re-store of the same one does not
  # grow the table) that would push it over the cap first reclaims lapsed rows and, if that
  # is not enough, drops the soonest-to-expire row — the same bound `Termelix.HttpCache`
  # puts on its cache. Best-effort, not serialized against concurrent stores.
  defp enforce_cap(state) do
    if not :ets.member(@state_table, state) and :ets.info(@state_table, :size) >= @max_states do
      sweep_expired()
      if :ets.info(@state_table, :size) >= @max_states, do: evict_soonest()
    end

    :ok
  end

  defp evict_soonest do
    fold = fn {k, _ctx, exp}, {_, best} = acc -> if exp < best, do: {k, exp}, else: acc end

    case :ets.foldl(fold, {nil, :infinity}, @state_table) do
      {nil, _} -> :ok
      {k, _} -> :ets.delete(@state_table, k)
    end
  end

  @doc false
  @spec reset_states() :: :ok
  def reset_states do
    ensure_table()
    :ets.delete_all_objects(@state_table)
    :ok
  end

  # --- callback-target classification (mirrors oidc-desktop-callback.ts) -----

  @callback_path "/oidc-callback"

  @doc "Desktop loopback callback URL for a numeric port string, or nil if invalid."
  @spec desktop_callback_url(term()) :: String.t() | nil
  def desktop_callback_url(value) when is_binary(value) do
    case Integer.parse(value) do
      {port, ""} when port >= 1 and port <= 65_535 -> "http://localhost:#{port}#{@callback_path}"
      _ -> nil
    end
  end

  def desktop_callback_url(_), do: nil

  # Both schemes, exactly like `resolve_app_callback/1` in `oidc_controller.ex:354-369`:
  # the shipped mobile app still registers the pre-rename `termix-mobile://` deep link, and
  # a scheme accepted there but rejected here redirects the client with no token, no error.
  @mobile_schemes ["termelix-mobile:", "termix-mobile:"]

  @doc "Whether a frontend origin is a token-callback target (mobile scheme or loopback)."
  @spec token_callback?(String.t()) :: boolean()
  def token_callback?(value) when is_binary(value) do
    if String.starts_with?(value, @mobile_schemes) do
      true
    else
      uri = URI.parse(value)

      uri.scheme == "http" and uri.host in ["localhost", "127.0.0.1"] and
        uri.path == @callback_path
    end
  end

  def token_callback?(_), do: false

  # --- token exchange + userinfo --------------------------------------------

  @doc "Exchange an authorization `code` for tokens at the provider token endpoint."
  @spec exchange_code(map(), String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def exchange_code(config, code, redirect_uri) do
    form = %{
      "grant_type" => "authorization_code",
      "client_id" => config["client_id"],
      "client_secret" => config["client_secret"],
      "code" => code,
      "redirect_uri" => redirect_uri
    }

    opts =
      [form: form, headers: [{"accept", "application/json"}], retry: false, redirect: false] ++
        req_options()

    case Req.post(config["token_url"], opts) do
      {:ok, %Req.Response{status: status, body: body}} when status in 200..299 ->
        {:ok, as_map(body)}

      {:ok, %Req.Response{status: status}} ->
        {:error, {:http_status, status}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    error -> {:error, error}
  end

  @doc """
  Resolve the OIDC userinfo for an exchanged token set. Verifies the `id_token` (signature +
  nonce) when present, then merges any userinfo-endpoint payload. Returns the combined claim
  map, `{:error, :nonce_mismatch}`, or `{:error, :no_userinfo}`.
  """
  @spec resolve_userinfo(map(), map(), String.t()) :: {:ok, map()} | {:error, term()}
  def resolve_userinfo(config, token_data, stored_nonce) do
    with {:ok, base} <- userinfo_from_id_token(config, token_data, stored_nonce) do
      merged = merge_userinfo_endpoint(config, token_data, base)

      case merged do
        nil -> {:error, :no_userinfo}
        map -> {:ok, map}
      end
    end
  end

  defp userinfo_from_id_token(config, token_data, stored_nonce) do
    case token_data["id_token"] do
      id_token when is_binary(id_token) and id_token != "" ->
        case verify_oidc_token(
               id_token,
               config["issuer_url"],
               config["client_id"],
               config["ca_cert"]
             ) do
          {:ok, claims} ->
            if claims["nonce"] == stored_nonce,
              do: {:ok, claims},
              else: {:error, :nonce_mismatch}

          {:error, reason} ->
            {:error, reason}
        end

      _ ->
        {:ok, nil}
    end
  end

  defp merge_userinfo_endpoint(config, token_data, base) do
    case token_data["access_token"] do
      token when is_binary(token) and token != "" ->
        config
        |> userinfo_urls()
        |> Enum.reduce_while(base, fn url, acc ->
          case fetch_userinfo(url, token) do
            {:ok, info} -> {:halt, Map.merge(acc || %{}, info)}
            :error -> {:cont, acc}
          end
        end)

      _ ->
        base
    end
  end

  defp userinfo_urls(config) do
    normalized = String.replace_trailing(config["issuer_url"] || "", "/", "")
    base_url = Regex.replace(~r{/application/o/[^/]+$}, normalized, "")

    discovered =
      case discover_userinfo_endpoint(config, normalized) do
        nil -> []
        url -> [url]
      end

    configured = if blank?(config["userinfo_url"]), do: [], else: [config["userinfo_url"]]

    configured ++
      discovered ++
      [
        "#{base_url}/userinfo/",
        "#{base_url}/userinfo",
        "#{normalized}/userinfo/",
        "#{normalized}/userinfo",
        "#{base_url}/oauth2/userinfo/",
        "#{base_url}/oauth2/userinfo",
        "#{normalized}/oauth2/userinfo/",
        "#{normalized}/oauth2/userinfo"
      ]
  end

  defp discover_userinfo_endpoint(config, normalized) do
    case http_get_json("#{normalized}/.well-known/openid-configuration", [], config["ca_cert"]) do
      {:ok, %{"userinfo_endpoint" => endpoint}} when is_binary(endpoint) -> endpoint
      _ -> nil
    end
  end

  defp fetch_userinfo(url, access_token) do
    case http_get_json(url, [{"authorization", "Bearer #{access_token}"}], nil) do
      {:ok, map} when is_map(map) -> {:ok, map}
      _ -> :error
    end
  end

  @doc """
  Fetch a GitHub user's profile (+ primary verified email) for the OIDC callback's GitHub
  branch. Returns `{:ok, userinfo}` or `{:error, :github_userinfo}`.
  """
  @spec fetch_github_userinfo(String.t() | nil) :: {:ok, map()} | {:error, :github_userinfo}
  def fetch_github_userinfo(access_token) when is_binary(access_token) and access_token != "" do
    headers = [
      {"authorization", "Bearer #{access_token}"},
      {"accept", "application/json"},
      {"user-agent", "Termelix"}
    ]

    case http_get_json("https://api.github.com/user", headers, nil) do
      {:ok, user} when is_map(user) and map_size(user) > 0 ->
        {:ok, Map.merge(user, github_primary_email(headers))}

      _ ->
        {:error, :github_userinfo}
    end
  end

  def fetch_github_userinfo(_), do: {:error, :github_userinfo}

  defp github_primary_email(headers) do
    case http_get_json("https://api.github.com/user/emails", headers, nil) do
      {:ok, emails} when is_list(emails) ->
        case Enum.find(emails, fn e -> e["primary"] == true and e["verified"] == true end) do
          %{"email" => email} -> %{"email" => email}
          _ -> %{}
        end

      _ ->
        %{}
    end
  end

  # --- id_token verification (mirrors verifyOIDCToken) ----------------------

  @doc """
  Verify an `id_token`'s signature against the provider JWKS and its issuer/audience/exp
  claims. Returns `{:ok, claims}` (string-keyed) or `{:error, reason}`.
  """
  @spec verify_oidc_token(String.t(), String.t(), String.t(), String.t() | nil) ::
          {:ok, map()} | {:error, term()}
  def verify_oidc_token(id_token, issuer_url, client_id, ca_cert) do
    with {:ok, header} <- decode_jwt_header(id_token),
         {:ok, jwks} <- fetch_jwks(issuer_url, ca_cert),
         {:ok, key} <- find_signing_key(jwks, header["kid"]),
         {:ok, claims} <- verify_signature(id_token, key, header["alg"]) do
      validate_claims(claims, issuer_url, client_id)
    end
  end

  defp decode_jwt_header(token) do
    with [header_b64 | _] <- String.split(token, "."),
         {:ok, json} <- base64url_decode(header_b64),
         {:ok, header} <- Jason.decode(json) do
      {:ok, header}
    else
      _ -> {:error, :bad_token_header}
    end
  end

  defp fetch_jwks(issuer_url, ca_cert) do
    normalized = String.replace_trailing(issuer_url || "", "/", "")
    stripped = Regex.replace(~r{/application/o/[^/]+$}, normalized, "")

    discovered =
      case http_get_json("#{normalized}/.well-known/openid-configuration", [], ca_cert) do
        {:ok, %{"jwks_uri" => uri}} when is_binary(uri) -> [uri]
        _ -> []
      end

    urls =
      discovered ++
        [
          "#{normalized}/.well-known/jwks.json",
          "#{normalized}/jwks/",
          "#{stripped}/.well-known/jwks.json"
        ]

    Enum.reduce_while(urls, {:error, :no_jwks}, fn url, acc ->
      case http_get_json(url, [], ca_cert) do
        {:ok, %{"keys" => keys} = jwks} when is_list(keys) -> {:halt, {:ok, jwks}}
        _ -> {:cont, acc}
      end
    end)
  end

  defp find_signing_key(%{"keys" => keys}, kid) do
    case Enum.find(keys, fn key -> key["kid"] == kid end) do
      nil -> {:error, :no_matching_key}
      key -> {:ok, key}
    end
  end

  defp verify_signature(token, jwk_map, alg) do
    algs = if is_binary(alg), do: [alg], else: ["RS256", "RS384", "RS512", "ES256", "ES384"]
    jwk = JOSE.JWK.from_map(jwk_map)

    case JOSE.JWT.verify_strict(jwk, algs, token) do
      {true, %JOSE.JWT{fields: claims}, _jws} -> {:ok, claims}
      _ -> {:error, :bad_signature}
    end
  rescue
    _ -> {:error, :bad_signature}
  end

  defp validate_claims(claims, issuer_url, client_id) do
    cond do
      expired?(claims["exp"]) -> {:error, :token_expired}
      not issuer_ok?(claims["iss"], issuer_url) -> {:error, :issuer_mismatch}
      not audience_ok?(claims["aud"], client_id) -> {:error, :audience_mismatch}
      true -> {:ok, claims}
    end
  end

  defp expired?(exp) when is_integer(exp), do: exp < System.system_time(:second)
  defp expired?(_), do: false

  # Accepts the raw issuer or its trailing-slash / application-path variants, like the Node
  # `possibleIssuers` list.
  defp issuer_ok?(nil, _issuer_url), do: false

  defp issuer_ok?(iss, issuer_url) do
    normalized = String.replace_trailing(issuer_url || "", "/", "")
    stripped = Regex.replace(~r{/application/o/[^/]+$}, normalized, "")

    iss in Enum.uniq([
      issuer_url,
      normalized,
      stripped,
      String.replace_trailing(issuer_url || "", "/", "")
    ])
  end

  defp audience_ok?(aud, client_id) when is_list(aud), do: client_id in aud
  defp audience_ok?(aud, client_id), do: aud == client_id

  # --- identity extraction --------------------------------------------------

  @doc """
  Extract `{identifier, name}` from a userinfo map per the provider's `identifier_path` /
  `name_path`, with the same fallback chain as the Node callback. Returns
  `{:error, :no_identifier}` when nothing resolves.
  """
  @spec extract_identity(map(), map()) :: {:ok, String.t(), String.t()} | {:error, :no_identifier}
  def extract_identity(config, userinfo) do
    identifier =
      first_present([
        get_nested_value(userinfo, config["identifier_path"]),
        userinfo[config["identifier_path"] || ""],
        userinfo["sub"],
        userinfo["email"],
        userinfo["preferred_username"]
      ])

    case identifier do
      nil ->
        {:error, :no_identifier}

      value ->
        name =
          first_present([
            get_nested_value(userinfo, config["name_path"]),
            userinfo[config["name_path"] || ""],
            userinfo["name"],
            userinfo["given_name"],
            value
          ])

        {:ok, to_string(value), to_string(name)}
    end
  end

  @doc "Read a dotted `path` out of a nested map, or nil."
  @spec get_nested_value(map(), String.t() | nil) :: term()
  def get_nested_value(_obj, path) when path in [nil, ""], do: nil

  def get_nested_value(obj, path) when is_map(obj) do
    Enum.reduce_while(String.split(path, "."), obj, fn key, acc ->
      case acc do
        %{} = m -> {:cont, Map.get(m, key)}
        _ -> {:halt, nil}
      end
    end)
  end

  def get_nested_value(_obj, _path), do: nil

  # --- allow-list + groups (mirrors user-oidc-utils) ------------------------

  @doc "Extract group/role names from a userinfo payload (see `extractOidcGroups`)."
  @spec extract_oidc_groups(map(), String.t() | nil) :: [String.t()]
  def extract_oidc_groups(userinfo, group_claim) do
    raw =
      if is_binary(group_claim) and String.trim(group_claim) != "" do
        Map.get(userinfo, String.trim(group_claim))
      end

    raw = raw || userinfo["groups"] || userinfo["roles"] || userinfo["group"]

    cond do
      is_list(raw) ->
        Enum.map(raw, &to_string/1)

      is_binary(raw) ->
        raw |> String.split(",") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))

      is_map(raw) ->
        Map.keys(raw)

      true ->
        []
    end
  end

  @doc "Whether `identifier`/`email` matches the `allowed_users` patterns (see `isOIDCUserAllowed`)."
  @spec oidc_user_allowed?(String.t() | nil, String.t(), String.t() | nil) :: boolean()
  def oidc_user_allowed?(allowed_users, identifier, email \\ nil) do
    patterns =
      (allowed_users || "")
      |> String.split(~r/[\n,]/)
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))

    values = [identifier | if(email && email != identifier, do: [email], else: [])]

    cond do
      blank?(allowed_users) -> true
      patterns == [] -> true
      true -> Enum.any?(patterns, &pattern_matches?(&1, values))
    end
  end

  defp pattern_matches?("*", _values), do: true

  defp pattern_matches?(pattern, values) do
    cond do
      String.contains?(pattern, "*") ->
        regex = wildcard_regex(pattern)
        Enum.any?(values, fn v -> v && Regex.match?(regex, String.downcase(v)) end)

      String.starts_with?(pattern, "@") ->
        Enum.any?(values, fn v ->
          v && String.ends_with?(String.downcase(v), String.downcase(pattern))
        end)

      true ->
        Enum.any?(values, fn v -> v && String.downcase(v) == String.downcase(pattern) end)
    end
  end

  # Escape every regex metachar except `*`, then turn `*` into `.*` — the same glob semantics
  # as the Node `isOIDCUserAllowed` wildcard branch.
  defp wildcard_regex(pattern) do
    body =
      pattern
      |> String.downcase()
      |> String.split("*")
      |> Enum.map_join(".*", &Regex.escape/1)

    Regex.compile!("^#{body}$")
  end

  # --- find-or-create user --------------------------------------------------

  @spec find_by_oidc_identifier(String.t()) :: User.t() | nil
  def find_by_oidc_identifier(identifier), do: Repo.get_by(User, oidcIdentifier: identifier)

  @doc """
  The provider-scoped form of a raw generic-OIDC `identifier`:
  `"oidc:<provider_db_id>:<identifier>"`, or `"oidc:<issuer_url>:<identifier>"` for env/legacy
  configs that have no provider row.

  The GitHub and LDAP flows have always scoped their identifiers (`github:<id>:…`,
  `ldap:<id>:…`). Without scoping, two providers whose users happen to share a `sub` resolve
  to the SAME local account — a cross-provider account takeover on multi-provider instances.
  """
  @spec scoped_identifier(integer() | nil, map(), String.t()) :: String.t()
  def scoped_identifier(provider_db_id, config, identifier)

  def scoped_identifier(provider_db_id, _config, identifier) when is_integer(provider_db_id),
    do: "oidc:#{provider_db_id}:#{identifier}"

  def scoped_identifier(nil, config, identifier),
    do: "oidc:#{config["issuer_url"]}:#{identifier}"

  @doc """
  Find or create the OIDC user for `identifier`, applying allow-list, auto-provision, DEK
  setup, default-role assignment, and admin-group sync. Returns `{:ok, user}` or a tagged
  error: `:not_allowed`, `:registration_disabled`, `:encryption_failed`.

  `:legacy_identifier` — the pre-scoping form of `identifier` (generic OIDC only): rows
  written before identifiers were provider-scoped are still matched by it, and migrated to
  the scoped form on a successful login, so the unscoped fallback window closes behind them.
  The fallback only matches a row this provider owns (`ssoProviderId`, or no owner at all) —
  see `claimable_legacy_row?/2`.
  """
  @spec find_or_create_user(map(), String.t(), String.t(), map(), integer() | nil, keyword()) ::
          {:ok, User.t()} | {:error, atom()}
  def find_or_create_user(config, identifier, name, userinfo, provider_db_id, opts \\ []) do
    case find_by_oidc_identifier(identifier) do
      nil ->
        legacy_lookup(
          config,
          identifier,
          name,
          userinfo,
          provider_db_id,
          opts[:legacy_identifier]
        )

      user ->
        update_existing_user(config, user, name, userinfo)
    end
  end

  defp legacy_lookup(config, scoped, name, userinfo, provider_db_id, nil),
    do: create_oidc_user(config, scoped, name, userinfo, provider_db_id)

  defp legacy_lookup(config, scoped, name, userinfo, provider_db_id, legacy) do
    user = find_by_oidc_identifier(legacy)

    if user && claimable_legacy_row?(user, provider_db_id) do
      with {:ok, user} <- update_existing_user(config, user, name, userinfo) do
        Logger.info("Migrating OIDC user #{user.id} to provider-scoped identifier")
        {:ok, Repo.update!(Ecto.Changeset.change(user, oidcIdentifier: scoped))}
      end
    else
      create_oidc_user(config, scoped, name, userinfo, provider_db_id)
    end
  end

  # The unscoped row must belong to the provider now presenting this `sub`, or the fallback
  # would reintroduce the very collision scoping exists to prevent: a second IdP handing out
  # a `sub` that matches another provider's not-yet-migrated row would claim that account.
  #
  # Equality, with no exception for an owner-less row. `nil == nil` already covers the
  # env-configured (provider-row-less) flow, which is the only case that needs to keep
  # working; an owner-less row claimed by a CONFIGURED provider is indistinguishable from the
  # takeover above, so it is refused. The cost is an instance that migrated from env config to
  # a provider row: those users land on a fresh account instead of their old one, recoverable
  # by an admin, which a takeover is not.
  defp claimable_legacy_row?(%User{ssoProviderId: owner}, provider_db_id),
    do: owner == provider_db_id

  defp create_oidc_user(config, identifier, name, userinfo, provider_db_id) do
    first? = Termelix.Accounts.user_count() == 0
    email = userinfo["email"]

    cond do
      not first? and present?(config["allowed_users"]) and
          not oidc_user_allowed?(config["allowed_users"], identifier, email) ->
        {:error, :not_allowed}

      not first? and not auto_provision?() ->
        {:error, :registration_disabled}

      true ->
        insert_oidc_user(config, identifier, name, userinfo, provider_db_id, first?)
    end
  end

  defp insert_oidc_user(config, identifier, name, userinfo, provider_db_id, first?) do
    id = Id.generate()

    user =
      Repo.insert!(%User{
        id: id,
        username: name,
        passwordHash: "",
        isAdmin: first?,
        isOidc: true,
        oidcIdentifier: identifier,
        ssoProviderId: provider_db_id,
        scopes: @default_scopes,
        totpEnabled: false,
        donationModalDismissed: false,
        registeredAt: iso_now()
      })

    assign_default_role(id, first?)

    try do
      UserKeyManager.create_user_dek(id)
      sync_admin_group(config, user, userinfo)
    rescue
      error ->
        Logger.error("OIDC DEK setup failed for #{id}: #{Exception.message(error)}")
        Repo.delete(user)
        {:error, :encryption_failed}
    else
      synced -> {:ok, synced}
    end
  end

  defp update_existing_user(config, user, name, userinfo) do
    email = userinfo["email"]

    if present?(config["allowed_users"]) and
         not oidc_user_allowed?(config["allowed_users"], user.oidcIdentifier || "", email) do
      {:error, :not_allowed}
    else
      # Non-dual-auth users get their username refreshed from the IdP; ensure a DEK exists.
      user =
        if present?(user.passwordHash),
          do: user,
          else: Repo.update!(Ecto.Changeset.change(user, username: name))

      ensure_dek(user.id)
      {:ok, sync_admin_group(config, user, userinfo)}
    end
  end

  defp sync_admin_group(config, user, userinfo) do
    admin_group = config["admin_group"]

    if present?(admin_group) do
      should_be_admin? = admin_group in extract_oidc_groups(userinfo, config["group_claim"])

      if user.isAdmin == true != should_be_admin? do
        updated = Repo.update!(Ecto.Changeset.change(user, isAdmin: should_be_admin?))
        switch_admin_role(user.id, should_be_admin?)
        updated
      else
        user
      end
    else
      user
    end
  end

  # --- role helpers ---------------------------------------------------------

  defp assign_default_role(user_id, first?) do
    role_name = if first?, do: "admin", else: "user"

    case Rbac.get_role_by_name(role_name) do
      nil -> :ok
      role -> Rbac.assign_role_to_user(user_id, role.id, user_id)
    end
  rescue
    _ -> :ok
  end

  defp switch_admin_role(user_id, should_be_admin?) do
    {add, remove} = if should_be_admin?, do: {"admin", "user"}, else: {"user", "admin"}

    with %{id: remove_id} <- Rbac.get_role_by_name(remove) do
      Rbac.remove_role_from_user(user_id, remove_id)
    end

    with %{id: add_id} <- Rbac.get_role_by_name(add) do
      unless Rbac.find_user_role(user_id, add_id) do
        Rbac.assign_role_to_user(user_id, add_id, user_id)
      end
    end

    :ok
  rescue
    _ -> :ok
  end

  defp ensure_dek(user_id) do
    unless UserKeyManager.has_user_dek?(user_id) do
      UserKeyManager.create_user_dek(user_id)
    end

    :ok
  rescue
    _ -> :ok
  end

  # --- auto-provision toggle ------------------------------------------------

  defp auto_provision? do
    setting =
      case Settings.get_value("oidc_auto_provision") do
        "true" -> true
        _ -> false
      end

    setting or
      (System.get_env("OIDC_ALLOW_REGISTRATION") || "") |> String.trim() |> String.downcase() ==
        "true"
  end

  # --- HTTP helper ----------------------------------------------------------

  # `redirect: false` on both calls: the URLs are admin-configured, but a 302/307 answer would
  # otherwise be followed with no re-vetting — and for `exchange_code` a 307 would re-POST the
  # `client_secret` to wherever the redirect points. A 3xx is just a non-2xx failure to the
  # callers, same as any other refused response.
  defp http_get_json(url, headers, _ca_cert) do
    opts =
      [headers: headers, retry: false, redirect: false, receive_timeout: 5_000] ++ req_options()

    case Req.get(url, opts) do
      {:ok, %Req.Response{status: status, body: body}} when status in 200..299 ->
        {:ok, decode_body(body)}

      _ ->
        :error
    end
  rescue
    _ -> :error
  end

  defp req_options, do: Application.get_env(:termelix, :req_options, [])

  # --- small helpers --------------------------------------------------------

  # Req auto-decodes JSON responses, but a text/plain body arrives as a binary to decode.
  defp decode_body(body) when is_map(body) or is_list(body), do: body

  defp decode_body(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} -> decoded
      _ -> body
    end
  end

  defp decode_body(other), do: other

  # Token responses are always objects; keep the map-only coercion for exchange_code.
  defp as_map(body) when is_map(body), do: body

  defp as_map(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, map} when is_map(map) -> map
      _ -> %{}
    end
  end

  defp as_map(_), do: %{}

  defp base64url_decode(str) do
    padded = str <> String.duplicate("=", rem(4 - rem(byte_size(str), 4), 4))

    case Base.url_decode64(padded) do
      {:ok, bin} -> {:ok, bin}
      :error -> Base.decode64(padded)
    end
  end

  defp first_present(values), do: Enum.find(values, &present_value?/1)

  defp present_value?(nil), do: false
  defp present_value?(""), do: false
  defp present_value?(_), do: true

  defp blank?(nil), do: true
  defp blank?(str) when is_binary(str), do: String.trim(str) == ""
  defp blank?(_), do: false

  defp present?(v) when is_binary(v), do: String.trim(v) != ""
  defp present?(_), do: false

  defp iso_now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
