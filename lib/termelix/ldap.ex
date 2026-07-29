defmodule Termelix.Ldap.Client do
  @moduledoc """
  The thin, mockable boundary in front of OTP `:eldap`.

  Every LDAP network primitive the auth flow needs is a callback here; the sole production
  implementation is `Termelix.Ldap.EldapClient` (the *only* module that talks to `:eldap`).
  Tests inject a fake via `config :termelix, :ldap_client, MyFake` (see
  `Termelix.Ldap.client_mod/0`), so the whole `Termelix.Ldap` flow runs without a live directory
  — the live integration against a real server is deferred (unavailable in CI).

  `search/2` receives a request map `%{base, filter, attributes, scope}` where `filter` is the
  neutral filter AST produced by `Termelix.Ldap.parse_filter/1` (never a raw `:eldap` term), and
  returns entries already normalised to `%{dn: String.t(), attributes: %{String.t() => [String.t()]}}`.
  """
  @type handle :: term()
  @type config :: map()
  @type entry :: %{dn: String.t(), attributes: %{String.t() => [String.t()]}}
  @type search_req :: %{
          base: String.t(),
          filter: Termelix.Ldap.filter_ast(),
          attributes: [String.t()],
          scope: :base | :one | :sub
        }

  @callback open(config()) :: {:ok, handle()} | {:error, term()}
  @callback bind(handle(), dn :: String.t(), password :: String.t()) :: :ok | {:error, term()}
  @callback search(handle(), search_req()) :: {:ok, [entry()]} | {:error, term()}
  @callback close(handle()) :: :ok
end

defmodule Termelix.Ldap do
  @moduledoc """
  LDAP authentication — the Elixir port of `ldap-auth-routes.ts`.

  Flow for `POST /users/ldap/login` (`login/3`): load + validate the provider's LDAP config,
  bind a service account, search for the login username, verify the password by re-binding as
  the found DN, optionally derive admin status from group membership, then find-or-create the
  local user and hand a resolved `%User{}` back to the controller to mint a real session (like
  `UserController.issue_session`).

  Everything that touches `:eldap` goes through the `Termelix.Ldap.Client` behaviour
  (`client_mod/0`), so the pure pieces — config parsing, filter escaping/parsing, attribute
  mapping and the allowed-users check — are unit-testable and the network calls are mockable.

  ## Lazy encryption note

  `oidcIdentifier` is in the `users` encrypted-field set, but — exactly as the Node backend —
  it is written in **plaintext** for SSO users (`LazyFieldEncryption` migrates only
  `totpSecret`/`totpBackupCodes` for the `users` table). Storing it plaintext is what keeps the
  `ldap:<providerId>:<identifier>` lookup a plain column match; a DEK is still created for the
  user so later-added encrypted fields have key material.
  """
  import Ecto.Query, only: [from: 2]
  require Logger

  alias Termelix.{Accounts, Id, Repo, Settings}
  alias Termelix.Crypto.{SystemSecrets, UserKeyManager}
  alias Termelix.Schema.User

  @typedoc "Neutral LDAP filter AST produced by `parse_filter/1` (no `:eldap` terms leak out)."
  @type filter_ast ::
          {:and, [filter_ast()]}
          | {:or, [filter_ast()]}
          | {:not, filter_ast()}
          | {:present, String.t()}
          | {:equal, String.t(), String.t()}
          | {:ge, String.t(), String.t()}
          | {:le, String.t(), String.t()}
          | {:approx, String.t(), String.t()}
          | {:substrings, String.t(), [{:initial | :any | :final, String.t()}]}

  @default_port 389
  @default_username_attribute "uid"
  @default_display_name_attribute "cn"
  @connect_timeout 10_000

  @doc "The injected LDAP client module (defaults to the real `:eldap` wrapper)."
  @spec client_mod() :: module()
  def client_mod, do: Application.get_env(:termelix, :ldap_client, Termelix.Ldap.EldapClient)

  # ---------------------------------------------------------------------------
  # Entry point
  # ---------------------------------------------------------------------------

  @doc """
  Authenticate `username`/`password` against the LDAP provider `provider_id` and resolve the
  local user, provisioning one on first login. Returns `{:ok, %User{}}` or a tagged error the
  controller maps onto the Node status ladder:

    * `:provider_not_found`     — 404 (unknown/disabled/non-LDAP provider)
    * `:misconfigured`          — 500 (missing host/bindDN/searchBase/searchFilter)
    * `:invalid_credentials`    — 401 (user not found or password bind failed)
    * `:not_allowed`            — 403 (not in the allowed-users list)
    * `:registration_disabled`  — 403 (auto-provision off and not the first user)
    * `:encryption_setup_failed`— 500 (DEK creation failed; user row rolled back)
    * `:ldap_error`             — 500 (any bind/search/transport/DB failure)
  """
  @spec login(pos_integer(), String.t(), String.t()) :: {:ok, User.t()} | {:error, atom()}
  def login(provider_id, username, password) do
    with {:ok, config} <- load_config(provider_id) do
      authenticate(provider_id, config, username, password)
    end
  rescue
    error ->
      Logger.error("LDAP login failed: #{Exception.message(error)}")
      {:error, :ldap_error}
  end

  defp authenticate(provider_id, config, username, password) do
    client = client_mod()

    case client.open(config) do
      {:ok, conn} ->
        try do
          do_authenticate(client, conn, provider_id, config, username, password)
        after
          client.close(conn)
        end

      {:error, reason} ->
        Logger.warning("LDAP connect failed: #{inspect(reason)}")
        {:error, :ldap_error}
    end
  end

  defp do_authenticate(client, conn, provider_id, config, username, password) do
    with :ok <- bind_service(client, conn, config),
         {:ok, entry} <- find_user(client, conn, config, username),
         {identifier, display_name, email} <- map_user_entry(entry, config, username),
         :ok <- ensure_allowed(config, identifier, email),
         :ok <- verify_password(client, config, entry.dn, password) do
      is_admin = admin?(client, conn, config, entry.dn)
      find_or_create_user(provider_id, identifier, display_name, is_admin, config)
    end
  end

  defp bind_service(client, conn, config) do
    case client.bind(conn, config.bind_dn, config.bind_password) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.warning("LDAP service bind failed: #{inspect(reason)}")
        {:error, :ldap_error}
    end
  end

  defp find_user(client, conn, config, username) do
    case build_search_filter(config, username) do
      {:ok, ast} ->
        req = %{
          base: config.user_search_base,
          filter: ast,
          attributes: search_attributes(config),
          scope: :sub
        }

        case client.search(conn, req) do
          {:ok, [entry | _]} -> {:ok, entry}
          {:ok, []} -> {:error, :invalid_credentials}
          {:error, reason} -> log_and(reason, "LDAP search failed", :ldap_error)
        end

      {:error, reason} ->
        # A misconfigured/unparseable userSearchFilter — treat as an LDAP error (500), the
        # bucket the Node route's outer catch would land it in.
        log_and(reason, "LDAP search filter parse failed", :ldap_error)
    end
  end

  defp ensure_allowed(config, identifier, email) do
    if user_allowed?(config.allowed_users, identifier, email) do
      :ok
    else
      {:error, :not_allowed}
    end
  end

  # Re-bind on a *fresh* connection as the found DN with the supplied password. Any failure
  # (bad password or connect issue) maps to the 401 "wrong password" branch, as in Node.
  defp verify_password(client, config, dn, password) do
    case client.open(config) do
      {:ok, conn} ->
        result = client.bind(conn, dn, password)
        client.close(conn)

        case result do
          :ok -> :ok
          {:error, _reason} -> {:error, :invalid_credentials}
        end

      {:error, _reason} ->
        {:error, :invalid_credentials}
    end
  end

  # ---------------------------------------------------------------------------
  # Provider config
  # ---------------------------------------------------------------------------

  @doc """
  Load and validate the LDAP config for `provider_id` from the `sso_providers` row. Returns
  `{:ok, config}` (a normalised map with atom keys), `{:error, :provider_not_found}` for an
  unknown/disabled/non-LDAP provider, or `{:error, :misconfigured}` when required keys are
  absent — mirroring `loadProviderConfig` + the route's config guards.
  """
  @spec load_config(pos_integer()) ::
          {:ok, map()} | {:error, :provider_not_found | :misconfigured}
  def load_config(provider_id) do
    case fetch_provider(provider_id) do
      %{type: "ldap", enabled: enabled, config: raw} ->
        if enabled?(enabled) do
          config = raw |> decode_config() |> parse_config()
          if valid_config?(config), do: {:ok, config}, else: {:error, :misconfigured}
        else
          {:error, :provider_not_found}
        end

      _ ->
        {:error, :provider_not_found}
    end
  end

  # Schemaless read — no `Termelix.Schema.SsoProvider` exists yet, and reading the row directly
  # keeps this port self-contained (and avoids racing a parallel OIDC port over a shared schema).
  defp fetch_provider(provider_id) do
    from(p in "sso_providers",
      where: p.id == type(^provider_id, :integer),
      select: %{type: p.type, enabled: p.enabled, config: p.config}
    )
    |> Repo.one()
  end

  defp enabled?(v), do: v in [1, true]

  defp decode_config(raw) when is_binary(raw) do
    case Jason.decode(raw) do
      {:ok, map} when is_map(map) -> map
      _ -> %{}
    end
  end

  defp decode_config(_), do: %{}

  @doc """
  Normalise a raw provider-config map (JSON string keys) into the atom-keyed config the flow
  uses, applying the same defaults as the Node route (`port` 389, `usernameAttribute` `uid`,
  `displayNameAttribute` `cn`) and decrypting `bindPassword`. Also carries the TLS policy keys:
  `caCert` (PEM CA for self-signed directories) and `insecureSkipVerify` (explicit certificate
  verification opt-out — see `Termelix.Ldap.EldapClient.ssl_options/1`).
  """
  @spec parse_config(map()) :: map()
  def parse_config(raw) when is_map(raw) do
    %{
      host: string_or_nil(raw["host"]),
      port: port(raw["port"]),
      use_tls: truthy(raw["useTLS"]),
      start_tls: truthy(raw["startTLS"]),
      bind_dn: string_or_nil(raw["bindDN"]),
      bind_password: decrypt_secret(raw["bindPassword"]) || "",
      user_search_base: string_or_nil(raw["userSearchBase"]),
      user_search_filter: string_or_nil(raw["userSearchFilter"]),
      username_attribute: nonblank(raw["usernameAttribute"], @default_username_attribute),
      display_name_attribute:
        nonblank(raw["displayNameAttribute"], @default_display_name_attribute),
      group_search_base: string_or_nil(raw["groupSearchBase"]),
      admin_group: string_or_nil(raw["adminGroup"]),
      allowed_users: string_or_nil(raw["allowedUsers"]),
      insecure_skip_verify: truthy(raw["insecureSkipVerify"]),
      ca_cert: string_or_nil(raw["caCert"]),
      timeout: @connect_timeout
    }
  end

  defp valid_config?(config) do
    present?(config.host) and present?(config.bind_dn) and
      present?(config.user_search_base) and present?(config.user_search_filter)
  end

  defp port(p) when is_integer(p) and p > 0, do: p

  defp port(p) when is_binary(p) do
    case Integer.parse(p) do
      {n, _} when n > 0 -> n
      _ -> @default_port
    end
  end

  defp port(_), do: @default_port

  # bindPassword is stored sealed under the instance key (`Termelix.Crypto.SystemSecrets`);
  # `open/2` also accepts the legacy `encoded:`/`encrypted:` base64 wrappers and bare values.
  # A sealed value that will not open raises (FieldCrypto's tamper contract) — `login/3`'s
  # rescue maps that to `:ldap_error`, and the envelope is never handed to the directory as a
  # password.
  defp decrypt_secret(nil), do: nil

  defp decrypt_secret(value) when is_binary(value),
    do: SystemSecrets.open(value, "bindPassword")

  defp decrypt_secret(_), do: nil

  # ---------------------------------------------------------------------------
  # Attribute mapping (pure)
  # ---------------------------------------------------------------------------

  @doc """
  Extract `{ldap_identifier, display_name, email}` from a normalised search `entry`, falling
  back to the login `username` for identifier/display name (as `getAttr(...) || username`) and
  to `""` for a missing email. Attribute lookup is case-insensitive.
  """
  @spec map_user_entry(map(), map(), String.t()) :: {String.t(), String.t(), String.t()}
  def map_user_entry(%{attributes: attrs}, config, username) do
    identifier = nonblank(get_attr(attrs, config.username_attribute), username)
    display_name = nonblank(get_attr(attrs, config.display_name_attribute), username)
    email = first_present([get_attr(attrs, "mail"), get_attr(attrs, "email")], "")
    {identifier, display_name, email}
  end

  # First value of the (case-insensitively matched) attribute, or "".
  defp get_attr(attrs, key) when is_map(attrs) do
    wanted = String.downcase(to_string(key))

    Enum.find_value(attrs, "", fn {k, values} ->
      if String.downcase(to_string(k)) == wanted, do: List.first(values) || "", else: false
    end)
  end

  defp first_present(values, default) do
    Enum.find(values, default, fn v -> is_binary(v) and v != "" end)
  end

  # ---------------------------------------------------------------------------
  # Allowed-users check (port of isOIDCUserAllowed)
  # ---------------------------------------------------------------------------

  @doc """
  Whether `identifier` (or `email`) satisfies the `allowed_users` list. An empty list allows
  everyone. Patterns: `*` (all), `*`-globs, `@domain` suffixes, or exact matches — all
  case-insensitive. Mirrors `isOIDCUserAllowed`.
  """
  @spec user_allowed?(String.t() | nil, String.t(), String.t() | nil) :: boolean()
  def user_allowed?(allowed_users, identifier, email \\ nil)

  def user_allowed?(allowed_users, identifier, email) do
    case patterns(allowed_users) do
      [] ->
        true

      patterns ->
        values = candidate_values(identifier, email)
        Enum.any?(patterns, &pattern_matches?(&1, values))
    end
  end

  defp patterns(nil), do: []

  defp patterns(allowed) when is_binary(allowed) do
    allowed
    |> String.split(~r/[\n,]/)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  defp candidate_values(identifier, email) do
    if is_binary(email) and email != "" and email != identifier do
      [identifier, email]
    else
      [identifier]
    end
  end

  defp pattern_matches?("*", _values), do: true

  defp pattern_matches?(pattern, values) do
    cond do
      String.contains?(pattern, "*") ->
        regex = glob_regex(pattern)
        Enum.any?(values, fn v -> v != "" and Regex.match?(regex, String.downcase(v)) end)

      String.starts_with?(pattern, "@") ->
        p = String.downcase(pattern)
        Enum.any?(values, fn v -> v != "" and String.ends_with?(String.downcase(v), p) end)

      true ->
        p = String.downcase(pattern)
        Enum.any?(values, fn v -> v != "" and String.downcase(v) == p end)
    end
  end

  defp glob_regex(pattern) do
    body =
      pattern
      |> String.downcase()
      |> then(&Regex.replace(~r/[.+^${}()|\[\]\\]/, &1, fn m -> "\\" <> m end))
      |> String.replace("*", ".*")

    Regex.compile!("^" <> body <> "$")
  end

  # ---------------------------------------------------------------------------
  # Filter escaping / substitution / parsing (pure)
  # ---------------------------------------------------------------------------

  @doc "Escape `\\ * ( )` and NUL as `\\HH` for safe embedding in a filter (port of `ldapEscapeFilter`)."
  @spec escape_filter(String.t()) :: String.t()
  def escape_filter(value) do
    value
    |> to_string()
    |> String.to_charlist()
    |> Enum.map(fn
      ?\\ -> "\\5c"
      ?* -> "\\2a"
      ?( -> "\\28"
      ?) -> "\\29"
      0 -> "\\00"
      c -> <<c::utf8>>
    end)
    |> IO.iodata_to_binary()
  end

  @doc "Substitute the escaped `username` into `userSearchFilter`'s `{{username}}` and parse it."
  @spec build_search_filter(map(), String.t()) :: {:ok, filter_ast()} | {:error, atom()}
  def build_search_filter(config, username) do
    config.user_search_filter
    |> String.replace("{{username}}", escape_filter(username))
    |> parse_filter()
  end

  @doc """
  Parse an RFC 4515 filter string into the neutral AST. Supports `& | !`, presence (`attr=*`),
  substrings (`attr=a*b`), equality/`>=`/`<=`/`~=`, and `\\HH` byte escapes (unescaped to the
  literal assertion value). Returns `{:ok, ast}` or `{:error, reason}`.
  """
  @spec parse_filter(String.t()) :: {:ok, filter_ast()} | {:error, atom()}
  def parse_filter(string) when is_binary(string) do
    case p_filter(String.trim(string)) do
      {:ok, ast, rest} ->
        if String.trim(rest) == "", do: {:ok, ast}, else: {:error, :trailing_input}

      {:error, _} = err ->
        err
    end
  end

  # filter = "(" filtercomp ")"
  defp p_filter("(" <> rest) do
    with {:ok, ast, rest2} <- p_comp(rest) do
      case rest2 do
        ")" <> rest3 -> {:ok, ast, rest3}
        _ -> {:error, :missing_close_paren}
      end
    end
  end

  defp p_filter(_), do: {:error, :missing_open_paren}

  defp p_comp("&" <> rest), do: p_group(:and, rest, [])
  defp p_comp("|" <> rest), do: p_group(:or, rest, [])

  defp p_comp("!" <> rest) do
    with {:ok, ast, rest2} <- p_filter(rest), do: {:ok, {:not, ast}, rest2}
  end

  defp p_comp(rest), do: p_item(rest)

  # One or more nested filters until the group's closing paren.
  defp p_group(op, "(" <> _ = rest, acc) do
    with {:ok, ast, rest2} <- p_filter(rest), do: p_group(op, rest2, [ast | acc])
  end

  defp p_group(_op, _rest, []), do: {:error, :empty_group}
  defp p_group(op, rest, acc), do: {:ok, {op, Enum.reverse(acc)}, rest}

  defp p_item(bin) do
    {attr, rest} = read_attr(bin)

    cond do
      attr == "" ->
        {:error, :empty_attribute}

      match?(">=" <> _, rest) ->
        simple_item(:ge, attr, chop(rest, 2))

      match?("<=" <> _, rest) ->
        simple_item(:le, attr, chop(rest, 2))

      match?("~=" <> _, rest) ->
        simple_item(:approx, attr, chop(rest, 2))

      match?("=" <> _, rest) ->
        eq_item(attr, chop(rest, 1))

      true ->
        {:error, :missing_operator}
    end
  end

  defp simple_item(tag, attr, value_rest) do
    with {:ok, value, rest} <- read_simple_value(value_rest, []) do
      {:ok, {tag, attr, value}, rest}
    end
  end

  defp eq_item(attr, value_rest) do
    with {:ok, segments, star?, rest} <- scan_value(value_rest, [], [], false) do
      {:ok, classify(attr, segments, star?), rest}
    end
  end

  # Equality vs presence vs substrings, from the `*`-split value segments.
  defp classify(attr, [segment], false), do: {:equal, attr, segment}

  defp classify(attr, segments, true) do
    if Enum.all?(segments, &(&1 == "")) do
      {:present, attr}
    else
      {:substrings, attr, substring_parts(segments)}
    end
  end

  defp substring_parts(segments) do
    first = List.first(segments)
    last = List.last(segments)
    middle = segments |> Enum.drop(1) |> Enum.drop(-1)

    initial = if first != "", do: [{:initial, first}], else: []
    anys = for s <- middle, s != "", do: {:any, s}
    final = if last != "", do: [{:final, last}], else: []

    initial ++ anys ++ final
  end

  defp read_attr(bin), do: read_attr(bin, [])

  defp read_attr(<<c, _::binary>> = bin, acc) when c in [?=, ?<, ?>, ?~],
    do: {acc |> Enum.reverse() |> IO.iodata_to_binary(), bin}

  defp read_attr(<<c, rest::binary>>, acc), do: read_attr(rest, [c | acc])
  defp read_attr(<<>>, acc), do: {acc |> Enum.reverse() |> IO.iodata_to_binary(), ""}

  defp chop(bin, n), do: binary_part(bin, n, byte_size(bin) - n)

  # Substring-aware value scan: splits on unescaped `*`, unescapes `\HH`, stops before `)`.
  defp scan_value(<<?\\, h1, h2, rest::binary>>, cur, segs, star)
       when (h1 in ?0..?9 or h1 in ?a..?f or h1 in ?A..?F) and
              (h2 in ?0..?9 or h2 in ?a..?f or h2 in ?A..?F) do
    scan_value(rest, [hex2(h1, h2) | cur], segs, star)
  end

  defp scan_value(<<?\\, rest::binary>>, cur, segs, star),
    do: scan_value(rest, [?\\ | cur], segs, star)

  defp scan_value(<<?*, rest::binary>>, cur, segs, _star),
    do: scan_value(rest, [], [seg(cur) | segs], true)

  defp scan_value(<<?), _::binary>> = rest, cur, segs, star),
    do: {:ok, Enum.reverse([seg(cur) | segs]), star, rest}

  defp scan_value(<<c, rest::binary>>, cur, segs, star),
    do: scan_value(rest, [c | cur], segs, star)

  defp scan_value(<<>>, _cur, _segs, _star), do: {:error, :unterminated_value}

  # Non-substring value scan (for >=, <=, ~=): `*` is literal, `\HH` unescaped, stops before `)`.
  defp read_simple_value(<<?\\, h1, h2, rest::binary>>, acc)
       when (h1 in ?0..?9 or h1 in ?a..?f or h1 in ?A..?F) and
              (h2 in ?0..?9 or h2 in ?a..?f or h2 in ?A..?F) do
    read_simple_value(rest, [hex2(h1, h2) | acc])
  end

  defp read_simple_value(<<?\\, rest::binary>>, acc), do: read_simple_value(rest, [?\\ | acc])

  defp read_simple_value(<<?), _::binary>> = rest, acc), do: {:ok, seg(acc), rest}

  defp read_simple_value(<<c, rest::binary>>, acc), do: read_simple_value(rest, [c | acc])

  defp read_simple_value(<<>>, _acc), do: {:error, :unterminated_value}

  defp seg(cur), do: cur |> Enum.reverse() |> :erlang.list_to_binary()

  defp hex2(h1, h2), do: hexv(h1) * 16 + hexv(h2)

  defp hexv(c) when c in ?0..?9, do: c - ?0
  defp hexv(c) when c in ?a..?f, do: c - ?a + 10
  defp hexv(c) when c in ?A..?F, do: c - ?A + 10

  defp search_attributes(config) do
    [config.username_attribute, config.display_name_attribute, "mail", "email"]
    |> Enum.uniq()
  end

  # ---------------------------------------------------------------------------
  # Admin group membership
  # ---------------------------------------------------------------------------

  # `(member=<dn>)` under groupSearchBase; admin if a returned group's cn or dn equals adminGroup.
  # Never fatal — any failure yields `false`, as in the Node route.
  defp admin?(client, conn, %{admin_group: ag, group_search_base: gb} = _config, dn)
       when is_binary(ag) and ag != "" and is_binary(gb) and gb != "" do
    with {:ok, ast} <- parse_filter("(member=" <> escape_filter(dn) <> ")"),
         req = %{base: gb, filter: ast, attributes: ["cn", "dn"], scope: :sub},
         {:ok, entries} <- client.search(conn, req) do
      Enum.any?(entries, fn entry ->
        get_attr(entry.attributes, "cn") == ag or entry.dn == ag
      end)
    else
      _ -> false
    end
  rescue
    error ->
      Logger.warning("LDAP group check failed: #{Exception.message(error)}")
      false
  end

  defp admin?(_client, _conn, _config, _dn), do: false

  # ---------------------------------------------------------------------------
  # Find-or-create local user
  # ---------------------------------------------------------------------------

  defp find_or_create_user(provider_id, identifier, display_name, is_admin, config) do
    oidc_identifier = "ldap:#{provider_id}:#{identifier}"

    case Repo.get_by(User, oidcIdentifier: oidc_identifier) do
      nil -> create_user(provider_id, oidc_identifier, display_name, is_admin)
      %User{} = user -> {:ok, sync_user(user, display_name, is_admin, config)}
    end
  end

  defp create_user(provider_id, oidc_identifier, display_name, is_admin) do
    first? = Accounts.user_count() == 0

    if not first? and not auto_provision?() do
      {:error, :registration_disabled}
    else
      insert_ldap_user(provider_id, oidc_identifier, display_name, first? or is_admin)
    end
  end

  defp insert_ldap_user(provider_id, oidc_identifier, display_name, admin?) do
    id = Id.generate()

    user = %User{
      id: id,
      username: display_name,
      # SSO users carry no password; oidcIdentifier is stored plaintext (see moduledoc).
      passwordHash: "",
      isAdmin: admin?,
      isOidc: true,
      oidcIdentifier: oidc_identifier,
      ssoProviderId: provider_id,
      scopes: "openid email profile",
      totpEnabled: false,
      donationModalDismissed: false
    }

    case Repo.insert(user) do
      {:ok, user} ->
        try do
          UserKeyManager.create_user_dek(id)
          {:ok, user}
        rescue
          error ->
            Logger.error(
              "Failed to setup LDAP user encryption for #{id}: #{Exception.message(error)}"
            )

            Repo.delete(user)
            {:error, :encryption_setup_failed}
        end

      {:error, _changeset} ->
        {:error, :ldap_error}
    end
  end

  # Existing SSO user: sync admin from group membership (only when adminGroup is configured) and
  # refresh the display name unless the account is dual-auth (also has a password).
  defp sync_user(user, display_name, is_admin, config) do
    user
    |> maybe_sync_admin(is_admin, config)
    |> maybe_sync_name(display_name)
  end

  defp maybe_sync_admin(user, is_admin, %{admin_group: ag}) when is_binary(ag) and ag != "" do
    if user.isAdmin == true != is_admin do
      update_user(user, isAdmin: is_admin)
    else
      user
    end
  end

  defp maybe_sync_admin(user, _is_admin, _config), do: user

  defp maybe_sync_name(user, display_name) do
    if not dual_auth?(user) and present?(display_name) and user.username != display_name do
      update_user(user, username: display_name)
    else
      user
    end
  end

  defp dual_auth?(%User{passwordHash: hash}) when is_binary(hash), do: String.trim(hash) != ""
  defp dual_auth?(_), do: false

  defp update_user(user, changes) do
    case Repo.update(Ecto.Changeset.change(user, Map.new(changes))) do
      {:ok, updated} -> updated
      {:error, _} -> user
    end
  end

  # Auto-provision: setting `oidc_auto_provision`, else env `OIDC_ALLOW_REGISTRATION == "true"`.
  defp auto_provision? do
    case safe_setting("oidc_auto_provision") do
      v when v in ["true", "1"] -> true
      _ -> env_allow_registration?()
    end
  end

  defp env_allow_registration? do
    (System.get_env("OIDC_ALLOW_REGISTRATION") || "") |> String.trim() |> String.downcase() ==
      "true"
  end

  defp safe_setting(key) do
    Settings.get_value(key)
  rescue
    _ -> nil
  end

  # ---------------------------------------------------------------------------
  # Provider-id coercion (used by the controller for the 400 guard)
  # ---------------------------------------------------------------------------

  @doc "Coerce a request `providerId` to a positive integer, or nil (Node's falsy `!providerId`)."
  @spec normalize_provider_id(term()) :: pos_integer() | nil
  def normalize_provider_id(v) when is_integer(v) and v > 0, do: v

  def normalize_provider_id(v) when is_binary(v) do
    case Integer.parse(String.trim(v)) do
      {n, ""} when n > 0 -> n
      _ -> nil
    end
  end

  def normalize_provider_id(_), do: nil

  # ---------------------------------------------------------------------------
  # small helpers
  # ---------------------------------------------------------------------------

  defp log_and(reason, message, tag) do
    Logger.warning("#{message}: #{inspect(reason)}")
    {:error, tag}
  end

  defp truthy(true), do: true
  defp truthy("true"), do: true
  defp truthy(1), do: true
  defp truthy(_), do: false

  defp string_or_nil(v) when is_binary(v), do: v
  defp string_or_nil(_), do: nil

  defp nonblank(v, _default) when is_binary(v) and v != "", do: v
  defp nonblank(_v, default), do: default

  defp present?(v) when is_binary(v), do: String.trim(v) != ""
  defp present?(_), do: false
end
