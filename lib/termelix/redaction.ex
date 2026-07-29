defmodule Termelix.Redaction do
  @moduledoc """
  The single place that decides whether a key names a secret.

  Sentry's built-in scrubber matches only `"password"`, `"passwd"` and `"secret"`, exactly
  (`deps/sentry/lib/sentry/scrubber.ex:78`), so every secret name this app actually uses —
  `key`, `keyPassword`, `sudoPassword`, `client_secret`, `token`, … — used to reach Sentry
  verbatim in the request body of any 500. `scrub_body/1` is wired as the `:body_scrubber` of
  `Sentry.PlugContext` in `lib/termelix_web/endpoint.ex`.

  Nothing here logs or inspects a value: secrets are replaced, never observed.
  """

  alias Termelix.Crypto.FieldCrypto

  @placeholder "[FILTERED]"

  # The tables of FieldCrypto's `@encrypted_fields` map (lib/termelix/crypto/field_crypto.ex:19).
  # Adding a *field* there extends the list below automatically; a new *table* has to be added
  # here too — test/termelix/redaction_test.exs cross-checks every table's fields.
  @encrypted_tables ~w(users ssh_data ssh_credentials opkssh_tokens termix_identity_ca
                       vault_tokens)

  # Secrets that never take the encrypted-column path: OIDC/LDAP client config, the bearer and
  # one-time tokens the API hands out, and the deployment env vars that unlock everything else.
  # Matching is EXACT on the normalized form (so `key` is a secret and `keyboard` is not), which
  # means a compound name has to be listed in full: `x-reauth-password` collapses to
  # `xreauthpassword`, not `password`, so it would sail past unlisted.
  @extra_secret_keys ~w(client_secret bindPassword totp_code temp_token token ticket jwt
                        DATABASE_KEY ENCRYPTION_KEY JWT_SECRET x-reauth-password)

  # Everything Sentry's own scrubbers would have caught, folded in at COMPILE TIME from its
  # constants rather than copied.
  #
  # Wiring a custom scrubber REPLACES the default outright — it does not layer on top — so a
  # hand-written list silently narrows coverage for anything the default knew and the list
  # forgot. That already happened here: `authentication` (header) and `passwd` / `secret`
  # (params) were dropped the moment these scrubbers were wired. Deriving from the source of
  # truth means adding a scrubber can only ever widen the set, and a Sentry upgrade that adds a
  # default is picked up on recompile.
  @sentry_defaults Sentry.Scrubber.default_header_keys() ++ Sentry.Scrubber.default_param_keys()

  @secret_keys @encrypted_tables
               |> Enum.flat_map(&FieldCrypto.encrypted_fields/1)
               |> Enum.concat(@extra_secret_keys)
               |> Enum.concat(@sentry_defaults)
               # Same transformation as normalize/1 below, spelled out twice because a module
               # attribute cannot call a function of the module being defined.
               |> Enum.map(&String.replace(String.downcase(&1), ~r/[^a-z0-9]/, ""))
               |> Enum.uniq()
               |> Enum.sort()

  @doc """
  Whether `key` names a secret.

  Case- and separator-insensitive: the same secret appears as `keyPassword` (Ecto/JSON) and
  `key_password` (params) across this codebase, so both collapse to one name. Comparison stays
  exact on the collapsed form — `key` is a secret, `keyboard` is not.
  """
  @spec secret_key?(term()) :: boolean()
  def secret_key?(key) when is_atom(key), do: secret_key?(Atom.to_string(key))
  def secret_key?(key) when is_binary(key), do: normalize(key) in @secret_keys
  def secret_key?(_key), do: false

  @doc """
  Request headers with every secret-named one replaced by `"#{@placeholder}"`, as a map.

  Shaped for `Sentry.PlugContext`'s `:header_scrubber`, whose default drops only
  `authorization` / `authentication` / `cookie`. That is not enough here: the admin cross-user
  export confirms the caller's own password in an `x-reauth-password` header, so a 500 anywhere
  in that request would have shipped an administrator's PLAINTEXT ACCOUNT PASSWORD to the error
  backend. Header names are matched with the same predicate as everything else, so a future
  header named after any known secret is covered without editing this function.
  """
  @spec scrub_headers(Plug.Conn.t()) :: map()
  def scrub_headers(%Plug.Conn{req_headers: headers}) do
    Map.new(headers, fn {name, value} ->
      {name, if(secret_key?(name), do: @placeholder, else: value)}
    end)
  end

  @doc """
  The request URL with every secret-named query parameter replaced by `"#{@placeholder}"`.

  Shaped for `Sentry.PlugContext`'s `:url_scrubber`, which defaults to
  `Sentry.Scrubber.scrub_url/1` — and that only knows `password`/`passwd`/`secret`. This app puts
  live credentials in the query string by design: the terminal WebSocket upgrade accepts the
  reusable account JWT as `?token=` and the scoped ticket as `?ticket=`
  (`docs/AUTH_HOST_CONTRACT.md`, `TermelixWeb.TerminalController`), because an in-WebView socket
  cannot set headers. Scrubbing only the body therefore filtered those names out of `data` and
  then shipped them to Sentry anyway in `request.url` on any 500 — Sentry derives `query_string`
  from this same URL, so fixing it here fixes both.
  """
  @spec scrub_url(Plug.Conn.t()) :: String.t()
  def scrub_url(%Plug.Conn{} = conn) do
    url = Plug.Conn.request_url(conn)

    case String.split(url, "?", parts: 2) do
      [_base] ->
        url

      [base, query] ->
        scrubbed =
          query
          |> URI.decode_query()
          |> Enum.map(fn {k, v} -> {k, if(secret_key?(k), do: @placeholder, else: v)} end)
          |> URI.encode_query()

        base <> "?" <> scrubbed
    end
  end

  @doc """
  Replaces every secret-named value with `"#{@placeholder}"`, recursing through nested maps and
  lists.

  Shaped for `Sentry.PlugContext`'s `:body_scrubber`, which passes a `%Plug.Conn{}` and takes the
  returned map as the reported request body (`deps/sentry/lib/sentry/scrubber.ex`). Any other
  term is accepted so the same function can scrub a bare payload; unknown leaves pass through.
  """
  @spec scrub_body(term()) :: term()
  def scrub_body(%Plug.Conn{params: params}), do: scrub_body(params)

  # Params are unfetched when the failure happened before Plug.Parsers ran; report nothing
  # rather than the placeholder struct.
  def scrub_body(%Plug.Conn.Unfetched{}), do: %{}

  # A struct may carry secret-named fields (Ecto schemas do), so scrub it as a map instead of
  # letting it through as an opaque leaf.
  def scrub_body(struct) when is_struct(struct), do: struct |> Map.from_struct() |> scrub_body()

  def scrub_body(map) when is_map(map) do
    Map.new(map, fn {key, value} ->
      {key, if(secret_key?(key), do: @placeholder, else: scrub_body(value))}
    end)
  end

  def scrub_body(list) when is_list(list), do: Enum.map(list, &scrub_body/1)

  # Pair lists (headers, decoded query params) carry their key in the tuple, not in a map.
  def scrub_body({key, value}) do
    {key, if(secret_key?(key), do: @placeholder, else: scrub_body(value))}
  end

  def scrub_body(other), do: other

  defp normalize(key), do: String.replace(String.downcase(key), ~r/[^a-z0-9]/, "")
end
