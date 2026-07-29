defmodule Termelix.Ldap.EldapClient do
  @moduledoc """
  The production `Termelix.Ldap.Client` — the single place that calls OTP `:eldap`.

  It translates the port's neutral values into `:eldap`'s API: opening a (optionally
  SSL/StartTLS) connection, simple binds, and searches whose neutral filter AST
  (`Termelix.Ldap.parse_filter/1`) is converted to `:eldap` filter terms and whose result records
  are normalised back to plain `%{dn, attributes}` maps.

  TLS verifies the directory's certificate by default (`verify_peer` against the provider's
  `caCert` when configured, else the OS trust store): the service bind password and every user
  password cross this connection, so the Node route's `rejectUnauthorized: false` is NOT
  carried over. Providers that genuinely cannot present a verifiable chain opt out explicitly
  with `insecureSkipVerify` in the provider config.

  Every request is time-bounded so a wedged directory cannot pin a Bandit process per login:

    * `open/1` passes `{:timeout, config.timeout}` — per the `:eldap` docs that is "the maximum
      time in milliseconds that each server request may take", covering the connect AND every
      bind/search recv (verified against OTP 29: `do_recv` hands it to `gen_tcp`/`ssl.recv`);
    * the search opts carry a `:timeout` too — note this one is the SERVER-side SearchRequest
      `timeLimit` (RFC 4511, seconds, 0 = infinity), converted from the configured ms;
    * `start_tls/3` gets the timeout explicitly — the `/2` form defaults the phase-2 TLS
      upgrade to `:infinity` (phase 1 uses the open timeout).

  The handle returned by `open/1` pairs the `:eldap` pid with that timeout so `search/2` and
  the StartTLS upgrade can reuse it.

  This boundary is exercised against a real directory only in a deferred integration pass — CI
  has none — so `Termelix.Ldap`'s logic is covered via an injected fake client instead.
  """
  @behaviour Termelix.Ldap.Client

  @impl true
  def open(config) do
    hosts = [String.to_charlist(config.host)]
    opts = [{:port, config.port}, {:timeout, config.timeout}] ++ tls_opts(config)

    with {:ok, pid} <- :eldap.open(hosts, opts),
         {:ok, pid} <- maybe_start_tls(pid, config) do
      {:ok, {pid, config.timeout}}
    end
  end

  defp tls_opts(%{use_tls: true} = config), do: [{:ssl, true}, {:sslopts, ssl_options(config)}]
  defp tls_opts(_config), do: []

  defp maybe_start_tls(pid, %{start_tls: true, use_tls: false} = config) do
    case :eldap.start_tls(pid, ssl_options(config), config.timeout) do
      :ok ->
        {:ok, pid}

      {:error, reason} ->
        :eldap.close(pid)
        {:error, reason}
    end
  end

  defp maybe_start_tls(pid, _config), do: {:ok, pid}

  @doc false
  # The `:ssl` options for both LDAPS (`:sslopts`) and StartTLS. Verification is ON unless the
  # provider config carries `insecure_skip_verify: true` (the LDAP `insecureSkipVerify` key) —
  # the explicit escape hatch for self-signed directories that cannot build a verifiable chain.
  # Public only so the option shape is testable without a live directory.
  @spec ssl_options(map()) :: keyword()
  def ssl_options(config) do
    if Map.get(config, :insecure_skip_verify, false) do
      [verify: :verify_none]
    else
      [
        verify: :verify_peer,
        cacerts: cacerts(config),
        server_name_indication: String.to_charlist(config.host),
        customize_hostname_check: [
          match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
        ]
      ]
    end
  end

  # The provider's own CA cert (`ca_cert`, PEM) wins — that is how a directory with a private
  # CA stays verified; with none configured, fall back to the OS trust store.
  defp cacerts(config) do
    case pem_cacerts(Map.get(config, :ca_cert)) do
      [] -> system_cacerts()
      certs -> certs
    end
  end

  defp pem_cacerts(pem) when is_binary(pem) and pem != "" do
    pem
    |> :public_key.pem_decode()
    |> Enum.flat_map(fn
      {:Certificate, der, _} -> [der]
      _other -> []
    end)
  end

  defp pem_cacerts(_pem), do: []

  # `:public_key.cacerts_get/0` (OTP 25+) exposes the OS trust store. On older OTP there is no
  # portable store, and an empty `:cacerts` list fails the handshake CLOSED — the provider must
  # then supply `caCert` or set `insecureSkipVerify`, rather than silently skipping verification.
  defp system_cacerts do
    if function_exported?(:public_key, :cacerts_get, 0), do: :public_key.cacerts_get(), else: []
  end

  @impl true
  def bind({pid, _timeout}, dn, password) do
    # DN as a charlist (eldap's canonical string form); password as a binary to keep raw bytes.
    # The /3 form's client-side wait is unbounded, but the eldap process bounds the server
    # wait with the open `{:timeout, ...}` (see the moduledoc) — and `simple_bind/4`'s fourth
    # argument is CONTROLS, not a timeout, so there is no per-call timeout to pass here.
    :eldap.simple_bind(pid, String.to_charlist(dn), password)
  end

  @impl true
  def search({pid, timeout}, req) do
    case :eldap.search(pid, search_options(req, timeout)) do
      {:ok, {:eldap_search_result, entries, _referrals, _controls}} ->
        {:ok, Enum.map(entries, &normalize_entry/1)}

      {:ok, {:eldap_search_result, entries, _referrals}} ->
        {:ok, Enum.map(entries, &normalize_entry/1)}

      {:error, _reason} = err ->
        err
    end
  end

  @doc false
  # The `:eldap.search/2` option list. The `:timeout` here is the SERVER-side SearchRequest
  # `timeLimit` (RFC 4511) — seconds, 0 means infinity — so the configured milliseconds are
  # converted with a 1s floor, since 0 would mean "no limit". Public only so the option shape
  # is testable.
  @spec search_options(Termelix.Ldap.Client.search_req(), non_neg_integer()) :: keyword()
  def search_options(req, timeout_ms) do
    [
      {:base, String.to_charlist(req.base)},
      {:filter, to_eldap_filter(req.filter)},
      {:scope, scope(req.scope)},
      {:attributes, Enum.map(req.attributes, &String.to_charlist/1)},
      {:timeout, max(div(timeout_ms, 1000), 1)}
    ]
  end

  @impl true
  def close({pid, _timeout}), do: :eldap.close(pid)

  # --- translation ----------------------------------------------------------

  defp scope(:base), do: :eldap.baseObject()
  defp scope(:one), do: :eldap.singleLevel()
  defp scope(_sub), do: :eldap.wholeSubtree()

  # `and`/`or`/`not` are Elixir operators, so reach them via apply/3.
  defp to_eldap_filter({:and, list}),
    do: apply(:eldap, :and, [Enum.map(list, &to_eldap_filter/1)])

  defp to_eldap_filter({:or, list}), do: apply(:eldap, :or, [Enum.map(list, &to_eldap_filter/1)])
  defp to_eldap_filter({:not, filter}), do: apply(:eldap, :not, [to_eldap_filter(filter)])
  defp to_eldap_filter({:present, attr}), do: :eldap.present(String.to_charlist(attr))

  defp to_eldap_filter({:equal, attr, value}),
    do: :eldap.equalityMatch(String.to_charlist(attr), value)

  defp to_eldap_filter({:ge, attr, value}),
    do: :eldap.greaterOrEqual(String.to_charlist(attr), value)

  defp to_eldap_filter({:le, attr, value}),
    do: :eldap.lessOrEqual(String.to_charlist(attr), value)

  defp to_eldap_filter({:approx, attr, value}),
    do: :eldap.approxMatch(String.to_charlist(attr), value)

  defp to_eldap_filter({:substrings, attr, parts}) do
    :eldap.substrings(String.to_charlist(attr), parts)
  end

  defp normalize_entry({:eldap_entry, object_name, attributes}) do
    %{
      dn: to_string(object_name),
      attributes:
        Map.new(attributes, fn {type, values} ->
          {to_string(type), Enum.map(values, &to_string/1)}
        end)
    }
  end
end
