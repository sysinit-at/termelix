defmodule TermelixWeb.Plugs.ForceSSL do
  @moduledoc """
  Runs `Plug.SSL` from *runtime* configuration, after `TermelixWeb.Plugs.TrustedProxy` has
  established the real scheme.

  Phoenix's `:force_ssl` endpoint option installs `Plug.SSL` ahead of every plug declared in the
  endpoint, so nothing can vet `x-forwarded-proto` before it acts. It also has to be set at
  compile time, which makes the redirect and HSTS behaviour impossible to key off anything known
  only at boot. Declaring `Plug.SSL` here instead fixes both:

    * the scheme it sees has already been trust-checked, so a direct client can no longer
      suppress the redirect by asserting `x-forwarded-proto: https` (it previously could);
    * `HSTS` becomes a runtime decision, which the built-in TLS work needs — a self-signed
      certificate paired with an unconditional `Strict-Transport-Security` header can lock a
      user out of their own instance for the duration of `max-age`.

  Reads `:termelix, :force_ssl` (a `Plug.SSL` option list, or `false`/absent to disable). No
  `:rewrite_on` is passed: `TrustedProxy` already did that, under a trust check `Plug.SSL` has
  none of. `:host` defaults to the endpoint's configured host, matching what Phoenix's
  `:force_ssl` did.
  """

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    case ssl_options() do
      nil -> conn
      opts -> Plug.SSL.call(conn, opts)
    end
  end

  # `Plug.SSL.init/1` builds the HSTS header string and validates `:exclude`; it is pure and the
  # configuration cannot change at runtime, so do it once rather than per request.
  defp ssl_options do
    case :persistent_term.get({__MODULE__, :opts}, :unset) do
      :unset ->
        opts = build_options()
        :persistent_term.put({__MODULE__, :opts}, opts)
        opts

      opts ->
        opts
    end
  end

  defp build_options do
    case Application.get_env(:termelix, :force_ssl) do
      enabled when enabled in [nil, false] ->
        nil

      opts ->
        opts
        |> Keyword.delete(:rewrite_on)
        |> Keyword.put_new(:host, {TermelixWeb.Endpoint, :host, []})
        |> Plug.SSL.init()
    end
  end

  @doc false
  # Test hook: drop the memoised options so a changed configuration takes effect.
  @spec reset_cache() :: :ok
  def reset_cache do
    _ = :persistent_term.erase({__MODULE__, :opts})
    :ok
  end
end
