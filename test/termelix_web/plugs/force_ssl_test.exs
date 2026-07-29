defmodule TermelixWeb.Plugs.ForceSSLTest do
  @moduledoc """
  `ForceSSL` composed with `TrustedProxy`, which is the only order it is ever used in.

  The point of moving off Phoenix's compile-time `:force_ssl` is that the redirect decision now
  runs *after* the scheme has been trust-checked, so a direct client can no longer suppress the
  HTTPS redirect by asserting `x-forwarded-proto: https`. That is the first test below.
  """
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  alias TermelixWeb.Plugs.{ForceSSL, TrustedProxy}

  setup do
    previous_proxies = Application.get_env(:termelix, :trusted_proxies)
    previous_ssl = Application.get_env(:termelix, :force_ssl)

    Application.put_env(:termelix, :trusted_proxies, "10.0.0.0/8")
    Application.put_env(:termelix, :force_ssl, exclude: [hosts: ["localhost", "127.0.0.1"]])
    TrustedProxy.reset_cache()
    ForceSSL.reset_cache()

    on_exit(fn ->
      restore(:trusted_proxies, previous_proxies)
      restore(:force_ssl, previous_ssl)
      TrustedProxy.reset_cache()
      ForceSSL.reset_cache()
    end)

    :ok
  end

  defp restore(key, nil), do: Application.delete_env(:termelix, key)
  defp restore(key, value), do: Application.put_env(:termelix, key, value)

  defp request(peer, host, headers) do
    headers
    |> Enum.reduce(%{conn(:get, "/version") | remote_ip: peer, host: host}, fn {k, v}, conn ->
      put_req_header(conn, k, v)
    end)
    |> TrustedProxy.call([])
    |> ForceSSL.call([])
  end

  test "a direct client cannot suppress the redirect by asserting x-forwarded-proto" do
    conn = request({100, 64, 0, 9}, "termelix.example.com", [{"x-forwarded-proto", "https"}])

    assert conn.status == 301
    assert conn.halted
  end

  test "a plain request from a direct client is redirected to https" do
    conn = request({100, 64, 0, 9}, "termelix.example.com", [])

    assert conn.status == 301
    assert conn.halted
  end

  test "a trusted proxy's https request passes through and gets HSTS" do
    conn = request({10, 23, 56, 5}, "termelix.example.com", [{"x-forwarded-proto", "https"}])

    refute conn.halted
    assert get_resp_header(conn, "strict-transport-security") != []
  end

  # The deployment's actual shape: the endpoint binds an IPv6 socket, so the proxy at 10.23.56.5
  # arrives as ::ffff:10.23.56.5. If that is not collapsed before the trust check, this request is
  # redirected to https, the proxy follows it back in, and the site sits in a redirect loop — while
  # the healthcheck below keeps passing, because it uses the excluded `localhost` host.
  test "a trusted proxy arriving IPv4-mapped is not redirected" do
    conn =
      request({0, 0, 0, 0, 0, 0xFFFF, 0x0A17, 0x3805}, "termelix.example.com", [
        {"x-forwarded-proto", "https"}
      ])

    refute conn.halted
    assert conn.status == nil
  end

  test "the excluded healthcheck host is not redirected" do
    conn = request({127, 0, 0, 1}, "localhost", [])

    refute conn.halted
    assert conn.status == nil
  end

  test "no configuration means the plug does nothing" do
    Application.delete_env(:termelix, :force_ssl)
    ForceSSL.reset_cache()

    conn = request({100, 64, 0, 9}, "termelix.example.com", [])

    refute conn.halted
    assert conn.status == nil
  end
end
