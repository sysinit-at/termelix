defmodule Termelix.Ldap.EldapClientTest do
  @moduledoc """
  Option-shape coverage for the production `:eldap` boundary, plus one local-socket
  integration test: certificate verification ON by default (system store or the provider's
  `caCert`), the `insecureSkipVerify` opt-out, and a real deadline on binds and searches —
  proven against a TCP server that accepts the connection but never answers.
  """
  use ExUnit.Case, async: true

  alias Termelix.Ldap.EldapClient

  describe "ssl_options/1" do
    test "verifies peers against the OS trust store by default" do
      opts = EldapClient.ssl_options(%{host: "ldap.example.com"})

      assert opts[:verify] == :verify_peer
      assert opts[:server_name_indication] == ~c"ldap.example.com"
      assert [match_fun: match_fun] = opts[:customize_hostname_check]
      assert is_function(match_fun, 2)

      if function_exported?(:public_key, :cacerts_get, 0) do
        assert opts[:cacerts] == :public_key.cacerts_get()
      else
        # OTP < 25 fails closed: no portable store, no silent verify_none fallback.
        assert opts[:cacerts] == []
      end
    end

    test "a configured caCert is used instead of the OS store" do
      der = :crypto.strong_rand_bytes(64)
      pem = :public_key.pem_encode([{:Certificate, der, :not_encrypted}])

      opts = EldapClient.ssl_options(%{host: "ldap.example.com", ca_cert: pem})

      assert opts[:verify] == :verify_peer
      assert opts[:cacerts] == [der]
    end

    test "insecureSkipVerify is the explicit verification opt-out" do
      assert EldapClient.ssl_options(%{host: "ldap.example.com", insecure_skip_verify: true}) ==
               [verify: :verify_none]
    end
  end

  describe "search_options/2" do
    test "carries the server-side timeLimit (seconds) alongside the translated request" do
      req = %{
        base: "ou=people,dc=example,dc=com",
        filter: {:equal, "uid", "alice"},
        attributes: ["uid", "cn"],
        scope: :sub
      }

      opts = EldapClient.search_options(req, 10_000)

      # RFC 4511 timeLimit: seconds, never 0 (which would mean infinity).
      assert opts[:timeout] == 10
      assert opts[:base] == ~c"ou=people,dc=example,dc=com"
      assert opts[:attributes] == [~c"uid", ~c"cn"]
      assert opts[:filter] == :eldap.equalityMatch(~c"uid", "alice")
      assert opts[:scope] == :eldap.wholeSubtree()

      # Sub-second timeouts round up rather than down to 0 (= infinity).
      assert EldapClient.search_options(req, 500)[:timeout] == 1
    end
  end

  describe "a wedged directory (accepts, never answers)" do
    @timeout_ms 500

    setup do
      {:ok, listen} = :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])
      {:ok, port} = :inet.port(listen)
      test_pid = self()

      # Hold the accepted socket open without ever sending an LDAP reply, until the test
      # process exits (monitored) or a generous backstop fires.
      holder =
        spawn_link(fn ->
          {:ok, sock} = :gen_tcp.accept(listen)
          send(test_pid, :accepted)
          ref = Process.monitor(test_pid)

          receive do
            {:DOWN, ^ref, :process, ^test_pid, _} -> :ok
          after
            30_000 -> :ok
          end

          :gen_tcp.close(sock)
        end)

      config = %{
        host: "127.0.0.1",
        port: port,
        timeout: @timeout_ms,
        use_tls: false,
        start_tls: false
      }

      {:ok, handle} = EldapClient.open(config)
      assert_receive :accepted, 2_000

      on_exit(fn ->
        EldapClient.close(handle)
        :gen_tcp.close(listen)
        if Process.alive?(holder), do: Process.exit(holder, :kill)
      end)

      %{handle: handle}
    end

    test "bind fails within the configured timeout instead of pinning forever", %{
      handle: handle
    } do
      started = System.monotonic_time(:millisecond)

      assert {:error, {:gen_tcp_error, :timeout}} = EldapClient.bind(handle, "cn=x", "pw")

      assert System.monotonic_time(:millisecond) - started < 5 * @timeout_ms
    end

    test "search fails within the configured timeout instead of pinning forever", %{
      handle: handle
    } do
      req = %{base: "dc=x", filter: {:present, "uid"}, attributes: ["uid"], scope: :sub}
      started = System.monotonic_time(:millisecond)

      assert {:error, {:gen_tcp_error, :timeout}} = EldapClient.search(handle, req)

      assert System.monotonic_time(:millisecond) - started < 5 * @timeout_ms
    end
  end
end
