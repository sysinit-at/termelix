defmodule TermelixWeb.McpControllerTest do
  @moduledoc """
  MCP is the door an agent walks through without being taught anything, so the properties that
  matter are the ones an agent depends on: a tool list it can trust, errors it can read, and
  the same scope boundaries as every other door.
  """
  use TermelixWeb.ConnCase, async: false

  alias Termelix.{Accounts, ApiKeys, Hosts}

  setup do
    {:ok, user, _} = Accounts.register_user("mcp-#{unique()}", "password-123-abc")

    {:ok, host} =
      Hosts.create_host(user.id, %{
        name: "mcp-host",
        ip: "127.0.0.1",
        port: 22,
        username: "tester",
        authType: "password",
        password: "secret",
        enableTmuxMonitor: true
      })

    {:ok, _k, read} =
      ApiKeys.create(user.id, %{name: "r", scopes: ["tmux:read"], host_ids: [host.id]})

    {:ok, _k, full} =
      ApiKeys.create(user.id, %{
        name: "f",
        scopes: ["tmux:read", "tmux:write", "tmux:wait"],
        host_ids: [host.id]
      })

    {:ok, _k, wait_only} =
      ApiKeys.create(user.id, %{name: "w", scopes: ["tmux:wait"], host_ids: [host.id]})

    %{user: user, host: host, read: read, full: full, wait_only: wait_only}
  end

  defp unique, do: System.unique_integer([:positive])

  defp rpc(token, method, params \\ nil, id \\ 1) do
    body = %{jsonrpc: "2.0", id: id, method: method}
    body = if params, do: Map.put(body, :params, params), else: body

    build_conn()
    |> put_req_header("authorization", "Bearer #{token}")
    |> put_req_header("content-type", "application/json")
    |> post("/mcp", Jason.encode!(body))
  end

  describe "handshake" do
    test "initialize advertises tools and a protocol version", ctx do
      body = rpc(ctx.full, "initialize") |> json_response(200)

      assert body["jsonrpc"] == "2.0"
      assert body["id"] == 1
      assert body["result"]["protocolVersion"]
      assert body["result"]["capabilities"]["tools"]
      assert body["result"]["serverInfo"]["name"] == "termelix"
    end

    test "an unknown method is a JSON-RPC error, not a 404", ctx do
      # A client must be able to tell "this server does not implement that" from "wrong URL".
      body = rpc(ctx.full, "resources/list") |> json_response(200)
      assert body["error"]["code"] == -32_601
      assert body["error"]["message"] =~ "resources/list"
    end

    test "no key is 401 before any JSON-RPC parsing happens" do
      conn =
        build_conn()
        |> put_req_header("content-type", "application/json")
        |> post("/mcp", Jason.encode!(%{jsonrpc: "2.0", id: 1, method: "initialize"}))

      assert json_response(conn, 401)
    end
  end

  describe "tools/list is filtered by scope" do
    test "a read-only key is not shown the write tools", ctx do
      tools = rpc(ctx.read, "tools/list") |> json_response(200) |> get_in(["result", "tools"])
      names = Enum.map(tools, & &1["name"])

      assert "list_hosts" in names
      assert "list_panes" in names
      assert "capture_pane" in names

      # An agent offered a tool it will be refused will call it, read the error as a transient
      # fault, and retry. The honest list is the one it can actually use.
      refute "run_command" in names
      refute "send_keys" in names
      refute "wait_for_pane" in names
    end

    test "a full key sees all of them", ctx do
      tools = rpc(ctx.full, "tools/list") |> json_response(200) |> get_in(["result", "tools"])
      assert length(tools) == 7
    end

    test "list_hosts is offered to every key, including one with no read scope", ctx do
      # `tmux:wait` is separate from `tmux:read` on purpose, so a wait-only key is a supported
      # configuration — and it needs a hostId for the one verb it CAN use. Gating list_hosts on
      # tmux:read left such a key unable to discover the ids it was granted, while the REST
      # door (`Termelix.Agent.hosts/1`, which gates on nothing) answered the same key normally.
      names =
        rpc(ctx.wait_only, "tools/list")
        |> json_response(200)
        |> get_in(["result", "tools"])
        |> Enum.map(& &1["name"])

      assert "list_hosts" in names
      assert "wait_for_pane" in names
      # Everything it genuinely lacks is still withheld.
      refute "list_panes" in names
      refute "capture_pane" in names
      refute "run_command" in names
      refute "send_keys" in names
    end

    test "every tool ships a usable input schema", ctx do
      tools = rpc(ctx.full, "tools/list") |> json_response(200) |> get_in(["result", "tools"])

      for tool <- tools do
        assert tool["description"] != "", "#{tool["name"]} has no description"
        assert tool["inputSchema"]["type"] == "object"
        assert is_map(tool["inputSchema"]["properties"])
      end
    end
  end

  describe "tools/call" do
    test "list_hosts returns only the key's hosts", ctx do
      body =
        rpc(ctx.read, "tools/call", %{name: "list_hosts", arguments: %{}}) |> json_response(200)

      refute body["result"]["isError"]
      [%{"type" => "text", "text" => text}] = body["result"]["content"]

      payload = Jason.decode!(text)
      assert [%{"name" => "mcp-host"}] = payload["hosts"]
    end

    test "a wait-only key can actually call list_hosts and learn its host ids", ctx do
      # The other half of the same defect: being offered the tool is useless if dispatch
      # refuses it. Both gates read the same table, so both had to change.
      body =
        rpc(ctx.wait_only, "tools/call", %{name: "list_hosts", arguments: %{}})
        |> json_response(200)

      refute body["result"]["isError"]
      [%{"text" => text}] = body["result"]["content"]
      payload = Jason.decode!(text)

      assert [%{"name" => "mcp-host", "id" => id} = host] = payload["hosts"]
      assert id == ctx.host.id
      assert payload["scopes"] == ["tmux:wait"]

      # Pin the exposure, since removing the scope gate is only defensible if this stays
      # bounded. Four fields about a host the key was already granted, and no credential —
      # not "only what the key already carries", which would be wrong: the key names ids, and
      # this adds the name and folder.
      assert Map.keys(host) |> Enum.sort() == ["folder", "id", "name", "tmuxMonitor"]

      for secret <- ~w(password key keyPassword username ip port authType) do
        refute Map.has_key?(host, secret), "list_hosts leaked #{secret}"
      end
    end

    test "a scope it really lacks is still refused at dispatch", ctx do
      body =
        rpc(ctx.wait_only, "tools/call", %{
          name: "list_panes",
          arguments: %{hostId: ctx.host.id}
        })
        |> json_response(200)

      assert body["result"]["isError"]
      [%{"text" => text}] = body["result"]["content"]
      assert text =~ "tmux:read"
    end

    test "calling a tool outside the key's scope is a TOOL error, not a transport error", ctx do
      body =
        rpc(ctx.read, "tools/call", %{
          name: "run_command",
          arguments: %{hostId: ctx.host.id, paneId: "%1", command: "ls"}
        })
        |> json_response(200)

      # `isError` on the result, and a 200 on the wire: the agent should read this and adapt,
      # not treat the connection as broken and reconnect.
      assert body["result"]["isError"]
      refute body["error"]
      [%{"text" => text}] = body["result"]["content"]
      assert text =~ "tmux:write"
    end

    test "a host outside the key's scope is refused through MCP too", ctx do
      {:ok, other, _} = Accounts.register_user("mcp-o-#{unique()}", "password-123-abc")

      {:ok, foreign} =
        Hosts.create_host(other.id, %{
          name: "foreign",
          ip: "127.0.0.1",
          port: 22,
          username: "t",
          authType: "password",
          password: "s"
        })

      body =
        rpc(ctx.read, "tools/call", %{name: "list_panes", arguments: %{hostId: foreign.id}})
        |> json_response(200)

      assert body["result"]["isError"]
    end

    test "an unknown tool is a JSON-RPC error", ctx do
      body =
        rpc(ctx.full, "tools/call", %{name: "rm_rf", arguments: %{}}) |> json_response(200)

      assert body["error"]["code"] == -32_602
    end

    test "the request id is echoed, so a client can match replies", ctx do
      body = rpc(ctx.full, "initialize", nil, 4242) |> json_response(200)
      assert body["id"] == 4242
    end
  end
end
