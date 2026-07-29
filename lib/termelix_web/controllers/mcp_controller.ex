defmodule TermelixWeb.McpController do
  @moduledoc """
  `POST /mcp` — Model Context Protocol over JSON-RPC 2.0, so an agent can use Termelix as a
  native tool server instead of being taught a bespoke HTTP API.

  The other half of "both, over one core". Every tool here dispatches into
  `TermelixWeb.AgentController`'s own helpers, which dispatch into `Termelix.Tmux.*`. Three
  doors — browser, CLI, MCP — one implementation, so there is nothing for them to disagree
  about when a bug is fixed in one.

  ## Scope

  Authenticated by the same API key, and gated by the same scopes as the REST door: an MCP
  client cannot reach a host the key does not name, or a verb it was not granted. The tool LIST
  is filtered by scope too, so an agent is not offered a tool it will be refused — an agent
  shown a tool it cannot use will call it, read the error as a transient fault, and retry.

  `list_hosts` carries `scope: nil` and is offered to every authenticated key, because the
  function behind it (`Termelix.Agent.hosts/1`) gates on nothing either. The gate that used to
  sit here made a `tmux:wait`-only key unable to discover the host id every other tool requires.

  What that answer contains, stated exactly: for each host the key is ALREADY scoped to, its id,
  name, folder and tmux-monitor flag, plus the key's own scopes. So it is not merely echoing the
  key — the key holds ids, and this adds names and folders. Bounded metadata about machines the
  key was deliberately granted.

  The thing keeping credentials out is the PROJECTION in `Termelix.Agent.hosts/1` — an
  `Enum.map` that names four fields, so nothing else can reach the response. Not `decrypt:
  false`, which is a DEK/cost choice and no safety property at all: per `Hosts.list_for_user/2`
  it leaves the secret columns "as stored (ciphertext envelopes or legacy plaintext)", so those
  structs may still hold a readable password. Widen that map and the gate is gone, which is why
  the field set is asserted in `mcp_controller_test.exs` rather than trusted to a comment.

  ## Transport

  Plain HTTP POST with a JSON-RPC body. No SSE stream and no session negotiation: this server
  has no server-initiated messages to push, and adding a transport for notifications nobody
  sends would be shape without substance. `tools/list` and `tools/call` are what an agent needs
  and what is implemented; anything else answers a proper JSON-RPC "method not found" rather
  than a 404, so a client can tell "wrong method" from "wrong URL".
  """
  use TermelixWeb, :controller

  alias Termelix.ApiKeys
  alias Termelix.Agent
  alias TermelixWeb.AgentParams

  @protocol_version "2024-11-05"

  @tools [
    %{
      # No scope, matching `Termelix.Agent.hosts/1` — which the REST door reaches with any
      # valid key. Gating it on `tmux:read` made a `tmux:wait`-only key — a combination the
      # scope docs call deliberate — unable to learn the host id every other tool demands, and
      # asked a key to hold a scope before it could read which scopes it holds.
      #
      # The exposure is small but real, and it is not "only what the key already carries": the
      # key names host IDS, while the answer adds each host's name, folder and tmux-monitor
      # flag. Metadata about machines this key was already granted, no credentials. See the
      # moduledoc.
      name: "list_hosts",
      scope: nil,
      description:
        "List the hosts this key may act on. Start here — every other tool needs a hostId.",
      schema: %{type: "object", properties: %{}, required: []}
    },
    %{
      name: "list_panes",
      scope: "tmux:read",
      description:
        "List every tmux pane on a host with what it is doing: idle, running, working, " <>
          "awaiting_input, or finished. `awaiting_input` means somebody is being asked a question.",
      schema: %{
        type: "object",
        properties: %{hostId: %{type: "integer", description: "Host id from list_hosts"}},
        required: ["hostId"]
      }
    },
    %{
      name: "open_session",
      scope: "tmux:write",
      description:
        "Create or attach a named tmux session on a host and return the pane to work in. " <>
          "Start here when you need somewhere to run something. Idempotent: calling it again " <>
          "returns the SAME session, so a reconnecting agent lands back where it was, and a " <>
          "human can attach to it at any time with `tmux attach -t <session>`.",
      schema: %{
        type: "object",
        properties: %{
          hostId: %{type: "integer"},
          session: %{type: "string", description: "A stable name, e.g. claude-foobar"},
          path: %{type: "string", description: "Working directory, applied only at creation"}
        },
        required: ["hostId", "session"]
      }
    },
    %{
      name: "capture_pane",
      scope: "tmux:read",
      description: "Read the last lines of a pane's screen, exactly as a human would see them.",
      schema: %{
        type: "object",
        properties: %{
          hostId: %{type: "integer"},
          paneId: %{type: "string", description: "A tmux pane id such as %3"},
          lines: %{type: "integer", description: "How many lines (default 200, max 2000)"}
        },
        required: ["hostId", "paneId"]
      }
    },
    %{
      name: "run_command",
      scope: "tmux:write",
      description:
        "Type a command into a pane and press Enter. The command runs in THAT pane, so a human " <>
          "can attach and take over mid-run. Returns immediately — use wait_for_pane to find out " <>
          "what happened.",
      schema: %{
        type: "object",
        properties: %{
          hostId: %{type: "integer"},
          paneId: %{type: "string"},
          command: %{type: "string", description: "A single line; newlines are rejected"}
        },
        required: ["hostId", "paneId", "command"]
      }
    },
    %{
      name: "send_keys",
      scope: "tmux:write",
      description:
        "Type text into a pane WITHOUT pressing Enter — for answering a prompt. Set enter=true " <>
          "to submit it.",
      schema: %{
        type: "object",
        properties: %{
          hostId: %{type: "integer"},
          paneId: %{type: "string"},
          text: %{type: "string"},
          enter: %{type: "boolean", description: "Press Enter after the text"}
        },
        required: ["hostId", "paneId", "text"]
      }
    },
    %{
      name: "wait_for_pane",
      scope: "tmux:wait",
      description:
        "Block until a pane needs attention or its command finishes. Costs nothing while it " <>
          "waits — prefer this over calling list_panes in a loop.",
      schema: %{
        type: "object",
        properties: %{
          hostId: %{type: "integer"},
          paneId: %{type: "string"},
          until: %{
            type: "array",
            items: %{
              type: "string",
              enum: ["awaiting_input", "finished", "idle", "running", "working"]
            },
            description: "Default: awaiting_input and finished"
          },
          timeoutMs: %{type: "integer", description: "Default 300000, max 900000"}
        },
        required: ["hostId", "paneId"]
      }
    }
  ]

  @doc "JSON-RPC entry point."
  def rpc(conn, params) do
    id = params["id"]

    case params["method"] do
      "initialize" -> reply(conn, id, initialize())
      "tools/list" -> reply(conn, id, %{tools: visible_tools(conn)})
      "tools/call" -> call_tool(conn, id, params["params"] || %{})
      "notifications/initialized" -> send_resp(conn, 204, "")
      "ping" -> reply(conn, id, %{})
      nil -> rpc_error(conn, id, -32_600, "Invalid Request: no method")
      method -> rpc_error(conn, id, -32_601, "Method not found: #{method}")
    end
  end

  defp initialize do
    %{
      protocolVersion: @protocol_version,
      capabilities: %{tools: %{}},
      serverInfo: %{name: "termelix", version: version()}
    }
  end

  # Filtered by scope. An agent offered a tool it will be refused will call it, read the 403 as
  # a transient fault, and retry — so the honest list is the one it can actually use.
  defp visible_tools(conn) do
    key = conn.assigns.api_key

    for tool <- @tools, offered?(key, tool) do
      %{name: tool.name, description: tool.description, inputSchema: tool.schema}
    end
  end

  # `scope: nil` means "any valid key" — the tool gates on nothing beyond authentication,
  # exactly as the REST route behind it does.
  defp offered?(_key, %{scope: nil}), do: true
  defp offered?(key, %{scope: scope}), do: ApiKeys.has_scope?(key, scope)

  defp call_tool(conn, id, %{"name" => name} = params) do
    args = params["arguments"] || %{}

    case Enum.find(@tools, &(&1.name == name)) do
      nil ->
        rpc_error(conn, id, -32_602, "Unknown tool: #{name}")

      tool ->
        if offered?(conn.assigns.api_key, tool) do
          run_tool(conn, id, name, args)
        else
          # A tool error, not a transport error: the agent should read it and adapt, not treat
          # the connection as broken.
          tool_error(conn, id, "This key lacks the #{tool.scope} scope")
        end
    end
  end

  defp call_tool(conn, id, _params), do: rpc_error(conn, id, -32_602, "Missing tool name")

  # Straight into `Termelix.Agent` — the same functions the REST door calls, and NOT the REST
  # controller's actions.
  #
  # The first version called those actions and re-wrapped what they wrote. That works under
  # `Plug.Test`, whose adapter buffers the response, and fails on a real socket where the bytes
  # are already gone: every test here passed while the live endpoint returned the bare REST body
  # and then crashed. A controller is not a core, and pretending otherwise only held up in the
  # one environment that could not tell.
  defp run_tool(conn, id, name, args) do
    key = conn.assigns.api_key
    caller = [client_ip: conn.remote_ip |> :inet.ntoa() |> to_string(), user_agent: "mcp"]

    result =
      case name do
        "list_hosts" ->
          Agent.hosts(key)

        "list_panes" ->
          Agent.panes(key, args["hostId"])

        "open_session" ->
          Agent.ensure_session(
            key,
            args["hostId"],
            to_string(args["session"] || ""),
            [start_directory: args["path"]] ++ caller
          )

        "capture_pane" ->
          Agent.capture(key, args["hostId"], args["paneId"],
            lines: AgentParams.to_int(args["lines"])
          )

        "run_command" ->
          Agent.dispatch(key, args["hostId"], args["paneId"], args["command"] || "", caller)

        "send_keys" ->
          named = if args["enter"] in [true, "true"], do: ["enter"], else: []

          # `caller` belongs here as much as on run_command — more, in fact. This is the verb
          # that answers password prompts, so an audit row without the client IP and
          # user-agent degrades the forensic record on exactly the riskiest call.
          Agent.send_keys(
            key,
            args["hostId"],
            args["paneId"],
            AgentParams.keys(args["text"], named),
            caller
          )

        "wait_for_pane" ->
          Agent.wait(key, args["hostId"], args["paneId"],
            until: AgentParams.until(args["until"]),
            timeout_ms: AgentParams.timeout(args["timeoutMs"])
          )
      end

    tool_result(conn, id, result)
  end

  # MCP's own shape for "the tool said no": a 200 carrying `isError`. An agent that gets an
  # HTTP error instead reads it as a broken connection and reconnects, rather than reading the
  # reason and adapting.
  defp tool_result(conn, id, {:ok, payload}),
    do: reply(conn, id, %{content: [text(payload)], isError: false})

  defp tool_result(conn, id, {:error, reason}),
    do: reply(conn, id, %{content: [text(%{error: Agent.message(reason)})], isError: true})

  defp text(payload), do: %{type: "text", text: Jason.encode!(payload)}

  defp reply(conn, id, result), do: json(conn, %{jsonrpc: "2.0", id: id, result: result})

  defp tool_error(conn, id, message) do
    json(conn, %{
      jsonrpc: "2.0",
      id: id,
      result: %{content: [%{type: "text", text: Jason.encode!(%{error: message})}], isError: true}
    })
  end

  defp rpc_error(conn, id, code, message),
    do: json(conn, %{jsonrpc: "2.0", id: id, error: %{code: code, message: message}})

  defp version do
    case :application.get_key(:termelix, :vsn) do
      {:ok, vsn} -> to_string(vsn)
      _ -> "0.0.0"
    end
  end
end
