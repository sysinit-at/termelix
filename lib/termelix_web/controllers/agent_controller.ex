defmodule TermelixWeb.AgentController do
  @moduledoc """
  The REST door onto `Termelix.Agent`.

  Deliberately thin: parse params, call the context, render. Everything that decides anything —
  scope, host scope, ownership, rate limit, audit — lives in `Termelix.Agent`, because there is
  a second door (`TermelixWeb.McpController`) and a check that lives in one door is a check the
  other one does not have.

  Every response is a small flat map with camelCase keys, and every error is
  `{"error": "..."}` with a real status. Agents parse this, and one that has to disambiguate a
  nested union will get it wrong on the path nobody tested.
  """
  use TermelixWeb, :controller

  alias Termelix.Agent

  def hosts(conn, _params), do: render_result(conn, Agent.hosts(key(conn)))

  def overview(conn, params),
    do: render_result(conn, Agent.panes(key(conn), params["hostId"]))

  def ensure_session(conn, params) do
    render_result(
      conn,
      Agent.ensure_session(
        key(conn),
        params["hostId"],
        to_string(params["session"] || ""),
        [start_directory: params["path"]] ++ caller(conn)
      )
    )
  end

  def capture(conn, params) do
    render_result(
      conn,
      Agent.capture(key(conn), params["hostId"], params["paneId"], lines: to_int(params["lines"]))
    )
  end

  def dispatch(conn, params) do
    render_result(
      conn,
      Agent.dispatch(
        key(conn),
        params["hostId"],
        params["paneId"],
        params["command"] || "",
        caller(conn)
      )
    )
  end

  def send_keys(conn, params) do
    render_result(
      conn,
      Agent.send_keys(key(conn), params["hostId"], params["paneId"], keys(params), caller(conn))
    )
  end

  def wait(conn, params) do
    render_result(
      conn,
      Agent.wait(key(conn), params["hostId"], params["paneId"],
        until: TermelixWeb.AgentParams.until(params["until"]),
        timeout_ms: TermelixWeb.AgentParams.timeout(params["timeoutMs"])
      )
    )
  end

  defp render_result(conn, {:ok, payload}), do: json(conn, Map.put(payload, :ok, true))

  defp render_result(conn, {:error, reason}) do
    conn
    |> put_status(Agent.status(reason))
    |> json(%{error: Agent.message(reason)})
  end

  defp key(conn), do: conn.assigns.api_key

  # The context has no conn, so what it needs travels explicitly. For a credential used by
  # machines, WHICH machine used it is close to the only forensic question worth asking.
  defp caller(conn) do
    [
      client_ip: conn.remote_ip |> :inet.ntoa() |> to_string(),
      user_agent: header(conn, "user-agent")
    ]
  end

  defp header(conn, name) do
    case get_req_header(conn, name) do
      [value | _] when is_binary(value) and value != "" -> value
      _ -> "api-key"
    end
  end

  defp keys(params), do: TermelixWeb.AgentParams.keys(params["text"], params["keys"])

  defp to_int(value), do: TermelixWeb.AgentParams.to_int(value)
end
