defmodule TermelixWeb.Plugs.ApiKeyAuth do
  @moduledoc """
  Authenticate a non-human caller by API key, and record what it is allowed to do.

  Deliberately NOT a fallback inside `Authenticate`. A JWT and an API key confer different
  authority — a JWT is the user, a key is a narrow slice of the user — and a plug that accepted
  either would leave every downstream handler responsible for remembering which one it got.
  They are separate pipelines, and the scope check below is a separate, explicit step.

  Assigns `:current_user_id` (so everything downstream keeps working unchanged) and
  `:api_key`, which is what `require_scope/2` and `require_host_scope/2` read. A request that
  arrives with a key never has `:current_user` — a key is not a session, and handlers that need
  a full user must say so.
  """
  import Plug.Conn

  alias Termelix.ApiKeys

  def init(opts), do: opts

  def call(conn, _opts) do
    case token(conn) do
      nil ->
        refuse(conn, 401, "Missing API key")

      token ->
        case ApiKeys.authenticate(token) do
          {:ok, key} ->
            conn
            |> assign(:api_key, key)
            |> assign(:current_user_id, key.userId)

          {:error, :expired} ->
            refuse(conn, 401, "API key expired")

          {:error, :invalid} ->
            refuse(conn, 401, "Invalid API key")
        end
    end
  end

  @doc """
  Halt unless the request's key carries `scope`.

  Used as `plug :require_scope, "tmux:write"` inside a controller, so the requirement sits next
  to the action rather than in a routing table someone has to cross-reference.
  """
  @spec require_scope(Plug.Conn.t(), String.t()) :: Plug.Conn.t()
  def require_scope(conn, scope) do
    if ApiKeys.has_scope?(conn.assigns.api_key, scope),
      do: conn,
      else: refuse(conn, 403, "This key lacks the #{scope} scope")
  end

  @doc """
  Halt unless the request's key may act on the host in `params["hostId"]`.

  Answers 403 for both "not in scope" and "not a host you own", and that is intentional: an
  agent key must not be usable to enumerate which host ids exist by comparing 403 with 404.
  """
  @spec require_host_scope(Plug.Conn.t(), term()) :: Plug.Conn.t()
  def require_host_scope(conn, _opts) do
    with host_id when is_integer(host_id) <- host_id(conn),
         true <- ApiKeys.allows_host?(conn.assigns.api_key, host_id) do
      assign(conn, :scoped_host_id, host_id)
    else
      _ -> refuse(conn, 403, "This key is not scoped to that host")
    end
  end

  defp host_id(conn) do
    case conn.params["hostId"] do
      id when is_integer(id) ->
        id

      id when is_binary(id) ->
        case Integer.parse(id) do
          {int, ""} -> int
          _ -> nil
        end

      _ ->
        nil
    end
  end

  # `Authorization: Bearer tmx_...`, or `X-Api-Key`. Both, because an MCP client and a shell
  # script reach for different ones and neither is wrong.
  defp token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token | _] -> String.trim(token)
      _ -> header(conn, "x-api-key")
    end
  end

  defp header(conn, name) do
    case get_req_header(conn, name) do
      [value | _] when is_binary(value) and value != "" -> String.trim(value)
      _ -> nil
    end
  end

  defp refuse(conn, status, message) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(%{error: message}))
    |> halt()
  end
end
