defmodule TermelixWeb.TerminalController do
  @moduledoc """
  Authenticates and upgrades the SSH terminal WebSocket (`/ssh/websocket/`).

  Auth is resolved in order; the first source that yields a valid user wins, and only if all
  fail is the upgrade rejected with 401:

    1. `?ticket=` — the preferred, non-JWT path: a short-lived scoped `Phoenix.Token` that
       `POST /users/ws-ticket` signs with the `"ssh_ws"` salt, valid for 30s and consumed on
       first use (`Termelix.WsTickets` — a replayed ticket is rejected). Our mobile client
       uses this so the reusable account JWT stays out of the URL (its in-page WebView WebSocket
       can send neither an `Authorization` header nor a `jwt` cookie);
    2. `?token=` — a **legacy compatibility fallback**: the account JWT in the query string,
       verified via `Accounts.verify_token/1`. This server is a compatibility fork that also
       serves the upstream Termelix web/Electron frontend, whose native clients authenticate the
       terminal WS this way and which we cannot update here. JWT-in-URL is the weaker path (it
       lands in server access logs); `?ticket=` is preferred wherever the client can mint one;
    3. the `jwt` cookie (browsers), then an `Authorization: Bearer` header — resolved by
       `Authenticate.extract_token/1` and verified via `Accounts.verify_token/1`.

  The `"ssh_ws"` salt scopes the ticket to *only* this upgrade: an account JWT can never
  authorize the ticket path, and a ticket can never authorize the account API. `pendingTOTP`/
  expired session tokens are rejected by `Accounts.verify_token/1`. The `OriginCheck` still
  guards browser cross-origin upgrades.
  """
  use Phoenix.Controller, formats: [:json]
  import Plug.Conn

  alias Termelix.{Accounts, WsTickets}
  alias TermelixWeb.OriginCheck
  alias TermelixWeb.Plugs.Authenticate

  def connect(conn, params) do
    if OriginCheck.allowed?(conn) do
      do_connect(conn, params)
    else
      conn |> put_status(403) |> json(%{error: "Origin not allowed"})
    end
  end

  defp do_connect(conn, params) do
    case authenticate(conn, params) do
      {:ok, user_id} ->
        # No :timeout opt: websock_adapter would otherwise arm a 60s idle-client kill;
        # sessions have their own expiry.
        conn
        |> WebSockAdapter.upgrade(
          TermelixWeb.TerminalSocket,
          %{user_id: user_id, client: nil},
          []
        )
        |> halt()

      :error ->
        deny(conn)
    end
  end

  # Resolve a user_id for the upgrade from the first source that yields a valid user, in order:
  #   1. the short-lived scoped `?ticket=` (`"ssh_ws"` salt, 30s TTL) — preferred, non-JWT;
  #   2. `?token=` — the legacy account-JWT-in-URL fallback for upstream native/Electron clients;
  #   3. the `jwt` cookie / bearer header (browsers), verified via `Accounts.verify_token/1`.
  # Only if all fail does `do_connect/2` return 401.
  defp authenticate(conn, params) do
    with :error <- ticket_user_id(params["ticket"]),
         :error <- token_user_id(params["token"]),
         :error <- session_user_id(conn) do
      :error
    end
  end

  defp ticket_user_id(ticket) when is_binary(ticket) and ticket != "" do
    # Single-use: the first successful verify consumes the ticket's jti (see
    # `Termelix.WsTickets`), so a captured ticket cannot be replayed for a second upgrade.
    WsTickets.consume("ssh", ticket)
  end

  defp ticket_user_id(_), do: :error

  # Legacy compatibility fallback: the account JWT passed as the `?token=` query param
  # (upstream native/Electron terminal clients). `pendingTOTP`/expired tokens are rejected.
  defp token_user_id(token) when is_binary(token) and token != "" do
    case Accounts.verify_token(token) do
      {:ok, %{user: user}} -> {:ok, user.id}
      _ -> :error
    end
  end

  defp token_user_id(_), do: :error

  defp session_user_id(conn) do
    with token when is_binary(token) <- Authenticate.extract_token(conn),
         {:ok, %{user: user}} <- Accounts.verify_token(token) do
      {:ok, user.id}
    else
      _ -> :error
    end
  end

  defp deny(conn) do
    conn |> put_status(401) |> json(%{error: "Authentication required"})
  end
end
