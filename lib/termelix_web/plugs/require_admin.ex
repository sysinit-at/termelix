defmodule TermelixWeb.Plugs.RequireAdmin do
  @moduledoc """
  Gates a router scope on the admin flag of the authenticated user, so authorization is
  readable in `router.ex` instead of hiding in six duplicated `defp admin?/1` helpers.

  Runs after `TermelixWeb.Plugs.Authenticate` and reads exactly what those helpers read —
  `conn.assigns.current_user.isAdmin == true` (Node's `permissionManager.isAdmin`). No new
  notion of admin: RBAC roles are deliberately *not* consulted here.

  The ported Node surface answers with three different 403 bodies ("Not authorized",
  "Admin access required", "Admin privileges required") which the SPA and the controller
  tests match byte-for-byte, so the message is a plug option rather than a constant.

  Rejecting before the action also removes an oracle: an admin check that ran *after* input
  validation let an unauthorized caller tell "bad input" (400) from "not admin" (403).
  """
  import Plug.Conn

  @default_message "Not authorized"

  def init(opts), do: Keyword.get(opts, :message, @default_message)

  def call(%Plug.Conn{assigns: %{current_user: %{isAdmin: true}}} = conn, _message), do: conn

  # Also the (unreachable) no-`current_user` case: a scope that forgot `:authenticated`
  # must deny, not crash on a missing assign.
  def call(conn, message) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(403, Jason.encode!(%{error: message}))
    |> halt()
  end
end
