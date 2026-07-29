defmodule TermelixWeb.UserControllerTest do
  @moduledoc """
  The `POST /users/ws-ticket` mint endpoint: an authenticated request returns a short-lived,
  scoped `Phoenix.Token` for the SSH terminal (`ssh`) WebSocket upgrade. An unknown scope is
  rejected with 400, and the endpoint requires authentication.

  Happy-path/bad-scope actions are invoked directly with a prepared `conn`; the auth-required
  case hits the real route so the `Authenticate` plug runs.
  """
  use TermelixWeb.ConnCase

  alias Termelix.Accounts
  alias TermelixWeb.UserController

  @password "correct horse battery staple"

  setup do
    user = register_and_login("alice", @password)
    %{user: user}
  end

  describe "POST /users/ws-ticket" do
    test "mints an ssh-scoped ticket that verifies under the ssh_ws salt", %{user: user} do
      resp = UserController.ws_ticket(authed(user), %{"scope" => "ssh"})

      assert %{"ticket" => ticket} = json_response(resp, 200)
      assert is_binary(ticket) and ticket != ""

      # The payload carries the user id plus the random jti `Termelix.WsTickets.consume/2`
      # burns on first use (single-use).
      assert {:ok, %{uid: uid, jti: jti}} =
               Phoenix.Token.verify(TermelixWeb.Endpoint, "ssh_ws", ticket, max_age: 30)

      assert uid == user.id
      assert is_binary(jti) and jti != ""

      # Scoping: the ssh ticket must NOT verify under any other salt.
      assert {:error, _} =
               Phoenix.Token.verify(TermelixWeb.Endpoint, "other_ws", ticket, max_age: 30)
    end

    # `docker` was a mintable scope until the Docker console was removed. A stale client still
    # asking for it must be refused rather than handed a ticket for a socket that is gone.
    test "400 for the retired docker scope", %{user: user} do
      assert %{"error" => _} =
               UserController.ws_ticket(authed(user), %{"scope" => "docker"})
               |> json_response(400)
    end

    test "400 for an unknown scope", %{user: user} do
      assert %{"error" => _} =
               UserController.ws_ticket(authed(user), %{"scope" => "bogus"})
               |> json_response(400)

      assert %{"error" => _} =
               UserController.ws_ticket(authed(user), %{}) |> json_response(400)
    end

    test "requires authentication (401 without a token)" do
      resp = post(build_conn(), "/users/ws-ticket", %{scope: "ssh"})
      assert %{"error" => _} = json_response(resp, 401)
    end
  end

  # --- helpers ---------------------------------------------------------------

  defp register_and_login(username, password) do
    conn = build_conn()
    conn |> post("/users/create", %{username: username, password: password}) |> json_response(200)
    post(conn, "/users/login", %{username: username, password: password})
    Accounts.get_user_by_username(username)
  end

  defp authed(user) do
    build_conn()
    |> Plug.Conn.assign(:current_user_id, user.id)
    |> Plug.Conn.assign(:current_user, user)
  end
end
