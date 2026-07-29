defmodule TermelixWeb.TerminalControllerTest do
  @moduledoc """
  The SSH terminal WebSocket upgrade (`GET /ssh/websocket/`): the short-lived scoped `?ticket=`
  (native clients) authenticates the upgrade, salt-scoping rejects a wrong-salt/expired ticket,
  and the `jwt` cookie path still works for browsers. An account JWT is never accepted from a
  query param — only a `"ssh_ws"`-salted ticket is.

  Actions are invoked directly with a prepared upgrade `conn`: a GET carrying the RFC 6455
  headers `WebSockAdapter.upgrade/4` validates, so a successful auth reaches the `:upgraded`
  state (no `origin` header → OriginCheck allows).
  """
  use TermelixWeb.ConnCase

  alias Termelix.Accounts
  alias TermelixWeb.TerminalController

  @password "correct horse battery staple"

  setup do
    user = register_and_login("alice", @password)
    Termelix.WsTickets.reset_all()
    %{user: user}
  end

  describe "GET /ssh/websocket/ (upgrade)" do
    test "upgrades with a freshly-signed ?ticket= (native clients)", %{user: user} do
      conn = TerminalController.connect(ws_upgrade_conn(), %{"ticket" => valid_ticket(user)})

      assert conn.state == :upgraded
      assert conn.status == 101
      assert conn.halted
    end

    test "a ?ticket= upgrades exactly once (single-use); the replay gets 401", %{user: user} do
      ticket = valid_ticket(user)

      conn = TerminalController.connect(ws_upgrade_conn(), %{"ticket" => ticket})
      assert conn.state == :upgraded

      resp = TerminalController.connect(ws_upgrade_conn(), %{"ticket" => ticket})
      assert %{"error" => "Authentication required"} = json_response(resp, 401)
    end

    test "two distinct ?ticket= tickets both upgrade", %{user: user} do
      for _ <- 1..2 do
        conn = TerminalController.connect(ws_upgrade_conn(), %{"ticket" => valid_ticket(user)})
        assert conn.state == :upgraded
      end
    end

    test "rejects a ?ticket= signed with the wrong salt with 401", %{user: user} do
      # A ticket salted for any other scope can never authorize this upgrade.
      ticket =
        Phoenix.Token.sign(TermelixWeb.Endpoint, "other_ws", %{uid: user.id, jti: "j"})

      resp = TerminalController.connect(build_conn(), %{"ticket" => ticket})
      assert %{"error" => "Authentication required"} = json_response(resp, 401)
    end

    test "rejects an expired ?ticket= with 401", %{user: user} do
      # Signed an hour ago; the controller verifies with max_age: 30, so it is past its TTL.
      ticket =
        Phoenix.Token.sign(TermelixWeb.Endpoint, "ssh_ws", %{uid: user.id, jti: "j"},
          signed_at: System.system_time(:second) - 3600
        )

      resp = TerminalController.connect(build_conn(), %{"ticket" => ticket})
      assert %{"error" => "Authentication required"} = json_response(resp, 401)
    end

    test "still upgrades via the jwt cookie when no ?ticket= is present (browsers)", %{user: user} do
      conn =
        ws_upgrade_conn()
        |> Plug.Test.put_req_cookie("jwt", valid_jwt(user))
        |> TerminalController.connect(%{})

      assert conn.state == :upgraded
      assert conn.halted
    end

    test "does NOT accept an account JWT in the ?ticket= param", %{user: user} do
      # The account JWT is a session token, not an "ssh_ws" Phoenix.Token — feeding it as the
      # ticket must fail. The legacy account JWT is accepted via `?token=` (below), never `?ticket=`.
      resp = TerminalController.connect(build_conn(), %{"ticket" => valid_jwt(user)})
      assert %{"error" => "Authentication required"} = json_response(resp, 401)
    end

    test "upgrades with a legacy ?token= account JWT (upstream native/Electron clients)", %{
      user: user
    } do
      # Backward-compat fallback for upstream clients we don't control, which put the account
      # JWT in `?token=`. Must keep upgrading.
      conn = TerminalController.connect(ws_upgrade_conn(), %{"token" => valid_jwt(user)})

      assert conn.state == :upgraded
      assert conn.halted
    end

    test "rejects a pendingTOTP ?token= with 401", %{user: user} do
      # `Accounts.verify_token/1` rejects a pendingTOTP (2FA-incomplete) token, so the legacy
      # fallback denies it too.
      resp =
        TerminalController.connect(build_conn(), %{"token" => Accounts.pending_totp_token(user)})

      assert %{"error" => "Authentication required"} = json_response(resp, 401)
    end

    test "rejects an unauthenticated upgrade with 401" do
      resp = TerminalController.connect(build_conn(), %{})
      assert %{"error" => "Authentication required"} = json_response(resp, 401)
    end
  end

  # --- helpers ---------------------------------------------------------------

  defp register_and_login(username, password) do
    conn = build_conn()
    conn |> post("/users/create", %{username: username, password: password}) |> json_response(200)
    post(conn, "/users/login", %{username: username, password: password})
    Accounts.get_user_by_username(username)
  end

  # A session-bound JWT that `Accounts.verify_token/1` accepts (inserts the backing session row).
  defp valid_jwt(user) do
    {:ok, token, _session} = Accounts.create_session(user, "web", "test", 3600)
    token
  end

  # A freshly-minted single-use WS-upgrade ticket the controller's `?ticket=` path accepts
  # (30s TTL, jti consumed on first upgrade).
  defp valid_ticket(user) do
    Termelix.WsTickets.mint(user.id, "ssh")
  end

  # A GET carrying the headers `WebSockAdapter.upgrade/4` validates before it will upgrade.
  defp ws_upgrade_conn do
    conn = build_conn(:get, "/ssh/websocket/")

    %{conn | req_headers: [{"host", "www.example.com"} | conn.req_headers]}
    |> Plug.Conn.put_req_header("connection", "upgrade")
    |> Plug.Conn.put_req_header("upgrade", "websocket")
    |> Plug.Conn.put_req_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
    |> Plug.Conn.put_req_header("sec-websocket-version", "13")
  end
end
