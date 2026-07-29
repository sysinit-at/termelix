defmodule TermelixWeb.AgentControllerTest do
  @moduledoc """
  The agent surface, and above all what a key must NOT be able to do.

  A scoped credential is only worth something if every widening is closed: a key must not reach
  a host it does not name, a host its owner does not own, a verb it was not granted, or any of
  the human-only surface. Each of those is a separate test here, because each is a separate
  mistake someone could make later — and a key that quietly works everywhere is
  indistinguishable from a key that works correctly until the day it matters.
  """
  use TermelixWeb.ConnCase, async: false

  alias Termelix.{Accounts, ApiKeys, Hosts}

  setup do
    {:ok, user, _} = Accounts.register_user("agent-#{unique()}", "password-123-abc")
    {:ok, other, _} = Accounts.register_user("agent-o-#{unique()}", "password-123-abc")

    {:ok, host} = create_host(user.id, "in-scope")
    {:ok, unscoped} = create_host(user.id, "not-in-scope")
    {:ok, foreign} = create_host(other.id, "someone-elses")

    {:ok, _key, read_token} =
      ApiKeys.create(user.id, %{name: "reader", scopes: ["tmux:read"], host_ids: [host.id]})

    {:ok, _key, write_token} =
      ApiKeys.create(user.id, %{
        name: "writer",
        scopes: ["tmux:read", "tmux:write"],
        host_ids: [host.id]
      })

    %{
      user: user,
      host: host,
      unscoped: unscoped,
      foreign: foreign,
      read_token: read_token,
      write_token: write_token
    }
  end

  defp unique, do: System.unique_integer([:positive])

  defp create_host(user_id, name) do
    Hosts.create_host(user_id, %{
      name: name,
      ip: "127.0.0.1",
      port: 22,
      username: "tester",
      authType: "password",
      password: "secret",
      enableTmuxMonitor: true
    })
  end

  defp with_key(token), do: put_req_header(build_conn(), "authorization", "Bearer #{token}")

  describe "authentication" do
    test "no key is 401" do
      assert build_conn() |> get("/agent/hosts") |> json_response(401)
    end

    test "a bad key is 401, and says nothing about which part was wrong" do
      body = with_key("tmx_nope") |> get("/agent/hosts") |> json_response(401)
      assert body["error"] == "Invalid API key"
    end

    test "the X-Api-Key header works too — a shell script and an MCP client reach for
          different ones and neither is wrong",
         ctx do
      assert build_conn()
             |> put_req_header("x-api-key", ctx.read_token)
             |> get("/agent/hosts")
             |> json_response(200)
    end

    test "an expired key is refused, and SAYS it expired", ctx do
      past = DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.to_iso8601()

      {:ok, _key, token} =
        ApiKeys.create(ctx.user.id, %{
          name: "stale",
          scopes: ["tmux:read"],
          host_ids: [ctx.host.id],
          expires_at: past
        })

      body = with_key(token) |> get("/agent/hosts") |> json_response(401)
      # Distinct from "invalid": conflating them sends whoever is debugging the agent looking
      # for a typo.
      assert body["error"] =~ "expired"
    end
  end

  describe "host scope — the boundary the whole feature rests on" do
    test "a key sees only the hosts it names", ctx do
      body = with_key(ctx.read_token) |> get("/agent/hosts") |> json_response(200)

      names = Enum.map(body["hosts"], & &1["name"])
      assert names == ["in-scope"]
      refute "not-in-scope" in names
      refute "someone-elses" in names
    end

    test "the host list is a four-field projection, and that is the only thing keeping
          credentials out of it",
         ctx do
      # `Termelix.Agent.hosts/1` reads rows with `decrypt: false`, which is a DEK/cost choice
      # and NOT a safety property: `Hosts.list_for_user/2` documents it as leaving secret
      # columns "as stored (ciphertext envelopes or legacy plaintext)". So the struct behind
      # this call may well hold a readable password, and the only reason none reaches the wire
      # is the explicit map. Widen it and the guarantee is gone silently — hence this test, on
      # both doors (see mcp_controller_test.exs for the MCP half).
      body = with_key(ctx.read_token) |> get("/agent/hosts") |> json_response(200)

      assert [host] = body["hosts"]
      assert Map.keys(host) |> Enum.sort() == ["folder", "id", "name", "tmuxMonitor"]

      for secret <- ~w(password key keyPassword username ip port authType) do
        refute Map.has_key?(host, secret), "GET /agent/hosts leaked #{secret}"
      end
    end

    test "a host the key does not name is refused", ctx do
      assert with_key(ctx.read_token)
             |> get("/agent/hosts/#{ctx.unscoped.id}/panes")
             |> json_response(403)
    end

    test "another user's host is refused with the SAME status as an out-of-scope one", ctx do
      # Both 403, deliberately. Different statuses would let a key enumerate which host ids
      # exist by comparing the answers.
      assert with_key(ctx.read_token)
             |> get("/agent/hosts/#{ctx.foreign.id}/panes")
             |> json_response(403)

      assert with_key(ctx.read_token)
             |> get("/agent/hosts/999999/panes")
             |> json_response(403)
    end

    test "a key cannot be created naming someone else's host", ctx do
      # Refused, not silently narrowed: quietly issuing a key that does less than asked is how
      # an automation gets debugged for an hour before anyone looks at the key.
      assert {:error, {:hosts_not_owned, [id]}} =
               ApiKeys.create(ctx.user.id, %{
                 name: "sneaky",
                 scopes: ["tmux:read"],
                 host_ids: [ctx.foreign.id]
               })

      assert id == ctx.foreign.id
    end
  end

  describe "verb scope" do
    test "a read key cannot dispatch", ctx do
      body =
        with_key(ctx.read_token)
        |> post("/agent/hosts/#{ctx.host.id}/dispatch", %{paneId: "%1", command: "ls"})
        |> json_response(403)

      assert body["error"] =~ "tmux:write"
    end

    test "a read key cannot send keys", ctx do
      assert with_key(ctx.read_token)
             |> post("/agent/hosts/#{ctx.host.id}/send-keys", %{paneId: "%1", text: "y"})
             |> json_response(403)
    end

    test "a write key still cannot wait — that is its own scope", ctx do
      # A wait holds a connection for minutes. Handing that out is a resource decision, not a
      # data-access one, so it is not implied by read or write.
      assert with_key(ctx.write_token)
             |> post("/agent/hosts/#{ctx.host.id}/wait", %{paneId: "%1"})
             |> json_response(403)
    end

    test "an unknown scope cannot be granted at all", ctx do
      assert {:error, {:unknown_scopes, ["hosts:write"]}} =
               ApiKeys.create(ctx.user.id, %{
                 name: "too much",
                 scopes: ["hosts:write"],
                 host_ids: [ctx.host.id]
               })
    end

    test "a key with no scopes is refused at creation, not left useless", ctx do
      assert {:error, :scopes_required} =
               ApiKeys.create(ctx.user.id, %{name: "empty", scopes: [], host_ids: [ctx.host.id]})
    end
  end

  describe "the human-only surface stays human-only" do
    test "an API key cannot mint another API key", ctx do
      # If it could, every scope boundary would be decorative: a narrow key would simply issue
      # itself a broad one.
      assert with_key(ctx.write_token)
             |> post("/api-keys", %{name: "escalated", scopes: ["tmux:write"]})
             |> json_response(401)
    end

    test "an API key cannot read hosts through the human API", ctx do
      assert with_key(ctx.read_token) |> get("/host/db/host") |> json_response(401)
    end

    test "an API key cannot reach the admin surface", ctx do
      assert with_key(ctx.write_token) |> get("/audit-logs") |> json_response(401)
    end
  end

  describe "revocation reaches API keys" do
    test "a revoked user's key stops working", ctx do
      # The surface that would have made the other four pointless. A key is long-lived by
      # design and carries no session, so stopping a user's terminals, tunnels, pooled
      # connections and watchers left the one credential that can re-open all of it working.
      assert with_key(ctx.read_token) |> get("/agent/hosts") |> json_response(200)

      assert %{keys: keys} = Termelix.Revocation.revoke_user(ctx.user.id, :test)
      assert keys >= 1

      assert with_key(ctx.read_token) |> get("/agent/hosts") |> json_response(401)
    end

    test "the key ROW survives, so the audit trail still explains what it did", ctx do
      Termelix.Revocation.revoke_user(ctx.user.id, :test)

      # Deactivated, not deleted: the row is the link between an action in the audit log and
      # the credential that took it, and destroying it erases what a revocation most needs to
      # explain afterwards.
      keys = ApiKeys.list_for_user(ctx.user.id)
      assert keys != []
      assert Enum.all?(keys, &(&1.isActive == false))
    end

    test "one user's revocation does not touch another's keys", ctx do
      {:ok, other, _} = Accounts.register_user("rev-k-#{unique()}", "password-123-abc")
      {:ok, other_host} = create_host(other.id, "theirs")

      {:ok, _k, other_token} =
        ApiKeys.create(other.id, %{
          name: "theirs",
          scopes: ["tmux:read"],
          host_ids: [other_host.id]
        })

      Termelix.Revocation.revoke_user(ctx.user.id, :test)

      assert with_key(other_token) |> get("/agent/hosts") |> json_response(200)
    end
  end

  describe "concurrent waits are bounded" do
    test "a ninth simultaneous wait is refused rather than pinning another connection", ctx do
      # A wait holds a connection for up to fifteen minutes and is exempt from the per-host
      # command budget, so without this it had NO bound: an agent in a loop pins one Bandit
      # process per call, indefinitely.
      {:ok, _k, token} =
        ApiKeys.create(ctx.user.id, %{
          name: "waiter",
          scopes: ["tmux:wait"],
          host_ids: [ctx.host.id]
        })

      key = ApiKeys.list_for_user(ctx.user.id) |> Enum.find(&(&1.name == "waiter"))
      Termelix.Agent.ensure_wait_table()

      # Hold the cap directly rather than opening eight real connections: the property is the
      # counter, and eight held HTTP requests would make this a slow test of Bandit.
      :ets.insert(:termelix_agent_waits, {ctx.user.id, 8})
      on_exit(fn -> :ets.delete(:termelix_agent_waits, ctx.user.id) end)

      assert {:error, :too_many_waits} =
               Termelix.Agent.wait(key, ctx.host.id, "%1", timeout_ms: 100)

      assert Termelix.Agent.status(:too_many_waits) == 429

      # And the slot is given back, so a finished wait does not leak the budget.
      :ets.insert(:termelix_agent_waits, {ctx.user.id, 0})
      Termelix.Agent.wait(key, ctx.host.id, "%1", timeout_ms: 100)
      assert [{_, 0}] = :ets.lookup(:termelix_agent_waits, ctx.user.id)
    end
  end

  describe "key lifecycle" do
    test "the token is returned exactly once and never again", ctx do
      conn = login_conn(ctx.user)

      created =
        conn
        |> post("/api-keys", %{name: "once", scopes: ["tmux:read"], hostIds: [ctx.host.id]})
        |> json_response(200)

      assert String.starts_with?(created["token"], "tmx_")
      assert created["warning"] =~ "once"

      listed = login_conn(ctx.user) |> get("/api-keys") |> json_response(200)
      key = Enum.find(listed["keys"], &(&1["name"] == "once"))

      assert key
      # The prefix, so a human can tell keys apart — and nothing that could be replayed.
      assert key["keyPrefix"]
      refute Map.has_key?(key, "token")
      refute Map.has_key?(key, "keyHash")
    end

    test "a deleted key stops working immediately", ctx do
      {:ok, key, token} =
        ApiKeys.create(ctx.user.id, %{
          name: "doomed",
          scopes: ["tmux:read"],
          host_ids: [ctx.host.id]
        })

      assert with_key(token) |> get("/agent/hosts") |> json_response(200)
      :ok = ApiKeys.delete(ctx.user.id, key.id)
      assert with_key(token) |> get("/agent/hosts") |> json_response(401)
    end

    test "one user cannot delete another user's key", ctx do
      {:ok, key, token} =
        ApiKeys.create(ctx.user.id, %{
          name: "mine",
          scopes: ["tmux:read"],
          host_ids: [ctx.host.id]
        })

      {:ok, thief, _} = Accounts.register_user("thief-#{unique()}", "password-123-abc")
      :ok = ApiKeys.delete(thief.id, key.id)

      # Still works: the delete was scoped to the caller and matched nothing.
      assert with_key(token) |> get("/agent/hosts") |> json_response(200)
    end
  end

  # A real login, because these tests are about the boundary between the two credential kinds
  # and a hand-minted token would not exercise it.
  defp login_conn(user) do
    login =
      post(build_conn(), "/users/login", %{
        username: user.username,
        password: "password-123-abc"
      })

    %{"jwt" => %{value: token}} = login.resp_cookies
    put_req_header(build_conn(), "authorization", "Bearer #{token}")
  end
end
