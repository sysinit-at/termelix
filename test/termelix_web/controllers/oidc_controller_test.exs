defmodule TermelixWeb.OidcControllerTest do
  @moduledoc """
  Coverage for the OIDC login + account-link controller. Routes are returned to the router (not
  registered in this port yet), so the actions are called directly with a prepared conn.

  The authorization-code callback is driven end-to-end with the token + userinfo HTTP calls
  stubbed through `Req.Test` (wired via the `:req_options` app env). The happy path uses an
  access-token/userinfo exchange (no `id_token`), so JWKS verification is out of the loop here —
  it is covered in `Termelix.OidcTest`.
  """
  use TermelixWeb.ConnCase, async: false

  import Plug.Conn

  alias Termelix.{Accounts, Id, Oidc, Repo, SsoProviders}
  alias Termelix.Schema.User
  alias TermelixWeb.OidcController

  @password "correct horse battery staple"
  @stub __MODULE__.ReqStub

  # --- authorize ------------------------------------------------------------

  describe "authorize" do
    test "returns auth_url/state/nonce and persists the state" do
      provider = create_provider()

      body =
        build_conn()
        |> OidcController.authorize(%{
          "providerId" => to_string(provider.id),
          "rememberMe" => "true"
        })
        |> json_response(200)

      assert body["auth_url"] =~ "client_id=cid"
      assert body["auth_url"] =~ "response_type=code"
      assert body["auth_url"] =~ "state=#{body["state"]}"
      assert is_binary(body["state"]) and body["state"] != ""
      assert is_binary(body["nonce"]) and body["nonce"] != ""

      # The flow context lives in a TTL'd ETS table now, not five rows in `settings` — that
      # table also holds every user's wrapped DEK, and authorize is unauthenticated.
      assert {:ok, ctx} = Oidc.fetch_state(body["state"])
      assert ctx.nonce == body["nonce"]
      assert ctx.remember_me == true
      assert ctx.provider_db_id == provider.id
    end

    test "404 when no provider is configured" do
      assert %{"error" => "OIDC not configured"} =
               build_conn() |> OidcController.authorize(%{}) |> json_response(404)
    end

    test "ignores spoofed X-Forwarded-Host: redirect_uri names the configured endpoint" do
      provider = create_provider()

      body =
        build_conn()
        |> put_req_header("x-forwarded-host", "attacker.tld")
        |> put_req_header("x-forwarded-proto", "https")
        |> Map.put(:host, "attacker.tld")
        |> OidcController.authorize(%{"providerId" => to_string(provider.id)})
        |> json_response(200)

      # The auth_url's redirect_uri must resolve to the configured endpoint origin,
      # never to a client-supplied host.
      query = body["auth_url"] |> URI.parse() |> Map.get(:query) |> URI.decode_query()
      expected = TermelixWeb.Endpoint.url() <> "/users/oidc/callback"
      assert query["redirect_uri"] == expected
      refute body["auth_url"] =~ "attacker.tld"

      # The same vetted callback is what the flow state hands to the code exchange.
      assert {:ok, ctx} = Oidc.fetch_state(body["state"])
      assert ctx.backend_callback == expected
    end

    test "desktopCallbackPort still yields a loopback frontend origin" do
      provider = create_provider()

      body =
        build_conn()
        |> OidcController.authorize(%{
          "providerId" => to_string(provider.id),
          "desktopCallbackPort" => "48721"
        })
        |> json_response(200)

      assert {:ok, ctx} = Oidc.fetch_state(body["state"])
      assert ctx.frontend_origin == "http://localhost:48721/oidc-callback"
    end
  end

  # --- callback -------------------------------------------------------------

  describe "callback" do
    setup do
      Application.put_env(:termelix, :req_options, plug: {Req.Test, @stub})
      on_exit(fn -> Application.delete_env(:termelix, :req_options) end)
      :ok
    end

    test "exchanges the code, provisions the first user, sets the jwt cookie, and redirects" do
      provider = create_provider()
      stub_token_and_userinfo(%{"sub" => "ext|42", "email" => "u@x.io", "name" => "Ursula"})

      state = seed_state(provider.id, "https://app.test")

      conn = build_conn() |> OidcController.callback(%{"code" => "code-1", "state" => state})

      assert conn.status == 302
      assert [location] = get_resp_header(conn, "location")
      assert location =~ "https://app.test"
      assert location =~ "success=true"
      refute location =~ "token="
      # Browser flow sets the httpOnly jwt cookie.
      assert %{"jwt" => %{value: token}} = conn.resp_cookies
      assert is_binary(token) and token != ""

      # The user now exists (first user → admin), found by the provider-scoped plaintext
      # identifier (generic-OIDC identifiers are keyed by provider — a shared `sub` across two
      # IdPs must not collide).
      user = Oidc.find_by_oidc_identifier("oidc:#{provider.id}:ext|42")
      assert user.isOidc == true
      assert user.isAdmin == true
      assert user.username == "Ursula"
    end

    test "a loopback token-callback appends ?token= instead of setting a cookie" do
      provider = create_provider()
      stub_token_and_userinfo(%{"sub" => "ext|77", "email" => "d@x.io", "name" => "Desk"})

      state = seed_state(provider.id, "http://localhost:5173/oidc-callback")

      conn = build_conn() |> OidcController.callback(%{"code" => "code-2", "state" => state})

      assert conn.status == 302
      assert [location] = get_resp_header(conn, "location")
      assert location =~ "token="
      # The token rides in the URL; the cookie is cleared (a deletion, not a real token).
      assert conn.resp_cookies["jwt"][:value] in [nil, ""]
    end

    test "400 without code/state" do
      assert %{"error" => "Code and state are required"} =
               build_conn() |> OidcController.callback(%{}) |> json_response(400)
    end

    # One atomic row replaced five independent settings keys, so "state exists but its redirect
    # URIs are missing" is no longer reachable and its distinct message is gone with it. An
    # expired state is deliberately indistinguishable from one that was never issued.
    test "400 for an unknown or expired state" do
      assert %{"error" => "Invalid state parameter"} =
               build_conn()
               |> OidcController.callback(%{"code" => "c", "state" => "nope"})
               |> json_response(400)
    end
  end

  # --- link / unlink --------------------------------------------------------

  describe "link_oidc_to_password" do
    setup do
      {:ok, admin, _} = Accounts.register_user("admin", @password)
      {:ok, target, _} = Accounts.register_user("target", @password)
      oidc_user = insert_oidc_user("oidcguy", "ext|link")
      %{admin: admin, target: target, oidc_user: oidc_user}
    end

    test "merges the OIDC identity into the password account and deletes the OIDC user", ctx do
      params = %{"oidcUserId" => ctx.oidc_user.id, "targetUsername" => "target"}

      assert %{"success" => true, "message" => message} =
               ctx.admin
               |> conn_for()
               |> OidcController.link_oidc_to_password(params)
               |> json_response(200)

      assert message =~ "oidcguy"

      merged = Accounts.get_user(ctx.target.id)
      assert merged.isOidc == true
      assert merged.oidcIdentifier == "ext|link"
      # The source OIDC-only account is removed.
      assert Accounts.get_user(ctx.oidc_user.id) == nil
    end

    # The non-admin 403 that used to live here has moved to
    # `test/termelix_web/admin_pipeline_test.exs`. It has to: authorization is now the router's
    # `:admin_access` pipeline, and these tests call the action FUNCTION directly, which bypasses
    # every plug. Left here it did not fail — it passed while a non-admin successfully performed
    # the account merge, which is worse than no test at all.
    test "requires both ids and a password-based target", ctx do
      assert %{"error" => "OIDC user ID and target username are required"} =
               ctx.admin
               |> conn_for()
               |> OidcController.link_oidc_to_password(%{})
               |> json_response(400)

      # Unknown OIDC user.
      assert %{"error" => "OIDC user not found"} =
               ctx.admin
               |> conn_for()
               |> OidcController.link_oidc_to_password(%{
                 "oidcUserId" => "missing",
                 "targetUsername" => "target"
               })
               |> json_response(404)
    end
  end

  describe "unlink_oidc_from_password" do
    setup do
      {:ok, admin, _} = Accounts.register_user("admin", @password)
      %{admin: admin}
    end

    test "removes OIDC from a dual-auth account", %{admin: admin} do
      dual = insert_dual_auth_user("dual", "ext|dual")

      assert %{"success" => true} =
               admin
               |> conn_for()
               |> OidcController.unlink_oidc_from_password(%{"userId" => dual.id})
               |> json_response(200)

      refreshed = Accounts.get_user(dual.id)
      assert refreshed.isOidc == false
      assert refreshed.oidcIdentifier == nil
    end

    test "rejects a user without a password", %{admin: admin} do
      oidc_only = insert_oidc_user("only", "ext|only")

      assert %{"error" => "Cannot unlink OIDC from a user without password authentication." <> _} =
               admin
               |> conn_for()
               |> OidcController.unlink_oidc_from_password(%{"userId" => oidc_only.id})
               |> json_response(400)
    end

    # Admin gating covered by admin_pipeline_test.exs — see the note above.
    test "requires an id", %{admin: admin} do
      assert %{"error" => "User ID is required"} =
               admin
               |> conn_for()
               |> OidcController.unlink_oidc_from_password(%{})
               |> json_response(400)
    end
  end

  # --- helpers --------------------------------------------------------------

  defp create_provider do
    SsoProviders.create(%{
      name: "Corp",
      type: "oidc",
      config:
        SsoProviders.encrypt_provider_config(%{
          "client_id" => "cid",
          "client_secret" => "sec",
          "issuer_url" => "https://idp.test",
          "authorization_url" => "https://idp.test/authorize",
          "token_url" => "https://idp.test/token",
          "userinfo_url" => "https://idp.test/userinfo"
        })
    })
  end

  defp seed_state(provider_db_id, frontend_origin) do
    state = Id.generate()

    Oidc.store_state(state,
      nonce: "nonce-#{state}",
      backend_callback: "https://app.test/users/oidc/callback",
      frontend_origin: frontend_origin,
      remember_me: false,
      provider_db_id: provider_db_id
    )

    state
  end

  defp stub_token_and_userinfo(userinfo) do
    Req.Test.stub(@stub, fn conn ->
      case conn.request_path do
        "/token" ->
          Req.Test.json(conn, %{"access_token" => "access-123", "token_type" => "bearer"})

        "/userinfo" ->
          Req.Test.json(conn, userinfo)

        _ ->
          Plug.Conn.send_resp(conn, 404, "not found")
      end
    end)
  end

  defp insert_oidc_user(username, identifier) do
    Repo.insert!(%User{
      id: Id.generate(),
      username: username,
      passwordHash: "",
      isAdmin: false,
      isOidc: true,
      oidcIdentifier: identifier,
      scopes: "openid email profile"
    })
  end

  defp insert_dual_auth_user(username, identifier) do
    Repo.insert!(%User{
      id: Id.generate(),
      username: username,
      passwordHash: "$2b$10$abcdefghijklmnopqrstuv",
      isAdmin: false,
      isOidc: true,
      oidcIdentifier: identifier,
      scopes: "openid email profile"
    })
  end

  defp conn_for(user) do
    build_conn()
    |> assign(:current_user, user)
    |> assign(:current_user_id, user.id)
  end
end
