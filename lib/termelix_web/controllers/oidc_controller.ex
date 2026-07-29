defmodule TermelixWeb.OidcController do
  @moduledoc """
  Ports the OIDC/SSO login endpoints and account-link routes (`users.ts` `/users/oidc/*` and
  `user-oidc-account-routes.ts`).

  `authorize/2` returns `{auth_url, state, nonce}` for the browser to redirect to; `callback/2`
  performs the authorization-code exchange, resolves userinfo, finds-or-creates the user, then
  mints a real session and either sets the `jwt` cookie and redirects (browser) or appends
  `?token=` to the redirect (desktop/mobile token-callbacks) — the exact session + cookie
  semantics of `UserController.issue_session` (see `AUTH_HOST_CONTRACT.md` §3/OIDC).

  `link_oidc_to_password/2` and `unlink_oidc_from_password/2` are admin-only account merges,
  gated by `TermelixWeb.Plugs.RequireAdmin` in the router. Their 403 bodies differ ("Admin
  access required" vs "Admin privileges required") because Node's did; each sits in the
  pipeline carrying its own wording.
  """
  use Phoenix.Controller, formats: [:json]

  import Plug.Conn
  import Ecto.Query, only: [from: 2]
  import TermelixWeb.AuthHelpers, only: [device: 1, put_jwt_cookie: 3]
  import TermelixWeb.Plugs.Authenticate, only: [clear_jwt_cookie: 1]

  alias Termelix.{Accounts, Id, Oidc, Repo}
  alias Termelix.Schema.UserRole

  @day 86_400

  # GET /users/oidc/authorize
  def authorize(conn, params) do
    remember_me = params["rememberMe"] == "true"
    provider_id = to_int(params["providerId"])
    origin = request_origin()
    backend_callback = origin <> base_path() <> "/users/oidc/callback"

    case Oidc.load_provider_config(provider_id) do
      nil ->
        error(conn, 404, "OIDC not configured")

      {:ok, %{config: config, provider_db_id: provider_db_id}} ->
        case resolve_frontend_origin(conn, params, origin) do
          {:error, status, message} ->
            error(conn, status, message)

          {:ok, frontend_origin} ->
            state = Id.generate()
            nonce = Id.generate()

            Oidc.store_state(state,
              nonce: nonce,
              backend_callback: backend_callback,
              frontend_origin: frontend_origin,
              remember_me: remember_me,
              provider_db_id: provider_db_id
            )

            auth_url = Oidc.build_authorize_url(config, backend_callback, state, nonce)
            json(conn, %{auth_url: auth_url, state: state, nonce: nonce})
        end
    end
  end

  # GET /users/oidc/callback
  def callback(conn, %{"code" => code, "state" => state})
      when is_binary(code) and code != "" and is_binary(state) and state != "" do
    # One lookup, not five: the flow context moved out of the `settings` table (where an
    # unauthenticated authorize could grow the store that also holds every wrapped DEK) into a
    # TTL'd ETS table. `:error` covers both "never existed" and "TTL lapsed", which is why the
    # two 400s below collapse into one — a state whose 10 minutes ran out is indistinguishable
    # from one that was never issued, and should be.
    case Oidc.fetch_state(state) do
      :error ->
        error(conn, 400, "Invalid state parameter")

      {:ok, ctx}
      when is_nil(:erlang.map_get(:backend_callback, ctx)) or
             is_nil(:erlang.map_get(:frontend_origin, ctx)) ->
        error(conn, 400, "Invalid state parameter - redirect URIs not found")

      {:ok, ctx} ->
        case Oidc.load_provider_config(ctx.provider_db_id) do
          nil ->
            error(conn, 500, "OIDC not configured")

          {:ok, %{config: config, provider_type: type, provider_db_id: provider_db_id}} ->
            Oidc.delete_provider(state)

            run_callback(conn, %{
              type: type,
              config: config,
              provider_db_id: provider_db_id,
              code: code,
              state: state,
              backend_callback: ctx.backend_callback,
              frontend_origin: ctx.frontend_origin,
              stored_nonce: ctx.nonce,
              remember_me: ctx.remember_me
            })
        end
    end
  end

  def callback(conn, _params), do: error(conn, 400, "Code and state are required")

  defp run_callback(conn, ctx) do
    result =
      case ctx.type do
        "github" -> github_flow(ctx)
        _ -> oidc_flow(ctx)
      end

    case result do
      {:ok, user, userinfo} ->
        complete_login(conn, user, userinfo, ctx.remember_me, ctx.frontend_origin)

      {:error, :nonce_mismatch} ->
        error(conn, 401, "Invalid OIDC token nonce")

      {:error, {:no_identifier, path}} ->
        error(conn, 400, "User identifier not found at path: #{path}")

      {:error, :not_allowed} ->
        redirect_with(conn, ctx.frontend_origin, error: "user_not_allowed")

      {:error, :registration_disabled} ->
        redirect_with(conn, ctx.frontend_origin, error: "registration_disabled")

      {:error, :encryption_failed} ->
        error(conn, 500, "Failed to setup user security - user creation cancelled")

      {:error, {:http_status, _status}} ->
        error(conn, 400, "Failed to exchange authorization code")

      {:error, :github_userinfo} ->
        error(conn, 400, "Failed to get GitHub user information")

      {:error, :no_userinfo} ->
        error(conn, 400, "Failed to get user information")

      {:error, _other} ->
        redirect_with(conn, ctx.frontend_origin, error: "OIDC authentication failed")
    end
  rescue
    _ -> redirect_with(conn, ctx.frontend_origin, error: "OIDC authentication failed")
  end

  defp oidc_flow(ctx) do
    with {:ok, token_data} <- Oidc.exchange_code(ctx.config, ctx.code, ctx.backend_callback),
         _ <- Oidc.delete_state(ctx.state),
         {:ok, userinfo} <- Oidc.resolve_userinfo(ctx.config, token_data, ctx.stored_nonce),
         {:ok, identifier, name} <- extract_identity(ctx.config, userinfo),
         # Provider-scope the identifier (as the github branch below always has), or two IdPs
         # handing out the same `sub` would collide on one local account; the raw identifier
         # stays as the legacy fallback for rows written before scoping.
         scoped = Oidc.scoped_identifier(ctx.provider_db_id, ctx.config, identifier),
         {:ok, user} <-
           Oidc.find_or_create_user(ctx.config, scoped, name, userinfo, ctx.provider_db_id,
             legacy_identifier: identifier
           ) do
      {:ok, user, userinfo}
    end
  end

  defp github_flow(ctx) do
    with {:ok, token_data} <- Oidc.exchange_code(ctx.config, ctx.code, ctx.backend_callback),
         _ <- Oidc.delete_state(ctx.state),
         {:ok, userinfo} <- Oidc.fetch_github_userinfo(token_data["access_token"]),
         identifier = "github:#{ctx.provider_db_id}:#{userinfo["id"] || userinfo["login"]}",
         name = to_string(userinfo["name"] || userinfo["login"] || identifier),
         {:ok, user} <-
           Oidc.find_or_create_user(ctx.config, identifier, name, userinfo, ctx.provider_db_id) do
      {:ok, user, userinfo}
    end
  end

  defp extract_identity(config, userinfo) do
    case Oidc.extract_identity(config, userinfo) do
      {:ok, identifier, name} -> {:ok, identifier, name}
      {:error, :no_identifier} -> {:error, {:no_identifier, config["identifier_path"] || "sub"}}
    end
  end

  # --- session issuance (mirrors UserController.issue_session) ---------------

  # The session's oidc_sub/oidc_sid/sso_provider_id columns (back-channel logout) are left
  # unset: this reuses `Accounts.create_session/4` verbatim, and back-channel logout is not
  # part of this task.
  defp complete_login(conn, user, _userinfo, remember_me, frontend_origin) do
    {device_type, device_info} = device(conn)
    ttl_seconds = oidc_ttl(device_type, remember_me)
    {:ok, token, _session} = Accounts.create_session(user, device_type, device_info, ttl_seconds)

    if Oidc.token_callback?(frontend_origin) do
      conn
      |> clear_jwt_cookie()
      |> redirect(external: add_query(frontend_origin, %{"success" => "true", "token" => token}))
    else
      conn
      |> put_jwt_cookie(token, ttl_seconds)
      |> redirect(external: add_query(frontend_origin, %{"success" => "true"}))
    end
  end

  # Desktop/mobile logins force a 30-day cookie; web honors rememberMe, else the session timeout.
  defp oidc_ttl(device_type, remember_me) do
    if device_type in ["desktop", "mobile"] or remember_me,
      do: 30 * @day,
      else: Accounts.session_timeout_hours() * 3600
  end

  # --- account link / unlink (user-oidc-account-routes.ts) ------------------

  # POST /users/link-oidc-to-password
  def link_oidc_to_password(conn, params) do
    oidc_user_id = params["oidcUserId"]
    target_username = params["targetUsername"]

    if present?(oidc_user_id) and present?(target_username) do
      do_link(conn, oidc_user_id, target_username)
    else
      error(conn, 400, "OIDC user ID and target username are required")
    end
  end

  defp do_link(conn, oidc_user_id, target_username) do
    oidc_user = Accounts.get_user(oidc_user_id)
    target_user = target_username && Accounts.get_user_by_username(target_username)

    cond do
      is_nil(oidc_user) ->
        error(conn, 404, "OIDC user not found")

      oidc_user.isOidc != true ->
        error(conn, 400, "Source user is not an OIDC user")

      is_nil(target_user) ->
        error(conn, 404, "Target password user not found")

      target_user.isOidc == true or not present?(target_user.passwordHash) ->
        error(conn, 400, "Target user must be a password-based account")

      present?(target_user.clientId) and present?(target_user.oidcIdentifier) ->
        error(conn, 400, "Target user already has OIDC authentication configured")

      true ->
        Repo.update!(
          Ecto.Changeset.change(target_user, %{
            isOidc: true,
            oidcIdentifier: oidc_user.oidcIdentifier,
            clientId: oidc_user.clientId,
            clientSecret: oidc_user.clientSecret,
            issuerUrl: oidc_user.issuerUrl,
            authorizationUrl: oidc_user.authorizationUrl,
            tokenUrl: oidc_user.tokenUrl,
            identifierPath: oidc_user.identifierPath,
            namePath: oidc_user.namePath,
            scopes: oidc_user.scopes || "openid email profile"
          })
        )

        Accounts.revoke_all_sessions(oidc_user_id)
        Repo.delete_all(from(ur in UserRole, where: ur.userId == ^oidc_user_id))
        Repo.delete(oidc_user)

        json(conn, %{
          success: true,
          message:
            "OIDC user #{oidc_user.username} has been linked to #{target_user.username}. " <>
              "The password account can now use both password and OIDC login."
        })
    end
  end

  # POST /users/unlink-oidc-from-password
  def unlink_oidc_from_password(conn, params) do
    user_id = params["userId"]

    if present?(user_id),
      do: do_unlink(conn, user_id),
      else: error(conn, 400, "User ID is required")
  end

  defp do_unlink(conn, user_id) do
    target_user = Accounts.get_user(user_id)

    cond do
      is_nil(target_user) ->
        error(conn, 404, "User not found")

      target_user.isOidc != true ->
        error(conn, 400, "User does not have OIDC authentication enabled")

      not present?(target_user.passwordHash) ->
        error(
          conn,
          400,
          "Cannot unlink OIDC from a user without password authentication. " <>
            "This would leave the user unable to login."
        )

      true ->
        Repo.update!(
          Ecto.Changeset.change(target_user, %{
            isOidc: false,
            oidcIdentifier: nil,
            clientId: "",
            clientSecret: "",
            issuerUrl: "",
            authorizationUrl: "",
            tokenUrl: "",
            identifierPath: "",
            namePath: "",
            scopes: "openid email profile"
          })
        )

        json(conn, %{
          success: true,
          message:
            "OIDC authentication has been removed from #{target_user.username}. " <>
              "User can now only login with password."
        })
    end
  end

  # --- frontend-origin resolution (mirrors the authorize branch) ------------

  defp resolve_frontend_origin(conn, params, origin) do
    desktop_port = params["desktopCallbackPort"]
    app_callback = params["appCallbackUrl"]

    cond do
      present?(desktop_port) ->
        case Oidc.desktop_callback_url(desktop_port) do
          nil -> {:error, 400, "Invalid desktop callback port"}
          url -> {:ok, url}
        end

      is_binary(app_callback) and app_callback != "" ->
        resolve_app_callback(app_callback)

      true ->
        case referer(conn) do
          nil -> {:ok, origin}
          ref -> {:ok, referer_origin(ref)}
        end
    end
  end

  defp resolve_app_callback(app_callback) do
    uri = URI.parse(app_callback)

    cond do
      is_nil(uri.scheme) ->
        {:error, 400, "Invalid app callback URL"}

      # "termix-mobile" stays accepted: the shipped mobile app still registers the
      # pre-rename deep-link scheme.
      uri.scheme not in ["termelix-mobile", "termix-mobile"] ->
        {:error, 400, "Unsupported app callback URL"}

      true ->
        {:ok, app_callback}
    end
  end

  defp referer_origin(referer) do
    uri = URI.parse(referer)
    host = if uri.port in [nil, 80, 443], do: uri.host, else: "#{uri.host}:#{uri.port}"
    "#{uri.scheme}://#{host}"
  end

  defp referer(conn) do
    case get_req_header(conn, "referer") do
      [ref | _] when is_binary(ref) and ref != "" -> ref
      _ -> nil
    end
  end

  # --- request origin (mirrors getRequestOriginWithForceHTTPS) --------------

  # The backend callback must name THIS instance, so the origin comes from the endpoint's
  # configured `:url` — never from request headers. `conn.host`/`conn.port` are the
  # client-supplied Host header, and `TermelixWeb.Plugs.TrustedProxy` vets only the forwarded
  # scheme and the peer address, not the host: an unauthenticated caller able to reach the app
  # port (on the tailnet deployment, every peer) could otherwise send `X-Forwarded-Host:
  # attacker.tld` and get an `auth_url` whose `redirect_uri` points at a host they control.
  defp request_origin do
    origin = TermelixWeb.Endpoint.url()

    if System.get_env("OIDC_FORCE_HTTPS") == "true",
      do: String.replace_prefix(origin, "http:", "https:"),
      else: origin
  end

  defp base_path do
    (System.get_env("BASE_PATH") || "") |> String.replace(~r{/+$}, "")
  end

  # --- helpers --------------------------------------------------------------

  defp add_query(url, params) do
    uri = URI.parse(url)
    existing = URI.decode_query(uri.query || "")
    merged = Map.merge(existing, params)
    URI.to_string(%{uri | query: URI.encode_query(merged)})
  end

  defp redirect_with(conn, frontend_origin, params) do
    redirect(conn,
      external: add_query(frontend_origin, Map.new(params, fn {k, v} -> {to_string(k), v} end))
    )
  end

  defp present?(v) when is_binary(v), do: String.trim(v) != ""
  defp present?(_), do: false

  defp to_int(nil), do: nil
  defp to_int(v) when is_integer(v), do: v

  defp to_int(v) when is_binary(v) do
    case Integer.parse(v) do
      {int, ""} -> int
      _ -> nil
    end
  end

  defp to_int(_), do: nil

  defp error(conn, status, message), do: conn |> put_status(status) |> json(%{error: message})
end
