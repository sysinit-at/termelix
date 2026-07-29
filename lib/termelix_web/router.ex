defmodule TermelixWeb.Router do
  use TermelixWeb, :router

  pipeline :api do
    plug :accepts, ["json"]
    plug TermelixWeb.Plugs.Cors
  end

  # SSE, not JSON. `plug :accepts, ["json"]` 406s a browser's `new EventSource(...)`, which
  # sends `Accept: text/event-stream` — so the `:api` pipeline would reject every real client
  # of `/events` while every test that forgot the header passed.
  pipeline :sse do
    plug :accepts, ["sse", "json"]
    plug TermelixWeb.Plugs.Cors
  end

  # Non-human callers. A separate pipeline, not a fallback inside `:authenticated`: a JWT is
  # the user and an API key is a narrow slice of the user, and a plug that accepted either
  # would leave every handler responsible for remembering which one it got.
  pipeline :api_key do
    plug TermelixWeb.Plugs.ApiKeyAuth
  end

  pipeline :authenticated do
    plug TermelixWeb.Plugs.Authenticate
  end

  # Admin gates. One check (`current_user.isAdmin`), three pipelines: the ported Node routes
  # answer with three different 403 bodies that the SPA and the controller tests match
  # byte-for-byte, so the wording is carried as a plug option.
  pipeline :admin do
    plug TermelixWeb.Plugs.RequireAdmin, message: "Not authorized"
  end

  pipeline :admin_access do
    plug TermelixWeb.Plugs.RequireAdmin, message: "Admin access required"
  end

  pipeline :admin_privileges do
    plug TermelixWeb.Plugs.RequireAdmin, message: "Admin privileges required"
  end

  # Liveness + unauthenticated bootstrap
  scope "/", TermelixWeb do
    pipe_through :api

    # `/health/live` is the container healthcheck target; `/health` is the legacy alias every
    # existing poller still uses — same action, so they can never drift apart.
    get "/health", HealthController, :index
    get "/health/live", HealthController, :index
    get "/health/ready", HealthController, :ready
  end

  scope "/users", TermelixWeb do
    pipe_through :api

    post "/create", UserController, :create
    post "/login", UserController, :login
    post "/ldap/login", LdapController, :login
    post "/totp/verify-login", TotpController, :verify_login
    get "/setup-required", UserController, :setup_required
    get "/registration-allowed", UserController, :registration_allowed
    get "/password-login-allowed", UserController, :password_login_allowed
    get "/sso-providers", SsoProviderController, :index
    get "/oidc/authorize", OidcController, :authorize
    get "/oidc/callback", OidcController, :callback
  end

  scope "/users", TermelixWeb do
    pipe_through [:api, :authenticated]

    get "/me", UserController, :me
    post "/logout", UserController, :logout
    get "/me/token", UserController, :token
    post "/ws-ticket", UserController, :ws_ticket
    post "/totp/setup", TotpController, :setup
    post "/totp/enable", TotpController, :enable
    post "/totp/disable", TotpController, :disable

    # Authenticated but deliberately NOT admin-gated: regular users list peers to pick sharing
    # targets, and the management-only fields are added per requester (admin_controller.ex:22).
    get "/list", AdminController, :list

    # Active sessions + data access.
    get "/sessions", UserSessionController, :sessions
    post "/sessions/revoke-all", UserSessionController, :revoke_all
    delete "/sessions/:sessionId", UserSessionController, :revoke_session
    get "/data-status", UserSessionController, :data_status
    post "/unlock-data", UserSessionController, :unlock_data

    # Trusted devices + the caller's OWN data export.
    get "/trusted-devices", TrustedDeviceController, :index
    delete "/trusted-devices/:id", TrustedDeviceController, :delete
    get "/data-export", UserDataExportController, :export
  end

  # The cross-user export is the app's single largest deliberate secret-egress path: it returns
  # another user's decrypted hosts and credentials. It belongs in an admin scope like every
  # other privileged route — leaving it gated only inside the controller was the one place the
  # phase's "privileged routes are visible in the router" claim was false.
  #
  # The controller keeps its own `isAdmin` check as well, and that redundancy is deliberate
  # here: this is the route where a mis-edited scope has the worst possible consequence.
  scope "/users", TermelixWeb do
    pipe_through [:api, :authenticated, :admin_access]

    get "/admin/export/:userId", UserDataExportController, :admin_export
  end

  # Admin user management — 403 body {"error": "Not authorized"}.
  scope "/users", TermelixWeb do
    pipe_through [:api, :authenticated, :admin]

    post "/make-admin", AdminController, :make_admin
    post "/remove-admin", AdminController, :remove_admin
    post "/admin-create", AdminController, :admin_create
    delete "/delete-user", AdminController, :delete_user
  end

  # Admin config surfaces — 403 body {"error": "Admin access required"}.
  scope "/users", TermelixWeb do
    pipe_through [:api, :authenticated, :admin_access]

    get "/count", AdminController, :count
    get "/error-reporting", AdminController, :error_reporting_status
    post "/error-reporting", AdminController, :set_error_reporting

    # SSO provider management (the public login-screen list stays in the unauthenticated scope).
    get "/sso-providers/admin", SsoProviderController, :admin_index
    post "/sso-providers", SsoProviderController, :create
    put "/sso-providers/:id", SsoProviderController, :update
    delete "/sso-providers/:id", SsoProviderController, :delete

    post "/link-oidc-to-password", OidcController, :link_oidc_to_password
  end

  # The one route Node answers with {"error": "Admin privileges required"} — kept verbatim.
  scope "/users", TermelixWeb do
    pipe_through [:api, :authenticated, :admin_privileges]

    post "/unlink-oidc-from-password", OidcController, :unlink_oidc_from_password
  end

  # Authenticated CRUD surfaces (mounted at the same external paths nginx exposed).
  scope "/", TermelixWeb do
    pipe_through [:api, :authenticated]

    get "/user-preferences", UserPreferenceController, :show
    put "/user-preferences", UserPreferenceController, :update
    get "/version", SystemController, :version
    get "/releases/rss", SystemController, :releases_rss
    # Host reachability status — powers the sidebar online/offline indicators.
    get "/status", MetricsController, :status_all
    get "/status/:id", MetricsController, :status
    # Poller notifications fired after host mutations (acknowledged; status is on demand).
    post "/refresh", MetricsController, :poller_ack
    post "/host-updated", MetricsController, :poller_ack
    post "/host-deleted", MetricsController, :poller_ack
  end

  # `:admin`, not `:authenticated` — defect 42. Creating a channel means naming a URL the
  # SERVER will dial, and `/:id/test` returns the outcome, so the pair is a request forger with
  # a read-back. `Termelix.Net.Egress` bounds WHERE it can reach; this bounds WHO can aim it.
  # Reading the list is not the dangerous half, but the sharing model is owner-or-admin, so
  # splitting the scope to keep `index` open would buy nothing.
  # The server-to-client push channel (P6). A held connection, not a request — see
  # `TermelixWeb.EventController`. The existing polls stay: this is an addition, and a client
  # that never subscribes keeps working exactly as it did.
  scope "/events", TermelixWeb do
    pipe_through [:sse, :authenticated]

    get "/", EventController, :stream
  end

  # The agent surface (P8). Same core the browser uses, different door and a narrower key:
  # tmux verbs on named hosts, nothing else.
  scope "/agent", TermelixWeb do
    pipe_through [:api, :api_key]

    get "/hosts", AgentController, :hosts
    get "/hosts/:hostId/panes", AgentController, :overview
    get "/hosts/:hostId/capture", AgentController, :capture
    post "/hosts/:hostId/sessions", AgentController, :ensure_session
    post "/hosts/:hostId/dispatch", AgentController, :dispatch
    post "/hosts/:hostId/send-keys", AgentController, :send_keys
    post "/hosts/:hostId/wait", AgentController, :wait
  end

  # Model Context Protocol, so an agent can use Termelix as a native tool server rather than
  # being taught a bespoke HTTP API. Same key, same scopes, same core.
  scope "/mcp", TermelixWeb do
    pipe_through [:api, :api_key]

    post "/", McpController, :rpc
  end

  # API key management is a HUMAN action — minting an agent credential must never be something
  # an agent credential can do, or the scoping is decorative.
  scope "/api-keys", TermelixWeb do
    pipe_through [:api, :authenticated]

    get "/", ApiKeyController, :index
    post "/", ApiKeyController, :create
    delete "/:id", ApiKeyController, :delete
  end

  scope "/notification-channels", TermelixWeb do
    pipe_through [:api, :authenticated, :admin]

    get "/", NotificationChannelController, :index
    post "/", NotificationChannelController, :create
    put "/:id", NotificationChannelController, :update
    delete "/:id", NotificationChannelController, :delete
    post "/:id/test", NotificationChannelController, :test
  end

  scope "/alert-rules", TermelixWeb do
    pipe_through [:api, :authenticated]

    get "/", AlertRuleController, :index
    post "/", AlertRuleController, :create
    put "/:id", AlertRuleController, :update
    delete "/:id", AlertRuleController, :delete
  end

  scope "/alert-firings", TermelixWeb do
    pipe_through [:api, :authenticated]

    get "/", AlertFiringController, :index
    post "/acknowledge-all", AlertFiringController, :acknowledge_all
    post "/:id/acknowledge", AlertFiringController, :acknowledge
  end

  # Retention is global config, so admin-only — 403 body {"error": "Admin access required"}.
  # Declared before the `/:id` scope so the literal path is not swallowed by the wildcard.
  scope "/session_logs", TermelixWeb do
    pipe_through [:api, :authenticated, :admin_access]

    get "/retention", SessionRecordingController, :retention
    put "/retention", SessionRecordingController, :set_retention
  end

  # The recordings themselves are per-user (ownership enforced in the context, not by role).
  scope "/session_logs", TermelixWeb do
    pipe_through [:api, :authenticated]

    get "/:id/content", SessionRecordingController, :content
    get "/:id", SessionRecordingController, :show
    delete "/:id", SessionRecordingController, :delete
    get "/", SessionRecordingController, :index
  end

  # `/rbac` is a MIXED scope and has to be split rather than relocated: the authorization model
  # itself is admin-only, while host sharing is owner-scoped and must stay reachable by ordinary
  # users. Keeping them in one scope is how `permissions_catalog` and `list_roles` ended up with
  # no check at all while every sibling had one — 403 body {"error": "Admin access required"}.
  scope "/rbac", TermelixWeb do
    pipe_through [:api, :authenticated, :admin_access]

    get "/permissions/catalog", RbacController, :permissions_catalog
    post "/roles", RbacController, :create_role
    put "/roles/:id", RbacController, :update_role
    delete "/roles/:id", RbacController, :delete_role
    post "/users/:userId/roles", RbacController, :assign_user_role
    delete "/users/:userId/roles/:roleId", RbacController, :remove_user_role
  end

  # Owner-scoped, plus the two reads a non-admin legitimately needs.
  #
  # `list_roles` deliberately stays here rather than moving above: the SPA's host-share modal
  # calls it to populate the "grant which role" dropdown and swallows failures with
  # `.catch(() => ({ roles: [] }))`, so a blanket 403 would silently empty that dropdown with no
  # error shown. It scopes its RESPONSE to the roles the caller may actually grant instead.
  # `list_user_roles` is self-or-admin, enforced in the action.
  scope "/rbac", TermelixWeb do
    pipe_through [:api, :authenticated]

    get "/roles", RbacController, :list_roles
    get "/users/:userId/roles", RbacController, :list_user_roles
    get "/shared-hosts", RbacController, :shared_hosts
    post "/host/:id/share", RbacController, :share_host
    get "/host/:id/access", RbacController, :host_access_list
    patch "/host/:id/access/:accessId", RbacController, :update_host_access
    delete "/host/:id/access/:accessId", RbacController, :revoke_host_access
  end

  scope "/ssh/tunnel", TermelixWeb do
    pipe_through [:api, :authenticated]

    get "/status", TunnelController, :status
    get "/status/stream", TunnelController, :status_stream
    get "/status/:tunnel_name", TunnelController, :status_by_name
    post "/connect", TunnelController, :connect
    post "/disconnect", TunnelController, :disconnect
    post "/cancel", TunnelController, :cancel
  end

  scope "/alerts", TermelixWeb do
    pipe_through [:api, :authenticated]

    get "/", SystemController, :alerts
    post "/dismiss", SystemController, :dismiss
    get "/dismissed", SystemController, :dismissed
    delete "/dismiss", SystemController, :undismiss
  end

  scope "/host", TermelixWeb do
    pipe_through [:api, :authenticated]

    get "/db/host", HostController, :index
    post "/db/host", HostController, :create
    get "/db/host/:id", HostController, :show
    put "/db/host/:id", HostController, :update
    delete "/db/host/:id", HostController, :delete
    post "/db/host/:id/wake", HostController, :wake
    patch "/bulk-update", HostController, :bulk_update

    get "/folders", HostFolderController, :index
    put "/folders/rename", HostFolderController, :rename_folder
    put "/folders/metadata", HostFolderController, :update_metadata
    delete "/folders/:name/hosts", HostFolderController, :delete_hosts
  end

  scope "/open-tabs", TermelixWeb do
    pipe_through [:api, :authenticated]

    get "/active-sessions", OpenTabController, :active_sessions
    get "/", OpenTabController, :index
    post "/", OpenTabController, :create
    put "/", OpenTabController, :update
    patch "/:id", OpenTabController, :patch
    delete "/:id", OpenTabController, :delete
  end

  scope "/terminal", TermelixWeb do
    pipe_through [:api, :authenticated]

    post "/command_history", HistoryController, :save_command
    post "/command_history/delete", HistoryController, :delete_command
    get "/command_history/:hostId", HistoryController, :list_commands
    delete "/command_history/:hostId", HistoryController, :clear_commands
  end

  scope "/activity", TermelixWeb do
    pipe_through [:api, :authenticated]

    get "/recent", HistoryController, :recent_activity
    post "/log", HistoryController, :log_activity
    delete "/reset", HistoryController, :reset_activity
  end

  scope "/ssh/file_manager", TermelixWeb do
    pipe_through [:api, :authenticated]

    post "/ssh/connect", FileManagerController, :connect
    post "/ssh/disconnect", FileManagerController, :disconnect
    get "/ssh/status", FileManagerController, :status
    post "/ssh/keepalive", FileManagerController, :keepalive
    get "/ssh/listFiles", FileManagerController, :list_files
    get "/ssh/readFile", FileManagerController, :read_file
    post "/ssh/writeFile", FileManagerController, :write_file
    post "/ssh/createFile", FileManagerController, :create_file
    post "/ssh/createFolder", FileManagerController, :create_folder
    delete "/ssh/deleteItem", FileManagerController, :delete_item
    put "/ssh/renameItem", FileManagerController, :rename_item
    put "/ssh/moveItem", FileManagerController, :move_item
    post "/ssh/uploadFileStream", FileManagerController, :upload_file_stream
    post "/ssh/downloadFile", FileManagerController, :download_file
    post "/ssh/downloadFileStream", FileManagerController, :download_file_stream
  end

  # File-manager metadata (recent / pinned / shortcuts) — mounted under /host.
  scope "/host/file_manager", TermelixWeb do
    pipe_through [:api, :authenticated]

    get "/recent", FileManagerMetaController, :recent
    post "/recent", FileManagerMetaController, :add_recent
    delete "/recent", FileManagerMetaController, :remove_recent
    get "/pinned", FileManagerMetaController, :pinned
    post "/pinned", FileManagerMetaController, :add_pinned
    delete "/pinned", FileManagerMetaController, :remove_pinned
    get "/shortcuts", FileManagerMetaController, :shortcuts
    post "/shortcuts", FileManagerMetaController, :add_shortcut
    delete "/shortcuts", FileManagerMetaController, :remove_shortcut
  end

  scope "/credentials", TermelixWeb do
    pipe_through [:api, :authenticated]

    # Literal segments before :id so they are not swallowed by the wildcard.
    get "/folders", CredentialController, :folders
    put "/folders/rename", CredentialController, :rename_folder
    get "/", CredentialController, :index
    post "/", CredentialController, :create
    get "/:id", CredentialController, :show
    put "/:id", CredentialController, :update
    delete "/:id", CredentialController, :delete
    post "/:id/apply-to-host/:hostId", CredentialController, :apply_to_host
    get "/:id/hosts", CredentialController, :hosts
  end

  scope "/", TermelixWeb do
    pipe_through [:api, :authenticated]

    get "/uptime", DashboardController, :uptime
    get "/service-links", DashboardController, :index_links
    post "/service-links", DashboardController, :create_link
    put "/service-links/:id", DashboardController, :update_link
    delete "/service-links/:id", DashboardController, :delete_link
  end

  scope "/tmux_monitor", TermelixWeb do
    pipe_through [:api, :authenticated]

    # Literal /overview (all hosts) before the /:hostId/* routes.
    get "/overview", TmuxController, :overview_all
    get "/:hostId/overview", TmuxController, :overview
    get "/:hostId/search", TmuxController, :search
    get "/:hostId/metrics", TmuxController, :metrics
    post "/:hostId/focus", TmuxController, :focus
    post "/:hostId/sessions", TmuxController, :create_session
    post "/:hostId/windows", TmuxController, :create_window
    post "/:hostId/rename", TmuxController, :rename
    post "/:hostId/kill", TmuxController, :kill
    post "/:hostId/kill-window", TmuxController, :kill_window
    post "/:hostId/kill-pane", TmuxController, :kill_pane
    post "/:hostId/split", TmuxController, :split
    put "/:hostId/tags", TmuxController, :set_tags

    # Orchestration verbs (P7): act on a pane without attaching a PTY to it. Same host gate as
    # the rest of the monitor, plus a per-(user, host) budget — these type keystrokes into a
    # live terminal, and nothing downstream limits how fast a shell will accept them.
    get "/:hostId/capture", TmuxController, :capture
    post "/:hostId/dispatch", TmuxController, :dispatch
    post "/:hostId/send-keys", TmuxController, :send_keys
    post "/:hostId/wait", TmuxController, :wait
  end

  # Whole surface is admin-only — 403 body {"error": "Not authorized"}.
  scope "/audit-logs", TermelixWeb do
    pipe_through [:api, :authenticated, :admin]

    get "/actions", AuditLogController, :actions
    get "/", AuditLogController, :index
  end

  # SSH terminal WebSocket upgrade (auth happens inside the controller).
  scope "/ssh", TermelixWeb do
    get "/websocket", TerminalController, :connect
    get "/websocket/*rest", TerminalController, :connect
  end

  # SPA fallback — serve the React app for the root and any client-side route the API did
  # not match. MUST be last so it never shadows an API route. Assets are served earlier by
  # Plug.Static in the endpoint.
  scope "/", TermelixWeb do
    get "/", PageController, :index
    get "/*path", PageController, :index
  end
end
