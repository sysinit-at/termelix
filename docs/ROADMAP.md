# Termelix → BEAM Port — Roadmap & Status

**Stack:** Elixir + Phoenix (Bandit) + Ecto (SQLite via `ecto_sqlite3`), OTP-native `:ssh`/`:crypto`.
Feasibility: **GO, no blockers** (see [FEASIBILITY.md](FEASIBILITY.md)). Contract the React frontend
depends on: [AUTH_HOST_CONTRACT.md](AUTH_HOST_CONTRACT.md).

The original Node/TS backend (~103K LOC) is being ported subsystem-by-subsystem. The React
frontend is reused unchanged; the Phoenix endpoint preserves the same external HTTP/WS paths that
nginx exposed in production, replacing nginx + all 12 Node micro-services with one supervised app.

## Done (verified e2e; ~150 tests passing)

- **Scaffold**: Phoenix app, supervision tree, health endpoint, credentialed CORS.
- **Data layer**: faithful 49-table migration mirroring `schema.ts` (data-compatible with an
  existing Termix SQLite DB). Ecto schemas use schema.ts camelCase struct keys over snake_case
  columns.
- **Crypto core** (byte-compatible with Node, proven against Node-generated vectors):
  HKDF-SHA256, AES-256-GCM field envelopes, v3 per-user DEK wrap, root secrets from `DATA_DIR/.env`,
  record encrypt/decrypt.
- **Auth** (contract-faithful): HS256 JWT, register (first-user admin, per-user DEK), bcrypt login,
  session-bound tokens, `Authenticate` plug with `{error,code}` 401 envelopes + cookie clearing,
  bootstrap endpoints.
- **Hosts**: full CRUD, DEK-encrypted secrets, secret-stripped camelCase responses (`HostNormalizer`).
  Host folders.
- **Credentials / snippets / user preferences / open-tabs**: CRUD (+ folders, reorder, TTL window).
- **History**: command history + recent activity.
- **SSH terminal** (signature feature, proven against an in-VM OTP ssh daemon): `Termelix.SSH.Client`
  (OTP `:ssh` connect/auth/pty/shell/resize, password + PEM key), `TerminalSocket` (WebSock, the
  original JSON protocol), `/ssh/websocket` upgrade. **Persistent sessions**: detach on socket
  death, 512 KB scrollback replay on `attachSession`, `listSessions`, per-user cap + expiry
  (Registry + DynamicSupervisor).
- **File manager**: SFTP over `:ssh_sftp` — list/read/write/create/delete/rename/move/upload/
  download; recent/pinned/shortcuts metadata.
- **Frontend**: built React SPA served same-origin from `priv/static/spa` with SPA fallback.
- **Packaging**: `mix release` (self-sufficient prod `runtime.exs` — DATA_DIR defaults, auto-generated
  SECRET_KEY_BASE), 3-stage Dockerfile + compose. Release boots, auto-migrates, serves UI, and
  handles register/login/me with only `DATA_DIR` set.

## Also done (batches 3–6; ~684 tests, live-verified across all subsystems)

- **System/bootstrap**: `/version`, `/releases/rss`, announcement `/alerts`; donation modal; me/token.
- **TOTP 2FA**: setup/enable/disable + verify-login second step (secrets DEK-encrypted).
- **RBAC + sharing**: roles CRUD, user-role assignment, host-access grants, shared-hosts (admin-gated).
- **Host metrics** (request-driven): combined SSH probe → CPU/mem/disk/net/uptime/processes/system;
  TCP status.
- **Docker/Podman**: connect/list/details/logs/stats + lifecycle (start/stop/restart/pause/remove).
- **SSH tunnels**: local forward over OTP `:ssh.tcpip_tunnel_to_server` (proven data path), one
  supervised GenServer per tunnel, status + auto-reconnect.
- **Homepage/dashboard**: items/layout + live ping/proxy/rss/favicon; uptime + service-links.
- **tmux monitor**, **network topology**, **Proxmox** discover/sync.
- **OIDC/SSO** (authorization-code + JWKS verify + link/unlink + provider CRUD), **LDAP** (`:eldap`),
  **termelix-id** public key resolver + identity/key/CA management.
- **Admin/audit/sessions**: admin user mgmt, audit log, active-session list/revoke, data-status/unlock.
- **Packaging**: `mix release` + 3-stage Dockerfile; self-sufficient prod config.

## Also done (batch 7)

- **SSH jump-hosts + SOCKS5**: `Termelix.SSH.Socks5` (RFC 1928/1929 dialer) + `Termelix.SSH.JumpChain`
  (multi-hop over `:ssh.tcpip_tunnel_to_server` with a loopback bridge) — proven end-to-end through
  nested in-VM `:ssh` daemons and a SOCKS5-fronted first hop.
- **Metrics history + alert engine**: interval collector GenServer, threshold evaluation (duration +
  cooldown), `alert_firings`, webhook + ntfy notifications; alert-rules / notification-channels /
  alert-firings / metrics-history CRUD.
- **Data export, trusted devices, session recordings** management surfaces.
- **Docker exec-console WebSocket** (`/docker/console`).

## Also done (batch 8 — 2026-07-24 bug sweep + rename)

- **Missing SPA surface ported** (each family used to 404 into the SPA's generic toast):
  file-manager session lifecycle (`/ssh/file_manager/ssh/connect|status|keepalive|disconnect`,
  virtual claim-check sessions in ETS over the short-lived SFTP pool), metrics viewer lifecycle +
  poller notifications (ack stubs over on-demand collection), tmux-monitor mutations
  (focus/create/rename/kill/split with audit + tag reconciliation) and batched search/pane-metrics.
- **Terminal**: `initialPath` / `executeCommand` / `tmuxAttachSession` connect extras (tmux
  monitor "Attach" opens a real tmux client); UTF-8-safe data frames (split codepoints no longer
  crash the socket — the fzf/`tms` failure).
- **Update check** behind `config :termelix, :update_check_enabled` (off until a public repo
  exists); **tmux monitor on by default** for new hosts; **Sentry** wired
  (`sentry.example.com` project `termelix`, DSN via `SENTRY_DSN`, empty disables).
- **Sentry is opt-in**: every event passes `Termelix.ErrorReporting.before_send/1`, which drops
  it unless the persisted `sentry_error_reporting` setting is `"true"` (absent = undecided =
  off). The SPA prompts the first admin who logs in (`prompt_error_reporting` on `/users/me`);
  `GET|POST /users/error-reporting` (admin) reads/flips the choice at runtime — also surfaced
  as the "Error Reporting" toggle in Admin Settings → General. With no DSN configured nothing
  is offered (`available: false` — no prompt, no toggle). Consent changes are **atomically
  audited**: `record_decision/3` writes the setting and the `error_reporting_enable`/`_disable`
  audit row (prior state in the details) in one transaction — a failed audit write rolls the
  change back — and consent rows are exempt from audit-log pruning, so the history stays
  reconstructible for the installation's lifetime.
- **Renamed Termix→Termelix** across server + client (app `:termelix`, `Termelix*` modules,
  `/termelix-id` paths, SPA branding/identifiers). Kept for data compatibility: SQLite table
  names `termix_identities`/`termix_identity_ca`/`termix_identity_keys` and the HKDF info
  string `termix:dek-wrap:v3:` (renaming either breaks existing encrypted databases);
  `src/backend` in the frontend checkout stays un-renamed as the upstream porting reference.
  **Upgrade compatibility** (post-review hardening): prod keeps using an existing
  `DATA_DIR/termix.db` (only fresh data dirs get `termelix.db`); the compose volume key stays
  `termix-data`; the server accepts the mobile app's legacy `termix-mobile://` OIDC callback
  scheme; Electron migrates a legacy "Termix" userData profile on first run and honors
  `TERMIX_DATA_DIR`; the frontend's `packaging/` (published upstream artifacts) is reverted
  to its upstream naming.

## Removed (scope trim for the SRE/sysadmin audience — vk543)

Five features were removed as low-value for professional SREs/sysadmins: **Homepage**,
the **Host Metrics dashboard**, **Network Graph**, **Termix ID**, and **Snippets**. Each
lost its routes/controllers/contexts/schemas/tests (server) and panel/tab/API-client/nav
(frontend). Kept on purpose:

- **Host online/offline indicators** — the `/status` reachability probe (a slimmed
  `Termelix.Metrics` + `MetricsController`) stays; only the CPU/mem/disk *dashboard*,
  history, and viewer lifecycle went.
- **Dashboard** — de-coupled from Homepage (ServiceLinks, recent activity, host status,
  uptime remain).

DB tables are **left in place** (no destructive migration) so existing databases keep
opening — a follow-up migration could drop `homepage_*`, `host_metrics_history`,
`network_topology`, `termix_identit*`, `snippets`, `snippet_folders` if desired. The
threshold alert engine's pure `decide/5` remains but is dormant (its metrics driver is
gone). Server `e5ba747`; frontend `9426e17`.

## Removed (remote desktop — RDP/VNC/Telnet via Guacamole)

**RDP**, **VNC** and **Telnet** were removed. The feature never worked properly, and the
product is focusing on being an excellent SSH session manager. All three rode the same
`guacd` bridge, so they went together: the server lost the AES-256-CBC connection token,
the Guacamole-protocol codec, the guacd TCP client, the connection/proxy processes and the
`/guacamole` routes + WebSocket proxy; the frontend lost the Guacamole display, toolbar and
clipboard, the host-editor RDP/VNC/Telnet tabs and the admin Guacamole settings. `guacd`
stops being an external runtime dependency — no container, no `GUACD_*` configuration.
Proxmox guest discovery went SSH-only with it: every discovered guest is provisioned as an
SSH host, and the "Windows / RDP detection" name-pattern setting
(`proxmoxConfig.windowsPatterns`) was dropped from the server and the host editor together.

Kept on purpose:

- **Wake-on-LAN** — `macAddress` / `wolBroadcastAddress` stay on the host schema and keep
  their inputs in the host editor's General tab. The sidebar's WoL button had never had a
  server route (it 404'd on both the Node and Elixir backends); `POST /host/db/host/:id/wake`
  is now implemented (`Termelix.WakeOnLan`, a UDP broadcast of the 102-byte magic packet to
  port 9), so the button does what it says.
- **Session recordings** — the listing/management surface is unchanged. A legacy row whose
  `format` is the retired `"guacamole"` is no longer a known format and falls through to a
  plain download. `protocol` is passed through verbatim, so legacy rows still report
  `"rdp"`/`"vnc"`/`"telnet"` in the listing.
- **The `guacamole-lite` npm dependency** in the frontend fork, with its `postinstall` patch
  (`scripts/patch-guacamole-lite.cjs`), that patch's test, its `knip.json` entry and the two
  `COPY`+`RUN` pairs in `docker/Dockerfile`. Only the *browser* half was removed
  (`guacamole-common-js`, its `@types`, the `.d.ts` shim and the `remote-desktop-vendor` vite
  chunk). `guacamole-lite` is imported by `src/backend/hosts/guacamole/{guacamole-server,routes}.ts`,
  and `src/backend` — the retired Node reference implementation — is still type-checked
  (`tsconfig.node.json` includes `src/backend/**/*.ts`), so dropping the dependency without
  deleting that tree breaks `npm run type-check`, `npm run build:backend` and the frontend
  Docker build. `src/backend` is deliberately frozen, so the dependency stays with it. It is
  build-time only: nothing in the shipped SPA or the Elixir server links against it.

DB columns are **left in place** (no destructive migration) so existing databases keep
opening: `enable_rdp`/`enable_vnc`/`enable_telnet`, `rdp_*`/`vnc_*`/`telnet_*`, `domain`,
`security`, `ignore_cert` and `guacamole_config` remain on `ssh_data` but are unmapped by
the Ecto schema and never read or written. Every one of them is nullable or carries a SQL
DEFAULT, so inserts that omit them succeed.

The live deployment's `guacd` container, the `DELETE FROM settings WHERE key LIKE 'guac%'`
purge below and the nginx `/guacamole/websocket/` + `^/guacamole(/.*)?$` location blocks on
`the reverse proxy` all belong to the **`termix-setup`** repo (workspace project `sysinit/termix-setup`,
normally checked out next to this one at `../termix-setup`). **That checkout is currently absent
from the workspace**, so the guacd retirement has no actionable target until it is restored —
restoring it is the first step of that follow-up, not an afterthought.

Two consequences of leaving the columns in place, both deliberate:

- **Legacy rows are folded onto SSH on read, not by a migration.** A host saved as RDP/VNC/
  Telnet-only carries `connection_type` in `("rdp","vnc","telnet")` and `enable_ssh = 0`;
  left alone it would still list but be unopenable, filtered out of the host picker and the
  command palette with no toggle left to switch SSH back on. `TermelixWeb.HostNormalizer`
  therefore pins `connectionType` to `"ssh"` on every read and forces `enableSsh` to true for
  exactly those rows. A row that stored `connection_type = "ssh"` keeps whatever `enableSsh`
  it has, so the editor's SSH toggle stays honest. The stored columns are untouched until the
  host is next saved.

  The fold rewrites exactly three columns on read — `connection_type`, `enable_ssh` and
  **`port`**. `port` is the non-obvious one: those rows stored the *remote-desktop* port
  (3389/5900/23) in `port` and the real SSH port in `ssh_port`, and every SSH consumer reads
  `port` first, so folding only the first two would make the host open and silently connect to
  RDP/VNC/Telnet with nothing visibly wrong (the editor shows `sshPort`). The rule lives in
  `Termelix.Hosts.effective_ssh_port/1` — `ssh_port || 22` for a legacy row, `port ||
  ssh_port || 22` otherwise — because the connect paths read the raw Ecto struct and would not
  see a normalizer-only change: terminal socket, SFTP, tmux, tunnels, metrics ping and the
  `GET /credentials/:id/hosts` listing all call it. `Termelix.Rbac.list_shared_hosts/2`
  (`GET /rbac/shared-hosts`) is the odd one out: its `select:` runs in
  SQLite, so it pulls `connection_type`/`ssh_port` along with `port` and folds the rows in
  Elixir afterwards. `Termelix.Proxmox.existing_port/1`
  likewise preserves an existing row's `port` across a re-sync only when that row is a genuine
  SSH host, so a re-sync cannot make the remote-desktop port permanent. Nothing else is folded
  — `username`, `ip` and the other feature toggles are read as stored.
- **`rdp_password` / `vnc_password` / `telnet_password` ciphertext is retained and
  unreadable.** Those columns are no longer in `FieldCrypto.@encrypted_fields` nor in the Ecto
  schema, so nothing decrypts them — including `Termelix.UserDataExport`, which no longer
  includes these secrets in a user's data export. The ciphertext stays on disk, reachable only
  by hand-written SQL plus manual DEK unwrapping, until a purge migration is run. Deferred on
  purpose: the removal ships without a destructive migration.

  The same deferred purge should also clear the orphaned admin settings the removed Guacamole
  panel wrote into the generic `settings` key/value table (`guac_url` and its enable flag).
  No reader remains — the guacd client and controller that called `Settings.get_value/1` are
  deleted — so the rows are harmless, but they are the last data trace of the feature and are
  still present on the live instance: `DELETE FROM settings WHERE key LIKE 'guac%'`.

## Removed (Docker and Proxmox)

**Docker** and **Proxmox** were removed to narrow the product to an SSH/tmux session manager
for humans and agents. Container management was a second product inside this one, competing
with the tools every operator already runs; Proxmox guest discovery was a bulk host-import
feature wearing a hypervisor label. Neither is on the new thesis.

Server (~4,060 lines): `Termelix.Docker`, `Termelix.Docker.Sessions`, `DockerController`,
`DockerConsoleController`, `DockerConsoleSocket`, `Termelix.Proxmox`, `ProxmoxController` and
their four test files. The `/docker`, `/docker/console` and `/proxmox` route scopes are gone,
as is the `Docker.Sessions` supervision child. Frontend: the Docker feature app (list, detail,
stats, logs, console terminal), `docker-api.ts`, and the Proxmox discovery/import dialogs.

- **`docker` is no longer a mintable WebSocket ticket scope.** `POST /users/ws-ticket` now
  accepts only `ssh`; a stale client asking for `docker` gets 400 rather than a ticket for a
  socket that no longer exists. Regression-tested.
- **`docker` is no longer a valid activity type** for `POST /terminal/activity`. Existing rows
  of that type stay in the table and are simply never written again.
- **The five host columns are retained and inert**: `enable_docker`, `show_docker_in_sidebar`,
  `docker_config`, `enable_proxmox`, `proxmox_config`. As with the remote-desktop columns, the
  Ecto schema fields and the API-layer params were dropped but no migration runs, so the
  removal ships without a destructive schema change. `enableProxmox` also leaves the
  `bulk_update_hosts/3` allow-list, taking its config-seeding branch with it.
- **One capability was lost, deliberately.** `DockerConsoleSocket` made the socket process
  itself the SSH subscriber, which is why it had correct end-to-end backpressure — the only
  place in the tree that did. The terminal socket does not, and its guard is inert
  (ARCHITECTURE_REVIEW defect 2). That reference implementation is now only in git history;
  the fix is scheduled as P9.

## Also done (batch 9 — 2026-07-27 robustness/security sweep, both repos)

A five-area review (backend security, backend robustness/perf, mobile robustness/perf,
mobile UI/UX, mobile security — on top of the P0–P11 state) produced ~35 verified
findings; all landed with regression tests. Details per bug: [BUG_REFERENCE.md](BUG_REFERENCE.md)
(and the mobile repo's own BUG_REFERENCE.md). Suite: **1155 tests** (was 1108).

- **Auth hardening**: LDAP login rate-limited like password login (was an unthrottled
  bind-per-attempt oracle); OIDC `redirect_uri` derived from the endpoint `:url`, never
  from `X-Forwarded-*`; generic-OIDC identifiers scoped by provider with legacy fallback.
- **Transport**: LDAP(S)/StartTLS default to `verify_peer` (system store or provider
  `caCert`; explicit `insecureSkipVerify` opt-out); StartTLS upgrade + search timeLimit
  bounded; notifier + OIDC HTTP clients pass `redirect: false` (one-hop SSRF past the
  Egress allowlist, and a 307 would have re-POSTed the OIDC `client_secret`).
- **Secrets at rest**: OIDC `client_secret` / LDAP `bindPassword` sealed via new
  `Termelix.Crypto.SystemSecrets` (FieldCrypto under the instance key; legacy base64
  still reads).
- **Tokens**: ws-tickets are single-use (`Termelix.WsTickets`, ETS jti consumption).
- **Terminal data path**: `SSH.Client` stops on owner exit (was swallowed by the
  catch-all); keystroke `send/4` with a 10 s timeout + typed `:send_failed` close
  (was `infinity` + discarded return); session recorder sheds past a 1k-chunk mailbox
  watermark; recording content/delete allowlist now includes the recorder's own
  `recordings/` root and resolves the data dir like the writer does.
- **Hygiene**: rate-limiter sweeps `:reauth` buckets; tmux fleet probe filters before
  decrypting; command-history writes enforce host ownership.
- **Mobile** (termEX-Mobile repo, commits `b6b8483`/`e19e02a`/`fa13f8f`/`a7ebf60`):
  WebView auth bridge origin-gated (session injection); app-switcher privacy overlay;
  pasteboard auto-clear; app lock fails closed on cold start; IPv6/IPv4 cleartext
  classifier hardened; WS 1001 reconnects (server redeploys no longer kill tabs);
  404-fallback requests carry auth (spurious-logout fix); JWT read cached in memory;
  event stream bounded + app-state aware; root error boundary; revoke-all keeps the
  current device; ~13 UI/UX fixes (back nav, confirms, a11y labels, touch targets,
  keyboard avoidance, error states). Mac Catalyst **does not build** (upstream RN 0.86
  podspec platform issue — investigation + reverts documented in `fa13f8f`); macOS
  story stays "Designed for iPad" on Apple Silicon.

## Assessed and declined

- **Native mosh transport (vk533)** — feasible on paper, not worth building. The browser
  can't speak UDP, so a mosh SSP client would have to run in the Phoenix server and only
  cover the server↔host hop (usually the stable one); the latency/roaming-sensitive
  browser↔server hop stays on WebSocket, where mosh's local-echo prediction and roaming
  never apply. Also blocked by crypto: mosh's AES-128-OCB is unavailable in the OTP OpenSSL
  build (`:crypto.supports/1` lists no OCB; `crypto_one_time_aead(:aes_128_ocb, …)` raises),
  so it would need a C NIF or a hand-rolled OCB. OTP persistent sessions + WS reconnect
  already provide the session-survival benefit mosh is usually wanted for, and the existing
  `autoMosh` / `moshCommand` terminal options already launch mosh to a flaky onward host
  from within the shell. Revisit only if server↔host roaming becomes a concrete need.

## Remaining backlog — requires external systems / hardware / new deps (not e2e-testable here)

1. **Passkeys/WebAuthn** (`wax` dep + a browser authenticator).
2. **Vault SSH signer** (a running HashiCorp Vault) and **opkssh** (the OpenPubkey binary + an OIDC IdP).
3. **Serial** console (`circuits_uart` + physical/virtual serial hardware).
4. **Live streaming** variants of tmux-monitor / metrics dashboards (request-driven versions are done).
5. **Opt-in** of jump-host/SOCKS5 into the default terminal/exec connect path (primitives built + tested;
   wiring them in is a follow-up), host-key TOFU enforcement, server-to-server transfer, C2S tunnel relay.

Everything that can be built and verified end-to-end in this environment is done: **zero warnings, a
deployable release that boots + auto-migrates + serves the real React UI**, with the crypto core proven
byte-compatible with the original Node backend.

## Porting conventions (follow these for consistency)

- **Ecto schema**: struct keys = schema.ts camelCase atoms; `source:` = snake_case column. Booleans
  are `:boolean` (SQLite 0/1), timestamps are `:string` (TEXT `CURRENT_TIMESTAMP`), no
  `timestamps()` macro. Text PKs: `@primary_key {:id, :string, autogenerate: false}`; autoincrement:
  `{:id, :id, autogenerate: true}`. Generate field lines with `scratchpad/gen_fields.exs`.
- **Secrets**: any field in `FieldCrypto.@encrypted_fields` is encrypted under the owning user's DEK
  via `DataCrypto`. Reads are lazy/graceful (`safe_decrypt`): plaintext returned as-is.
- **JSON**: responses are the exact shapes in AUTH_HOST_CONTRACT.md — host objects camelCase, a few
  auth fields snake_case. Build response maps explicitly in controllers; never leak secret fields.
- **Errors**: `{error, message}` (+ optional `code`); 401 codes `TOTP_REQUIRED`/`SESSION_NOT_FOUND`/
  `SESSION_EXPIRED` clear the `jwt` cookie.
- **Routes**: mount under the same external paths nginx used; auth via the `Authenticate` plug.
- **Tests**: each subsystem ships tests (ConnCase for HTTP, DataCase for contexts, in-VM `:ssh`
  daemon for SSH paths). Keep the suite green.
