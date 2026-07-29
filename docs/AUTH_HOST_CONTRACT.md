# Termelix Auth + Host HTTP API Contract

Reverse-engineered from the Node/TypeScript backend so the Elixir/Phoenix port matches
byte-for-byte and the existing React frontend runs unchanged.

Source repo: `../termelix-frontend`

## 0. Service topology and route mounting

The backend is split into several Express apps, each on its own port. The frontend
(`src/ui/main-axios.ts`) points different axios instances at different ports. In the
single-container deployment a reverse proxy fronts them all under one origin (see the
frontend's `getBasePath()` production branch).

| Frontend axios instance | Port | Base path | Evidence |
|---|---|---|---|
| `hostApi` / `sshHostApi` | 30001 | `/host` | `main-axios.ts:846` |
| `tunnelApi` | 30003 | `/ssh` | `main-axios.ts:850` |
| `fileManagerApi` | 30004 | `/ssh/file_manager` | `main-axios.ts:853` |
| `statsApi` | 30005 | `` (root) | `main-axios.ts:859` |
| `authApi` | 30001 | `` (root) | `main-axios.ts:862` |
| `dashboardApi` | 30006 | `` | `main-axios.ts:865` |
| `rbacApi` | 30001 | `` | `main-axios.ts:868` |
| Terminal WebSocket | 30002 | `/ssh/websocket/` | `terminal/index.ts:105`, `Terminal.tsx:999` |

The main database service mounts the routers (`database.ts:1731-1735`):

```
app.use("/users", userRoutes);   // src/backend/database/routes/users.ts
app.use("/host",  hostRoutes);   // src/backend/database/routes/host.ts
```

So `authApi` (port 30001, root base) hits `/users/*`, and `sshHostApi` (port 30001,
`/host` base) hits `/host/*`. **Every route path in this document is the full path as the
frontend calls it.**

All axios instances are created with `withCredentials: true` and
`headers: {"Content-Type": "application/json"}`, timeout 30000 ms (`main-axios.ts:392-397`).

---

## 1. JWT

### Algorithm and secret

- **Algorithm: HS256** (HMAC-SHA256). `jsonwebtoken` is used with no explicit `algorithm`
  option, so it defaults to HS256, and the system self-reports HS256
  (`system-crypto.ts:302` — `getSystemKeyStatus()` returns `algorithm: "HS256"`).
- **Secret source** (`system-crypto.ts:22-66`, `initializeJWTSecret`):
  1. `process.env.JWT_SECRET` if present **and length ≥ 64**.
  2. Otherwise the `JWT_SECRET=` line in `${DATA_DIR}/.env` (must be length ≥ 64).
     `DATA_DIR` defaults to `./db/data` (`system-crypto.ts:30`).
  3. Otherwise auto-generated: `crypto.randomBytes(32).toString("hex")` → a **64-char hex
     string**, written back to `${DATA_DIR}/.env` (`system-crypto.ts:198-212`).
- The secret is the raw string (hex text), used directly as the HMAC key — it is **not**
  hex-decoded before signing. The Elixir port must treat the `JWT_SECRET` string verbatim
  as the HMAC key.

### Payload / claim shape

`JWTPayload` (`auth-manager.ts:39-46`):

```ts
interface JWTPayload {
  userId: string;        // the app user id (a nanoid), NOT "sub"
  sessionId?: string;    // a nanoid; present for real login sessions
  pendingTOTP?: boolean; // true ONLY for the interim "TOTP required" token
  dataKeyWrap?: {...};   // legacy upgrade shim, normally absent (see note below)
  iat?: number;          // added by jsonwebtoken
  exp?: number;          // added by jsonwebtoken from expiresIn
}
```

Key facts for the port:

- The user identity claim is **`userId`**, a top-level custom claim. There is **no `sub`**,
  **no `isAdmin`**, **no `username`** in the token. Admin status and username are always
  re-read from the DB on each request (e.g. `createAdminMiddleware` at `auth-manager.ts:937`).
- `sessionId` is a separate nanoid, generated in `generateJWTToken` and also stored as a
  row in the `sessions` table (`auth-manager.ts:293-318`). Its presence makes the token
  "session-bound": verification and middleware reject the token if the session row is gone
  or expired.
- `pendingTOTP: true` marks the short-lived interim token returned by `/users/login` when
  2FA is required. Any auth middleware or WS handler rejects a `pendingTOTP` token for
  normal access (`auth-manager.ts:706-711`, `929-934`; `terminal/index.ts:140`).
- `dataKeyWrap` is a backward-compat field for pre-2.5 tokens (`auth-manager.ts:231-254`).
  New tokens do not set it; the Elixir port can omit it.

### Expiration duration (`generateJWTToken`, `auth-manager.ts:256-331`)

- `pendingTOTP` interim token: `"10m"` (set by caller at `users.ts:1551-1554`).
- `rememberMe`: `"30d"`.
- Default: `${session_timeout_hours}h` where `session_timeout_hours` is a settings-table
  value, default 24 → `"24h"` (`auth-manager.ts:271-285`).
- OIDC desktop/mobile logins force 30-day cookies regardless (`users.ts:1366-1371`).
- `expiresIn` strings are parsed by `parseExpiresIn` (`auth-manager.ts:333-352`) supporting
  `s`/`m`/`h`/`d` suffixes.

### Transmission — cookie AND bearer

Both are accepted; the cookie is primary for browsers, the header for native clients.

- **Cookie name: `jwt`.** Set on successful login/TOTP/OIDC via
  `res.cookie("jwt", token, getSecureCookieOptions(req, maxAge))`.
  Cookie options (`getSecureCookieOptions`, `auth-manager.ts:579-590`):
  `httpOnly: true`, `secure: req.secure || x-forwarded-proto === "https"`,
  `sameSite: "lax"`, `path: "/"`, `maxAge`.
- **`Authorization: Bearer <token>` header.** Read as a fallback when the cookie is
  absent (`createAuthMiddleware`, `auth-manager.ts:680-687`). The frontend only attaches
  this header in **Electron** mode, pulling the JWT from `localStorage["jwt"]`
  (`main-axios.ts:426-440`). It also sets `X-Electron-App: true` there.
- The **token is returned in the JSON body only for native app requests**
  (`isNativeAppRequest`: User-Agent starts with `Termelix-Mobile/` OR header
  `X-Electron-App: true` — `users.ts:111-116`). Login response spreads
  `...(isNativeAppRequest(req) ? { token } : {})` (`users.ts:1595`). Browser clients never
  receive the token in the body; they rely on the httpOnly `jwt` cookie.
- **API keys** are a separate scheme: a token beginning with `tmx_` is treated as an API
  key, not a JWT — matched by prefix then `bcrypt.compare` against a stored hash
  (`auth-manager.ts:693-695`, `601-668`). Not JWT; out of scope for the port's JWT logic
  but the middleware branch must exist so `tmx_...` bearer tokens are not fed to JWT verify.

### Verification (`verifyJWTToken`, `auth-manager.ts:354-399`)

1. `jwt.verify(token, secret)` (HS256).
2. If `payload.sessionId` present → look up the session row; **return null if missing**
   (revoked/expired-and-cleaned sessions therefore invalidate the token).
3. Returns the decoded payload or `null`.

The auth middleware additionally, for session-bound tokens, checks `session.expiresAt`,
revokes+`clearCookie("jwt")`+401 on expiry, and asynchronously touches `lastActiveAt`
(`auth-manager.ts:713-780`).

---

## 2. Registration

### `POST /users/create` (`users.ts:170-309`)

Frontend: `registerUser()` → `authApi.post("/users/create", {username, password})`
(`main-axios.ts:1641-1654`).

- **Body:** `{ username: string, password: string }`.
- **Guards / errors:**
  - Registration disabled → `403 {error: "Registration is currently disabled"}`.
    `isRegistrationAllowed()`: env `ALLOW_REGISTRATION` (`"true"`/`"false"`), else setting
    `allow_registration`, default **true** (`users.ts:78-87`).
  - Missing/blank username or password → `400 {error: "Username and password are required"}`.
  - Username already exists → `409 {error: "Username already exists"}`.
  - Encryption setup failure → user rolled back, `500 {error: "Failed to setup user security - user creation cancelled"}`.
- **Password hash:** `bcrypt.hash(password, 10)` — bcryptjs, cost factor **10**
  (`users.ts:209`). Stored in `users.password_hash`. The Elixir port must verify against
  standard bcrypt (`$2a$`/`$2b$`, 10 rounds).
- **User id generation:** `id = nanoid()` (`users.ts:210`). Default `nanoid` — **21
  characters**, URL-safe alphabet `A-Za-z0-9_-` (the library's default `urlAlphabet`). No
  custom length or alphabet is passed anywhere user ids are minted (also `users.ts:896,1184`).
  The id is the `users.id` TEXT primary key and the value of the JWT `userId` claim.
- **First-user-becomes-admin:** `createFirstLocalUser(...)` returns `{ isFirstUser }`
  (`users.ts:212-228`). The default role is `"admin"` when `isFirstUser`, else `"user"`
  (`users.ts:231`). `is_admin: isFirstUser` is echoed in the response.
- **Per-user DEK creation:** `authManager.registerUser(id, password)` →
  `UserKeyManager.createUserDEK(userId)` (`auth-manager.ts:116-120`, `user-keys.ts:108-116`).
  - Stored as a **settings-table row keyed `user_dek_v3_<userId>`** (`user-keys.ts:45-47`).
  - Value = 32 random bytes (`DEK_LENGTH = 32`) wrapped with **AES-256-GCM**; the wrap key
    is `HKDF-SHA256(masterKey = ENCRYPTION_KEY, salt = "", info = "termix:dek-wrap:v3:<userId>", 32 bytes)`,
    with **AAD = `<userId>` (utf8)**. Serialized JSON `{v:3, alg:"aes-256-gcm", iv, ct, tag,
    createdAt}` with iv/ct/tag base64 (`user-keys.ts:164-195`). The DEK is created at
    registration and is what later decrypts the host secret fields.
- **Success 200 body:**
  ```json
  { "message": "User created",
    "is_admin": <boolean firstUser>,
    "toast": { "type": "success", "message": "User created: <username>" } }
  ```

### `POST /users/admin-create` (`user-admin-routes.ts:374+`)

Frontend: `adminCreateUser()` (`main-axios.ts:1656-1669`). Admin-only.

- Caller must be admin, else `403 {error: "Not authorized"}`.
- Body `{username, password}`; `400` on missing, `409` on existing username.
- Creates a **non-admin** user (`isAdmin: false`), assigns role `"user"`, `id = nanoid()`,
  `bcrypt.hash(password, 10)`, creates the DEK (`registerUser`). Same rollback-on-encryption
  -failure behavior.

---

## 3. Login

### `POST /users/login` (`users.ts:1426-1614`)

Frontend: `loginUser(username, password, rememberMe)` →
`authApi.post("/users/login", {username, password, rememberMe})` (`main-axios.ts:1671-1724`).

- **Body:** `{ username: string, password: string, rememberMe?: boolean }`.
- **Error ladder:**
  - Missing username/password → `400 {error: "Invalid username or password"}`.
  - Rate limited (per IP+username) → `429 {error: "Too many login attempts. Please try
    again later.", remainingTime}`.
  - Password login disabled → `403 {error: "Password authentication is currently disabled"}`
    (`isPasswordLoginAllowed`, `users.ts:89-98`).
  - User not found → `401 {error: "Invalid username or password"}`.
  - OIDC-only user (no password hash) trying password login →
    `403 {error: "This user uses external authentication"}`.
  - Bad password (`bcrypt.compare`) → `401 {error: "Invalid username or password"}`.
  - DEK unlock failure → `401 {error: "Incorrect password"}`.
- **Password verification:** `bcrypt.compare(password, userRecord.passwordHash)`
  (`users.ts:1495`). bcryptjs; hashes are standard bcrypt `$2a$`/`$2b$` cost 10.
- **TOTP / 2FA fold-in** (`users.ts:1536-1562`):
  - If `userRecord.totpEnabled` and the device is **not** a trusted device:
    generate an interim token `generateJWTToken(id, {pendingTOTP: true, expiresIn: "10m"})`
    and return **200** (no cookie set):
    ```json
    { "success": true, "requires_totp": true,
      "temp_token": "<pendingTOTP JWT>", "rememberMe": <bool> }
    ```
  - If TOTP enabled but device is trusted, TOTP is bypassed and login proceeds normally.
- **Full success** (no TOTP, or trusted device):
  - Mint a session token `generateJWTToken(id, {rememberMe, deviceType, deviceInfo})` —
    this creates a `sessions` row (see §5).
  - Set the **`jwt` cookie** with `maxAge = rememberMe ? 30d : session_timeout_hours*3600*1000`
    (`users.ts:1598-1608`).
  - Body:
    ```json
    { "success": true,
      "is_admin": <bool>,
      "username": "<username>",
      "token": "<jwt>"   // present ONLY for native app requests
    }
    ```
  - `500 {error: "Login failed"}` on unexpected error.

The frontend stores `response.data.token` into `localStorage["jwt"]` when present
(`main-axios.ts:1702-1704`) and calls `markUserAuthenticated()` on non-TOTP success.

### `POST /users/totp/verify-login` (second login step) (`user-totp-routes.ts:505-679`)

Frontend: `verifyTOTPLogin(temp_token, totp_code, rememberMe)` →
`authApi.post("/users/totp/verify-login", ...)`.

- **Body:** `{ temp_token: string, totp_code: string, rememberMe?: boolean }`.
- Validates `temp_token` is a `pendingTOTP` JWT; else `401 {error: "Invalid temporary token"}`.
- Verifies `totp_code` via `speakeasy.totp.verify({encoding:"base32", window:2})`, or a
  backup code (consumed on use). Bad code → `401 {error: "Invalid TOTP code",
  remainingAttempts}`. Rate-limited → `429 {..., code:"TOTP_RATE_LIMITED"}`.
- On success mints a real session token, sets the **`jwt` cookie** (same maxAge logic), and
  returns:
  ```json
  { "success": true, "is_admin": <bool>, "username": "<u>",
    "userId": "<id>", "is_oidc": <bool>, "totp_enabled": true,
    "token": "<jwt>"   // native app only }
  ```

### OIDC login (context)

`GET /users/oidc/authorize` returns `{auth_url, state, nonce}`; `GET /users/oidc/callback`
performs the exchange and either sets the `jwt` cookie and redirects, or (for
token-callback / mobile) appends `?token=<jwt>` to the redirect (`users.ts:625-1391`).
Same JWT shape and cookie semantics as above.

---

## 4. "Who am I"

### `GET /users/me` (`users.ts:1749-1785`)

Frontend: `getUserInfo()` → `authApi.get("/users/me")` (`main-axios.ts:1772-1780`).
Requires auth (`authenticateJWT`).

- **200 body (exact field names the frontend consumes):**
  ```json
  { "userId": "<id>",
    "username": "<username>",
    "is_admin": <bool>,
    "is_oidc": <bool>,
    "is_dual_auth": <bool>,     // has BOTH a password hash and an oidc identifier
    "totp_enabled": <bool>,
    "show_donation_modal": <bool> }
  ```
- Errors: `401 {error: "Invalid userId"}`, `401 {error: "User not found"}`,
  `500 {error: "Failed to get username"}`.
- The frontend `UserInfo` type (`main-axios.ts:197-206`) also has optional
  `password_hash`, `data_unlocked` — **not** returned by `/users/me`; they come from other
  endpoints. Only the seven fields above are emitted here.

### `GET /users/me/token` (`users.ts:1850-1854`)

Returns `{ token: <jwt cookie value> | null }`. For mobile WebViews that cannot read the
httpOnly cookie. Requires auth.

### Auxiliary unauthenticated status endpoints (frontend bootstraps with these)

- `GET /users/setup-required` → `{ setup_required: <count===0> }` (`users.ts:1870`).
- `GET /users/registration-allowed` → `{ allowed: <bool> }` (`users.ts:1953`).
- `GET /users/password-login-allowed` → `{ allowed: <bool> }` (`users.ts:2146`).
- `GET /users/count` → `{ count }` **admin only**, else `403 {error:"Admin access required"}`.
- `GET /users/data-status` → `{ unlocked, message }` (auth) (`user-data-access-routes.ts:105`).
- `POST /users/unlock-data` `{password}` → re-derives DEK, may refresh the session token +
  reset cookie, `{success:true, message:"Data unlocked successfully"}`; wrong password →
  `401 {error:"Invalid password"}` (`user-data-access-routes.ts:42-89`).

---

## 5. Logout and session handling

### `POST /users/logout` (`users.ts:1630-1653`)

Requires auth. Revokes the current session (or all of the user's sessions if no
`sessionId`), then `res.clearCookie("jwt", getClearCookieOptions(req))` and returns
`{ success: true, message: "Logged out successfully" }`. `500 {error:"Logout failed"}` on error.

`getClearCookieOptions` (`auth-manager.ts:592-599`): `httpOnly`, `secure` (same rule),
`sameSite:"lax"`, `path:"/"` (no maxAge).

### `sessions` table (`schema.ts:56-74`)

DB columns are **snake_case**; the Drizzle model exposes camelCase properties.

| Property (JSON/model) | DB column | Notes |
|---|---|---|
| `id` | `id` (PK, TEXT) | a `nanoid()`; equals the JWT `sessionId` |
| `userId` | `user_id` | FK → users.id, `onDelete: cascade` |
| `jwtToken` | `jwt_token` | the issued token stored server-side |
| `deviceType` | `device_type` | one of `"web" | "desktop" | "mobile"` |
| `deviceInfo` | `device_info` | human string, see below |
| `oidcSub` | `oidc_sub` | nullable; set for OIDC logins |
| `oidcSid` | `oidc_sid` | nullable; OIDC session id for back-channel logout |
| `ssoProviderId` | `sso_provider_id` | nullable |
| `createdAt` | `created_at` | ISO string |
| `expiresAt` | `expires_at` | ISO string; enforced by middleware |
| `lastActiveAt` | `last_active_at` | touched on each authenticated request |

- **Row creation**: only inside `generateJWTToken` when both `deviceType` and `deviceInfo`
  are supplied and the token is **not** `pendingTOTP` (`auth-manager.ts:292-328`). The
  `sessionId = nanoid()` is embedded in the JWT and used as the row `id`.
- `deviceType` / `deviceInfo` come from `parseUserAgent(req)`
  (`user-agent-parser.ts:44-207`): `type` is `web|desktop|mobile`; `deviceInfo` is e.g.
  `"Chrome 120 on macOS"` (web), `"Termelix Desktop on <os>"`, or `"Termelix Mobile on <os>"`.
- **Lookup**: `verifyJWTToken` and the auth middleware load the row by `sessionId`; a
  missing row → `401 {error:"Session not found", code:"SESSION_NOT_FOUND"}`; an expired row
  → revoke + `401 {error:"Session has expired", code:"SESSION_EXPIRED"}` (both clear the
  `jwt` cookie) (`auth-manager.ts:713-780`).
- Expired sessions are also swept every 5 minutes (`auth-manager.ts:89-102`, `533-554`).

---

## 6. Host listing

### `GET /host/db/host` (`host.ts:1242-1349`)

Frontend: `loadSSHHostsFromApi()` → `sshHostApi.get("/db/host")`
(`ssh-host-management-api.ts:24-27`). `sshHostApi` base is `/host`, so the wire path is
**`GET /host/db/host`**. Middlewares: `authenticateJWT`, `requireDataAccess` (attaches the
user's DEK to the request). Response: a **JSON array** of host objects.

Pipeline:

1. Resolve RBAC-visible hosts: the user's own rows plus shared rows they have access to
   (`host.ts:1258-1274`).
2. **Own rows are decrypted** with the user's DEK via
   `DataCrypto.decryptRecord("ssh_data", row, userId, dek)` (`host.ts:1276-1296`). Rows that
   fail to decrypt are skipped. Shared rows are left as-is (secrets never exposed).
3. Each row → `transformHostResponse(row)` (`host-normalizers.ts:304-388`) plus injected
   fields `isShared`, `permissionLevel`, `sharedExpiresAt`, `ownerUsername`
   (`host.ts:1314-1330`).
4. `resolveHostCredentials` merges in linked-credential values where applicable.
5. **Sanitize** (`host.ts:1332-1339`):
   - Own hosts → `stripSensitiveFields(host)`.
   - Shared hosts → `sanitizeHostForRecipient(host, permissionLevel)`.
6. `res.json(sanitized)`.

`500 {error:"Failed to fetch SSH data"}` on error; `400 {error:"Invalid userId"}` if the
token has no userId.

### Field naming: snake_case DB → camelCase JSON

The `ssh_data` table columns are snake_case (`schema.ts:112-231`, e.g. `enable_terminal`,
`auth_type`, `sudo_password`, `tunnel_connections`, `default_path`, `use_warpgate`), but
Drizzle maps them to camelCase model properties, and `transformHostResponse` both reads and
emits **camelCase**. **The JSON returned to the frontend is entirely camelCase** — matching
the frontend `Host` type (`src/types/index.ts:110-223`). The Elixir port must emit camelCase
keys regardless of DB column naming.

### Inert columns (remote desktop)

The hosts table still carries the RDP/VNC/Telnet columns (`enable_rdp`, `enable_vnc`,
`enable_telnet`, `rdp_*`, `vnc_*`, `telnet_*`, `domain`, `security`, `ignore_cert`,
`guacamole_config`) because no destructive migration was run. They are **inert**: the Ecto
schema does not map them, and nothing in the API reads or writes them. They are absent from
every request and response shape described below. See `ROADMAP.md` for the removal record.

None of them are read. The legacy fold keys off the ordinary mapped columns `connection_type`,
`enable_ssh` and `port`: a host that stored `connection_type` in (`rdp`, `vnc`, `telnet`) is
emitted with `connectionType: "ssh"` and `enableSsh: true`, so pre-removal remote-desktop hosts
appear as ordinary SSH hosts instead of listing but being unopenable. Rows that stored
`connection_type = "ssh"` keep their own `enableSsh`.

`port` is folded with them, and it has to be: those rows put the *remote-desktop* port
(3389/5900/23) in `port` and the SSH port in `ssh_port`, while every SSH consumer prefers
`port`. A fold that rewrote only `connection_type`/`enable_ssh` would leave the host openable
but silently dialling RDP/VNC/Telnet. `Termelix.Hosts.effective_ssh_port/1` is the single
definition — `ssh_port || 22` for a legacy row, the usual `port || ssh_port || 22` otherwise —
and both the normalizer and every connect path (terminal, SFTP, Docker, tmux, tunnels,
metrics, Proxmox) go through it. `Termelix.Rbac.list_shared_hosts/2` (`GET /rbac/shared-hosts`)
is the one DB-side `select:` that reports a port, so it fetches `connection_type`/`ssh_port`
alongside and folds the result in Elixir before returning. Columns the fold **does not** touch: `username`, `ip`, the
`enable_*` feature toggles other than `enable_ssh`, and the inert list above.

The fold is read-only: nothing is rewritten on disk until the host is next saved (re-saving in
the editor persists the corrected `port`), and there is no migration.

The retained `rdp_password` / `vnc_password` / `telnet_password` ciphertext is **excluded from
the user data export** (`GET /users/data-export`): those fields left the encrypted-field map,
so nothing decrypts them. They await a purge migration.

### Secret fields — always stripped, never sent to the browser

`stripSensitiveFields` (`host-normalizers.ts:206-232`) deletes these keys entirely:

```
key, keyPassword, autostartKey, autostartKeyPassword, password, sudoPassword,
socks5Password, autostartPassword
```

and adds presence booleans: **`hasKey`, `hasKeyPassword`, `hasPassword`, `hasSudoPassword`**.

(These same fields are the encrypted-at-rest set — `lazy-field-encryption.ts:296-308`
lists the `ssh_data` sensitive fields; note the encrypted set and the stripped set overlap
but the stripped set additionally always removes them from the response.)

### `transformHostResponse` output normalization (`host-normalizers.ts:304-388`)

- `tags`: comma-string → `string[]` (empty array if none).
- Boolean coercions for all `enable*` / `show*InSidebar` flags. `enableFileManager` defaults
  to `true` unless explicitly `false`. `forceKeyboardInteractive` is `=== "true"` (stored as
  text). `useWarpgate`, `pin` → booleans.
- Migration heuristic for old hosts that only had `connectionType`: infers `enableSsh` from
  `connectionType`.
- Port defaults: `sshPort ?? port ?? 22`.
- JSON.parse'd into objects/arrays: `tunnelConnections` (→`[]`), `jumpHosts` (→`[]`),
  `quickActions` (→`[]`), `statsConfig` (→`undefined`), `terminalConfig`, `dockerConfig`,
  `proxmoxConfig`, `socks5ProxyChain` (→`[]`), `portKnockSequence` (→`[]`).

### Shared-host reduction (`sanitizeHostForRecipient`, `host-normalizers.ts:285-302`)

- Always strips secrets (all permission levels).
- For `permissionLevel === "connect"`, additionally reduces the object to the
  `CONNECT_LEVEL_FIELDS` allowlist (`host-normalizers.ts:235-278`): id, ownership/share
  metadata, connection essentials (name/ip/port/username/folder/tags/pin/authType/
  connectionType/credentialId), the enable/show flags, the ssh port, `defaultPath`,
  `scpLegacy`, `tunnelConnections`, `jumpHosts`, `createdAt`, `updatedAt`.

### The full host object shape (frontend `Host`, `src/types/index.ts:110-223`)

Identity/connection: `id:number`, `name`, `ip`, `port:number`, `username`, `folder`,
`tags:string[]`, `pin:boolean`, `authType` (one of
`password|key|credential|none|opkssh|tailscale|agent|vault`), `connectionType`
(`ssh`), `userId`, `credentialId?`, `vaultProfileId?`,
`overrideCredentialUsername?`, `useWarpgate?`, `keyType?`, `forceKeyboardInteractive?`.

Feature flags: `enableTerminal`, `enableSessionLogging`, `enableCommandHistory`,
`enableTunnel`, `enableFileManager`, `scpLegacy?`, `enableDocker`, `enableProxmox`,
`enableTmuxMonitor`, `showTerminalInSidebar`, `showFileManagerInSidebar`,
`showTunnelInSidebar`, `showDockerInSidebar`, `showServerStatsInSidebar`.

Config blobs (parsed): `tunnelConnections[]`, `jumpHosts?[]`, `quickActions?[]`,
`statsConfig?`, `terminalConfig?`, `proxmoxConfig?`, `dockerConfig?`,
`socks5ProxyChain?`, `portKnockSequence?`, `defaultPath`, `notes?`.

Protocol details: `enableSsh?`, `sshPort?`.

Secret **presence** booleans (added by strip): `hasKey?`, `hasKeyPassword?` (plus
`hasPassword`, `hasSudoPassword` emitted by the backend).

Timestamps + share metadata: `createdAt`, `updatedAt`, `isShared?`,
`permissionLevel?` (`connect|view|edit|manage`), `sharedExpiresAt?`, `ownerUsername?`.

**Secrets that are NEVER present in the list response:** `password`, `key`, `keyPassword`,
`sudoPassword`, `socks5Password`, `autostartPassword`, `autostartKey`,
`autostartKeyPassword`.

### Related host routes (same `/host` mount)

- `GET /host/db/host/:id` — single host; owner gets `stripSensitiveFields`, non-owner gets
  `sanitizeHostForRecipient` (`host.ts:1375-1465`).
- `GET /host/db/host/:id/password?field=password|sudoPassword` — **Node only, not ported and
  not portable.** It was the copy-password feature's single-secret fetch (`host.ts:1492-1544`);
  reading a stored secret back out contradicts the write-only-secrets rule in `CLAUDE.md`, so
  the Elixir `/host` scope (`router.ex:192-207`) has no such route. The SPA still calls it from
  `src/ui/api/credentials-api.ts:97-109` — consumed by the terminal's sudo-password auto-fill
  (`Terminal.tsx:684-688`), the sidebar copy-password action (`SidebarTree.tsx:333`) and
  `SshToolsPanel.tsx:76` — but all three `catch { return null }`, so those features silently
  no-op against this backend rather than erroring. Removing the dead SPA calls is a separate
  follow-up.
- `GET /host/db/host/:id/export` — includes decrypted credentials (`host.ts:1570+`).
- `POST /host/db/host` (create), `PUT /host/db/host/:id` (update), `DELETE /host/db/host/:id`.
- `POST /host/db/host/:id/wake` — broadcasts a Wake-on-LAN magic packet for the host's stored
  `macAddress` (to `wolBroadcastAddress`, default `255.255.255.255`, UDP port 9) →
  `{ success: true }`, `400` when no valid MAC is configured, `404` when the caller does not
  own the host.
- `POST /host/bulk-import`, `POST /host/ssh-config-import`, `PATCH /host/bulk-update`,
  autostart routes, `POST /host/db/proxy/test` (`ssh-host-management-api.ts`).

---

## 7. Auth response headers, error shapes, status codes

### Error body shape

Overwhelmingly **`{ "error": "<message>" }`**, sometimes with a **`code`** discriminator.
A few success/info bodies use `message`. The frontend reads `error` first, then `message`
(`main-axios.ts:1015-1019`, `handleApiError`). The Elixir port should use `{"error": ...}`
(+ optional `{"code": ...}`) as the canonical error envelope.

### 401 (Unauthorized) variants (auth middleware, `auth-manager.ts:677-797`)

| Condition | Body |
|---|---|
| No token | `{error: "Missing authentication token"}` |
| JWT invalid/expired signature | `{error: "Invalid token"}` (+ clears `jwt` cookie) |
| `pendingTOTP` token used for normal access | `{error: "TOTP verification required", code: "TOTP_REQUIRED"}` |
| Session row missing | `{error: "Session not found", code: "SESSION_NOT_FOUND"}` (clears cookie) |
| Session expired | `{error: "Session has expired", code: "SESSION_EXPIRED"}` (clears cookie) |

The frontend treats `SESSION_EXPIRED`, `SESSION_NOT_FOUND`, `Invalid token`, and (when
previously authenticated) `Authentication required` / `Missing authentication token` as a
logout trigger — clears the `jwt` cookie and resets auth state (`main-axios.ts:357-386`,
`562-616`).

### 403 (Forbidden) variants

- `{error: "Admin access required"}` (non-admin hitting admin route,
  `auth-manager.ts:950`; also API-key admin path `:651`).
- `{error: "Not authorized"}` (route-local admin checks, e.g. `users.ts:332`).
- Impersonation (`X-Admin-Target-User` header handling, `auth-manager.ts:805-880`):
  `{error:"Admin access required", code:"IMPERSONATION_DENIED"}`,
  `{error:"Impersonation is not allowed for this route", code:"IMPERSONATION_NOT_ALLOWED"}`,
  `{error:"Impersonation is not allowed with API key authentication", code:"IMPERSONATION_NOT_ALLOWED"}`.
- `404 {error:"Target user not found", code:"TARGET_USER_NOT_FOUND"}` and
  `423 {error:"Target user's data stays locked until their next login", code:"TARGET_DATA_LOCKED"}`
  for impersonation edge cases.

### Auth-related response headers

- Set-Cookie for `jwt` on login/TOTP/OIDC/unlock; `clearCookie` for `jwt` on
  logout/invalid/expired. No custom auth response headers beyond the cookie.
- The back-channel logout route sets `Cache-Control: no-store` (`users.ts:1677`).
- CORS is applied per service via `createCorsMiddleware` + `cookieParser()`; requests are
  credentialed (`withCredentials: true` on the client). The port must echo credentials-
  compatible CORS (allow-credentials + specific origin, not `*`) for the cookie to flow.

### Admin impersonation header (data-plane only)

`X-Admin-Target-User: <userId>` lets an admin act on another user's data, but only for the
allowlisted paths `^/host/db/`, `^/credentials(/|$)`, `^/snippets(/|$)`
(`auth-manager.ts:70-78`). On success `req.userId` becomes the target user. Relevant to the
host-list route (an admin can list another user's hosts via this header).

---

## 8. INTERNAL_AUTH_TOKEN (service-to-service auth)

### Source (`system-crypto.ts:157-196`, `getInternalAuthToken`)

1. `process.env.INTERNAL_AUTH_TOKEN` if length ≥ 32.
2. Else the `INTERNAL_AUTH_TOKEN=` line in `${DATA_DIR}/.env` (length ≥ 32).
3. Else auto-generated `crypto.randomBytes(32).toString("hex")` (64 hex chars), written to
   `.env` (`system-crypto.ts:248-265`).

### Purpose and header names

It authenticates **backend-to-backend** calls between the split services (the tunnel,
metrics, alert, and autostart subsystems live in separate processes/ports and cannot present
a user JWT). It is a shared static secret, compared by exact string equality — **not** a JWT.

Header names in use (inconsistent casing across subsystems — the port must honor each as
found):

- **`X-Internal-Auth-Token`** — the primary one. Sent by the tunnel manager
  (`hosts/tunnel/manager.ts:99`, `hosts/tunnel/routes.ts:260`); validated by the host
  internal routes which read `req.headers["x-internal-auth-token"]`
  (`host-internal-routes.ts:25,115`).
- **`x-internal-auth`** — used by the metrics service (`hosts/metrics/index.ts:2802`) and
  alert trigger (`utils/alert-trigger.ts:18`).

### Endpoints gated by it

- `GET /host/db/host/internal` — autostart hosts with auto-start tunnels. Missing/mismatched
  token → `403 {error:"Forbidden"}` (`host-internal-routes.ts:23-95`).
- `GET /host/db/host/internal/all` — all hosts (internal). Missing token →
  `401 {error:"Internal authentication token required"}`; mismatched →
  `401 {error:"Invalid internal authentication token"}` (`host-internal-routes.ts:113-170`).
  These return a **reduced host projection** (id, userId, name, ip, port, username, authType,
  keyType, credentialId, tunnelConnections, and sidebar/enable flags) — **no secrets**.

### Does the user-facing host list or terminal path depend on it? **No.**

- The user-facing host list (`GET /host/db/host`) authenticates with the **user JWT**
  (cookie or bearer) — it never consults `INTERNAL_AUTH_TOKEN`.
- The terminal WebSocket (port 30002) authenticates the connection with the **user JWT**,
  read from the `jwt` cookie, then `Authorization: Bearer`, then `?token=` query param, and
  runs it through `verifyJWTToken` (rejecting `pendingTOTP`) — see §9. It does not use
  `INTERNAL_AUTH_TOKEN` for user auth. (It does mint a short user JWT for one internal
  OPKSSH callback at `terminal/index.ts:1845`, but that is unrelated to connection auth.)

`INTERNAL_AUTH_TOKEN` is therefore only needed for the port if you also reimplement the
split-service internal endpoints (autostart tunnels, cross-service metrics/alerts). The core
auth + host-list + terminal contract the React app depends on runs entirely on the user JWT.

---

## 9. Terminal WebSocket auth (port 30002) — for completeness

`terminal/index.ts:108-171`:

1. Extract token: `Cookie: jwt=<...>` (URL-decoded) → else `Authorization: Bearer <...>` →
   else `?token=<...>` query param. None → `ws.close(1008, "Authentication required")`.
   (The browser sends the httpOnly cookie automatically; Electron/mobile append
   `?token=<localStorage jwt>` — `Terminal.tsx:981-1002`.)
2. `payload = await authManager.verifyJWTToken(token)`. Reject if no `payload.userId` or
   `payload.pendingTOTP` → close 1008.
3. `userId = payload.userId`, `sessionId = payload.sessionId`.
4. Require an unlocked DEK (`DataCrypto.getUserDataKey(userId)`); if locked, send
   `{type:"error", message:"Data locked - re-authenticate with password", code:"DATA_LOCKED"}`
   and close 1008.

Same JWT, same secret, same verification path as the HTTP side — so a single JWT
implementation in the Elixir port serves both HTTP and WS.

---

## 10. Quick reference — Elixir port checklist

- JWT: HS256, key = raw `JWT_SECRET` string (or `${DATA_DIR}/.env`, or auto-gen 64-hex).
  Claims: `userId`, optional `sessionId`, optional `pendingTOTP`, plus `iat`/`exp`. No
  `sub`/`isAdmin`.
- Accept token from `jwt` cookie first, then `Authorization: Bearer`. Treat `tmx_*` as API
  keys, not JWT. Emit token in JSON body only for native clients
  (`X-Electron-App: true` or UA `Termelix-Mobile/*`).
- Cookie `jwt`: httpOnly, sameSite=lax, path=/, secure iff https/x-forwarded-proto=https.
- Registration `POST /users/create`; login `POST /users/login`; 2FA step
  `POST /users/totp/verify-login`; identity `GET /users/me`; logout `POST /users/logout`.
- bcrypt cost 10; user id = 21-char nanoid; per-user DEK stored under settings key
  `user_dek_v3_<userId>`.
- Host list `GET /host/db/host` → camelCase JSON array, secrets stripped, `hasKey`/
  `hasPassword`/`hasKeyPassword`/`hasSudoPassword` booleans added, shared hosts sanitized.
- Sessions table with snake_case columns; session-bound tokens require a live row.
- Error envelope `{error, code?}`; 401 codes `TOTP_REQUIRED`/`SESSION_NOT_FOUND`/
  `SESSION_EXPIRED`; clear the `jwt` cookie on those.
- `INTERNAL_AUTH_TOKEN` only for internal service-to-service endpoints; the user host-list
  and terminal paths do not use it.
