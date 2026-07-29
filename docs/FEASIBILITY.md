# Termelix → BEAM Port — Feasibility Study

**Date:** 2026-07-23 · **Decision: GO (no hard blockers)** · **Target stack: Elixir + Phoenix + Ecto (SQLite), OTP-native `:ssh`/`:crypto`/`:eldap`.**

> **Historical document.** This is the pre-port analysis and is kept as written. One item has since
> been superseded: **every mention of Guacamole / guacd / RDP / VNC / Telnet below** — the port-30008
> row in §2, the library row in §3, the guac items in §4 and §5's route list, and "guacamole" in the
> M4+ breadth list in §6 — describes a subsystem that was ported and then **removed**. See the
> supersession note in §4 (item 3) and the removal record in `ROADMAP.md`.

## 1. What Termelix is

Self-hosted SSH / remote-desktop management platform. Source: `../termelix-frontend` (v2.5.1).

- **Frontend:** React 19 + Vite + Electron. ~unaffected by the port — it talks to the backend over
  same-origin HTTP + WebSocket paths (see §5). **Reused as-is.**
- **Backend (the port target):** Node/TypeScript, **~103K LOC over ~230 source files** (+~90 test files).
  Structured as **~12 independent Express/`ws` servers** on ports 30001–30012, fronted by **nginx** (:8080)
  which routes by path. SQLite data store (49 tables), encrypted at rest.

## 2. Service topology (Node → BEAM)

| Port | Node service | Responsibility | BEAM home |
|------|--------------|----------------|-----------|
| 30001 | `database/database.ts` | Main REST API: users, hosts, credentials, rbac, snippets, vault, alerts, termelix-id, proxmox, audit… | Phoenix Router + controllers |
| 30002 | `hosts/terminal` | SSH terminal WS (xterm) | Phoenix Channel + `:ssh` |
| 30003 | `hosts/tunnel` | SSH tunnels, SOCKS, C2S relay WS | GenServer per tunnel + `:ssh` |
| 30004 | `hosts/file-manager` | SFTP browse/transfer engine | Channel/controller + `:ssh_sftp` |
| 30005 | `hosts/metrics` | Host metric collectors + alert engine | GenServer collectors + `:ssh` exec |
| 30006 | `services/dashboard` | Dashboard aggregation | Controller |
| 30007 | `hosts/docker` | Container mgmt (docker/podman over SSH) | Controller + `:ssh` exec |
| 30008 | `hosts/guacamole` | RDP/VNC/Telnet WS ↔ guacd | Channel + reimplemented guac proxy |
| 30009 | `hosts/docker/console` | Docker exec console WS | Channel + `:ssh` |
| 30010 | `hosts/tmux` | tmux monitor | Controller/GenServer |
| 30011 | `hosts/serial` | Serial console WS | Channel + `circuits_uart` |
| 30012 | `services/homepage` | Homepage/service-links (ping/proxy/rss/favicon) | Controller |

**Key simplification:** In production every one of these is reached through nginx on a **single origin**
by path (`/users`, `/host`, `/ssh/websocket/`, `/guacamole/websocket/`, …). A **single Phoenix endpoint**
that preserves those external paths replaces nginx **and** all 12 Node processes, under one OTP supervision
tree — no internal port fan-out needed, and the React frontend needs no changes in production.

## 3. Dependency mapping — every Node dep has a BEAM path

| Node dependency | Purpose | BEAM equivalent | Risk |
|---|---|---|---|
| express / body-parser / cors / multer | HTTP, uploads | Phoenix / Plug / `Plug.Upload` | Low |
| ws | WebSocket servers | Phoenix Channels (Bandit/Cowboy) | Low |
| **ssh2** | SSH client (terminal, sftp, exec, forward) | **OTP `:ssh` + `:ssh_sftp` (native)** | Med |
| better-sqlite3 + drizzle-orm | SQLite + query builder | **Ecto + `ecto_sqlite3`/`exqlite`** | Low |
| jose / jsonwebtoken | JWT | `joken` (+ `jose`) | Low |
| bcryptjs | password hashing | `bcrypt_elixir` (reads existing `$2a$` hashes) | Low |
| speakeasy | TOTP | `nimble_totp` | Low |
| qrcode | TOTP QR | `eqrcode` | Low |
| @simplewebauthn/server | passkey/WebAuthn | `wax` | Med |
| ldapjs | LDAP auth | **OTP `:eldap` (native)** | Low-Med |
| socks (SocksClient) | SOCKS5 proxy dialing | thin `:gen_tcp` SOCKS5 client | Med |
| guacamole-lite | guac protocol WS↔guacd | **reimplement** (simple length-prefixed text proto) | Med-High |
| serialport | serial console | `circuits_uart` | Low-Med |
| node `crypto` (AES-256-GCM, HKDF-SHA256, whole-file GCM) | field + DB-file encryption | **OTP `:crypto` (native, byte-compatible)** | Low |
| undici / axios | outbound HTTP (proxmox, oidc, rss, ping) | `Req`/`Finch` | Low |
| jszip / js-yaml / nanoid / chalk | misc | `zip`/`yaml_elixir`/`nanoid`/IO.ANSI | Low |
| opkssh (bundled binary) | OpenPubkey SSH | shell out to same binary (unchanged) | Low |

## 4. Blocker analysis

Searched the three highest-risk subsystems for anything the BEAM **cannot** express:

1. **Crypto / data compatibility.** Field encryption = `AES-256-GCM` with per-field key
   `HKDF-SHA256(masterKey, salt, "<recordId>:<field>")`; DB file = `AES-256-GCM` over the whole SQLite
   blob with a length-prefixed JSON metadata header. Both are plain `:crypto` primitives → **byte-for-byte
   reproducible**, so the port can read an existing encrypted Termelix database. *No blocker.*
2. **SSH.** Uses password / pubkey / keyboard-interactive auth, `exec`, `shell`, SFTP, `forwardOut`
   (direct-tcpip), and **jump-host chaining** + optional **SOCKS5**. OTP `:ssh` covers auth/exec/shell/sftp
   natively; jump hosts map to bridging a `direct-tcpip` channel into `:ssh.connect/4` on a pre-connected
   socket; SOCKS5 is a small hand-rolled dialer. More work than importing a lib, but **no missing
   capability.** *No blocker.*
3. **Guacamole (RDP/VNC/Telnet).** `guacd` is an **external daemon in both worlds** (shipped as a separate
   container). `guacamole-lite` only speaks the Guacamole wire protocol between browser-WS and guacd-TCP —
   a documented, simple, length-prefixed text protocol. Reimplementing the proxy in Elixir is bounded work.
   *No blocker.* **Superseded:** the subsystem was ported, then removed — RDP, VNC and Telnet are no
   longer product features and `guacd` is no longer a runtime dependency. See `ROADMAP.md`.

**Non-blocking caveats (scoped, not fatal):**
- **Electron desktop packaging** currently embeds the Node backend. A BEAM backend would ship as an Erlang
  *release*; bundling that inside Electron is more awkward than bundling Node. The **primary deployment
  (self-hosted Docker server) is unaffected**, and the desktop client can point at a server. Desktop-embed
  packaging is deferred, not blocking.
- **opkssh, certbot** remain external runtime deps — identical to today. (`guacd` was one too until
  the remote-desktop removal; see §4.3.)

**Conclusion:** No hard technical blocker. The BEAM is in several respects a *better* fit — OTP supervision
for long-lived SSH sessions/pools/tunnels, native SSH/crypto/LDAP, and Phoenix Channels for the terminal/
tunnel/console streams. The single real cost is **scope** (~103K LOC), addressed by milestone delivery (§6).

## 5. Frontend contract (must be preserved)

Prod: same-origin paths via nginx (`/users`, `/host`, `/ssh`, `/ssh/websocket/`, `/ssh/tunnel/`,
`/ssh/file_manager`, `/guacamole`, `/guacamole/websocket/`, `/docker`, `/tmux_monitor`, `/homepage`,
`/alerts`, `/rbac`, `/credentials`, `/snippets`, `/vault`, `/termelix-id`, `/proxmox`, `/audit-logs`,
`/session_logs`, `/tailscale`, …). Dev: axios/`getApiUrl` hit `localhost:<port>` directly, overridable via
`VITE_API_HOST`. The port keeps the prod path contract → **React app runs unchanged behind the Phoenix
endpoint.**

## 6. Delivery plan (milestones)

M0 Scaffold: Phoenix umbrella-less app, config, supervision tree, health endpoint. ·
M1 Data layer: 49 Ecto schemas + migrations mirroring `schema.ts`; `:crypto` field + DB-file encryption
(data-compatible). · M2 Auth: users, JWT, sessions, bcrypt, TOTP, RBAC middleware. · M3 e2e vertical slice:
login → list hosts → **open SSH terminal via Phoenix Channel to a real host** (proves the full stack). ·
M4+ Breadth: credentials/hosts/snippets/vault CRUD, file-manager (SFTP), tunnels, metrics, docker, guacamole,
homepage — ported subsystem-by-subsystem with tests, each committed. Orchestrated fan-out (Fable coordinates,
Opus implements) for the parallelizable route/schema/collector work.

Toolchain present: Erlang/OTP 29, Elixir 1.20.2, Mix, hex, rebar3.
