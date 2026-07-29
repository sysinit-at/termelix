# Termix on the BEAM (Termelix)

An Elixir/Phoenix port of [Termix](https://github.com/Termix-SSH/Termix) — self-hosted SSH & remote
management — onto the Erlang VM. The original Node/TypeScript backend (~103K LOC across 12
micro-services fronted by nginx) is reimplemented as a **single supervised Phoenix app** that
preserves the exact external HTTP/WS paths, so the original **React frontend runs unchanged**.

Why the BEAM: OTP gives native SSH (`:ssh`), crypto (`:crypto`), and LDAP (`:eldap`); Phoenix
Channels/WebSockets fit the terminal/tunnel/console streams; and OTP supervision models the
long-lived SSH sessions, pools, and tunnels far better than Node singletons. The feasibility
study concluded **GO, no blockers**.

## Status

Working and verified end-to-end:

- **Data**: faithful 49-table schema, data-compatible with an existing Termix SQLite DB.
- **Crypto**: HKDF, AES-256-GCM field envelopes, v3 per-user DEK wrap — **byte-compatible with the
  Node implementation** (proven against Node-generated vectors).
- **Auth**: register / login (JWT `jwt` cookie) / `/users/me` / logout, bcrypt, sessions.
- **Hosts**: full CRUD, DEK-encrypted secrets, secret-stripped camelCase responses.
- **SSH terminal**: over WebSocket via OTP `:ssh` (connect/auth/PTY/shell/resize) — proven against
  an in-VM SSH daemon.
- **Credentials, snippets, user preferences**: CRUD.
- **Frontend**: the built React SPA is served same-origin from `priv/static/spa`.

## Quick start

Requires Erlang/OTP 26+ and Elixir 1.17+ (developed on OTP 29 / Elixir 1.20).

```sh
mix deps.get
mix ecto.create && mix ecto.migrate
./scripts/build-frontend.sh        # builds the React SPA into priv/static/spa (optional)
mix phx.server                     # http://localhost:4000
```

Root secrets (JWT/DB/encryption keys) are generated on first boot into `DATA_DIR/.env`
(`DATA_DIR` defaults to `./db/data`). To reuse an existing Termix database, point `DATABASE_PATH`
at it and provide the matching `ENCRYPTION_KEY`/`JWT_SECRET`/`DATABASE_KEY`.

```sh
mix test        # crypto compat, auth flow, SSH terminal, CRUD suites
```

## Container image

Multi-arch images (`linux/amd64`, `linux/arm64`) are built by CI from this repo plus the
[frontend fork](https://github.com/sysinit-at/termelix-frontend) and published to GHCR:

```sh
docker run -p 8080:8080 -v termelix-data:/app/data ghcr.io/sysinit-at/termelix:latest
```

## Layout

- `lib/termelix/crypto/` — HKDF, field crypto, DEK wrap, system keys (byte-compatible with Node)
- `lib/termelix/schema/` — Ecto schemas (schema.ts camelCase keys over snake_case columns)
- `lib/termelix/ssh/` — OTP `:ssh` client (terminal engine) + client-key callback
- `lib/termelix/*.ex` — contexts (accounts, hosts, credentials, snippets, preferences, …)
- `lib/termelix_web/` — endpoint, router, plugs (auth/CORS), controllers, terminal WebSocket

## License

MIT — see [LICENSE](LICENSE). [Termix](https://github.com/Termix-SSH/Termix) itself is a separate
project, Apache-2.0 licensed; this repo contains no Termix code (the React SPA is built from its
own checkout and is not part of this tree).
