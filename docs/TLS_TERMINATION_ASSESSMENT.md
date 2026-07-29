# Built-in TLS termination — assessment

How should Termelix terminate TLS itself, for users who do **not** run their own reverse proxy?

_Assessed 2026-07-24. Sources: upstream Termix's `docker/entrypoint.sh` + `docker/Dockerfile`, Bandit and
site_encrypt documentation, and this repo's `config/prod.exs` / `config/runtime.exs`._

**Verdict: two tiers are small, dependency-light and should ship (BYO cert + self-signed bootstrap); ACME
belongs out-of-process, not in a library.**

## The constraint the port inherits

Upstream Termix terminates TLS in the **nginx** that its image bundles, driven by this env contract
(`docker/entrypoint.sh`): `ENABLE_SSL` (default `false`), `SSL_PORT` (8443), `SSL_CERT_PATH`
(`/app/data/ssl/termix.crt`), `SSL_KEY_PATH`, `SSL_DOMAIN`. When enabled with no certificate present it
generates a self-signed one with `openssl` and regenerates it once it is within 30 days of expiry; its
image also carries `certbot` + `python3-certbot-dns-cloudflare` and an ACME webroot under
`/app/data/acme-webroot`.

Termelix deleted the nginx layer on purpose — the Phoenix endpoint **is** the server (Bandit `~> 1.5`).
So the feature must be reimplemented in the endpoint, and **the env contract should be preserved verbatim**
so a migrating Termix user's compose file keeps working.

## Tier 1 — bring-your-own certificate (static files)

Documented, first-class Bandit capability: `scheme: :https` with `certfile`/`keyfile`, and Phoenix's
standard `https:` endpoint key under `Bandit.PhoenixAdapter`. Concretely: when `ENABLE_SSL=true`, add a
second listener in `config/runtime.exs` on `SSL_PORT` pointing at `SSL_CERT_PATH`/`SSL_KEY_PATH`.

Three things must not be lost when doing it:

- **Keep the HTTP listener running.** It serves the redirect, the container healthcheck, and any ACME
  http-01 challenge. The `exclude: [hosts: ["localhost", "127.0.0.1"]]` that lets the healthcheck hit
  `http://localhost:8080/health` stays load-bearing. It now lives in `config/runtime.exs` under
  `:termelix, :force_ssl` and is applied by `TermelixWeb.Plugs.ForceSSL`, not by Phoenix's compile-time
  `:force_ssl` — see the HSTS point below.
- **`ALLOWED_ORIGINS` must include the https origin** on the *reverse-proxy* topology, or
  `TermelixWeb.OriginCheck` rejects the WebSocket upgrades and every terminal session breaks
  while plain pages still load. The mechanism is the port, not the scheme: `OriginCheck` allows
  same-origin, and `TrustedProxy` already folds `x-forwarded-proto` into `conn.scheme`, but `conn.port`
  comes from the `Host` header (80), while the browser's `https://…` origin normalises to 443 — so
  same-origin does not match and the explicit entry is required. That is why the deployment carries
  `ALLOWED_ORIGINS=https://termelix.example.com,…` today.

  With **built-in** TLS the app terminates the connection itself, so scheme *and* port line up and
  same-origin matches without configuration. Do not assume enabling TLS breaks origins; verify it,
  since the failure mode is silent (pages load, terminals don't).
- **HSTS + self-signed is a trap.** HSTS combined with a self-signed certificate can lock a user out of
  their own instance for the max-age, so it must be gated on a non-self-signed certificate (or an
  explicit opt-in). Phoenix's `:force_ssl` is compile-time, which made that gating impossible; HTTPS
  enforcement therefore moved to `TermelixWeb.Plugs.ForceSSL`, which reads runtime configuration. That
  work is **already done** — Tier 2 only has to decide the flag, not restructure the pipeline.

## Tier 2 — self-signed bootstrap (parity with upstream)

So that `ENABLE_SSL=true` alone yields a working HTTPS port on first boot. The `x509` package (0.9.2,
pure Elixir) generates key + self-signed certificate into `DATA_DIR/ssl` at startup — no `openssl` binary
in the runtime image, and it mirrors upstream's regenerate-when-expiring behaviour. This is the tier that
makes the feature self-contained; it is roughly one module plus a boot hook.

## Tier 3 — ACME / Let's Encrypt: keep the client out-of-process

The tempting answer is `site_encrypt` (native Elixir ACME, integrated with the endpoint). **Not
recommended as the primary path**, on evidence: its documentation demonstrates **Cowboy only** and says
nothing about Bandit, and the project describes its native ACME client as *"very new, and not considered
stable"* (latest 0.7.0, updated 2025-12). Betting the TLS story on an unverified adapter pairing is the
wrong risk for a self-hosted product.

Preferred shape — the same architecture upstream chose, minus the Python stack:

1. An ACME client as a **separate process/sidecar** (`lego` is a single static Go binary; `certbot` if
   parity with upstream's Cloudflare plugin matters) writing to `DATA_DIR/ssl`.
2. Termelix **watches those files** and restarts only the HTTPS listener when they change.

Cert reload is **less constrained than Bandit's own documentation suggests**. Bandit documents only static
`certfile`/`keyfile`, but it forwards `thousand_island_options.transport_options` to the TLS transport, and
Thousand Island explicitly accepts `sni_fun` as an alternative to `certfile`/`keyfile`
(`deps/thousand_island/lib/thousand_island/transports/ssl.ex:74,81`). `sni_fun` is invoked *per handshake*,
so a renewed certificate can be picked up with **no listener restart at all** — the renewal story is a
callback reading the current cert, not a supervised-child restart dance.

Two caveats before relying on it: clients that send no SNI fall back to the listener's static cert (every
browser sends SNI, so this is a non-issue here), and the pairing is undocumented by Bandit, so it deserves
a short spike rather than blind adoption. If the spike fails, the restart-a-supervised-child design remains
the fallback.

Challenge-type trade-off, which decides the default advice:

- **http-01** needs inbound `:80` reachable — awkward for the homelab audience behind NAT/CGNAT, and it
  collides with rootless Podman's inability to bind ports below 1024
  (see [PODMAN_QUADLET_ASSESSMENT.md](PODMAN_QUADLET_ASSESSMENT.md)).
- **dns-01** needs no inbound port at all and is the better default for that audience — which is precisely
  why upstream shipped a DNS plugin.

## Recommendation

1. **Tier 1 + Tier 2** (BYO cert, self-signed bootstrap) under upstream's exact env contract, with the
   origin/HSTS/health caveats above. Small, one new dependency (`x509`), and it closes the "no reverse
   proxy" gap for most self-hosters.
2. Document **reverse proxy as the recommended production topology** regardless — it is what this
   deployment uses, and it keeps cert lifecycle out of the app.
3. **Tier 3 later**, as a file-watching integration with an external ACME client (dns-01 first), not as a
   library-integrated ACME stack.

Keep the default HTTPS port at **8443**, never 443: a low port cannot be bound rootless, and users who
want 443 can map it at the container/host boundary.
