# Rootless Podman + Quadlet as the default deployment — assessment

Should Termelix's default container deployment move from Docker Compose to **quadlet-managed, rootless
Podman**, and where could that bite?

_Assessed 2026-07-24 against the live deployment (`termelix.example.com`) and Podman's own docs
(`../podman`, v5.x)._

**Verdict: feasible, nothing structurally blocks it — but one prerequisite (client-IP handling) must land
first, and the network shape is not the obvious one.**

## Why it fits

Nothing in the stack needs root, and this is verified on the running deployment rather than assumed:

- The app container already runs unprivileged: `docker exec termelix id` → `uid=1000(termelix)`.
  The image's final stage is `USER termelix`. (The live stack still has a second container, the
  `guacd` sidecar; the code that talked to it is gone, but retiring the container itself is a
  `termix-setup` follow-up — see `ROADMAP.md`. Everything below describes the post-retirement
  single-container target.)
- One published port, **8080** — above 1024, so a rootless bind works untouched.
- **No `docker.sock` mount.** The Docker-management features talk to remote hosts over SSH, so the
  container never needs the local daemon socket — the single most common rootless blocker does not apply.
- No `privileged`, no `cap_add`, no devices, no host networking. Storage is one named volume.
- Debian 13 ships **podman 5.4.2** and **passt** — quadlet in 5.x has `.container`, `.pod`, `.volume`,
  `.network`, `.build` and `.image` units, and generates the systemd dependencies for you.

## The bites

### 1. Client source IP — the real one, and it dictates the topology

Podman's own docs (`docs/source/markdown/options/network.md`):

> For rootless bridge networks, port forwarding uses `rootlessport` by default. Setting
> `rootless_port_forwarder="pasta"` … preserves the original client source IP address inside the
> container. **This option is experimental** …

> **pasta**: … Port forwarding preserves the original source IP address.

The naive port — a user-defined bridge network — lands squarely on `rootlessport`, i.e. **every client
appears with the same internal source address**. What that costs:

- `Termelix.RateLimiter` registration budget is keyed on **IP alone** (`{:register, ip}`, 10/hour), so it
  degrades to *ten registrations per hour for the entire instance*.
- The login budget is keyed `{:login, ip, username}`, so per-user isolation survives — a brute-forcer on
  one account does not lock out others. (Correcting a looser earlier claim.)
- Session/audit rows record the collapsed address.

**Fix the topology, not the setting:** give the container `Network=pasta` directly. Only 8080 is
published and source IPs are preserved, with no experimental flags. (An earlier version of this
assessment reached for a quadlet **`.pod`**; that existed solely to share a netns with the `guacd`
sidecar. Once that sidecar is retired the deployment is a single container, and the pod buys
nothing.)

### 2. Prerequisite: client-IP handling was inconsistent — **done** (`TermelixWeb.Plugs.TrustedProxy`)

Independent of Podman, the codebase disagreed with itself about what a client IP *is*:

- `user_controller.ex` (login/registration limits) deliberately uses `conn.remote_ip` only, documented as
  *"no x-forwarded-for trust, since this app may sit behind an untrusted proxy"*.
- `user_session_controller.ex`, `admin_controller.ex` and `tmux_controller.ex` each define their own
  private `client_ip/1` that takes the **first** `X-Forwarded-For` value with no trust check, and write it
  to session and audit rows.

So anyone who could reach the app port directly — on our deployment, any tailnet peer hitting `:8080` —
could forge the IP recorded in audit trails. The refusing half was **not** the safe side either: behind
the reverse proxy every request carried the proxy's address, so `{:login, ip, username}` collapsed onto
one IP (an attacker could burn any known user's failed-login budget and lock them out) and
`{:register, ip}` became a single global 10-per-hour bucket for all clients. Three copies of the helper
also violated the AGENTS.md rule about shared controller helpers.

Resolved by `TermelixWeb.Plugs.TrustedProxy`, first in the endpoint: XFF is walked right-to-left past
trusted hops (so a client-supplied prefix cannot win) and applied only when the direct peer is a trusted
proxy; everything downstream just reads `conn.remote_ip`, and the four helpers are now one
`ControllerHelpers.client_ip/1`. `TRUSTED_PROXIES` defaults to `loopback,private`, which covers the
proxy here (`10.23.56.5`) with no config change, and deliberately excludes CGNAT/tailnet space because
that is precisely where direct clients arrive from.

The same trust decision governs `x-forwarded-proto`, which required moving HTTPS enforcement off
Phoenix's compile-time `:force_ssl` (installed ahead of every endpoint plug, so nothing could vet the
header first) onto `TermelixWeb.Plugs.ForceSSL`. Verified before the change: a direct client sending
`X-Forwarded-Proto: https` suppressed the redirect.

**Consequence for this decision:** the Podman networking choice is no longer a security question. Note
that under pasta the app sees the pasta-translated peer, so if that address is not
loopback/RFC1918, `TRUSTED_PROXIES` must name it explicitly — verify the observed peer address after
any cutover rather than assuming the default still matches.

### 3. Outbound tailnet reachability must be re-verified

The product's core action is outbound SSH, and on this deployment many targets are tailnet addresses
(`100.64.0.0/10`) reached through the host's `tailscale0`. pasta copies the host's addresses and routes,
so this is expected to work — but it is the one thing whose breakage would be total, so verify it against
a real tailnet host before any cutover rather than trusting the model.

### 4. Volume migration is a copy, not a switch

Data sits in a Docker named volume owned `1000:1000` on the host. Rootless Podman maps container uid 1000
into the user's subuid range, so migration means copying the data and fixing ownership inside the user
namespace (`podman unshare chown -R 1000:1000 …`). Quadlet volume naming also differs from Compose's
project-prefixed names, so nothing is adopted in place. Copy, verify a boot, then retire the old volume.

### 5. Build flow and auto-update

The current deployment builds from source on the host (`docker compose build`). Quadlet's `.build` unit
covers that, but **`podman auto-update` only tracks registry images** — a locally built image opts out of
it. If unattended updates matter, publish to the GitLab registry and consume the tag.

### 6. Operational surface changes

`loginctl enable-linger` is required or the stack dies with the login session; logs move from
`docker logs` to `journalctl --user -u termelix`; healthchecks become `HealthCmd=`/systemd, and
and `depends_on` becomes quadlet's generated ordering.

### 7. Interaction with built-in TLS

If TLS termination ever defaults to **443**, rootless cannot bind it without
`net.ipv4.ip_unprivileged_port_start` or a host-side redirect. Keep 8080/8443 as defaults — see
[TLS_TERMINATION_ASSESSMENT.md](TLS_TERMINATION_ASSESSMENT.md).

## Shape of the port

```systemd
# termelix.container — pasta gives source-IP-preserving forwarding; only 8080 is published
[Container]
Image=localhost/termelix:latest        # or a registry tag, to keep auto-update
Network=pasta
PublishPort=8080:8080
Volume=termelix-data.volume:/app/data
EnvironmentFile=%h/.config/termelix/env
[Service]
Restart=always
[Install]
WantedBy=default.target
```

## Recommendation

Ship it as a **documented, first-class alternative** rather than ripping out Compose: the existing user
base runs Docker, and Compose stays the lowest-friction on-ramp. Sequence:

1. **Client-IP resolver** (shared helper + trusted-proxy config) — a security fix in its own right and the
   precondition that makes the networking choice safe either way.
2. Quadlet units in `docker/quadlet/` (the pasta shape above) with a short migration note covering the
   volume copy and lingering.
3. Verify tailnet SSH egress before recommending it.

Our own instance should stay on Compose until step 1 lands.
