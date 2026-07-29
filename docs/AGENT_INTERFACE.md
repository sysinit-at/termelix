# Termelix — the agent interface (`tmx` CLI and MCP)

Last Updated: 2026-07-27

Termelix exposes its tmux verbs through three doors: the browser, a REST surface (`/agent`, driven
by the `bin/tmx` shell script), and Model Context Protocol (`POST /mcp`). All three end in the same
`Termelix.Tmux.*` modules, so the verbs themselves cannot drift apart.

The two headless doors additionally share `Termelix.Agent` (`lib/termelix/agent.ex`), which does its
own authorization — scope, host scope, ownership, rate limit and audit — rather than trusting the
controller that called it. The browser door is **not** that: `TermelixWeb.TmuxController` calls
`Termelix.Tmux.Orchestrator` directly and carries its own JWT-based authorization. Everything this
document says about scopes, host lists and key-based audit describes the headless doors only.

**Sharing that core makes the two doors consistent where it counts.** It does not make them
identical by construction, though, and reviewing this document turned up two places where they had
genuinely drifted apart. Both were code defects rather than documentation gaps, and both are now
fixed:

| | REST (`/agent`, `bin/tmx`) | MCP (`/mcp`) |
|---|---|---|
| Host list | Needs **no scope**: `Termelix.Agent.hosts/1` checks none | Same — `list_hosts` carries `scope: nil` |
| Every other verb | Scope checked in `Termelix.Agent` | The same check, plus the controller's own gate first |
| `send_keys` audit | Records the caller's IP and user-agent | Same — the caller opts are passed |

The MCP door used to gate `list_hosts` on `tmux:read`, which made a `tmux:wait`-only key — a
combination the scope table below calls deliberate — unable to discover the host id every other
tool demands, while `tmx hosts` with the same key answered normally. It also asked a key to hold a
scope before it could read which scopes it holds. The gate was removed rather than added to
`Termelix.Agent.hosts/1`, because tightening REST instead would have broken discovery for
`tmux:write`-only keys as well.

Be precise about what that opens up, since "it only echoes the key back" would be wrong: for each
host the key is **already scoped to**, the answer carries the id, name, folder and tmux-monitor
flag, plus the key's own scopes. The key itself names only ids, so host names and folders are
genuinely additional — bounded metadata about machines the key was deliberately granted.

What keeps credentials out is the projection in `Termelix.Agent.hosts/1`: it maps each row to
those four fields, so nothing else can reach the response. It is **not** the `decrypt: false` on
the lookup — that is a cost choice, and `Hosts.list_for_user/2` documents it as leaving secret
columns "as stored (ciphertext envelopes or legacy plaintext)", so the structs behind that call
may still hold a readable password. The projection is the whole guarantee, which is why the field
set is pinned by a test rather than by prose like this paragraph.

The MCP door also dropped the caller opts on `send_keys` alone, so an `agent_send_keys` row from an
MCP agent recorded no client IP or user-agent — on the one verb that answers password prompts.

The remaining asymmetry is deliberate: the MCP controller checks scope before dispatch so that
`tools/list` can be filtered honestly, and `Termelix.Agent` checks it again. Two gates, one answer.

This document is the setup and usage guide for the two headless doors: how to mint a key, how to
drive it from a shell, and how to wire it into Claude Code or Codex.

**What it is for.** An agent opens a *named tmux session on a real host*, runs something in it,
and is told when that something finishes or starts asking questions. Because the work happens in
tmux and not in a hidden exec channel, a human can `tmux attach -t <session>` at any moment and
see — and take over — exactly what the agent is doing.

---

## 1. What an agent key can and cannot do

An API key is deliberately **narrower than the human who issued it**: tmux verbs on named hosts,
nothing else (`lib/termelix/api_keys.ex:4-25`).

| Scope | Grants |
|---|---|
| `tmux:read` | list panes, capture a pane's screen |
| `tmux:write` | open a session, type a command, send keys |
| `tmux:wait` | block until a pane changes state |

`tmux:wait` is separate from `tmux:read` on purpose: a wait holds a connection for minutes, which
is a resource decision rather than a data-access one.

A key **cannot** read credentials, create or edit hosts, run anything outside a tmux session,
administer users, or mint another key. Key management sits behind the human JWT pipeline
(`lib/termelix_web/router.ex:197-205`) precisely so that an agent credential cannot widen itself.

**Hosts are named explicitly.** There is no "all hosts" value, and an empty host list means *no
hosts* — not every host. Both halves are checked on every call: the host must be named on the key
**and** still owned by the key's user.

**The token** is `tmx_` + 32 random bytes, base64url, stored only as SHA-256. It is returned once,
at creation, and cannot be recovered. Send it as `Authorization: Bearer tmx_...` or `X-Api-Key:
tmx_...` — both are accepted (`lib/termelix_web/plugs/api_key_auth.ex:87-94`).

---

## 2. Minting a key

### 2.1 The SPA form cannot set hosts — mint with `curl` instead

The admin UI (Settings → API Keys) posts only `name`, `scopes` and `expiresAt`. The resulting key
names **zero hosts**, and the key list then labels that as "All hosts" — the exact opposite of what
the server means by it. A key minted that way authenticates fine, returns an empty `hosts` array,
and answers `403 {"error":"This key is not scoped to that host"}` to every host call.

The panel is also admin-only while the endpoints themselves are open to any authenticated user, so
a non-admin has no UI for their own keys at all. (All three are in the **frontend** checkout,
`../termelix-frontend`: `src/ui/sidebar/AdminSettingsPanel.tsx:696-700` posts the
body, `src/ui/sidebar/AdminApiKeysSection.tsx:244-246` prints the label, `src/ui/AppShell.tsx:1734`
gates the panel.)

Until the form grows a host picker, mint agent keys over HTTP or on the server.

### 2.2 Over HTTP (verified end to end)

```bash
BASE=https://termelix.example.com

# 1. Log in as the human who owns the hosts. The JWT arrives as the `jwt` cookie.
curl -s -c jar.txt -X POST "$BASE/users/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"you","password":"…"}'

# 2. Find the host ids the key should be allowed to touch.
curl -s -b jar.txt "$BASE/host/db/host" | jq -c '[.[] | {id, name}]'

# 3. Mint the key.
curl -s -b jar.txt -X POST "$BASE/api-keys" \
  -H 'Content-Type: application/json' \
  -d '{"name":"claude-code","scopes":["tmux:read","tmux:write","tmux:wait"],
       "hostIds":[3],"expiresAt":"2026-12-31T00:00:00Z"}'
```

The response carries the plaintext once:

```json
{"key":{"id":"Xg3muOMYdxoepegwlIWed","name":"claude-code","keyPrefix":"tmx_Example0",
        "scopes":["tmux:read","tmux:write","tmux:wait"],"hostIds":[3],
        "expiresAt":"2026-12-31T00:00:00Z","isActive":true,"createdAt":"…"},
 "token":"tmx_Example0Example1Example2Example3Example4123",
 "warning":"This token is shown once and cannot be recovered."}
```

Mistakes are refused rather than silently narrowed — naming someone else's host answers
`403 {"error":"Not your hosts: 1"}`, an unknown scope answers `400`, and a missing name or empty
scope list answers `400`.

`GET /api-keys` lists the caller's keys and `availableScopes`; `DELETE /api-keys/:id` revokes one.

### 2.3 On the server, without a browser

```bash
docker exec termelix /app/bin/termelix eval \
  'Termelix.ApiKeys.create("<userId>", %{name: "codex", scopes: ["tmux:read","tmux:wait"],
                                         host_ids: [3]}) |> IO.inspect()'
```

**Use `host_ids:` (snake, atom) or `"hostIds" =>` (camel, string).** The attribute lookup accepts
those two spellings only (`lib/termelix/api_keys.ex:66-69`); an atom `hostIds:` misses both and falls back to
the empty list, producing a key that silently reaches nothing. Confirm `hostIds` in the returned
struct before handing the token out.

---

## 3. The CLI: `bin/tmx`

`bin/tmx` is a single bash script that depends on `curl` alone (`jq` is used when present, never
required). Copy it to wherever the agent runs — it carries no server-side counterpart, because
every command is one HTTP call to `/agent`.

```bash
export TERMELIX_URL=https://termelix.example.com
export TERMELIX_TOKEN=tmx_…

tmx hosts                                   # what this key may touch
tmx open <host-id> <session> [path]         # create or attach; prints the pane id
tmx panes <host-id>                         # every pane, with what it is doing
tmx capture <host-id> <pane-id> [lines]     # read the screen (default 200, max 2000)
tmx run <host-id> <pane-id> <command...>    # type it and press Enter
tmx keys <host-id> <pane-id> <text>         # type without Enter (answering a prompt)
tmx wait <host-id> <pane-id> [states] [timeout-seconds]
tmx watch <host-id> <pane-id> <command...>  # run, wait, then show the screen
```

`tmx help` works without credentials; every other command requires both variables.

The whole loop:

```bash
pane=$(tmx open 3 claude-foobar /srv/foobar | jq -r .paneId)
tmx watch 3 "$pane" 'make test'
```

Notes worth knowing:

- Pane ids are tmux's own (`%3`) and must match `^%\d+$`. Quote them — `%` is also the
  percent-escape introducer in a query string, which is why `capture` sends it through
  `--data-urlencode` rather than interpolating it.
- `wait` states default to `awaiting_input,finished`; pass a comma-separated list to override.
  `gone` is accepted too, though a wait returns it either way when the pane disappears (§6).
- `wait` sets `--max-time` above the server's own budget on purpose: a wait that runs out returns
  `200` with `"timedOut": true`, and letting curl give up first would turn a considered answer
  into a transport error.

---

## 4. Claude Code

Add the endpoint as an HTTP MCP server, with the key in a header:

```bash
claude mcp add --transport http termelix https://termelix.example.com/mcp \
  --header "Authorization: Bearer tmx_…"
```

`--scope` selects where it is written: `local` (default, this project only), `user` (all your
projects), or `project` (a committed `.mcp.json` — **do not** put a live token in one).

Verify:

```
$ claude mcp list
Checking MCP server health…
termelix: https://termelix.example.com/mcp (HTTP) - ✔ Connected
```

Tools then appear as `mcp__termelix__list_hosts`, `mcp__termelix__open_session`, and so on. Each
call prompts for approval unless allowlisted — via `/permissions` in a session, or `--allowedTools
"mcp__termelix__list_hosts"` headless. A sensible split is to allowlist the read-only tools and
keep `run_command` / `send_keys` interactive.

```bash
claude -p "Which Termelix hosts can you see?" --allowedTools "mcp__termelix__list_hosts"
```

---

## 5. Codex

Codex speaks streamable HTTP and reads the bearer token from an environment variable, so the token
never lands in the config file:

```bash
codex mcp add termelix --url https://termelix.example.com/mcp \
  --bearer-token-env-var TERMELIX_TOKEN
```

The equivalent in `~/.codex/config.toml`:

```toml
[mcp_servers.termelix]
url = "https://termelix.example.com/mcp"
bearer_token_env_var = "TERMELIX_TOKEN"
tool_timeout_sec = 900              # default is 300 — raise it if you use wait_for_pane
default_tools_approval_mode = "approve"

[mcp_servers.termelix.tools.run_command]
approval_mode = "prompt"            # keep the verbs that type into a terminal interactive
```

`TERMELIX_TOKEN` must be exported in the environment Codex itself starts in — it is read by the
client process, not by a shell the model spawns.

Two behaviours to plan for:

- **Approvals.** MCP tool calls need approval by default. In a headless `codex exec` run (where
  the approval policy is `never`) an unapproved call is auto-denied and comes back as `user
  cancelled MCP tool call`. `default_tools_approval_mode = "approve"` is what makes headless runs
  work; scope it per tool if that is too broad.
- **Timeouts.** Codex's default MCP tool timeout is 300 s, which is exactly `wait_for_pane`'s
  default budget — a wait that runs its course would race the client's own deadline. Set
  `tool_timeout_sec = 900` to match the server's ceiling.

---

## 6. The tools

| Tool | Scope | What it does |
|---|---|---|
| `list_hosts` | *none* | The hosts this key may act on, plus its scopes. Start here. |
| `list_panes` | `tmux:read` | Every pane on a host with its state and the evidence for it. |
| `open_session` | `tmux:write` | Create **or attach** a named session; returns the pane to work in. |
| `capture_pane` | `tmux:read` | The last lines of a pane's screen, plus an activity verdict. |
| `run_command` | `tmux:write` | Type a single-line command into a pane and press Enter. Returns at once. |
| `send_keys` | `tmux:write` | Type text *without* Enter (`enter: true` to submit) — for answering prompts. |
| `wait_for_pane` | `tmux:wait` | Block until the pane needs attention or the command finishes. |

`tools/list` is filtered by the key's scopes, so an agent is never offered a tool it will be
refused — being shown one it cannot use makes it read the refusal as a transient fault and retry.
`list_hosts` is the exception that proves it: it needs no scope, so every authenticated key is
offered it, because a key that cannot discover its own host ids cannot use the tools it *does*
hold. It returns id, name, folder and the tmux-monitor flag for the hosts the key is already
scoped to — no credentials, and nothing about hosts it is not.

**Pane states** — the classifier's verdicts (`lib/termelix/tmux/activity.ex:118`):

| State | Meaning |
|---|---|
| `idle` | A shell prompt with nothing running. |
| `running` | A foreground process burning CPU. |
| `working` | Alive but not burning CPU — waiting on I/O, network, or a subprocess. |
| `awaiting_input` | The screen ends in a prompt for a human. The state the product exists for. |
| `finished` | The command ended and the shell is back. |
| `crashed` | Same, with a non-zero status — see below. |

`finished` means *the shell came back*, not *it succeeded*. tmux does not expose the exit status of
a command its shell has already reaped, so the watcher can never produce `crashed`, and it is
deliberately absent from the wait defaults rather than advertised as an outcome that never arrives
(`lib/termelix/tmux/orchestrator.ex:296-310`). An agent that cares about success must read the
output — or have the command write its own status into the pane.

`wait_for_pane` adds one state of its own: if the pane disappears while you are waiting, the wait
returns `gone` whether or not you asked for it (`lib/termelix/tmux/orchestrator.ex:378-384`). A
closed pane cannot reach any state, so reporting it beats hanging until the timeout.

**The loop that works:**

1. `open_session` with a stable name (`claude-<project>`). It is idempotent: a reconnecting agent
   lands back in the same session, and a human can attach to it at any time.
2. `run_command` — returns immediately.
3. `wait_for_pane` — costs nothing while it waits, and is woken by the same event that would have
   notified a human. Do **not** poll `list_panes` in a loop instead.
4. `capture_pane` when the wait returns, then `send_keys` if it stopped at `awaiting_input`.

---

## 7. Errors

REST answers `{"error": "…"}` with a real status. MCP wraps the same messages as a `200` carrying
`isError: true` — an HTTP error would be read as a broken connection and reconnected, rather than
read and adapted to. The exception is authentication: the key is checked by a plug before the
controller runs, so a missing, unknown, deactivated or expired key is a real `401` on both doors.

| Status | Message | Meaning |
|---|---|---|
| 401 | `Missing API key` / `Invalid API key` | No key, or an unknown/deactivated one. |
| 401 | `API key expired` | Distinct on purpose — nothing to debug, just re-mint. |
| 403 | `This key lacks the tmux:write scope` | Scope missing. |
| 403 | `This key is not scoped to that host` | Host not named on the key, or no longer owned. |
| 423 | `Encrypted data is locked` | The owner's DEK will not unseal. |
| 429 | `Too many commands for this host` | Rate limit (§8). |
| 429 | `Too many concurrent waits` | More than 8 waits open for one user. |
| 400 | `Command must be a single line`, `Invalid pane ID`, `Invalid session name` | Refused before a shell sees it. |
| 502 | `Could not reach the host` | SSH failed. |

A host that does not exist answers the same `403` as one that is out of scope — otherwise a key
could enumerate which host ids exist by comparing the two. `423` means the wrapped DEK will not
open: either the wrong `ENCRYPTION_KEY` for this database, or the user has not logged in since the
key format changed and must do so once to migrate.

Protocol-level mistakes get proper JSON-RPC errors rather than a 404 — an unknown method answers
`{"code":-32601,"message":"Method not found: resources/list"}`, so a client can tell "wrong method"
from "wrong URL".

---

## 8. Limits, audit, revocation

- **Rate limit**: 60 calls per minute per (user, host) — `lib/termelix/rate_limiter.ex:77`. It
  covers the three verbs that act (`open_session`, `run_command`, `send_keys`); reads and waits are
  exempt, a wait because it costs no SSH of its own.
- **Concurrent waits**: 8 per user (`lib/termelix/agent.ex:266`). A wait pins a connection process, so this is
  a real resource, not a formality.
- **Wait budget**: 300 s default, 900 s ceiling (`lib/termelix_web/agent_params.ex:30`). A wait that runs out
  returns `200` with `timedOut: true` and the last state seen.
- **Capture**: 200 lines default, 2000 maximum (`lib/termelix/tmux/orchestrator.ex:452`).
- **Audit**: the actor is the *key*, not just the user — `key:tmx_Example0` — for actions
  `agent_ensure_session`, `agent_dispatch` and `agent_send_keys`, with the caller's IP. `dispatch`
  records the command; `send_keys` records only the *count* of keys, because that is the verb that
  answers a password prompt.
- **Last-used** timestamps are buffered in memory and flushed on a timer, not written per request
  (SQLite has one writer; an agent polling in a loop would otherwise write as fast as it reads).
- **Revocation**: `DELETE /api-keys/:id`, the trash icon in the UI, or, for everything a user
  holds, `Termelix.Console.revoke_keys("<userId>")` on the server. "Revoke all sessions"
  (`POST /users/sessions/revoke-all`) and deleting a user also deactivate their keys, via
  `Termelix.Revocation.revoke_user/2` — otherwise an agent holding one would simply carry on.

---

## 9. Behaviour worth knowing before you debug it

- **MCP is POST-only.** No SSE stream, no session negotiation: this server has no
  server-initiated messages to push. `initialize`, `tools/list`, `tools/call`, `ping` and
  `notifications/initialized` are implemented.
- **`GET /mcp` returns the SPA**, not a `405`, because the catch-all frontend route matches it. No
  client tested here cared (neither opens the optional SSE channel), but a client that *requires*
  it will get HTML rather than a clean refusal.
- **The protocol version is pinned** to `2024-11-05` and is returned regardless of what the client
  asks for (`lib/termelix_web/controllers/mcp_controller.ex:32`). Both clients tested accept it.
- **Secrets stay write-only.** Nothing on this surface returns a password, key, or passphrase —
  only `hasPassword` / `hasKey` presence booleans elsewhere in the API.
- **Sessions are shared, not hidden.** `open_session` attaches to an existing session of that
  name. Two agents given the same session name will type into the same pane.
- **An agent that "cannot see any hosts" is almost always a host-scope problem, not a bug.** A key
  minted with an empty `hostIds` answers `hosts: []` to both doors and `403` to every host call.
  (Until 2026-07-27 there was a second cause — MCP gated `list_hosts` on `tmux:read`, so a key
  without it was never shown the tool. That is fixed; see the introduction.)

---

## 10. What was verified, and when

Checked on 2026-07-27 against a local dev server (`mix phx.server`, dev SQLite DB), with Claude
Code 2.1.220 and codex-cli 0.145.0:

- Key minting over HTTP end to end: login → host list → `POST /api-keys` with `hostIds`, plus the
  `Not your hosts` and empty-`hostIds` paths.
- `POST /mcp`: `initialize` (with a streamable-HTTP `Accept` header), `tools/list` filtered by
  scope (4 tools for a read+wait key, 7 for a full one), `tools/call list_hosts`, a scope refusal
  surfacing as `isError`, and `-32601` for an unknown method.
- Host scoping: a zero-host key sees `hosts: []` and gets `403` on a host call.
- The REST/MCP divergence the introduction records as **fixed**, caught here: one `tmux:wait`-only
  key was given the host list by `GET /agent/hosts` (`200`) and refused it by MCP — `tools/list`
  offered only `wait_for_pane`, and `tools/call list_hosts` answered `isError` with "This key lacks
  the tmux:read scope". That live result is what prompted the code change; the same key is now
  offered `list_hosts` and answered by both doors, pinned by two regression tests in
  `test/termelix_web/controllers/mcp_controller_test.exs` that fail against the old gate.
- `bin/tmx hosts` and `bin/tmx help` (the latter without credentials).
- Claude Code: `claude mcp add --transport http` → `claude mcp list` reports `✔ Connected`, and a
  headless `claude -p` run called `mcp__…__list_hosts` and got the real payload back.
- Codex: `codex mcp add --url … --bearer-token-env-var` → `codex exec` called `list_hosts`
  successfully once `default_tools_approval_mode = "approve"` was set (it is auto-denied without
  it).

Against the live instance (`https://termelix.example.com`, unauthenticated probes only):
`POST /mcp` and `/agent/hosts` reach Phoenix through the proxy and answer `401 {"error":"Missing
API key"}`; a bogus token in either `Authorization: Bearer` or `X-Api-Key` comes back as `Invalid
API key`, which is what proves nginx forwards both headers rather than eating them. `GET /mcp`
there returns the SPA, as it does locally.

Not re-run here: the tmux verbs themselves against a live host — the dev database's host was
unreachable (`502 Could not reach the host`, which is itself the documented failure shape). That
loop — `open_session` → `run_command` → `wait_for_pane` → `capture_pane` → `send_keys`, confirmed
by attaching to the same session with `tmux attach` — was verified over the real proxy during P8;
see the P8 row in `ARCHITECTURE_REVIEW.md` (internal review) §6.2.
