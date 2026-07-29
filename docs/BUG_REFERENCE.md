# Bug reference

Last Updated: 2026-07-27

## OIDC `redirect_uri` was built from untrusted `X-Forwarded-*` headers

### What was wrong

`OidcController.request_origin/1` assembled the OAuth `redirect_uri` — the value sent
to the IdP at authorize time and matched again at the token exchange — from raw
`x-forwarded-proto` / `x-forwarded-host` / `x-forwarded-port` request headers, with no
trust check. `TermelixWeb.Plugs.TrustedProxy` vets only the forwarded *scheme* and the
peer address, not the host: `conn.host` is the client-supplied `Host` header. So an
unauthenticated caller (on a tailnet deployment, every peer) could ask
`/users/oidc/authorize` with `X-Forwarded-Host: attacker.tld`, receive an `auth_url`
whose `redirect_uri` points at the attacker's host, and get a victim to complete the
real IdP login from that link. The attacker captures `code`+`state`, calls the real
callback server-to-server (the stored flow state is valid, and authorize-time and
token-time `redirect_uri` match), and the final 302 carries `?token=<JWT for the
victim's account>`. Exploitability depends on the IdP tolerating an unregistered
redirect_uri — but the server must never make IdP registration the only enforcement
point. This was the same mistake class as documented defect 35, in the OAuth callback
URL instead of a cookie flag.

### The fix

The origin derives from the endpoint's configured `:url`
(`TermelixWeb.Endpoint.url()` — `https://$PHX_HOST` in prod), never from request
headers; all the raw header readers are deleted. `OIDC_FORCE_HTTPS` and the desktop
loopback-callback handling are unchanged. Regression tests pin that spoofed
`X-Forwarded-Host`/`proto` produce a `redirect_uri` on the configured endpoint, in the
returned `auth_url` and in the stored flow state.

## LDAP: an unthrottled password oracle, and TLS that verified nothing

### What was wrong

Two independent defects on the directory path.

1. **`POST /users/ldap/login` had no rate limiting.** The password login path
   rate-limits (10 failures/10 min per IP+username, contract 429 envelope); the LDAP
   path had zero `RateLimiter` calls, and every attempt performs a **live LDAP bind as
   the user's DN** — an unauthenticated caller could password-spray directory accounts
   at full request rate, and trip directory-side lockouts as a DoS against legitimate
   users. A direct violation of the AGENTS.md convention that auth-like endpoints must
   use `Termelix.RateLimiter`.

2. **LDAPS and StartTLS both passed `verify: :verify_none`.** A network-position
   attacker between Termelix and the directory could present any certificate and
   harvest the service bind password plus every end-user password transiting the login
   re-bind. The setting was inherited from Node's `rejectUnauthorized: false` —
   faithful porting, real exposure, and an admin who sets `useTLS` reasonably believes
   they bought protection.

### The fix

- `LdapController.login/2` runs the same `check_login` / `record_login_failure` /
  `reset_login` flow as `UserController`, with the identical 429 envelope, keyed on
  the TrustedProxy-vetted client IP + username.
- `EldapClient` defaults to `verify_peer` with `server_name_indication` and hostname
  matching; CA trust comes from the provider's new `caCert` PEM config, else the
  system store (`:public_key.cacerts_get()`). Self-signed directories opt out
  explicitly via `insecureSkipVerify` in the provider config — a deliberate choice,
  visible in the config, rather than the silent default.
- Timeouts, with a correction to the review's premise: `:eldap.simple_bind/4`'s
  fourth argument is *Controls*, not a timeout (verified against OTP source), and the
  `{:timeout, ...}` already passed to `:eldap.open/2` is documented as bounding every
  server request — a wedged directory was probed live and bind/search fail in ~1s.
  What actually needed bounding got bounded: the StartTLS upgrade (`start_tls/3`; the
  `/2` form's phase 2 is `infinity`) and the search opts' RFC 4511 server-side
  `timeLimit`.

### Prevention

`ldap_controller_test.exs` pins the 429-after-10-failures contract and the
success-resets-budget path. `test/termelix/ldap/eldap_client_test.exs` pins the ssl
option shapes (peer/system-store/caCert/opt-out) and proves, against a local socket
that accepts and never answers, that bind and search fail within the configured
timeout instead of hanging forever.

## The Egress SSRF gate was bypassed by one HTTP redirect

`Termelix.Net.Egress` bound the notifier's webhook/ntfy dial to an allowlist — but
`Req` follows redirects by default, and no hop was re-checked, so an allowed channel
URL that 302s to `http://169.254.169.254/…` or an RFC1918 address sailed through the
control whose entire job is "bound where the server dials". The notifier now passes
`redirect: false` (3xx was already a delivery failure), and so do OIDC's
`http_get_json/3` and — worse, found while fixing — `exchange_code/3`, where a 307
would have re-POSTed the `client_secret` to the redirect target. Tests prove a 302 to
`169.254.169.254` is never followed.

## OIDC `client_secret` and LDAP `bindPassword` were stored as reversible base64

Every other credential in the system is sealed under a per-user DEK; the two
highest-value *instance-level* secrets — the OIDC client secret and the directory
service-account bind password — sat in `sso_providers.config` as base64 with an
`encoded:`/`encrypted:` label, so a database-file copy yielded them directly. There is
no user DEK for instance config, so they're now sealed by the new
`Termelix.Crypto.SystemSecrets`: `FieldCrypto` envelopes (AES-256-GCM/HKDF) keyed with
the instance `SystemCrypto.encryption_key()` under a fixed per-field record context.
Reads stay backward compatible — sealed envelopes, legacy base64 wrappers, and bare
values all open — writes only ever seal. An unopenable sealed `bindPassword` raises
before it can be handed to the directory, mapping to the login flow's ordinary
`:ldap_error`.

## The ws-ticket was reusable for its whole 30-second lifetime

A `Phoenix.Token` is stateless: nothing consumed it. A ticket captured from a
reverse-proxy access log (it rides in `?ticket=` by design) could be replayed for up
to 30 s to open unlimited terminal WebSockets as the victim. `Termelix.WsTickets` now
mints with a random `jti` and `consume/2` does an atomic `:ets.insert_new`
check-and-consume on first use (table owned and swept by the existing
`Termelix.EtsOwner`; jtis retained 60 s, so the table stays bounded). Same ticket
twice → 401 on the second upgrade; two tickets work independently; clients re-mint
via the existing `POST /users/ws-ticket`.

## Generic-OIDC account lookup was not scoped to the provider

`find_by_oidc_identifier` matched `oidcIdentifier` globally, while the GitHub and LDAP
flows both scope by provider. On a multi-provider instance, a login through provider B
whose identifier collided with a provider A user's stored identifier (trivial with
`identifier_path: "email"`) logged into that user's account. Generic-OIDC identifiers
are now scoped (`"oidc:<provider_db_id>:<sub>"`), with a fallback lookup that migrates
legacy unscoped rows on successful login. That fallback is itself ownership-checked
(`claimable_legacy_row?/2`): the row's `ssoProviderId` must equal the provider presenting
the `sub`. Without that check the compatibility path would have re-opened the very
collision — a second IdP could claim another provider's not-yet-migrated row.

The check is plain equality, with no exception for an owner-less row. `nil == nil` already
covers the env-configured (provider-row-less) flow, which is the only case that has to keep
working; an owner-less row claimed by a *configured* provider is indistinguishable from the
takeover, so it is refused. The cost falls on an instance that migrates from env config to
a provider row: those users are re-provisioned rather than re-linked, which an admin can
repair and a takeover cannot be.

**Behaviour note:** `allowed_users` patterns
now match the scoped form for generic OIDC — the same trade-off the GitHub branch
already made; operators using those patterns should review them on upgrade.

## `POST /terminal/command_history` recorded commands against foreign hosts

`save_command` never validated that `hostId` belongs to the caller — the sibling
`log_activity/2` in the same controller did. Reads were self-scoped, so the worst case
was polluting one's own history with rows pinned to foreign host ids, but the missing
check was an oversight, not a decision: it now returns the same
`"Host not found or access denied"` 404 via `History.host_owned?/2` before anything is
persisted.

## Terminal data-path hardening: owner-exit swallow, unbounded send, and the recorder queue

### What was wrong

Three defects on the interactive-SSH path, all variations on "one process's problem
becomes everyone's problem".

1. **`SSH.Client` swallowed its owner's exit.** The client traps exits (so `terminate/2`
   closes the connection politely), but every `handle_info` fell through to the catch-all —
   including `{:EXIT, owner, _}` from the `Terminal.Session` that `start_link`ed it. An
   owner that exited *without* going through its own `terminate/2` left the client holding
   an open SSH connection and a live remote shell with nobody reading it. (The `:kill`
   paths were always safe — `:killed` is untrappable and propagates down the link chain,
   taking the client and connection with it; a regression test now pins that too, because
   the earlier review claimed otherwise and the distinction matters.)

2. **Keystroke send could wedge the client forever.** `handle_cast({:send, …})` called
   `:ssh_connection.send/3`, which is `send(…, infinity)` in OTP's `ssh_connection.erl`,
   and discarded the return value. A remote that stops reading its PTY (exhausted channel
   window — a backgrounded reader with a full input queue) blocked the one process the
   whole backpressure design needs responsive: while blocked it cannot process `:ssh_cm`
   output, acks, or the connection's `:DOWN`. And when the send did fail, the keystrokes
   vanished silently.

3. **The session recorder was the last unbounded queue.** Every output chunk is a
   fire-and-forget cast processed synchronously (JSON encode → AES-GCM seal → write). A
   detached session acks the SSH client immediately, so a `yes`-class producer arrives at
   line rate on a slow volume and grows VM binary memory without bound — the session's
   own heap guard deliberately doesn't cover refcounted binaries, and it's a different
   process anyway.

### The fix

- `SSH.Client` stops when its subscriber's `{:EXIT, _, _}` arrives, and a new
  `send/4` with a 10 s timeout gains an error branch: a failed send surfaces
  `{:ssh_closed, :send_failed}` (a typed close the socket maps like any other drop)
  instead of a silent drop or an infinite wedge.
- The recorder sheds load past a 1,000-chunk mailbox watermark: `record/2` returns
  `:dropped`, counts it in telemetry (`[:termelix, :terminal, :recorder, :drop]`), and
  the transcript just has a gap — recording is documented as lossy, and a lagging
  transcript never justifies a dying node.

### Prevention

- `client_test.exs` pins all three behaviours: trappable owner exit stops the client and
  closes the connection; owner `:kill` propagates (`:killed` DOWN, conn DOWN); a failed
  send (queued cast + killed connection handler, deterministically ordered via
  `:sys.suspend/resume`) yields `{:ssh_closed, :send_failed}` and a `:normal` stop.
- `recorder_test.exs` floods a suspended recorder with 1,100 chunks and asserts at most
  the watermark was cast and the rest returned `:dropped`.

## Session-recording path allowlist didn't include the recorder's own directory

### What was wrong

`SessionRecordingController.allow_path/1` (ported from Node's `isAllowedRecordingPath`)
permitted only `DATA_DIR/session_logs/` and `DATA_DIR/session_recordings/`. The P10
recorder writes `DATA_DIR/recordings/<user_id>/*.cast` — so `GET /session_logs/:id/content`
403'd for **every recording the system actually produced**, and `DELETE` removed the row
while silently keeping the file. The retention pruner finds files *by selecting rows*, so
once the row was gone the ciphertext was orphaned on the volume permanently: an operator
who deleted a sensitive recording had deleted nothing. A second mismatch compounded it:
the controller resolved the data dir from `DATA_DIR` only, while the recorder
(`TerminalSocket`) and the pruner use the canonical chain — app env first.

### The fix

`recordings/` joined the allowlist, and the controller resolves the data dir the same way
as the writer and the pruner (`Application.get_env(:termelix, :data_dir) ||
System.get_env("DATA_DIR") || "./db/data"`). Content, delete, and the pruner now agree on
where recordings live.

### Prevention

`session_recording_controller_test.exs` serves content from `recordings/`, asserts delete
unlinks the file, keeps the out-of-root refusal, and the test helper writes under the
resolved data dir rather than a throwaway `DATA_DIR` env var — so the test exercises the
allowlist the way production resolves it.


## The sudo password: cleartext at rest, and why auto-fill is gone

### What was wrong

Three separate violations of the write-only-secrets rule, all with one origin.

The host editor stored the sudo password **inside the `terminalConfig` JSON blob**. That column is
plain `TEXT`: not in `Termelix.Crypto.FieldCrypto`'s encrypted set, and not reachable by
`HostNormalizer`'s `Map.drop` over top-level keys. Consequences, each confirmed against a running
server rather than inferred:

| | Evidence |
|---|---|
| Returned by the API | a probe host came back as `terminalConfig: {"sudoPassword": "…"}` in the host list |
| Cleartext at rest | `terminal_config` held it verbatim beside a correctly encrypted `sudo_password` envelope |
| Not replace-only | `hasSudoPassword` flipped `true → false` on an update that merely renamed the host |

The third is the nastiest: `base_attrs/4` wrote `sudoPassword: nilify(params["sudoPassword"])`
unconditionally, while the editor only ever sent a **nested** value. So every save nulled the
encrypted column, leaving the cleartext copy as the only one.

**Why it was built that way:** the sudo auto-fill feature had the BROWSER type the password at a
prompt, so the browser needed the plaintext — and `terminalConfig` was the field that round-tripped
back down. The leak was load-bearing for the feature, not an oversight beside it.

### The fix

- `HostNormalizer` scrubs secrets out of JSON blobs on **read**, so rows written by an older client
  stop leaking immediately, without waiting for a migration or a client update.
- `HostController` scrubs `terminalConfig` on **write** too, because a client that has not been
  updated is still sending the secret in there.
- `sudoPassword` is **not accepted from either position** any more — see the section below. An
  intermediate version promoted a nested value into the encrypted column and made updates
  replace-only; that was correct while the value still had a consumer, and is now moot.
- Migration `20260726200000` strips the cleartext already in the database; `20260726210000` nulls the
  encrypted column. Both irreversible on purpose — `down` cannot un-leak a secret.

### Why there is no "type the stored password" feature

**Two attempts at a safe version are in the git history and both were credential-reveal primitives.
Do not add a third without reading this.**

`Session.input/2` writes into the PTY, which is indistinguishable from the user typing. Whether the
secret is echoed back is decided by the **remote's** terminal settings, which this server cannot
observe: SSH does not relay remote termios.

1. **First attempt — a plain `fillStoredPassword` frame.** At an ordinary shell prompt the remote
   echoes, so a client could ask for a fill with no prompt pending and read the plaintext out of its
   own terminal stream. The echo is ordinary shell output, so it also landed in the 512 KB scrollback
   buffer — replayed to every reattaching client — and in the encrypted session recording.

2. **Second attempt — gate on a server-side password-prompt detector.** This fails for a subtler
   reason: **the client chooses what the remote prints.** Sending `echo -n "Password: "` puts a
   convincing prompt at the tail of the buffer, and the fill that follows is echoed straight back.
   Any heuristic over remote output has this hole, because the input producing that output comes
   from the party being defended against.

There is no server-side rule that closes this. The feature is therefore **removed**, not guarded.

`sudoPassword` is **no longer collected or stored at all**. Removing the consumer while leaving the
editor asking for it, and the server keeping the answer, was the worst of both: users were prompted
for a credential that did nothing, and the result sat encrypted forever with nothing able to use it.
A stored secret with no consumer is liability, not a dormant feature — it can still leak and it
cannot help. Migration `20260726210000` nulls the column; the column itself stays, since dropping it
buys nothing and `@secret_fields` keeps redacting whatever a stray write might put there.

**What a safe replacement would have to look like:** the secret must never enter a channel the
client can read. That rules out anything typed into the PTY. Options that would qualify:

- the user types the password themselves into a masked field per session (not a stored-secret
  reveal — it is the user entering their own secret, exactly as typing it at the prompt would be);
- `sudo NOPASSWD` on the host, or a privileged helper, so no password is needed interactively;
- the server executing a specific privileged command over its own SSH channel with the secret,
  returning only the command's result — never a shell the client is attached to.

### Rollback is not safe past this fix

**The scrub is enforced by application code, not by the schema.** There is no `CHECK` constraint
stopping a secret going into `terminal_config` — SQLite cannot add one without rebuilding the
table, which is not a thing to do casually to the table holding every credential.

The migrations correctly do not reverse (`down` cannot un-leak a secret), so the *data* stays clean
across a rollback. The *behaviour* does not: an image built before `2c23edc` accepts a nested
`sudoPassword`, stores it in cleartext, does not scrub on read, and nulls the encrypted column on
every save. One `docker compose up -d` on an old tag reintroduces the leak, and new cleartext starts
accumulating from the first host save.

Mitigated by removing the artifacts rather than trusting a note. Deleted from the host on
2026-07-26:

- the 25 `termelix:rollback-*` tags predating the cleartext fix, plus build contexts
  `/opt/termex.prev` and `.prev2`;
- `rollback-2026-07-26-174049` and `rollback-2026-07-26-173013`, plus contexts `.prev3` and
  `.prev4` — these post-dated the cleartext fix but still contained the **fill primitive** described
  above, gated in one and ungated in the other. Keeping them behind a warning would have repeated
  exactly the mistake the previous paragraph is about.

Two rollback points remain, both verified to contain neither the cleartext behaviour nor the fill
primitive:

| Tag | State |
|---|---|
| `rollback-2026-07-26-181302` | full removal; the editor no longer solicits a sudo password |
| `rollback-2026-07-26-175742` | fill primitive removed, but the editor still solicited one |

Prefer `181302`. Verified by grepping the shipped bundle inside each image, not by reasoning about
which commit went where.

The source for every removed image is still in git, so an older build can be reconstructed
deliberately — which is the point. What is gone is the ability to reintroduce a known vulnerability
with one command and no thought.

### The database-level guard, and why the first version was wrong

A trigger on `ssh_data` refuses any write that puts a `sudoPassword` into `terminal_config`. It
matters because everything above is enforced by application code, which holds only while the fixed
image is the one running.

The first attempt (`20260726220000`) matched `"sudoPassword":` as text with spaces stripped. It was
wrong in both directions, and both were demonstrated:

| Input | Old text match | Correct |
|---|---|---|
| `{"sudoPassword"\t:"LEAK"}` | allowed | refuse |
| `{"sudoPassword"\n:"LEAK"}` | allowed | refuse |
| `{"env":{"sudoPassword":"x"}}` | refused | allow — a nested key is not the secret |

The reason it stripped spaces at all — `json_config/1` passes a pre-encoded string through verbatim,
so an old client chooses the exact bytes — applies identically to tabs and newlines. Matching JSON
with `LIKE` was the mistake.

`20260726230000` asked SQLite's JSON parser instead — `json_extract(…, '$.sudoPassword')` — which
fixed the escapes and whitespace but asked only about a TOP-LEVEL key of an OBJECT. Two shapes
answered no while carrying the secret, both confirmed end to end as stored unencrypted **and**
returned in the host-list response:

    [{"sudoPassword":"..."}]        # the document is an array: no top-level key
    {"a":{"sudoPassword":"..."}}    # nested one level down

The nested case had been allowed **deliberately**, reasoning that the application only reads
`terminalConfig.sudoPassword` at the top level so a nested one is not "the secret". That confused
*does not use it* with *does not hand it over*. The rule is that the API never returns a stored
secret; one it does not happen to read is still one it returned. The same top-level-only assumption
was in the read scrub (`_not_a_map -> acc` skipped list blobs entirely) and the write scrub.

`20260726240000` uses `json_tree`, which walks the whole document: refuse an object key named
`sudoPassword` at any depth holding anything. Both scrubs are recursive to match, and
`20260726250000` cleans rows already stored. The motivating false positive is still allowed —
`{"env":[{"key":"sudoPassword","value":"x"}]}` has the word as a VALUE, and `json_tree.key` is only
the key when the parent is an object.

One exclusion remains deliberate: a key present but `null`/`""` passes. The old editor sent
`sudoPassword: form.sudoPassword || null`, so refusing it would stop a pre-fix client saving at all,
with no secret involved.

The second exclusion — invalid JSON passes — was wrong, and wrong in the same shape as the nested
case above. The reasoning was that a blob which will not parse cannot leak, because `parse_json/2`
falls back to `nil` and the field returns null rather than raw text. True of the host list, and
checked only there. `Termelix.UserDataExport` builds its rows with `Map.from_struct/1`, so it emits
every column verbatim, and a malformed blob went straight into the `format: "encrypted"` export —
the one documented as "a safe backup that never exposes plaintext". Measured against a running
server, with `terminalConfig` sent as `{"sudoPassword":"MALFORMED-LEAK",}`:

| Exit | Before | After |
|---|---|---|
| stored at rest | 1 | 0 |
| host-list response | 0 | 0 |
| encrypted export | **1** | 0 |

Checking one exit and concluding the room was sealed is the recurring error in this whole chain —
first the write path, then the read path, then the host list, and now the export.

`20260726260000` therefore requires `terminal_config` to be valid JSON and clears the malformed rows
already stored. This costs nothing: the column is written by `json_config/1` from a map or a
pre-encoded document, so anything that will not parse is junk no reader can use. Rejecting the whole
category beats pattern-matching secrets inside text that has no structure to match against. It is
two triggers per event rather than one with an `OR`, so a host refused for carrying a secret is not
told its JSON is malformed; the secret trigger keeps its `json_valid` guard because `json_tree`
raises on malformed input and trigger firing order is unspecified.

`UserDataExport.to_map/1` now scrubs the blob columns as well. That is the fourth layer and it is
not there for this bug — it is there because the function's contract is "every field", so the next
plain column to acquire a secret would otherwise reach exports with nobody having decided it should.

### Prevention

- `terminal_socket_test.exs` carries a regression guard that manufactures the exact prompt the old
  gate accepted, asserts `fillStoredPassword`/`fillSudoPassword` are unhandled frames, and asserts
  the secret never reaches the PTY. Reinstating either verb fails it.
- `host_controller_test.exs` pins that a sudo password is stored from NEITHER position — not
  top-level, not nested — and that a blob written by an older client still does not leak on read.
  Two negative controls: re-accepting a top-level value, and dropping the blob scrub.
- `HostEditorData.test.ts` pins that the editor collects neither field and ignores both when loading
  a host saved by an older client.
- `terminal_config_trigger_test.exs` pins each shape that evaded an earlier version of the guard —
  escaped and whitespace-separated keys, array documents, nesting, and now malformed JSON.
- `user_data_export_test.exs` pins that the export scrubs a row written before the guard existed
  (triggers dropped inside the sandbox transaction), while non-secret configuration survives.
  Negative control: dropping the scrub call fails it.
