# Tmux power-feature evaluation (vk539)

Assessment of features from **herdr** (`../herdr`, a Rust
tmux-alternative + agent multiplexer) and **tmux-switcher / `tms`**
(`../tmux-switcher`, a zsh fzf switcher) worth porting into
Termelix's tmux monitor to make it the product's #1 power feature.

_Last updated via the 2026-07-24 task sweep._

## The load-bearing constraint

herdr and `tms` are **local** tools with direct process/filesystem/socket access to the
machine they run on. Termelix observes **remote** tmux over short-lived SSH `exec` (tmux
`-F` format strings + `ps`, parsed server-side). So "port" means **reimplement the concepts
with data reachable over SSH**, not lift the Rust/zsh code. Anything that depends on
local-only state (herdr's socket API, `~/.agents/registry.json`, `~/.tmuxp`, the workspace
layout) needs a per-host, over-SSH equivalent or is out of scope.

## What the monitor already has

Per-host overview (sessions → windows → panes) with `pane_current_command`, per-pane
CPU/mem/GPU (`ps` process-tree), tags, scrollback search, and the mutating actions
(create/rename/kill/split/focus). Plus the new **global view** (all sessions across all
hosts, vk536).

## Feasibility ranking

### 1. Agent / activity status per session — HIGH value, feasible → **the flagship feature**
herdr's headline ("every agent at a glance — blocked, working, done") and `tms`'s live
tiering (waiting agents → working → idle). Termelix already collects the raw signals:
`pane_current_command` + per-pane CPU + process tree. Classify each session/pane into
`working` / `idle` / `waiting-for-input` (heuristic: foreground command ∈ known agent set
or non-shell + CPU threshold → working; shell prompt + ~0 CPU → idle; a known agent process
that is idle → waiting), surface a status badge per session in both the per-host and global
views, and **tier-sort** sessions by it (waiting/working first). Optional refinement: read a
per-host agent registry file over SSH when present. This turns the monitor into an
at-a-glance multi-host agent dashboard — the single highest-leverage item.

### 2. Tiering + fuzzy filter in the global view — HIGH value, low effort
`tms`'s ranked live view: tier by status (from #1), recency within tier, and a fuzzy filter
box. Pure frontend once #1 provides the status field. Natural fast-follow to #1.

### 3. "Remotes" awareness — MEDIUM
`tms`'s remotes view flags panes whose foreground is an ssh/mosh/autossh/et client (nested
SSH). We have `pane_current_command`; flag ssh-family panes and show the command line as
typed. Niche in a web monitor but cheap given the data.

### 4. tmuxp template / project awareness — MEDIUM/LOW
`tms` spawns sessions from `~/.tmuxp` templates and jumps into project dirs. A per-host
"new session from tmuxp template" is feasible only where tmuxp is installed on the host, and
the "projects" notion is tied to the user's local workspace layout — low fit for remote
monitoring.

### Out of scope
herdr's socket API, plugin marketplace, kitty-graphics rendering, and Rust internals; and
any feature keyed on local-only state that has no per-host over-SSH equivalent.

## Implementation status (2026-07-24)

Recommendation implemented — **#1, #2, #3 shipped**:

- **#1 activity status** — the overview probe samples `ps`; every pane/session is classified
  `waiting`/`working`/`running`/`idle` server-side (`Termelix.Tmux.classify_pane/3` +
  `session_status/1`), with per-pane `cpuPercent`/`topCommand`. Available in the per-host
  overview and the aggregate.
- **#2 tiering + filter** — the global view tier-sorts sessions by status and has a filter
  box; a shared `TmuxStatusBadge` shows the status dot in both the global view and the
  per-host `SessionTree`.
- **#3 remotes flag** — panes running an ssh/mosh/et client are flagged `isRemote`; sessions
  with a remote pane get an "ssh" chip.

**#4 (tmuxp/projects)** and the out-of-scope items remain deferred.

## Recommendation

Implement **#1 (agent/activity status)** as the next focused piece, with **#2 (tiering +
fuzzy filter)** immediately after — together they realize herdr's "at a glance" promise and
`tms`'s live tiering across all hosts, building directly on data the monitor already
gathers. #3 is a cheap add-on; #4 and the rest are deferred/out of scope. Each should be its
own scoped change (status classifier + badge → tiering/filter → remotes flag).
