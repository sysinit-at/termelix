#!/bin/sh
# Creates and starts the disposable e2e/screenshot stack in /tmp/tmx-e2e:
#
#   - a user-mode sshd on 127.0.0.1:2299 (key auth only, sftp enabled)
#   - a prod-mode Termelix server on 127.0.0.1:4321 with DATA_DIR=/tmp/tmx-e2e/data
#
# Idempotent: safe to re-run after a reboot or /tmp wipe. Keys, the data dir and the
# generated root secrets persist only as long as /tmp does — the stack is disposable by
# design, and `scripts/seed-e2e.sh` recreates the fixtures from nothing.
#
# The SPA Playwright suite (frontend repo, e2e/) and the screenshot generator
# (e2e-screenshots/) both point at it via TERMELIX_E2E_URL=http://127.0.0.1:4321.
set -eu

ROOT=/tmp/tmx-e2e
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SSH_PORT=2299
HTTP_PORT=4321

mkdir -p "$ROOT" "$ROOT/data" "$ROOT/tmux"
chmod 700 "$ROOT"

# --- SSH material -------------------------------------------------------------------------
[ -f "$ROOT/ssh_host_ed25519_key" ] ||
  ssh-keygen -q -t ed25519 -N '' -C tmx-e2e-host -f "$ROOT/ssh_host_ed25519_key"
[ -f "$ROOT/client_ed25519" ] ||
  ssh-keygen -q -t ed25519 -N '' -C tmx-e2e-client -f "$ROOT/client_ed25519"
cp "$ROOT/client_ed25519.pub" "$ROOT/authorized_keys"
chmod 600 "$ROOT/authorized_keys"

# Listen on loopback plus any showcase-fleet aliases that exist (scripts/e2e-net-aliases.sh).
# Conditional because sshd refuses to start when a ListenAddress is not present on the system,
# and the stack must come up with or without the sudo-only alias step.
LISTEN="ListenAddress 127.0.0.1"
for ip in $(ifconfig lo0 | awk '/inet 10\./ {print $2}'); do
  LISTEN="$LISTEN
ListenAddress $ip"
done

# StrictModes off: /tmp's sticky bit fails sshd's ownership walk even though $ROOT is 0700.
cat > "$ROOT/sshd_config.new" <<EOF
Port $SSH_PORT
$LISTEN
HostKey $ROOT/ssh_host_ed25519_key
PidFile $ROOT/sshd.pid
AuthorizedKeysFile $ROOT/authorized_keys
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
# Isolated tmux socket dir: sessions the app opens through this sshd must not share the
# developer's default tmux server — the tmux monitor would list (and screenshots would show)
# their personal sessions, and cleanup could never safely kill-server.
SetEnv TMUX_TMPDIR=$ROOT/tmux
Subsystem sftp /usr/libexec/sftp-server
EOF

# --- server scripts -----------------------------------------------------------------------
cat > "$ROOT/run-server.sh" <<EOF
#!/bin/sh
cd "$REPO"
# BIND=loopback: this instance carries committed fixture credentials and must never be
# reachable from the network — the prod default binds all interfaces.
exec env MIX_ENV=prod PORT=$HTTP_PORT DATA_DIR=$ROOT/data PHX_HOST=127.0.0.1 BIND=loopback mix phx.server
EOF
chmod +x "$ROOT/run-server.sh"

# Simulates `docker compose up -d`: same data dir, same secrets, new process.
cat > "$ROOT/restart.sh" <<EOF
#!/bin/sh
set -eu
if [ -f $ROOT/server.pid ]; then
  kill "\$(cat $ROOT/server.pid)" 2>/dev/null || true
  i=0
  while kill -0 "\$(cat $ROOT/server.pid)" 2>/dev/null; do
    i=\$((i + 1)); [ "\$i" -gt 100 ] && { echo "server would not die" >&2; exit 1; }
    sleep 0.2
  done
fi
nohup $ROOT/run-server.sh >> $ROOT/server.log 2>&1 &
echo \$! > $ROOT/server.pid
i=0
until curl -fs http://127.0.0.1:$HTTP_PORT/health > /dev/null 2>&1; do
  i=\$((i + 1)); [ "\$i" -gt 300 ] && { echo "server did not become healthy; see $ROOT/server.log" >&2; exit 1; }
  sleep 0.5
done
echo "termelix ready on http://127.0.0.1:$HTTP_PORT"
EOF
chmod +x "$ROOT/restart.sh"

# --- bring it up --------------------------------------------------------------------------
# Restart sshd only when its config changed (e.g. new lo0 aliases to listen on); an
# unchanged running sshd keeps its connections.
if ! cmp -s "$ROOT/sshd_config.new" "$ROOT/sshd_config" 2>/dev/null; then
  mv "$ROOT/sshd_config.new" "$ROOT/sshd_config"
  if [ -f "$ROOT/sshd.pid" ]; then
    old_pid="$(cat "$ROOT/sshd.pid")"
    kill "$old_pid" 2>/dev/null || true
    i=0
    while kill -0 "$old_pid" 2>/dev/null; do
      i=$((i + 1)); [ "$i" -gt 50 ] && break
      sleep 0.1
    done
  fi
else
  rm "$ROOT/sshd_config.new"
fi

if [ -f "$ROOT/sshd.pid" ] && kill -0 "$(cat "$ROOT/sshd.pid")" 2>/dev/null; then
  echo "sshd already running (pid $(cat "$ROOT/sshd.pid"))"
else
  # Absolute path: sshd re-execs itself and refuses a relative invocation.
  /usr/sbin/sshd -f "$ROOT/sshd_config"
  echo "sshd listening on port $SSH_PORT"
fi

# Compile ahead of the nohup'd start so the health poll measures boot, not the build.
(cd "$REPO" && MIX_ENV=prod mix compile --no-optional-deps > /dev/null)

# Migrations auto-run only in a release (RELEASE_NAME set); under `mix phx.server` the
# boot-time migrator is skipped, so a fresh DATA_DIR needs this or there are no tables.
(cd "$REPO" && MIX_ENV=prod DATA_DIR="$ROOT/data" mix ecto.migrate > /dev/null)

"$ROOT/restart.sh"
