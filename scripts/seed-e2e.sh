#!/bin/sh
# Seeds the /tmp/tmx-e2e stack (scripts/e2e-stack.sh) with its two fixture users:
#
#   admin / <fixed showcase password>  — a plausible-looking fleet for website screenshots.
#     Every fleet entry is fake (10.x addresses, never connected) except `web-01`, which
#     points at the stack's own sshd so terminals, file manager and tmux are real in shots.
#   e2e / e2e-password-123             — the SPA Playwright suite's fixture: host `e2e-local`.
#
# Idempotent: existing users and hosts are left alone. Everything here is disposable,
# loopback-only fixture data — none of these credentials guard anything real.
set -eu

BASE=http://127.0.0.1:4321
ROOT=/tmp/tmx-e2e

ADMIN_USER=admin
ADMIN_PASS=uFhh7A9AG13lXZw4g1lxLPp
E2E_USER=e2e
E2E_PASS=e2e-password-123

ADMIN_JAR="$ROOT/seed-admin-cookies.txt"
E2E_JAR="$ROOT/seed-e2e-cookies.txt"

# api <jar> <method> <path> <json-body|-> ; prints body, returns curl's -f status
api() {
  jar=$1 method=$2 path=$3 body=$4
  if [ "$body" = "-" ]; then
    curl -fsS -X "$method" "$BASE$path" -b "$jar" -c "$jar"
  else
    curl -fsS -X "$method" "$BASE$path" -b "$jar" -c "$jar" \
      -H 'Content-Type: application/json' -d "$body"
  fi
}

login() {
  jar=$1 user=$2 pass=$3
  api "$jar" POST /users/login \
    "$(jq -n --arg u "$user" --arg p "$pass" '{username: $u, password: $p}')" > /dev/null
}

# Registration may be open (fine) or closed after the first user (fall back to the
# admin-only door). "Already exists" is success for a seeding script.
ensure_user() {
  user=$1 pass=$2
  body="$(jq -n --arg u "$user" --arg p "$pass" '{username: $u, password: $p}')"
  api /dev/null POST /users/create "$body" > /dev/null 2>&1 ||
    api "$ADMIN_JAR" POST /users/admin-create "$body" > /dev/null 2>&1 ||
    true
}

# ensure_host <jar> <json> — skipped if a host with that name already exists for the user.
ensure_host() {
  jar=$1 json=$2
  name="$(printf '%s' "$json" | jq -r .name)"
  if printf '%s' "$EXISTING" | jq -e --arg n "$name" 'index($n)' > /dev/null; then
    echo "  = $name (exists)"
  else
    api "$jar" POST /host/db/host "$json" > /dev/null
    echo "  + $name"
  fi
}

fetch_existing() { EXISTING="$(api "$1" GET /host/db/host - | jq '[.[].name]')"; }

# Fake fleet entries share one throwaway password; it is write-only and never used.
DUMMY_PASS="$(head -c 18 /dev/urandom | base64)"

fake_host() {
  # name ip port username folder tags(comma) pinned(true/false)
  jq -n --arg name "$1" --arg ip "$2" --argjson port "$3" --arg user "$4" \
        --arg folder "$5" --arg tags "$6" --argjson pin "$7" --arg pw "$DUMMY_PASS" '
    {name: $name, ip: $ip, port: $port, username: $user, authType: "password",
     password: $pw, folder: $folder, tags: ($tags | split(",")), pin: $pin,
     enableSsh: true, enableTerminal: true, enableFileManager: true, enableTunnel: true}'
}

real_host() {
  # name ip folder tags pinned — the stack sshd with the stack client key
  jq -n --arg name "$1" --arg ip "$2" --arg folder "$3" --arg tags "$4" --argjson pin "$5" \
        --rawfile key "$ROOT/client_ed25519" '
    {name: $name, ip: $ip, port: 2299, username: "'"$(id -un)"'",
     authType: "key", key: $key, folder: $folder, tags: ($tags | split(",")), pin: $pin,
     enableSsh: true, enableTerminal: true, enableFileManager: true, enableTunnel: true,
     enableTmuxMonitor: true}'
}

# web-01 is the host screenshots open a real terminal on. With the lo0 aliases in place
# (scripts/e2e-net-aliases.sh, sudo) it lives on its fleet address; without them it falls
# back to plain loopback so the terminal still works.
WEB01_IP=127.0.0.1
ifconfig lo0 2>/dev/null | grep -q "inet 10\.0\.4\.11 " && WEB01_IP=10.0.4.11

echo "users:"
ensure_user "$ADMIN_USER" "$ADMIN_PASS"   # first registration => admin
login "$ADMIN_JAR" "$ADMIN_USER" "$ADMIN_PASS"
ensure_user "$E2E_USER" "$E2E_PASS"
login "$E2E_JAR" "$E2E_USER" "$E2E_PASS"
echo "  admin, e2e ready"

echo "hosts ($E2E_USER):"
fetch_existing "$E2E_JAR"
ensure_host "$E2E_JAR" "$(real_host e2e-local 127.0.0.1 '' '' false)"

# Fake fleet addresses must stay in sync with scripts/e2e-net-aliases.sh. Port 2299 on every
# entry: the sidebar shows only user@ip, and 2299 is what the stack sshd answers on, so the
# TCP status probe reports the whole fleet online once the aliases exist.
echo "hosts ($ADMIN_USER):"
fetch_existing "$ADMIN_JAR"
ensure_host "$ADMIN_JAR" "$(real_host web-01 "$WEB01_IP" Production prod,web true)"
while IFS='|' read -r name ip port user folder tags pin; do
  ensure_host "$ADMIN_JAR" "$(fake_host "$name" "$ip" "$port" "$user" "$folder" "$tags" "$pin")"
done <<'EOF'
web-02|10.0.4.12|2299|deploy|Production|prod,web|true
web-03|10.0.4.13|2299|deploy|Production|prod,web|false
db-primary|10.0.4.20|2299|postgres|Production|prod,db|true
db-replica|10.0.4.21|2299|postgres|Production|prod,db|false
cache-01|10.0.4.30|2299|deploy|Production|prod,cache|false
lb-edge|10.0.4.5|2299|admin|Production|prod,edge|false
staging-app|10.1.4.11|2299|deploy|Staging|staging,web|false
staging-db|10.1.4.20|2299|postgres|Staging|staging,db|false
build-runner-1|10.2.0.7|2299|ci|Infrastructure|ci|false
build-runner-2|10.2.0.8|2299|ci|Infrastructure|ci|false
monitoring|10.2.0.10|2299|admin|Infrastructure|infra,metrics|false
backup-vault|10.2.0.15|2299|borg|Infrastructure|infra,backup|false
EOF

echo "seeded."
