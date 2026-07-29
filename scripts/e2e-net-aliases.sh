#!/bin/sh
# Adds the loopback aliases that make the seeded showcase fleet (scripts/seed-e2e.sh) look
# real: each fake host's 10.x address exists on lo0, the stack sshd listens on it, and the
# server's TCP status probe therefore reports every host as ONLINE with sub-second /status
# responses (instead of 5s-timeout "offline" for unroutable addresses).
#
# Needs root; run as:  sudo scripts/e2e-net-aliases.sh
# Aliases are host-local (/32 on lo0), not routed, and vanish on reboot. Re-run after a
# reboot, then re-run scripts/e2e-stack.sh so sshd picks the addresses up.
#
# The list must match the fleet in scripts/seed-e2e.sh.
set -eu

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }

for ip in \
  10.0.4.5 10.0.4.11 10.0.4.12 10.0.4.13 10.0.4.20 10.0.4.21 10.0.4.30 \
  10.1.4.11 10.1.4.20 \
  10.2.0.7 10.2.0.8 10.2.0.10 10.2.0.15; do
  if ifconfig lo0 | grep -q "inet $ip "; then
    echo "  = $ip (already aliased)"
  else
    ifconfig lo0 alias "$ip" 255.255.255.255
    echo "  + $ip"
  fi
done
echo "done — now re-run scripts/e2e-stack.sh (as your user, not root)"
