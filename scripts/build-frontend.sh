#!/usr/bin/env bash
# Build the Termelix React SPA and stage it into priv/static/spa/ for Phoenix to serve.
#
# The production build uses same-origin API paths, so the SPA talks to this Phoenix
# endpoint directly (no nginx). Override TERMELIX_FRONTEND_SRC to point at the React source.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${TERMELIX_FRONTEND_SRC:-$ROOT/../termelix-frontend}"
DEST="$ROOT/priv/static/spa"

echo "Building Termelix frontend from: $SRC"
cd "$SRC"
npm install --ignore-scripts --no-audit --no-fund
NODE_OPTIONS="--max-old-space-size=4096" npx vite build

mkdir -p "$DEST"
rsync -a --delete "$SRC/dist/" "$DEST/"

# Pre-compress text assets: Plug.Static serves the .gz variant when the client accepts
# gzip (the Vite build itself emits none). Keep the originals for non-gzip clients.
find "$DEST" -type f \( -name '*.js' -o -name '*.css' -o -name '*.html' -o -name '*.svg' \
  -o -name '*.json' -o -name '*.wasm' \) -size +1k -exec gzip -9 -k {} +

# ...and brotli, which `Plug.Static` prefers. Skipped silently when the binary is absent: a
# local staging run without brotli should still work, just with gzip only.
if command -v brotli >/dev/null 2>&1; then
  find "$DEST" -type f \( -name '*.js' -o -name '*.css' -o -name '*.html' -o -name '*.svg' \
    -o -name '*.json' -o -name '*.wasm' \) -size +1k -exec brotli -q 11 -k {} +
fi

echo "Staged SPA -> $DEST"
