# Termelix on the BEAM — production image.
#
# Stage 1 builds the React SPA from the original Termix frontend source (vendored in at
# build time via the build context, see docker-compose.yml), stage 2 builds the Elixir
# release with the SPA staged into priv/static/spa, stage 3 is a slim runtime.
#
# The single container replaces the original's nginx + 12 Node services: the Phoenix
# endpoint serves the SPA and every API/WS path on one port.

ARG ELIXIR_IMAGE=elixir:1.20-otp-29-slim

# --- Stage 1: frontend (optional; skipped when priv/static/spa is pre-staged) -----------
FROM node:24-slim AS frontend
WORKDIR /src
# The build expects the Termelix frontend source at ./frontend (git submodule or copy).
COPY frontend/package*.json frontend/.npmrc* ./
RUN npm install --ignore-scripts --no-audit --no-fund || true
COPY frontend/ ./
RUN if [ -f package.json ]; then \
      NODE_OPTIONS="--max-old-space-size=3072" npx vite build; \
    else \
      mkdir -p dist; \
    fi

# Pre-compress, because `Plug.Static` is configured with `gzip: true`/`brotli: true` and those
# options serve a `.gz`/`.br` sibling ONLY if one exists on disk — Vite emits neither. Without
# this the endpoint quietly serves every asset raw: 756 KB of JavaScript on each cold load
# instead of 236 KB, and the flag in `endpoint.ex` looks like it is doing something.
#
# `scripts/build-frontend.sh` has always done this for a locally staged SPA; the container path
# copies `dist/` straight out of this stage and so never ran it. Two ways to produce the same
# directory and only one of them compressed.
#
# Compressing at BUILD time rather than per request: these files are immutable and
# fingerprinted, so paying maximum-effort compression once is strictly better than paying a
# cheaper compression on every request forever.
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends brotli \
    && rm -rf /var/lib/apt/lists/* \
    && find dist -type f \
         \( -name '*.js' -o -name '*.css' -o -name '*.html' -o -name '*.svg' \
            -o -name '*.json' -o -name '*.wasm' \) -size +1k \
         -exec gzip -9 -k {} + \
    && find dist -type f \
         \( -name '*.js' -o -name '*.css' -o -name '*.html' -o -name '*.svg' \
            -o -name '*.json' -o -name '*.wasm' \) -size +1k \
         -exec brotli -q 11 -k {} +

# --- Stage 2: release --------------------------------------------------------------------
FROM ${ELIXIR_IMAGE} AS build
ENV MIX_ENV=prod
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends build-essential git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mix local.hex --force && mix local.rebar --force

COPY mix.exs mix.lock ./
RUN mix deps.get --only prod && mix deps.compile

COPY config config
COPY lib lib
COPY priv priv
# `mix release` renders rel/env.sh.eex into the release; without this COPY it silently falls
# back to the default all-commented env.sh and the hardening in it is lost.
COPY rel rel
# Stage the SPA (from stage 1, or the pre-staged priv/static/spa already copied above).
COPY --from=frontend /src/dist/ priv/static/spa/

RUN mix compile && mix release

# --- Stage 3: runtime --------------------------------------------------------------------
FROM debian:trixie-slim
# ERL_CRASH_DUMP_SECONDS mirrors rel/env.sh.eex so it still holds when that script is bypassed
# — `docker exec` into the container, or a CMD override that boots the erts erl directly. A
# crash dump would contain :persistent_term and every ETS table, i.e. the encryption key and
# every cached DEK in plaintext; 0 makes the VM skip writing it.
ENV LANG=C.UTF-8 \
    DATA_DIR=/app/data \
    PHX_SERVER=true \
    PORT=8080 \
    PHX_HOST=localhost \
    ERL_CRASH_DUMP_SECONDS=0
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
      libstdc++6 openssl libncurses6 locales ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m termelix \
    && mkdir -p /app/data && chown -R termelix:termelix /app

COPY --from=build --chown=termelix:termelix /app/_build/prod/rel/termelix ./

USER termelix
VOLUME ["/app/data"]
EXPOSE 8080

# Liveness only — deliberately NOT /health/ready. Terminal sessions are `restart: :temporary`
# processes holding their SSH connection and scrollback in memory, so an unhealthy verdict acted
# on by an autoheal sidecar (or a `service_healthy` dependency) destroys every live session. A
# database that has gone away must page a human, not restart the container. Poll /health/ready
# from the proxy or a monitor instead.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD wget -q -O /dev/null http://localhost:8080/health/live || exit 1

CMD ["bin/termelix", "start"]
