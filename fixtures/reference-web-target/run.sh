#!/usr/bin/env sh
# Serve the reference web target: http://127.0.0.1:9201/ (site) and
# http://localhost:9202/ (third-party service). Extra arguments pass through
# (--port, --third-party-port).
cd "$(dirname "$0")" && exec node server.mjs "$@"
