#!/usr/bin/env bash
#
# docker/healthcheck.sh
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#
# Probes /ready on exactly the transport this container start serves, as
# recorded by app.server in /run/wirebuddy/listener.env. It never reads the
# database: HTTPS switched on in the UI only takes effect after a restart, and
# the probe must not flip before the listener does. No https-then-http
# fallback either, which would report a wrongly started plain listener healthy.

set -euo pipefail

STATE_FILE="/run/wirebuddy/listener.env"
[ -r "$STATE_FILE" ] || exit 1

SCHEME=""
HOST=""
PORT=""
while IFS='=' read -r key value; do
    case "$key" in
        SCHEME) SCHEME="$value" ;;
        HOST) HOST="$value" ;;
        PORT) PORT="$value" ;;
    esac
done < "$STATE_FILE"

case "$PORT" in
    ''|*[!0-9]*) exit 1 ;;
esac
[ -n "$HOST" ] || exit 1

case "$SCHEME" in
    http)
        exec curl --fail --silent --show-error --max-time 5 \
            "http://${HOST}:${PORT}/ready"
        ;;
    https)
        # --insecure is fine here: the probe targets the local listener to check
        # readiness, not the public server identity, and the certificate may be
        # self-signed.
        exec curl --fail --silent --show-error --max-time 5 --insecure \
            "https://${HOST}:${PORT}/ready"
        ;;
    *)
        exit 1
        ;;
esac
