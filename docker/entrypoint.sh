#!/usr/bin/env bash
#
# docker/entrypoint.sh
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# WireBuddy Docker Entrypoint
# Reads GUI settings from database before starting uvicorn

set -euo pipefail

is_valid_port() {
    case "$1" in
        ''|*[!0-9]*)
            return 1
            ;;
    esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

is_valid_host() {
    case "$1" in
        ''|*[[:space:]]*|*://*|*/*)
            return 1
            ;;
        0.0.0.0|127.0.0.1|localhost|::|::1)
            return 0
            ;;
        *)
            case "$1" in
                *[!A-Za-z0-9._:-]*)
                    return 1
                    ;;
                *)
                    return 0
                    ;;
            esac
            ;;
    esac
}

is_valid_timeout() {
    case "$1" in
        ''|*[!0-9]*)
            return 1
            ;;
    esac
    [ "$1" -ge 1 ] && [ "$1" -le 300 ]
}

normalize_bool() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

read_setting() {
    local key="$1"
    local sql
    local value

    case "$key" in
        gui_localhost_only)
            sql="SELECT value FROM settings WHERE key='gui_localhost_only' LIMIT 1"
            ;;
        gui_port)
            sql="SELECT value FROM settings WHERE key='gui_port' LIMIT 1"
            ;;
        *)
            echo "Refusing unknown setting key: '$key'" >&2
            return 1
            ;;
    esac

    if ! command -v sqlite3 >/dev/null 2>&1; then
        echo "sqlite3 binary not found; cannot read GUI setting '$key'" >&2
        return 1
    fi

    if ! value="$(sqlite3 "$DB_PATH" "$sql" 2>&1)"; then
        echo "Could not read setting '$key': $value" >&2
        return 1
    fi

    printf '%s' "$value"
}

# ─── NODE MODE ───────────────────────────────────────────
# In node mode, skip all master logic and run the daemon directly
SERVER_MODE="${SERVER_MODE:-master}"
case "$SERVER_MODE" in
    master)
        ;;
    node)
        echo "Starting WireBuddy in NODE mode"
        exec python -c "from app.node.daemon import run; run()"
        ;;
    *)
        echo "Invalid SERVER_MODE='$SERVER_MODE' expected 'master' or 'node'" >&2
        exit 1
        ;;
esac

# ─── MASTER MODE ─────────────────────────────────────────
DATA_DIR="${WIREBUDDY_DATA_DIR:-/app/data}"
DB_PATH="${DATA_DIR}/wirebuddy.db"
HOST="0.0.0.0"
PORT="8000"

if [ -f "$DB_PATH" ] && ! command -v sqlite3 >/dev/null 2>&1; then
    echo "Database exists but sqlite3 is missing; refusing to ignore GUI bind settings" >&2
    exit 1
fi

# Read settings from database if it exists
if [ -f "$DB_PATH" ]; then
    # Extract gui_localhost_only setting (default: false). This is a
    # security-relevant bind decision, so a read failure (lock, corrupt DB,
    # missing table, ...) must fail closed instead of silently defaulting to
    # 0.0.0.0.
    if ! LOCALHOST_ONLY="$(read_setting gui_localhost_only)"; then
        echo "Could not read gui_localhost_only; refusing to start with an unknown bind exposure" >&2
        exit 1
    fi
    LOCALHOST_ONLY="$(normalize_bool "$LOCALHOST_ONLY")"
    case "$LOCALHOST_ONLY" in
        1|true|yes|on)
            HOST="127.0.0.1"
            echo "GUI binding to localhost only (127.0.0.1)"
            ;;
        ''|0|false|no|off)
            ;;
        *)
            echo "Unrecognised gui_localhost_only value '$LOCALHOST_ONLY'; refusing to start with an unknown bind exposure" >&2
            exit 1
            ;;
    esac

    # Extract gui_port setting (default: 8000)
    if ! DB_PORT="$(read_setting gui_port)"; then
        echo "Could not read gui_port from database" >&2
        exit 1
    fi
    if [ -n "$DB_PORT" ] && is_valid_port "$DB_PORT"; then
        PORT="$DB_PORT"
    elif [ -n "$DB_PORT" ]; then
        echo "Ignoring invalid gui_port from database: '$DB_PORT'" >&2
    fi
fi

# Allow environment override
if [ -n "${WIREBUDDY_HOST:-}" ]; then
    if is_valid_host "$WIREBUDDY_HOST"; then
        HOST="$WIREBUDDY_HOST"
    else
        echo "Invalid WIREBUDDY_HOST='$WIREBUDDY_HOST'" >&2
        exit 1
    fi
fi
if [ -n "${WIREBUDDY_PORT:-}" ]; then
    if is_valid_port "$WIREBUDDY_PORT"; then
        PORT="$WIREBUDDY_PORT"
    else
        echo "Invalid WIREBUDDY_PORT='$WIREBUDDY_PORT'" >&2
        exit 1
    fi
fi

GRACEFUL_SHUTDOWN_TIMEOUT="${UVICORN_GRACEFUL_SHUTDOWN_TIMEOUT:-8}"

if ! is_valid_timeout "$GRACEFUL_SHUTDOWN_TIMEOUT"; then
    echo "Invalid UVICORN_GRACEFUL_SHUTDOWN_TIMEOUT='$GRACEFUL_SHUTDOWN_TIMEOUT' - forcing 8" >&2
    GRACEFUL_SHUTDOWN_TIMEOUT="8"
fi

# app.server reads WIREBUDDY_TRUSTED_PROXIES for uvicorn's proxy-header trust
# and the application-level checks (app/utils/config.py) share it, so there is
# one variable for "who is my reverse proxy". Loopback is trusted by default so
# HTTPS origin checks work behind a local Caddy or nginx.
if [ "${WIREBUDDY_TRUSTED_PROXIES:-}" = "*" ]; then
    echo "WIREBUDDY_TRUSTED_PROXIES='*' is unsafe; configure explicit proxy IPs" >&2
    exit 1
fi
echo "Trusting proxy headers from: ${WIREBUDDY_TRUSTED_PROXIES:-127.0.0.1,::1}"

# Runtime state, not data: recreated on every start, so a stale file from the
# previous run can never describe this one. app.server writes it once the
# listener (and, with HTTPS, the certificate) is resolved; the HEALTHCHECK
# reads only this file.
export WIREBUDDY_LISTENER_STATE="/run/wirebuddy/listener.env"
rm -f "$WIREBUDDY_LISTENER_STATE"

# Single start path shared with run.py: app.server decides HTTP vs built-in
# HTTPS from gui_https_enabled, resolves the certificate (Let's Encrypt or
# self-signed) and runs one uvicorn worker - the job queue and session/rate-
# limit state live in-process.
echo "Starting WireBuddy on ${HOST}:${PORT}"
exec python -m app.server \
    --host "$HOST" \
    --port "$PORT" \
    --timeout-graceful-shutdown "$GRACEFUL_SHUTDOWN_TIMEOUT"
