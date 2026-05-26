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
    # Extract gui_localhost_only setting (default: false)
    LOCALHOST_ONLY="$(read_setting gui_localhost_only || true)"
    LOCALHOST_ONLY="$(normalize_bool "$LOCALHOST_ONLY")"
    case "$LOCALHOST_ONLY" in
        1|true|yes|on)
            HOST="127.0.0.1"
            echo "GUI binding to localhost only (127.0.0.1)"
            ;;
    esac
    
    # Extract gui_port setting (default: 8000)
    DB_PORT="$(read_setting gui_port || true)"
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
WORKERS_RAW="${UVICORN_WORKERS:-1}"
GRACEFUL_SHUTDOWN_TIMEOUT="${UVICORN_GRACEFUL_SHUTDOWN_TIMEOUT:-8}"

case "$WORKERS_RAW" in
    ''|*[!0-9]*)
        echo "Invalid UVICORN_WORKERS='$WORKERS_RAW' - forcing 1" >&2
        WORKERS="1"
        ;;
    0)
        echo "UVICORN_WORKERS must be >= 1 - forcing 1" >&2
        WORKERS="1"
        ;;
    1)
        WORKERS="1"
        ;;
    *)
        echo "UVICORN_WORKERS=$WORKERS_RAW requested, but WireBuddy web mode is single-worker only - forcing 1" >&2
        WORKERS="1"
        ;;
esac

if ! is_valid_timeout "$GRACEFUL_SHUTDOWN_TIMEOUT"; then
    echo "Invalid UVICORN_GRACEFUL_SHUTDOWN_TIMEOUT='$GRACEFUL_SHUTDOWN_TIMEOUT' - forcing 8" >&2
    GRACEFUL_SHUTDOWN_TIMEOUT="8"
fi

echo "Starting WireBuddy on ${HOST}:${PORT} with ${WORKERS} worker(s)"

UVICORN_ARGS=(
    app:create_app
    --host "$HOST"
    --port "$PORT"
    --factory
    --workers "$WORKERS"
    --timeout-graceful-shutdown "$GRACEFUL_SHUTDOWN_TIMEOUT"
)

# Trust loopback proxy headers by default so HTTPS origin checks work behind
# a local reverse proxy like Caddy or nginx on the same host. Direct clients
# are unaffected because uvicorn still only trusts the configured proxy IPs.
TRUST_PROXY_HEADERS="$(normalize_bool "${WIREBUDDY_TRUST_PROXY_HEADERS:-1}")"

case "$TRUST_PROXY_HEADERS" in
    1|true|yes|on)
        FORWARDED_ALLOW_IPS_VALUE="${FORWARDED_ALLOW_IPS:-127.0.0.1}"
        if [ "$FORWARDED_ALLOW_IPS_VALUE" = "*" ]; then
            echo "FORWARDED_ALLOW_IPS='*' is unsafe; configure explicit proxy IPs" >&2
            exit 1
        fi

        echo "Trusting proxy headers from: ${FORWARDED_ALLOW_IPS_VALUE}"

        UVICORN_ARGS+=(
            --proxy-headers
            --forwarded-allow-ips="$FORWARDED_ALLOW_IPS_VALUE"
        )
        ;;
esac

exec uvicorn "${UVICORN_ARGS[@]}"
