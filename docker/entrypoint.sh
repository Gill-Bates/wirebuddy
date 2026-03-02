#!/bin/sh
# WireBuddy Docker Entrypoint
# Reads GUI settings from database before starting uvicorn

set -e

DB_PATH="${WIREBUDDY_DATA_DIR:-/data}/wirebuddy.db"
HOST="0.0.0.0"
PORT="8000"

# Read settings from database if it exists
if [ -f "$DB_PATH" ]; then
    # Extract gui_localhost_only setting (default: false)
    LOCALHOST_ONLY=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='gui_localhost_only'" 2>/dev/null || echo "")
    if [ "$LOCALHOST_ONLY" = "1" ] || [ "$LOCALHOST_ONLY" = "true" ] || [ "$LOCALHOST_ONLY" = "yes" ]; then
        HOST="127.0.0.1"
        echo "GUI binding to localhost only (127.0.0.1)"
    fi
    
    # Extract gui_port setting (default: 8000)
    DB_PORT=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='gui_port'" 2>/dev/null || echo "")
    if [ -n "$DB_PORT" ] && [ "$DB_PORT" -eq "$DB_PORT" ] 2>/dev/null; then
        PORT="$DB_PORT"
    fi
fi

# Allow environment override
HOST="${WIREBUDDY_HOST:-$HOST}"
PORT="${WIREBUDDY_PORT:-$PORT}"

echo "Starting WireBuddy on ${HOST}:${PORT}"

exec uvicorn app:create_app \
    --host "$HOST" \
    --port "$PORT" \
    --factory \
    --workers "${UVICORN_WORKERS:-2}" \
    --proxy-headers \
    --forwarded-allow-ips="${FORWARDED_ALLOW_IPS:-}"
