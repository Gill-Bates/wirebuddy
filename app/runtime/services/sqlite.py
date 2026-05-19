#
# app/runtime/services/sqlite.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: AGPL-3.0
#

"""SQLite database lifecycle service.

Manages:
- Schema initialization
- Secret key validation
- WAL checkpointing
- Connection cleanup
- Graceful shutdown with data integrity
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING

from ..service import RuntimeService, ServiceHealth

if TYPE_CHECKING:
    from ...utils.config import Config

_log = logging.getLogger(__name__)


class SQLiteService(RuntimeService):
    """SQLite database lifecycle management.

    Handles database initialization at startup and ensures clean
    WAL checkpoint + connection closure at shutdown.
    """

    name = "sqlite"
    dependencies = []  # No dependencies - foundational service
    start_timeout = 30.0
    stop_timeout = 15.0

    # WAL checkpoint retry configuration
    CHECKPOINT_MAX_ATTEMPTS = 10
    CHECKPOINT_RETRY_DELAY = 0.2

    def __init__(self, config: Config) -> None:
        super().__init__()
        self._config = config
        self._db_path = config.db_path
        self._key_mismatch = False
        self._schema_version: str | None = None

    @property
    def db_path(self) -> Path:
        """Database file path."""
        return self._db_path

    @property
    def key_mismatch(self) -> bool:
        """True if secret key doesn't match database encryption."""
        return self._key_mismatch

    async def _do_start(self) -> None:
        """Initialize database schema and validate secret key."""
        result = await asyncio.to_thread(self._bootstrap_sync)
        self._key_mismatch = result.get("key_mismatch", False)
        self._schema_version = result.get("schema_version")

        if self._key_mismatch:
            raise RuntimeError("WIREBUDDY_SECRET_KEY does not match database encryption key")

        _log.info(
            "SQLITE_INITIALIZED path=%s schema_version=%s",
            self._db_path,
            self._schema_version,
        )

    async def _do_stop(self) -> None:
        """Checkpoint WAL and close all connections."""
        checkpoint, closed = await asyncio.to_thread(self._shutdown_sync)

        _log.info(
            "SQLITE_SHUTDOWN connections_closed=%d checkpoint_mode=%s busy=%s "
            "log_frames=%s checkpointed_frames=%s attempts=%s",
            closed,
            checkpoint.get("mode"),
            checkpoint.get("busy"),
            checkpoint.get("log_frames"),
            checkpoint.get("checkpointed_frames"),
            checkpoint.get("attempts"),
        )

    async def check_health(self) -> ServiceHealth:
        """Verify database connectivity."""
        health = await super().check_health()

        if not self.is_running:
            return health

        try:
            ok = await asyncio.to_thread(self._check_connectivity)
            health.healthy = ok
            if not ok:
                health.error = "Database connectivity check failed"
        except Exception as exc:
            health.healthy = False
            health.error = str(exc)

        return health

    def _bootstrap_sync(self) -> dict[str, object]:
        """Synchronous database bootstrap (runs in thread)."""
        from ...db.sqlite_runtime import connect, close_connection
        from ...db.sqlite_schema import init_schema, insert_default_settings
        from ...db.sqlite_settings import validate_secret_key

        conn = connect(self._db_path)
        result: dict[str, object] = {"key_mismatch": False}

        try:
            init_schema(conn)

            # Validate secret key
            if not validate_secret_key(conn, self._config.secret_key):
                result["key_mismatch"] = True
                _log.critical(
                    "KEY_MISMATCH_DETECTED: WIREBUDDY_SECRET_KEY does not match "
                    "the key used to encrypt this database"
                )
                return result

            insert_default_settings(conn)

            # Get schema version for health reporting
            cursor = conn.execute("PRAGMA user_version")
            row = cursor.fetchone()
            result["schema_version"] = str(row[0]) if row else "unknown"

        finally:
            close_connection(conn)

        return result

    def _shutdown_sync(self) -> tuple[dict[str, int | str | None], int]:
        """Synchronous database shutdown (runs in thread)."""
        from ...db.sqlite_runtime import checkpoint_wal, close_all_connections

        closed_connections = close_all_connections()
        checkpoint: dict[str, int | str | None] = {
            "mode": "RESTART",
            "busy": -1,
            "log_frames": -1,
            "checkpointed_frames": -1,
            "attempts": 0,
        }

        for attempt in range(1, self.CHECKPOINT_MAX_ATTEMPTS + 1):
            checkpoint = checkpoint_wal(self._db_path, mode="RESTART")
            checkpoint["attempts"] = attempt
            if int(checkpoint.get("busy", -1)) == 0:
                break
            time.sleep(self.CHECKPOINT_RETRY_DELAY)

        return checkpoint, closed_connections

    def _check_connectivity(self) -> bool:
        """Synchronous connectivity check (runs in thread)."""
        from ...db.sqlite_runtime import connect, close_connection

        conn = connect(self._db_path)
        try:
            result = conn.execute("SELECT 1").fetchone()
            return result is not None and result[0] == 1
        finally:
            close_connection(conn)
