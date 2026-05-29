#!/usr/bin/env python3
#
# app/runtime/services/tsdb.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: AGPL-3.0
#

"""Time-series database lifecycle service.

Manages:
- TSDB initialization
- Graceful shutdown with fsync
- Retention enforcement
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

from ..service import RuntimeService, ServiceHealth

if TYPE_CHECKING:
    from ...utils.config import Config

_log = logging.getLogger(__name__)


class TSDBService(RuntimeService):
    """Time-series database lifecycle management.

    Handles TSDB initialization at startup and ensures clean
    shutdown with data fsync.
    """

    name = "tsdb"
    dependencies = ()  # Standalone service
    start_timeout = 30.0
    stop_timeout = 15.0

    def __init__(self, config: Config) -> None:
        super().__init__()
        self._config = config
        self._tsdb_dir = config.tsdb_dir

    @property
    def tsdb_dir(self) -> Path:
        """TSDB data directory."""
        return self._tsdb_dir

    async def _do_start(self) -> None:
        """Initialize TSDB storage."""
        from ...db import tsdb

        await asyncio.to_thread(tsdb.init_tsdb, self._tsdb_dir)

        expected_dirs = (
            self._tsdb_dir / "peers",
            self._tsdb_dir / "traffic",
            self._tsdb_dir / "network",
            self._tsdb_dir / "speedtest",
            self._tsdb_dir / "dns",
        )
        if not all(path.is_dir() for path in expected_dirs):
            raise RuntimeError(f"TSDB initialization incomplete: {self._tsdb_dir}")

        _log.info("TSDB_INITIALIZED dir=%s", self._tsdb_dir)

    async def _do_stop(self) -> None:
        """Finalize TSDB with fsync."""
        from ...db import tsdb

        try:
            stats = await asyncio.to_thread(tsdb.finalize_shutdown, self._tsdb_dir)

            series = int(stats.get("series", 0))
            rotated = int(stats.get("rotated", 0))
            pruned = int(stats.get("pruned", 0))
            synced_files = int(stats.get("synced_files", 0))
            synced_dirs = int(stats.get("synced_dirs", 0))

            _log.info(
                "TSDB_SHUTDOWN series=%d rotated=%d pruned=%d synced_files=%d synced_dirs=%d",
                series,
                rotated,
                pruned,
                synced_files,
                synced_dirs,
            )
        except Exception:
            _log.exception("TSDB_SHUTDOWN_ERROR")

    async def check_health(self) -> ServiceHealth:
        """Check TSDB health."""
        health = await super().check_health()
        health.details = dict(health.details)

        if not self.is_running:
            return health

        try:
            exists = self._tsdb_dir.exists()
            writable = exists and self._tsdb_dir.is_dir() and os.access(
                self._tsdb_dir,
                os.R_OK | os.W_OK | os.X_OK,
            )

            health.details["dir_exists"] = exists
            health.details["dir_writable"] = writable

            if not writable:
                health.healthy = False
                health.error = "TSDB directory unavailable"
        except Exception:
            _log.exception("TSDB_HEALTH_CHECK_FAILED")
            health.healthy = False
            health.error = "TSDB health check failed"

        return health
