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
    dependencies = []  # Standalone service
    start_timeout = 30.0
    stop_timeout = 15.0

    def __init__(self, config: Config) -> None:
        super().__init__()
        self._config = config
        self._tsdb_dir = config.tsdb_dir
        self._series_count = 0

    @property
    def tsdb_dir(self) -> Path:
        """TSDB data directory."""
        return self._tsdb_dir

    async def _do_start(self) -> None:
        """Initialize TSDB storage."""
        from ...db import tsdb

        await asyncio.to_thread(tsdb.init_tsdb, self._tsdb_dir)
        _log.info("TSDB_INITIALIZED dir=%s", self._tsdb_dir)

    async def _do_stop(self) -> None:
        """Finalize TSDB with fsync."""
        from ...db import tsdb

        try:
            stats = tsdb.finalize_shutdown(self._tsdb_dir)
            _log.info(
                "TSDB_SHUTDOWN series=%d rotated=%d pruned=%d synced_files=%d synced_dirs=%d",
                stats.get("series", 0),
                stats.get("rotated", 0),
                stats.get("pruned", 0),
                stats.get("synced_files", 0),
                stats.get("synced_dirs", 0),
            )
        except Exception as exc:
            _log.warning("TSDB_SHUTDOWN_ERROR: %s", exc)

    async def check_health(self) -> ServiceHealth:
        """Check TSDB health."""
        health = await super().check_health()

        if not self.is_running:
            return health

        try:
            exists = self._tsdb_dir.exists()
            health.details["dir_exists"] = exists
            if not exists:
                health.healthy = False
                health.error = "TSDB directory missing"
        except Exception as exc:
            health.healthy = False
            health.error = str(exc)

        return health
