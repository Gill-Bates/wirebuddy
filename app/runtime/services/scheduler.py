#!/usr/bin/env python3
#
# app/runtime/services/scheduler.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: AGPL-3.0
#

"""Background task scheduler service.

Manages:
- Scheduled task registration
- Task lifecycle
- Graceful shutdown
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from ..service import RuntimeService, ServiceHealth

if TYPE_CHECKING:
    from ...utils.config import Config
    from ...utils.scheduler import Scheduler

_log = logging.getLogger(__name__)


class SchedulerService(RuntimeService):
    """Background task scheduler lifecycle management.

    Handles scheduler initialization, task registration, and
    graceful shutdown with task completion.
    """

    name = "scheduler"
    dependencies = ["sqlite", "tsdb"]  # Needs DB and metrics storage
    start_timeout = 30.0
    stop_timeout = 10.0

    def __init__(self, config: Config) -> None:
        super().__init__()
        del config
        self._scheduler: Scheduler | None = None

    @property
    def scheduler(self) -> Scheduler | None:
        """The underlying scheduler instance."""
        return self._scheduler

    async def _do_start(self) -> None:
        """Initialize and start the scheduler."""
        from ...utils.scheduler import Scheduler
        from ...tasks.scheduler_config import register_all_tasks

        if self._container is None:
            raise RuntimeError("SchedulerService requires container injection")

        scheduler = Scheduler()

        try:
            # register_all_tasks currently requires service-container access
            # for runtime dependency resolution.
            await register_all_tasks(scheduler, self._container)
            await scheduler.start()
        except Exception:
            try:
                await scheduler.stop_graceful(timeout=self.stop_timeout)
            except Exception:
                _log.exception("SCHEDULER_START_CLEANUP_FAILED")
            raise

        self._scheduler = scheduler
        _log.info("SCHEDULER_STARTED")

    async def _do_stop(self) -> None:
        """Stop scheduler gracefully."""
        scheduler = self._scheduler

        if scheduler is None:
            return

        try:
            await scheduler.stop_graceful(timeout=self.stop_timeout)
            _log.info("SCHEDULER_STOPPED")
        except Exception:
            _log.exception("SCHEDULER_STOP_FAILED")
            raise
        finally:
            self._scheduler = None

    async def check_health(self) -> ServiceHealth:
        """Check scheduler health."""
        health = await super().check_health()
        health.details = dict(health.details)

        if not self.is_running or not self._scheduler:
            health.details["scheduler_initialized"] = self._scheduler is not None
            return health

        try:
            status = self._scheduler.get_status()
            health.details["scheduler_initialized"] = True
            health.details["task_count"] = len(status)
            health.details["running"] = any(item["is_running"] for item in status)
        except Exception:
            _log.exception("SCHEDULER_HEALTH_CHECK_FAILED")
            health.healthy = False
            health.error = "Scheduler health check failed"

        return health
