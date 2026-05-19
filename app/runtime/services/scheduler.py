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
        self._config = config
        self._scheduler: Scheduler | None = None

    @property
    def scheduler(self) -> Scheduler | None:
        """The underlying scheduler instance."""
        return self._scheduler

    async def _do_start(self) -> None:
        """Initialize and start the scheduler."""
        from ...utils.scheduler import Scheduler
        from ...tasks.scheduler_config import register_all_tasks

        self._scheduler = Scheduler()

        # Register all scheduled tasks
        # Note: register_all_tasks expects a LifespanContext, but we pass
        # the container reference via self._container
        await register_all_tasks(self._scheduler, self._container)

        await self._scheduler.start()
        _log.info("SCHEDULER_STARTED")

    async def _do_stop(self) -> None:
        """Stop scheduler gracefully."""
        if self._scheduler:
            await self._scheduler.stop_graceful(timeout=5.0)
            _log.info("SCHEDULER_STOPPED")

    async def check_health(self) -> ServiceHealth:
        """Check scheduler health."""
        health = await super().check_health()

        if not self.is_running or not self._scheduler:
            return health

        try:
            # Get task info from scheduler
            health.details["running"] = True
            # Add task count if available
        except Exception as exc:
            health.healthy = False
            health.error = str(exc)

        return health
