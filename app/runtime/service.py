#!/usr/bin/env python3
#
# app/runtime/service.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: AGPL-3.0
#

"""Runtime service protocol and base implementation.

Defines the contract for all runtime services (DNS, WireGuard, TSDB, etc.)
and provides common lifecycle management infrastructure.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .container import ServiceContainer

_log = logging.getLogger(__name__)


class ServiceState(StrEnum):
    """Runtime service lifecycle states."""

    CREATED = "created"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass
class ServiceHealth:
    """Health status of a runtime service."""

    state: ServiceState
    healthy: bool = True
    last_check: datetime | None = None
    error: str | None = None
    details: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Serialize health status for API responses."""
        return {
            "state": self.state.value,
            "healthy": self.healthy,
            "last_check": self.last_check.isoformat() if self.last_check else None,
            "error": self.error,
            **self.details,
        }


class RuntimeService(ABC):
    """Base class for runtime services with lifecycle management.

    Subclasses implement domain-specific start/stop logic while this base
    provides:
    - State tracking
    - Health reporting
    - Graceful shutdown coordination
    - Error handling and recovery

    Example:
        class DNSRuntime(RuntimeService):
            name = "dns"

            async def _do_start(self) -> None:
                await self._start_unbound()
                await self._start_ingestion()

            async def _do_stop(self) -> None:
                await self._stop_ingestion()
                await self._stop_unbound()
    """

    # Subclasses must define a unique service name
    name: str = "unnamed"

    # Dependencies: list of service names that must start before this one
    dependencies: list[str] = []

    # Timeout for start/stop operations
    start_timeout: float = 30.0
    stop_timeout: float = 15.0

    def __init__(self, container: ServiceContainer | None = None) -> None:
        self._container = container
        self._state = ServiceState.CREATED
        self._health = ServiceHealth(state=self._state)
        self._started_at: datetime | None = None
        self._stopped_at: datetime | None = None
        self._background_tasks: set[asyncio.Task[object]] = set()
        self._shutdown_event = asyncio.Event()

    @property
    def state(self) -> ServiceState:
        """Current lifecycle state."""
        return self._state

    @property
    def health(self) -> ServiceHealth:
        """Current health status."""
        return self._health

    @property
    def is_running(self) -> bool:
        """True if service is in running state."""
        return self._state == ServiceState.RUNNING

    @property
    def uptime_seconds(self) -> float | None:
        """Seconds since service started, or None if not running."""
        if self._started_at is None:
            return None
        end = self._stopped_at or datetime.now(UTC)
        return (end - self._started_at).total_seconds()

    def get_dependency(self, name: str) -> RuntimeService | None:
        """Get a dependency service from the container."""
        if self._container is None:
            return None
        return self._container.get(name)

    async def start(self) -> None:
        """Start the service with timeout protection.

        Raises:
            RuntimeError: If service is not in startable state.
            asyncio.TimeoutError: If start exceeds timeout.
        """
        if self._state not in (ServiceState.CREATED, ServiceState.STOPPED, ServiceState.FAILED):
            raise RuntimeError(f"Cannot start {self.name} in state {self._state}")

        self._state = ServiceState.STARTING
        self._health = ServiceHealth(state=self._state)
        self._shutdown_event.clear()

        try:
            await asyncio.wait_for(self._do_start(), timeout=self.start_timeout)
            self._state = ServiceState.RUNNING
            self._started_at = datetime.now(UTC)
            self._stopped_at = None
            self._health = ServiceHealth(state=self._state, healthy=True)
            _log.info("SERVICE_STARTED name=%s", self.name)
        except asyncio.TimeoutError:
            self._state = ServiceState.FAILED
            self._health = ServiceHealth(
                state=self._state,
                healthy=False,
                error=f"Start timed out after {self.start_timeout}s",
            )
            _log.error("SERVICE_START_TIMEOUT name=%s timeout=%.1fs", self.name, self.start_timeout)
            raise
        except Exception as exc:
            self._state = ServiceState.FAILED
            self._health = ServiceHealth(
                state=self._state,
                healthy=False,
                error=str(exc),
            )
            _log.error("SERVICE_START_FAILED name=%s error=%s", self.name, exc)
            raise

    async def stop(self) -> None:
        """Stop the service gracefully with timeout protection.

        Cancels background tasks and calls _do_stop(). Safe to call
        multiple times or in any state.
        """
        if self._state in (ServiceState.STOPPED, ServiceState.STOPPING):
            return

        previous_state = self._state
        self._state = ServiceState.STOPPING
        self._health = ServiceHealth(state=self._state)
        self._shutdown_event.set()

        # Cancel all background tasks
        for task in self._background_tasks:
            if not task.done():
                task.cancel()

        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
            self._background_tasks.clear()

        try:
            if previous_state == ServiceState.RUNNING:
                await asyncio.wait_for(self._do_stop(), timeout=self.stop_timeout)
            self._state = ServiceState.STOPPED
            self._stopped_at = datetime.now(UTC)
            self._health = ServiceHealth(state=self._state, healthy=True)
            _log.info("SERVICE_STOPPED name=%s", self.name)
        except asyncio.TimeoutError:
            self._state = ServiceState.STOPPED
            self._stopped_at = datetime.now(UTC)
            self._health = ServiceHealth(
                state=self._state,
                healthy=False,
                error=f"Stop timed out after {self.stop_timeout}s",
            )
            _log.warning("SERVICE_STOP_TIMEOUT name=%s timeout=%.1fs", self.name, self.stop_timeout)
        except Exception as exc:
            self._state = ServiceState.STOPPED
            self._stopped_at = datetime.now(UTC)
            self._health = ServiceHealth(
                state=self._state,
                healthy=False,
                error=str(exc),
            )
            _log.warning("SERVICE_STOP_FAILED name=%s error=%s", self.name, exc)

    async def restart(self) -> None:
        """Stop and start the service."""
        await self.stop()
        await self.start()

    async def check_health(self) -> ServiceHealth:
        """Perform health check and update health status.

        Default implementation checks state only. Override for
        domain-specific health checks.
        """
        self._health.last_check = datetime.now(UTC)
        self._health.healthy = self._state == ServiceState.RUNNING
        return self._health

    def create_background_task(self, coro, *, name: str | None = None) -> asyncio.Task:
        """Create a managed background task that is cancelled on stop.

        Args:
            coro: Coroutine to run.
            name: Optional task name for debugging.

        Returns:
            The created task.
        """
        task = asyncio.create_task(coro, name=name or f"{self.name}-task")
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        return task

    async def wait_for_shutdown(self, timeout: float | None = None) -> bool:
        """Wait for shutdown signal.

        Args:
            timeout: Maximum seconds to wait, or None for indefinite.

        Returns:
            True if shutdown was signaled, False if timeout elapsed.
        """
        try:
            await asyncio.wait_for(self._shutdown_event.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    @abstractmethod
    async def _do_start(self) -> None:
        """Implement service-specific startup logic.

        Called by start() with timeout protection. Should raise on failure.
        """
        ...

    @abstractmethod
    async def _do_stop(self) -> None:
        """Implement service-specific shutdown logic.

        Called by stop() with timeout protection. Should be idempotent.
        """
        ...
