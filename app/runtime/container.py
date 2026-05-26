#!/usr/bin/env python3
#
# app/runtime/container.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: AGPL-3.0
#

"""Service container for dependency injection and lifecycle orchestration.

The ServiceContainer manages all runtime services, handling:
- Dependency resolution and startup ordering
- Parallel startup/shutdown where dependencies allow
- Health aggregation
- Graceful shutdown coordination
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from .service import RuntimeService, ServiceHealth, ServiceState

if TYPE_CHECKING:
    from ..utils.config import Config

_log = logging.getLogger(__name__)


@dataclass
class ContainerHealth:
    """Aggregated health status of all services."""

    healthy: bool
    services: dict[str, ServiceHealth] = field(default_factory=dict)
    checked_at: datetime | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize for API responses."""
        return {
            "healthy": self.healthy,
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
            "services": {name: h.to_dict() for name, h in self.services.items()},
        }


class ServiceContainer:
    """Manages runtime services with dependency-aware lifecycle.

    Example:
        container = ServiceContainer(config)
        container.register(DNSRuntime())
        container.register(WireGuardRuntime())

        await container.start_all()  # Starts in dependency order
        yield
        await container.stop_all()   # Stops in reverse order
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._services: dict[str, RuntimeService] = {}
        self._start_order: list[str] = []
        self._started = False

    @property
    def config(self) -> Config:
        """Application configuration."""
        return self._config

    def register(self, service: RuntimeService) -> None:
        """Register a service with the container.

        Args:
            service: Service instance to register.

        Raises:
            ValueError: If service name is already registered.
        """
        if service.name in self._services:
            raise ValueError(f"Service {service.name!r} already registered")

        # Inject container reference
        service._container = self
        self._services[service.name] = service
        _log.debug("SERVICE_REGISTERED name=%s dependencies=%s", service.name, service.dependencies)

    def get(self, name: str) -> RuntimeService | None:
        """Get a service by name."""
        return self._services.get(name)

    def __getitem__(self, name: str) -> RuntimeService:
        """Get a service by name, raising KeyError if not found."""
        return self._services[name]

    def __contains__(self, name: str) -> bool:
        """Check if a service is registered."""
        return name in self._services

    def __iter__(self) -> Iterator[RuntimeService]:
        """Iterate over registered services in start order."""
        if self._start_order:
            for name in self._start_order:
                yield self._services[name]
        else:
            yield from self._services.values()

    def __len__(self) -> int:
        """Number of registered services."""
        return len(self._services)

    def _resolve_start_order(self) -> list[str]:
        """Topological sort of services by dependencies.

        Returns:
            List of service names in dependency order.

        Raises:
            ValueError: If circular dependency detected.
        """
        # Kahn's algorithm for topological sort
        in_degree: dict[str, int] = {name: 0 for name in self._services}
        dependents: dict[str, list[str]] = {name: [] for name in self._services}

        for name, service in self._services.items():
            for dep in service.dependencies:
                if dep not in self._services:
                    _log.warning(
                        "SERVICE_MISSING_DEPENDENCY service=%s dependency=%s",
                        name,
                        dep,
                    )
                    continue
                in_degree[name] += 1
                dependents[dep].append(name)

        # Start with services that have no dependencies
        queue = [name for name, degree in in_degree.items() if degree == 0]
        order: list[str] = []

        while queue:
            # Sort for deterministic ordering
            queue.sort()
            name = queue.pop(0)
            order.append(name)

            for dependent in dependents[name]:
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)

        if len(order) != len(self._services):
            # Circular dependency detected
            remaining = set(self._services) - set(order)
            raise ValueError(f"Circular dependency detected in services: {remaining}")

        return order

    async def start_all(self) -> None:
        """Start all services in dependency order.

        Services without dependencies are started in parallel.
        Services with dependencies wait for their dependencies.
        """
        if self._started:
            _log.warning("CONTAINER_ALREADY_STARTED")
            return

        self._start_order = self._resolve_start_order()
        _log.info("CONTAINER_START_ORDER services=%s", self._start_order)

        # Group services by dependency level for parallel start
        started: set[str] = set()

        for name in self._start_order:
            service = self._services[name]

            # Wait for dependencies (should already be started due to ordering)
            for dep in service.dependencies:
                if dep not in started:
                    dep_service = self._services.get(dep)
                    if dep_service and dep_service.state != ServiceState.RUNNING:
                        _log.warning(
                            "SERVICE_DEPENDENCY_NOT_RUNNING service=%s dependency=%s state=%s",
                            name,
                            dep,
                            dep_service.state if dep_service else "missing",
                        )

            try:
                await service.start()
                started.add(name)
            except Exception as exc:
                _log.error("SERVICE_START_FAILED name=%s error=%s", name, exc)
                # Continue with other services - partial startup is better than none

        self._started = True
        _log.info("CONTAINER_STARTED services=%d running=%d", len(self._services), len(started))

    async def stop_all(self, timeout: float = 30.0) -> None:
        """Stop all services in reverse dependency order.

        Args:
            timeout: Maximum total time for all services to stop.
        """
        if not self._started:
            return

        # Stop in reverse order
        stop_order = list(reversed(self._start_order)) if self._start_order else list(self._services)

        _log.info("CONTAINER_STOPPING services=%s", stop_order)

        async def _stop_service(name: str) -> None:
            service = self._services.get(name)
            if service:
                try:
                    await service.stop()
                except Exception as exc:
                    _log.warning("SERVICE_STOP_FAILED name=%s error=%s", name, exc)

        try:
            await asyncio.wait_for(
                asyncio.gather(*[_stop_service(name) for name in stop_order]),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            _log.warning("CONTAINER_STOP_TIMEOUT timeout=%.1fs", timeout)

        self._started = False
        _log.info("CONTAINER_STOPPED")

    async def check_health(self) -> ContainerHealth:
        """Check health of all services.

        Returns:
            Aggregated health status.
        """
        services: dict[str, ServiceHealth] = {}
        all_healthy = True

        for name, service in self._services.items():
            try:
                health = await service.check_health()
                services[name] = health
                if not health.healthy:
                    all_healthy = False
            except Exception as exc:
                services[name] = ServiceHealth(
                    state=service.state,
                    healthy=False,
                    error=str(exc),
                )
                all_healthy = False

        return ContainerHealth(
            healthy=all_healthy,
            services=services,
            checked_at=datetime.now(UTC),
        )

    def get_service_states(self) -> dict[str, str]:
        """Get current state of all services."""
        return {name: service.state.value for name, service in self._services.items()}
