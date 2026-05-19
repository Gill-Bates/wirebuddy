#
# app/runtime/lifecycle.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: AGPL-3.0
#

"""Application lifecycle management.

Coordinates startup and shutdown phases, ensuring proper ordering
and cleanup across all runtime services.
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .container import ServiceContainer
from .signals import SignalManager

if TYPE_CHECKING:
    from fastapi import FastAPI

    from ..utils.config import Config

_log = logging.getLogger(__name__)


@dataclass
class LifecycleContext:
    """State passed through lifecycle phases.

    This is a transitional structure that will be replaced by the
    ServiceContainer as services are migrated. Kept minimal to
    discourage adding new fields.
    """

    config: Config
    app: FastAPI
    container: ServiceContainer
    signal_manager: SignalManager
    shutdown_event: asyncio.Event = field(default_factory=asyncio.Event)

    # Legacy fields - migrate to services
    key_mismatch: bool = False


class LifecycleManager:
    """Manages application startup and shutdown lifecycle.

    Coordinates:
    - Signal handler installation
    - Service container startup
    - Graceful shutdown with timeout
    - Cleanup ordering

    Example:
        lifecycle = LifecycleManager(config)
        lifecycle.register_service(DNSRuntime())
        lifecycle.register_service(WireGuardRuntime())

        @asynccontextmanager
        async def lifespan(app):
            async with lifecycle.managed(app):
                yield
    """

    # Total shutdown timeout before forced exit
    SHUTDOWN_TIMEOUT = 30.0

    def __init__(self, config: Config) -> None:
        self._config = config
        self._container = ServiceContainer(config)
        self._shutdown_event = asyncio.Event()
        self._signal_manager = SignalManager(self._shutdown_event)
        self._started = False

    @property
    def container(self) -> ServiceContainer:
        """Service container."""
        return self._container

    @property
    def shutdown_event(self) -> asyncio.Event:
        """Event set when shutdown is requested."""
        return self._shutdown_event

    def register_service(self, service) -> None:
        """Register a runtime service.

        Args:
            service: RuntimeService instance.
        """
        self._container.register(service)

    @asynccontextmanager
    async def managed(self, app: FastAPI):
        """Context manager for application lifespan.

        Args:
            app: FastAPI application instance.

        Yields:
            LifecycleContext for access during lifespan.

        Example:
            @asynccontextmanager
            async def lifespan(app):
                async with lifecycle.managed(app):
                    yield
        """
        loop = asyncio.get_running_loop()
        self._signal_manager.install(loop)

        # Expose shutdown event on app.state for SSE/long-poll handlers
        app.state.shutdown_signal_event = self._shutdown_event
        app.state.services = self._container

        ctx = LifecycleContext(
            config=self._config,
            app=app,
            container=self._container,
            signal_manager=self._signal_manager,
            shutdown_event=self._shutdown_event,
        )

        try:
            await self._startup(ctx)
            self._started = True
            _log.info("APPLICATION_STARTED pid=%d services=%d", os.getpid(), len(self._container))
            yield ctx
        finally:
            self._shutdown_event.set()
            self._signal_manager.restore()
            await self._shutdown(ctx)

    async def _startup(self, ctx: LifecycleContext) -> None:
        """Execute startup sequence.

        Override in subclass for custom startup logic.
        """
        await self._container.start_all()

    async def _shutdown(self, ctx: LifecycleContext) -> None:
        """Execute shutdown sequence.

        Override in subclass for custom shutdown logic.
        """
        _log.info("APPLICATION_SHUTTING_DOWN")

        try:
            await asyncio.wait_for(
                self._container.stop_all(),
                timeout=self.SHUTDOWN_TIMEOUT,
            )
        except asyncio.TimeoutError:
            _log.warning("SHUTDOWN_TIMEOUT timeout=%.1fs", self.SHUTDOWN_TIMEOUT)

        _log.info("APPLICATION_SHUTDOWN_COMPLETE")
