#!/usr/bin/env python3
#
# app/runtime/signals.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: AGPL-3.0
#

"""Signal handling for graceful shutdown coordination.

Provides signal handler installation/restoration that preserves Uvicorn's
existing handlers while adding shutdown event notification for long-lived
connections (SSE, WebSockets).
"""

from __future__ import annotations

import asyncio
import logging
import signal
from collections.abc import Callable
from typing import Any

_log = logging.getLogger(__name__)


class SignalManager:
    """Manages process signal handlers with shutdown coordination.

    Preserves existing signal handlers (e.g., Uvicorn's) while adding
    side-effect notification via an asyncio Event.

    Example:
        shutdown_event = asyncio.Event()
        signal_mgr = SignalManager(shutdown_event)
        signal_mgr.install()
        try:
            await main_loop()
        finally:
            signal_mgr.restore()
    """

    # Signals to handle for graceful shutdown
    SHUTDOWN_SIGNALS = (signal.SIGTERM, signal.SIGINT)

    def __init__(self, shutdown_event: asyncio.Event) -> None:
        """
        Args:
            shutdown_event: Event to set when shutdown signal received.
        """
        self._shutdown_event = shutdown_event
        self._loop: asyncio.AbstractEventLoop | None = None
        self._previous_handlers: list[tuple[signal.Signals, Any]] = []
        self._installed = False

    @property
    def is_installed(self) -> bool:
        """True if signal handlers are currently installed."""
        return self._installed

    def install(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Install shutdown signal handlers.

        Args:
            loop: Event loop for call_soon_threadsafe. Defaults to running loop.

        Note:
            Safe to call multiple times - subsequent calls are no-ops.
        """
        if self._installed:
            return

        self._loop = loop or asyncio.get_running_loop()
        self._previous_handlers.clear()

        for sig in self.SHUTDOWN_SIGNALS:
            try:
                previous = signal.getsignal(sig)
            except (OSError, ValueError):
                continue

            # Respect an explicit "ignore this signal" from the environment;
            # everything else (SIG_DFL, Python's default_int_handler, or a real
            # server handler) gets wrapped so the shutdown event is always set.
            if previous is signal.SIG_IGN:
                _log.debug("Not overriding ignored signal %s", sig.name)
                continue

            handler = self._create_handler(sig, previous)

            try:
                signal.signal(sig, handler)
            except (ValueError, RuntimeError) as exc:
                _log.debug("Could not install signal handler for %s: %s", sig.name, exc)
                continue
            self._previous_handlers.append((sig, previous))

        self._installed = bool(self._previous_handlers)
        _log.debug("SIGNAL_HANDLERS_INSTALLED signals=%s", [s.name for s, _ in self._previous_handlers])

    def restore(self) -> None:
        """Restore original signal handlers.

        Safe to call multiple times or without prior install().
        """
        if not self._installed:
            return

        for sig, previous in self._previous_handlers:
            try:
                signal.signal(sig, previous)
            except (ValueError, RuntimeError):
                continue

        self._previous_handlers.clear()
        self._installed = False
        _log.debug("SIGNAL_HANDLERS_RESTORED")

    def _create_handler(
        self,
        sig: signal.Signals,
        previous: Callable[[int, Any], None] | int | None,
    ) -> Callable[[int, Any], None]:
        """Create a signal handler that notifies shutdown and chains to previous.

        Args:
            sig: Signal being handled.
            previous: Previous signal handler to chain to.

        Returns:
            New signal handler function.
        """

        def _handler(signum: int, frame: Any) -> None:
            # Notify shutdown event (thread-safe)
            if self._loop is not None and not self._loop.is_closed():
                try:
                    self._loop.call_soon_threadsafe(self._shutdown_event.set)
                except RuntimeError:
                    _log.debug("Event loop closed while handling %s", sig.name)

            # Chain only to a real pre-existing handler (e.g. Uvicorn's). We
            # deliberately do NOT chain to Python's defaults: SIG_DFL / SIG_IGN
            # are no-ops here, and default_int_handler would raise
            # KeyboardInterrupt before the lifecycle shutdown can run.
            if callable(previous) and previous is not signal.default_int_handler:
                previous(signum, frame)

        return _handler

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
