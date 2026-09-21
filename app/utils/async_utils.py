#!/usr/bin/env python3
#
# app/utils/async_utils.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Generic async utilities for task management."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine
from typing import Any

_log = logging.getLogger(__name__)

__all__ = ["cancel_tasks", "interruptible_sleep", "spawn_tracked_task"]


def spawn_tracked_task(
    coro: Coroutine[object, object, None],
    *,
    name: str,
    registry: set[asyncio.Task[None]],
    log: logging.Logger,
) -> None:
    """Start a fire-and-forget task that cannot be garbage-collected early.

    The event loop only keeps a weak reference to tasks, so the caller's
    *registry* holds the strong one until the task finishes. It stays per
    caller so each module can cancel just its own tasks on shutdown. Failures
    are reported through *log*, keeping them under the caller's logger name.
    """
    task = asyncio.create_task(coro, name=name)
    registry.add(task)

    def _cleanup(done_task: asyncio.Task[None]) -> None:
        registry.discard(done_task)
        if done_task.cancelled():
            return
        try:
            exc = done_task.exception()
        except Exception:
            log.exception("Background task %s completion check failed", name)
            return
        if exc is not None:
            log.error("Background task %s failed: %s", name, exc)

    task.add_done_callback(_cleanup)


async def interruptible_sleep(delay: float, shutdown_event: asyncio.Event) -> bool:
    """Sleep for *delay* seconds and return True if shutdown was requested."""
    if delay <= 0:
        return shutdown_event.is_set()
    try:
        await asyncio.wait_for(shutdown_event.wait(), timeout=delay)
        return True
    except TimeoutError:
        return False


async def cancel_tasks(*tasks: asyncio.Task[Any]) -> None:
    """Cancel background tasks and collect any unexpected failures."""
    if not tasks:
        return
    for task in tasks:
        if not task.done():
            task.cancel()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for task, result in zip(tasks, results, strict=False):
        if isinstance(result, asyncio.CancelledError):
            continue
        if isinstance(result, BaseException):
            _log.error(
                "Task %s crashed",
                task.get_name(),
                exc_info=(type(result), result, result.__traceback__),
            )
