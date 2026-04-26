#!/usr/bin/env python3
#
# app/utils/async_utils.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Generic async utilities for task management."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

_log = logging.getLogger(__name__)

__all__ = ["interruptible_sleep", "cancel_tasks"]


async def interruptible_sleep(delay: float, shutdown_event: asyncio.Event) -> bool:
    """Sleep for *delay* seconds and return True if shutdown was requested."""
    if delay <= 0:
        return shutdown_event.is_set()
    try:
        await asyncio.wait_for(shutdown_event.wait(), timeout=delay)
        return True
    except asyncio.TimeoutError:
        return False


async def cancel_tasks(*tasks: asyncio.Task[Any]) -> None:
    """Cancel background tasks and collect any unexpected failures."""
    for task in tasks:
        if not task.done():
            task.cancel()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for task, result in zip(tasks, results):
        if isinstance(result, Exception) and not isinstance(result, asyncio.CancelledError):
            _log.error("Task %s crashed: %s", task.get_name(), result, exc_info=True)
