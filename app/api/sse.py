#!/usr/bin/env python3
#
# app/api/sse.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Shared Server-Sent Events formatting helpers.

Only formatting and fan-out helpers live here. Each SSE endpoint owns its own
streaming lifecycle (cancellation, queueing, error handling) because their
requirements differ; a shared generic streamer previously existed here but was
unused and duplicated those concerns.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

__all__ = [
	"broadcast_event_to_queues",
	"format_sse_close",
	"format_sse_event",
	"format_sse_keepalive",
]


def format_sse_event(event_type: str, payload: Any, *, ensure_ascii: bool = False) -> str:
	"""Format a server-sent event payload."""
	return f"event: {event_type}\ndata: {json.dumps(payload, ensure_ascii=ensure_ascii, default=str)}\n\n"


def format_sse_keepalive() -> str:
	"""Return a lightweight SSE ping frame that keeps connections alive."""
	return format_sse_event("ping", {})


def format_sse_close(reason: str = "server_shutdown") -> str:
	"""Return an SSE close event payload."""
	return format_sse_event("close", {"reason": reason})


def broadcast_event_to_queues(queues: list[asyncio.Queue[Any]], event: Any) -> None:
	"""Broadcast an event to queues, dropping the oldest buffered item on overflow."""
	for queue in queues:
		try:
			queue.put_nowait(event)
		except asyncio.QueueFull:
			try:
				queue.get_nowait()
				queue.put_nowait(event)
			except (asyncio.QueueEmpty, asyncio.QueueFull):
				continue
