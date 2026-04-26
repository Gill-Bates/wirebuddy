#!/usr/bin/env python3
#
# app/api/sse.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Shared Server-Sent Events formatting helpers."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncGenerator, Callable, Coroutine
from typing import Any

from fastapi import HTTPException, Request

_log = logging.getLogger(__name__)


def format_sse_event(event_type: str, payload: Any, *, ensure_ascii: bool = False) -> str:
	"""Format a server-sent event payload."""
	return f"event: {event_type}\ndata: {json.dumps(payload, ensure_ascii=ensure_ascii, default=str)}\n\n"


def format_sse_keepalive() -> str:
	"""Return a comment frame that keeps SSE connections alive."""
	return ": keepalive\n\n"


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


async def stream_with_progress(
	request: Request,
	task_coro_factory: Callable[[Callable[[Any], None]], Coroutine[Any, Any, tuple[Any, bool]]],
	queue_size: int = 32,
) -> AsyncGenerator[str, None]:
	"""Generic helper to stream progress events via SSE for a long-running task.
	
	The task_coro_factory must accept a progress_callback function and return an awaitable
	that evaluates to a (result, stored) tuple.
	"""
	progress_queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=queue_size)
	loop = asyncio.get_running_loop()

	def progress_callback(event: Any) -> None:
		try:
			loop.call_soon_threadsafe(broadcast_event_to_queues, [progress_queue], event)
		except Exception:
			pass

	test_task = asyncio.create_task(task_coro_factory(progress_callback))
	queue_task: asyncio.Task[Any] = asyncio.create_task(progress_queue.get())
	try:
		while not test_task.done():
			if await request.is_disconnected():
				test_task.cancel()
				break

			done, _ = await asyncio.wait(
				[test_task, queue_task],
				timeout=30.0,
				return_when=asyncio.FIRST_COMPLETED,
			)

			if not done:
				# 30s of silence — send keepalive and loop again
				yield format_sse_keepalive()
				continue

			if queue_task in done:
				event = await queue_task
				queue_task = asyncio.create_task(progress_queue.get())
				if event is not None:
					yield format_sse_event("progress", event)
			# else: test_task finished — outer while condition ends loop

		# Drain any remaining queued events
		while True:
			try:
				event = progress_queue.get_nowait()
			except asyncio.QueueEmpty:
				break
			if event is not None:
				yield format_sse_event("progress", event)

		try:
			result, stored = await test_task
		except asyncio.CancelledError:
			return
		except Exception as exc:
			if isinstance(exc, HTTPException):
				yield format_sse_event("error", {"reason": str(exc.detail)})
			else:
				_log.exception("Task failed")
				yield format_sse_event("error", {"reason": "Internal task failure"})
			return

		# Send final result to client
		yield format_sse_event("result", {**result, "stored": stored})
	finally:
		queue_task.cancel()
		with contextlib.suppress(asyncio.CancelledError):
			await queue_task
		if not test_task.done():
			test_task.cancel()
			with contextlib.suppress(asyncio.CancelledError):
				await test_task
