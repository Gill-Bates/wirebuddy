#!/usr/bin/env python3
#
# tests/test_speedtest_progress_callback.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""_emit() must not let a blocking synchronous progress callback stall the event loop.

ProgressCallback's public type explicitly allows a plain synchronous
callable (``Awaitable[None] | None``). Calling it directly on the event
loop would block the loop - and therefore the whole speedtest - for as
long as the callback runs, with no way to apply _PROGRESS_CALLBACK_TIMEOUT
after the fact. A synchronous callback must run in a worker thread so the
existing timeout actually bounds it.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from app.speedtest import tester


@pytest.mark.asyncio
async def test_blocking_sync_callback_does_not_stall_the_event_loop():
	loop_progressed = asyncio.Event()

	async def _background_ticker() -> None:
		# If the event loop were blocked by the synchronous callback below,
		# this would never get a chance to run before _emit() returns.
		await asyncio.sleep(0)
		loop_progressed.set()

	def _blocking_callback(event: tester.ProgressEvent) -> None:
		time.sleep(0.05)

	ticker_task = asyncio.create_task(_background_ticker())
	await tester._emit(_blocking_callback, "download", 0.5, "test")
	await ticker_task

	assert loop_progressed.is_set()


@pytest.mark.asyncio
async def test_sync_callback_timeout_is_enforced(monkeypatch):
	monkeypatch.setattr(tester, "_PROGRESS_CALLBACK_TIMEOUT", 0.05)

	def _very_slow_callback(event: tester.ProgressEvent) -> None:
		time.sleep(2.0)

	start = time.monotonic()
	# Must not raise - timeouts are logged and swallowed, not propagated.
	await tester._emit(_very_slow_callback, "download", 0.5, "test")
	elapsed = time.monotonic() - start

	assert elapsed < 1.0


@pytest.mark.asyncio
async def test_async_callback_still_invoked_directly():
	calls: list[tester.ProgressEvent] = []

	async def _async_callback(event: tester.ProgressEvent) -> None:
		calls.append(event)

	await tester._emit(_async_callback, "download", 0.5, "test")

	assert len(calls) == 1
	assert calls[0]["phase"] == "download"


@pytest.mark.asyncio
async def test_sync_callback_exception_is_swallowed():
	def _raising_callback(event: tester.ProgressEvent) -> None:
		raise ValueError("boom")

	# Must not propagate - _emit() logs and continues.
	await tester._emit(_raising_callback, "download", 0.5, "test")
