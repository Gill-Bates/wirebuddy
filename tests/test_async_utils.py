#!/usr/bin/env python3
#
# tests/test_async_utils.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Regression tests for fire-and-forget task tracking."""

from __future__ import annotations

import asyncio
import logging

from app.utils.async_utils import spawn_tracked_task

_log = logging.getLogger("tests.async_utils")


def test_task_is_tracked_until_done_then_released():
	async def scenario():
		registry: set[asyncio.Task[None]] = set()
		release = asyncio.Event()

		async def work():
			await release.wait()

		spawn_tracked_task(work(), name="job", registry=registry, log=_log)
		assert len(registry) == 1
		release.set()
		await asyncio.gather(*registry)
		await asyncio.sleep(0)  # let the done-callback run
		return registry

	assert asyncio.run(scenario()) == set()


def test_failure_is_logged_under_the_callers_logger(caplog):
	async def scenario():
		registry: set[asyncio.Task[None]] = set()

		async def boom():
			raise RuntimeError("kaputt")

		spawn_tracked_task(boom(), name="job", registry=registry, log=_log)
		await asyncio.gather(*registry, return_exceptions=True)
		await asyncio.sleep(0)
		return registry

	with caplog.at_level(logging.ERROR, logger=_log.name):
		assert asyncio.run(scenario()) == set()
	records = [r for r in caplog.records if r.name == _log.name]
	assert [r.getMessage() for r in records] == ["Background task job failed: kaputt"]


def test_cancellation_is_not_reported_as_failure(caplog):
	async def scenario():
		registry: set[asyncio.Task[None]] = set()
		spawn_tracked_task(asyncio.sleep(3600), name="job", registry=registry, log=_log)
		for task in list(registry):
			task.cancel()
		await asyncio.gather(*registry, return_exceptions=True)
		await asyncio.sleep(0)
		return registry

	with caplog.at_level(logging.DEBUG, logger=_log.name):
		assert asyncio.run(scenario()) == set()
	assert not [r for r in caplog.records if r.name == _log.name]
