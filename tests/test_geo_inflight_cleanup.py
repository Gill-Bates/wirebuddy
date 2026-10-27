#!/usr/bin/env python3
#
# tests/test_geo_inflight_cleanup.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Cancelled GeoIP lookups must not pin an IP in the in-flight dedup map.

A cancellation during the threadpool lookup is a BaseException, not caught
by the generic except; without explicit handling the per-IP future stays
pending and shielded waiters hang until process restart. After a cancel the
in-flight entry must be cleared so a later lookup for the same IP succeeds.
"""

from __future__ import annotations

import asyncio
import threading

from app.api import wireguard_stats_geo as geo

_IP = "198.51.100.7"


def _clear_state() -> None:
	geo._geo_inflight.clear()
	geo._geo_cache.clear()


def test_cancelled_lookup_clears_inflight_and_does_not_deadlock():
	async def _run() -> None:
		_clear_state()
		release = threading.Event()

		def _blocking(ip: str):
			release.wait(timeout=5.0)
			return {"country": "DE"}

		geo.lookup_ip = _blocking  # type: ignore[assignment]
		try:
			task = asyncio.ensure_future(geo._lookup_geo_cached(_IP))
			# Let the task reach the threadpool await, then cancel it.
			await asyncio.sleep(0.05)
			task.cancel()
			with_cancelled = False
			try:
				await task
			except asyncio.CancelledError:
				with_cancelled = True
			assert with_cancelled

			# The cancelled lookup must not leave the IP pinned.
			assert _IP not in geo._geo_inflight
		finally:
			release.set()

		# A fresh lookup for the same IP must complete promptly, not hang on a
		# dead shielded future.
		geo.lookup_ip = lambda ip: {"country": "FR"}  # type: ignore[assignment]
		result_ip, info = await asyncio.wait_for(geo._lookup_geo_cached(_IP), timeout=2.0)
		assert result_ip == _IP
		assert info == {"country": "FR"}

	asyncio.run(_run())


def test_successful_lookup_caches_and_clears_inflight():
	async def _run() -> None:
		_clear_state()
		geo.lookup_ip = lambda ip: {"country": "DE"}  # type: ignore[assignment]

		result_ip, info = await geo._lookup_geo_cached(_IP)
		assert result_ip == _IP
		assert info == {"country": "DE"}
		assert _IP not in geo._geo_inflight
		assert _IP in geo._geo_cache

	asyncio.run(_run())
