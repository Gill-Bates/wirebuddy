#!/usr/bin/env python3
#
# tests/test_geoip_dns_timeout.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""resolve_country_from_url() must actually bound a slow DNS resolution.

socket.getaddrinfo() has no timeout parameter. A caller-side
asyncio.wait_for()/asyncio.timeout() around a to_thread() call only
abandons the await; the blocking resolver call keeps running to completion
in its worker thread. resolve_country_from_url() must therefore enforce the
timeout itself (via the dedicated DNS executor), so a slow resolver returns
None promptly instead of hanging the caller.
"""

from __future__ import annotations

import threading
import time

import pytest

from app.utils import geoip


def test_resolve_country_from_url_times_out_on_slow_resolver(monkeypatch):
	release_resolver = threading.Event()

	def _slow_addrinfo(hostname: str):
		release_resolver.wait(timeout=5.0)
		return [(None, None, None, None, ("203.0.113.1", 0))]

	monkeypatch.setattr(geoip, "_resolve_hostname_addrinfo", _slow_addrinfo)

	start = time.monotonic()
	try:
		result = geoip.resolve_country_from_url("https://slow.example.com", timeout=0.2)
		elapsed = time.monotonic() - start

		assert result is None
		# Bounded by the requested timeout, not by the resolver's 5s delay.
		assert elapsed < 2.0
	finally:
		release_resolver.set()


def test_resolve_country_from_url_without_timeout_still_resolves(monkeypatch):
	"""timeout=None (the default) preserves the previous unbounded behaviour."""

	def _fast_addrinfo(hostname: str):
		return [(None, None, None, None, ("203.0.113.1", 0))]

	monkeypatch.setattr(geoip, "_resolve_hostname_addrinfo", _fast_addrinfo)
	monkeypatch.setattr(geoip, "_public_ip", lambda ip: False)  # avoid a real GeoIP lookup

	result = geoip.resolve_country_from_url("https://fast.example.com")

	assert result is None  # _public_ip stubbed to False, so no GeoIP lookup happens


def test_dns_lookup_executor_has_bounded_worker_count():
	"""Repeated slow lookups must be capped by a fixed-size executor, not the caller's own (shared) thread pool."""
	assert geoip._DNS_LOOKUP_EXECUTOR._max_workers == geoip._DNS_LOOKUP_MAX_WORKERS


def test_cancelled_geo_lookup_does_not_pin_inflight_key(monkeypatch):
	"""A cancelled lookup must clear its in-flight entry so later lookups do not hang."""
	import asyncio

	from app.api import wireguard_stats_geo as geo

	ip = "203.0.113.7"
	release = threading.Event()
	monkeypatch.setattr(geo, "lookup_ip", lambda _ip: release.wait(timeout=5.0) or {"country": "XX"})
	geo._geo_inflight.pop(ip, None)
	geo._geo_cache.pop(ip, None)

	async def _scenario():
		task = asyncio.create_task(geo._lookup_geo_cached(ip))
		await asyncio.sleep(0.1)
		task.cancel()
		with pytest.raises(asyncio.CancelledError):
			await task
		assert ip not in geo._geo_inflight
		release.set()
		monkeypatch.setattr(geo, "lookup_ip", lambda _ip: {"country": "XX"})
		return await asyncio.wait_for(geo._lookup_geo_cached(ip), timeout=2.0)

	try:
		result_ip, info = asyncio.run(_scenario())
	finally:
		release.set()
		geo._geo_cache.pop(ip, None)
	assert result_ip == ip
	assert info == {"country": "XX"}


def test_async_resolver_never_uses_global_to_thread(monkeypatch):
	"""The async wrapper must route through the dedicated executor, not asyncio.to_thread.

	A hung resolver that reached the global default executor would pin a worker
	shared with the rest of the app; the dedicated pool exists to isolate it.
	"""
	import asyncio

	release_resolver = threading.Event()

	def _slow_addrinfo(hostname: str):
		release_resolver.wait(timeout=5.0)
		return [(None, None, None, None, ("203.0.113.1", 0))]

	def _fail_to_thread(*_args, **_kwargs):
		raise AssertionError("resolve_country_from_url_async must not use the global to_thread pool")

	monkeypatch.setattr(geoip, "_resolve_hostname_addrinfo", _slow_addrinfo)
	monkeypatch.setattr(asyncio, "to_thread", _fail_to_thread)

	async def _scenario():
		start = time.monotonic()
		result = await geoip.resolve_country_from_url_async("https://slow.example.com")
		return result, time.monotonic() - start

	try:
		result, elapsed = asyncio.run(_scenario())
	finally:
		release_resolver.set()

	assert result is None
	# Bounded by the wrapper's 3s timeout, not the resolver's 5s delay.
	assert elapsed < 4.5


def test_async_resolver_releases_slot_after_timeout(monkeypatch):
	"""A timed-out lookup must free its dedicated-executor semaphore slot once the resolver finishes."""
	import asyncio

	release_resolver = threading.Event()
	entered = threading.Event()

	def _slow_addrinfo(hostname: str):
		entered.set()
		release_resolver.wait(timeout=5.0)
		return [(None, None, None, None, ("203.0.113.1", 0))]

	monkeypatch.setattr(geoip, "_resolve_hostname_addrinfo", _slow_addrinfo)

	async def _scenario():
		loop = asyncio.get_running_loop()
		if hasattr(loop, "_wirebuddy_geoip_dns_semaphore"):
			delattr(loop, "_wirebuddy_geoip_dns_semaphore")
		result = await geoip.resolve_country_from_url_async("https://slow.example.com")
		sem = loop._wirebuddy_geoip_dns_semaphore
		# Resolver still blocked -> slot not yet released.
		slot_held_during_run = sem._value
		release_resolver.set()
		# Give the executor callback time to run and release the slot.
		for _ in range(50):
			if sem._value == 8:
				break
			await asyncio.sleep(0.05)
		return result, slot_held_during_run, sem._value

	try:
		result, held, released = asyncio.run(_scenario())
	finally:
		release_resolver.set()

	assert result is None
	assert held == 7  # one of eight slots taken while the resolver ran
	assert released == 8  # slot returned after the resolver completed
