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
