#!/usr/bin/env python3
#
# tests/test_status_dns_leak.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Tests for the status page DNS leak indicator and outbound IP probe.

Locks the runtime-verification path: readable DNS logs must yield a
(state, detail) tuple, not fall through and return None.
"""

from __future__ import annotations

import asyncio
import ipaddress
from datetime import UTC, datetime

import pytest
from gillbates_public_ip import FamilyResult, PublicIPs

from app.api import frontend_status


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch):
	monkeypatch.setattr(frontend_status, "_dns_leak_cache", {})
	monkeypatch.setattr(frontend_status, "_dns_config_indicator", lambda _iface: (True, "config ok"))


def _indicator(monkeypatch, queries):
	monkeypatch.setattr(frontend_status.dns_ingestion, "read_recent_queries", lambda *_a, **_kw: queries)
	return asyncio.run(frontend_status._dns_leak_indicator(ipaddress.ip_address("10.13.13.2"), None))


def test_recent_query_from_client_is_verified(monkeypatch):
	state, detail = _indicator(monkeypatch, [{"client": "10.13.13.2", "ts": datetime.now(UTC).isoformat()}])
	assert state == frontend_status.CheckState.OK
	assert "Verified" in detail


def test_no_query_from_client_warns(monkeypatch):
	state, detail = _indicator(monkeypatch, [{"client": "10.13.13.9", "ts": datetime.now(UTC).isoformat()}])
	assert state == frontend_status.CheckState.WARN
	assert "No DNS query" in detail


@pytest.mark.parametrize(
	("client", "forwarded", "expected"),
	[
		("8.8.8.8", "1.1.1.1", "8.8.8.8"),
		("10.0.0.2", "1.1.1.1", "1.1.1.1"),
		("127.0.0.1", "1.1.1.1", "1.1.1.1"),
		("fe80::1", "1.1.1.1", "1.1.1.1"),
		("10.0.0.2", "192.168.1.9", None),
		("10.0.0.2", "169.254.1.1", None),
		("10.0.0.2", None, None),
	],
)
def test_public_client_ip_skips_private_loopback_and_link_local(client, forwarded, expected):
	result = frontend_status._resolve_public_client_ip(None, ipaddress.ip_address(client), None, forwarded)
	assert result == expected


class _FakeDetector:
	def __init__(self, ipv4: str | None, ipv6: str | None) -> None:
		self._result = PublicIPs(
			ipv4=FamilyResult("ipv4", address=ipv4, error=None if ipv4 else "all_failed"),
			ipv6=FamilyResult("ipv6", address=ipv6, error=None if ipv6 else "no_route"),
			in_container=True,
		)

	async def adetect_all(self) -> PublicIPs:
		return self._result


@pytest.mark.parametrize(
	("ipv4", "ipv6", "expected"),
	[
		("203.0.113.7", "2001:db8::7", ("2001:db8::7", "Detected via external probe")),
		("203.0.113.7", None, ("203.0.113.7", "Detected via external probe")),
		(None, None, (None, "Outbound IP probe unavailable")),
	],
)
def test_outbound_ip_prefers_ipv6_and_reports_unavailable(monkeypatch, ipv4, ipv6, expected):
	monkeypatch.setattr(frontend_status, "_public_ip_detector", _FakeDetector(ipv4, ipv6))
	assert asyncio.run(frontend_status._detect_outbound_ip_cached()) == expected


def test_speedtest_check_emits_raw_numbers_for_browser_formatting(monkeypatch, tmp_path):
	"""The status card carries raw values; the browser formats them in its own locale."""
	from types import SimpleNamespace

	point = SimpleNamespace(
		ts=datetime.now(UTC),
		value={"status": "ok", "download_mbit": 1234.5, "upload_mbit": 87.25, "rtt_ms": 12.345, "server": "speed.example.org"},
	)
	monkeypatch.setattr(frontend_status.tsdb, "query_latest", lambda *_a, **_kw: [point])
	monkeypatch.setattr(frontend_status, "get_config", lambda: SimpleNamespace(tsdb_dir=tmp_path))
	parts = frontend_status._latest_speedtest_check()["detail_parts"]
	assert [(p.get("kind"), p.get("value")) for p in parts[:3]] == [("bandwidth", 1234.5), ("bandwidth", 87.25), ("fixed", 12.345)]
	assert parts[-1] == {"text": "speed.example.org"}


@pytest.mark.parametrize("chain", ["203.0.113.7, garbage", "203.0.113.7, garbage, 127.0.0.1", "garbage"])
def test_forwarded_chain_fails_closed_on_unparseable_hop(chain):
	"""An unreadable hop ends the walk (None) instead of being skipped, as in resolve_client_ip."""
	assert frontend_status._pick_forwarded_client_ip(chain, {"127.0.0.1"}) is None


def test_forwarded_chain_still_skips_trusted_hops():
	picked = frontend_status._pick_forwarded_client_ip("198.51.100.1, 203.0.113.7, 127.0.0.1", {"127.0.0.1"})
	assert str(picked) == "203.0.113.7"
