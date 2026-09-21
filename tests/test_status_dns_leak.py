#!/usr/bin/env python3
#
# tests/test_status_dns_leak.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Tests for the status page DNS leak indicator.

Locks the runtime-verification path: readable DNS logs must yield a
(state, detail) tuple, not fall through and return None.
"""

from __future__ import annotations

import asyncio
import ipaddress
from datetime import UTC, datetime

import pytest

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
