#!/usr/bin/env python3
#
# tests/test_frontend_shared_geoip.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""GeoIP frontend adapters must tolerate addresses without a GeoIP record."""

from app.api import frontend_shared


def test_lookup_ip_cached_returns_none_for_missing_geoip_result(monkeypatch):
    monkeypatch.setattr(frontend_shared, "_geoip_lookup_cached", lambda _ip: None)

    assert frontend_shared.lookup_ip_cached("127.0.0.1") is None


def test_lookup_ip_cached_copies_geoip_mapping(monkeypatch):
    source = {"country": "DE", "city": "Berlin"}
    monkeypatch.setattr(frontend_shared, "_geoip_lookup_cached", lambda _ip: source)

    result = frontend_shared.lookup_ip_cached("203.0.113.10")

    assert result == source
    assert result is not source
