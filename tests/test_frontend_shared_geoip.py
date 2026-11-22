#!/usr/bin/env python3
#
# tests/test_frontend_shared_geoip.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""GeoIP frontend adapters must tolerate addresses without a GeoIP record."""

from app.api import frontend_shared


def test_lookup_ip_cached_returns_none_for_missing_geoip_result(monkeypatch):
	monkeypatch.setattr(frontend_shared, "lookup_ip", lambda _ip: None)

	assert frontend_shared.lookup_ip_cached("127.0.0.1") is None


def test_lookup_ip_cached_returns_none_when_lookup_fails(monkeypatch):
	def _boom(_ip):
		raise RuntimeError("binding not configured")

	monkeypatch.setattr(frontend_shared, "lookup_ip", _boom)

	assert frontend_shared.lookup_ip_cached("203.0.113.10") is None


def test_lookup_ip_cached_does_not_pin_a_cold_start_miss(monkeypatch):
	# Invalidation belongs to gillbates-geoip; a second cache here would keep the miss after the download.
	answers = iter([None, {"country": "DE", "city": "Berlin"}])
	monkeypatch.setattr(frontend_shared, "lookup_ip", lambda _ip: next(answers))

	assert frontend_shared.lookup_ip_cached("203.0.113.10") is None
	assert frontend_shared.lookup_ip_cached("203.0.113.10") == {
		"country": "DE",
		"city": "Berlin",
	}


def test_extract_geo_fields_country_code_is_a_safe_flag_name():
	# The code becomes a flag file name, so only two ASCII letters may pass, normalised to lowercase.
	def country(raw):
		return frontend_shared.extract_geo_fields({"country": raw})["country_code"]

	assert country(" DE ") == "de"
	for raw in ("../", "DEU", "d", "", None, "ß", "1a"):
		assert country(raw) is None
