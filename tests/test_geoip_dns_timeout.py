#!/usr/bin/env python3
#
# tests/test_geoip_dns_timeout.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Contract of the ``app.utils.geoip`` binding over ``gillbates-geoip``.

Download, readers and DNS timeouts are tested in the package itself; here only
the environment mapping and the WireBuddy result shapes are checked.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from gillbates_geoip import GeoIPUnavailableError

from app.utils import geoip


class _FakeDb:
	def __init__(self, location=None, asn=(None, None), unavailable=False):
		self._location = location
		self._asn = asn
		self._unavailable = unavailable

	def locate(self, ip):
		return self._location

	def lookup_asn(self, ip):
		return self._asn

	def ensure(self, *, force=False):
		if self._unavailable:
			raise GeoIPUnavailableError("down")
		return {"city": True, "asn": True}


def test_build_config_maps_environment(monkeypatch, tmp_path):
	monkeypatch.setattr("app.utils.config.get_config", lambda: SimpleNamespace(data_dir=tmp_path))
	monkeypatch.setenv("WIREBUDDY_GEOIP_DB_PATH", str(tmp_path / "c.mmdb"))
	monkeypatch.setenv("WIREBUDDY_ASN_DB_PATH", str(tmp_path / "a.mmdb"))
	monkeypatch.setenv("WIREBUDDY_GEOIP_ALLOWED_HOSTS", "Mirror.Example.com, ")
	monkeypatch.setenv("WIREBUDDY_GEOIP_CACHE_SIZE", "5")
	cfg = geoip._build_config()
	assert cfg.directory == tmp_path / "geolite2"
	assert cfg.city_path == Path(tmp_path / "c.mmdb").resolve()
	assert cfg.asn_path == Path(tmp_path / "a.mmdb").resolve()
	assert "mirror.example.com" in cfg.allowed_hosts
	assert "github.com" in cfg.allowed_hosts
	assert cfg.cache_size == 128


@pytest.mark.parametrize("raw", [None, "abc"])
def test_build_config_cache_size_defaults_to_package_default(monkeypatch, tmp_path, raw):
	monkeypatch.setattr("app.utils.config.get_config", lambda: SimpleNamespace(data_dir=tmp_path))
	monkeypatch.delenv("WIREBUDDY_GEOIP_CACHE_SIZE", raising=False)
	if raw is not None:
		monkeypatch.setenv("WIREBUDDY_GEOIP_CACHE_SIZE", raw)
	assert geoip._build_config().cache_size == geoip.GeoIPConfig().cache_size == 4096


def test_build_config_ignores_invalid_min_size(monkeypatch, tmp_path):
	monkeypatch.setattr("app.utils.config.get_config", lambda: SimpleNamespace(data_dir=tmp_path))
	monkeypatch.setenv("WIREBUDDY_TEST_MODE", "1")
	monkeypatch.setenv("WIREBUDDY_MIN_GEOIP_SIZE", "abc")
	defaults = geoip.GeoIPConfig()
	cfg = geoip._build_config()
	assert cfg.min_city_size == max(geoip._ABSOLUTE_MIN_SIZE, defaults.min_city_size)
	assert cfg.min_asn_size == max(geoip._ABSOLUTE_MIN_SIZE, defaults.min_asn_size)


def test_build_config_keeps_min_size_floor(monkeypatch, tmp_path):
	monkeypatch.setattr("app.utils.config.get_config", lambda: SimpleNamespace(data_dir=tmp_path))
	monkeypatch.setenv("WIREBUDDY_TEST_MODE", "1")
	monkeypatch.setenv("WIREBUDDY_MIN_GEOIP_SIZE", "50")
	cfg = geoip._build_config()
	assert cfg.min_city_size == geoip._ABSOLUTE_MIN_SIZE
	assert cfg.min_asn_size == geoip._ABSOLUTE_MIN_SIZE


def test_lookup_ip_shape(monkeypatch):
	loc = {"lat": 1.0, "lon": 2.0, "city": "X", "country": "DE", "subdivision": None, "accuracy_radius": 5}
	monkeypatch.setattr(geoip, "_get_db", lambda: _FakeDb(loc, (64496, "Org")))
	assert geoip.lookup_ip("203.0.113.1") == {"lat": 1.0, "lon": 2.0, "city": "X", "country": "DE", "asn": 64496, "as_org": "Org"}


def test_lookup_ip_none_without_location(monkeypatch):
	monkeypatch.setattr(geoip, "_get_db", _FakeDb)
	assert geoip.lookup_ip("203.0.113.1") is None


def test_ensure_returns_false_dict_when_unavailable(monkeypatch):
	monkeypatch.setattr(geoip, "_get_db", lambda: _FakeDb(unavailable=True))
	assert geoip.ensure_geoip_databases() == {"city": False, "asn": False}
