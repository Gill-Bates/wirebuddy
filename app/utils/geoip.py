#!/usr/bin/env python3
#
# app/utils/geoip.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""GeoIP lookup binding over the shared ``gillbates-geoip`` package.

The package owns download, verification, readers, caches and the DNS pool.
This module only maps WireBuddy's environment and data directory onto it and
keeps the result shapes (``lat/lon/city/country`` and ``asn/as_org``) that the
callers use.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from threading import Lock
from typing import Required, TypedDict

from gillbates_geoip import DEFAULT_ALLOWED_HOSTS, GeoIPConfig, GeoIPDatabases, GeoIPUnavailableError, LogSink

_log = logging.getLogger(__name__)

__all__ = [
	"GeoLocation",
	"IPInfo",
	"eager_init",
	"ensure_geoip_databases",
	"geolocate_ip",
	"lookup_asn",
	"lookup_ip",
	"refresh_geoip_databases",
	"resolve_speedtest_server_country",
]

_GEOIP_SUBDIR = "geolite2"
_DEFAULT_CACHE_SIZE = GeoIPConfig().cache_size
_MAX_CACHE_SIZE = 65_536
_ABSOLUTE_MIN_SIZE = 100_000  # 100 KB safety floor in test mode
_USER_AGENT = "WireBuddy/1.0"
_ASYNC_DNS_TIMEOUT = 3.0

_db: GeoIPDatabases | None = None
_db_lock = Lock()


class GeoLocation(TypedDict):
	lat: float
	lon: float
	city: str | None
	country: str | None


class IPInfo(TypedDict, total=False):
	lat: Required[float]
	lon: Required[float]
	city: str | None
	country: str | None
	asn: int | None
	as_org: str | None


def _cache_size() -> int:
	raw = os.getenv("WIREBUDDY_GEOIP_CACHE_SIZE", str(_DEFAULT_CACHE_SIZE))
	try:
		value = int(raw)
	except ValueError:
		_log.warning("Invalid WIREBUDDY_GEOIP_CACHE_SIZE=%r; using default", raw)
		return _DEFAULT_CACHE_SIZE
	return min(max(value, 128), _MAX_CACHE_SIZE)


def _min_size(default: int) -> int:
	"""Test-mode size floor from WIREBUDDY_MIN_GEOIP_SIZE, never below the safety floor."""
	raw = os.getenv("WIREBUDDY_MIN_GEOIP_SIZE")
	if raw is None:
		return max(_ABSOLUTE_MIN_SIZE, default)
	try:
		value = int(raw)
	except ValueError:
		_log.warning("Invalid WIREBUDDY_MIN_GEOIP_SIZE=%r; using default", raw)
		return max(_ABSOLUTE_MIN_SIZE, default)
	return max(_ABSOLUTE_MIN_SIZE, value)


def _env_path(name: str) -> Path | None:
	raw = os.getenv(name)
	return Path(raw).resolve() if raw else None


def _build_config() -> GeoIPConfig:
	from app.utils.config import get_config

	defaults = GeoIPConfig()
	extra_hosts = {host.strip().lower() for host in os.getenv("WIREBUDDY_GEOIP_ALLOWED_HOSTS", "").split(",") if host.strip()}
	min_city, min_asn = defaults.min_city_size, defaults.min_asn_size
	if os.getenv("WIREBUDDY_TEST_MODE") == "1":
		min_city = _min_size(min_city)
		min_asn = _min_size(min_asn)
	return GeoIPConfig(
		directory=get_config().data_dir / _GEOIP_SUBDIR,
		city_path=_env_path("WIREBUDDY_GEOIP_DB_PATH"),
		asn_path=_env_path("WIREBUDDY_ASN_DB_PATH"),
		city_url=os.getenv("WIREBUDDY_GEOIP_CITY_DOWNLOAD_URL", defaults.city_url).strip(),
		asn_url=os.getenv("WIREBUDDY_GEOIP_ASN_DOWNLOAD_URL", defaults.asn_url).strip(),
		allowed_hosts=frozenset(DEFAULT_ALLOWED_HOSTS | extra_hosts),
		user_agent=_USER_AGENT,
		min_city_size=min_city,
		min_asn_size=min_asn,
		cache_size=_cache_size(),
	)


def _get_db() -> GeoIPDatabases:
	global _db
	with _db_lock:
		if _db is None:
			_db = GeoIPDatabases(
				_build_config(),
				log=LogSink(debug=_log.debug, info=_log.info, warning=_log.warning, error=_log.error),
			)
		return _db


def refresh_geoip_databases(force: bool = False) -> tuple[dict[str, bool], bool]:
	"""Blocking download/verify of both databases.

	Returns ``(usable, confirmed)``: which copies are usable, and whether the
	remote check succeeded (or the stamp was still fresh). A valid, unchanged
	pair is usable and confirmed, so only ``usable`` decides about missing data.
	"""
	try:
		result = _get_db().ensure(force=force)
	except GeoIPUnavailableError as exc:
		_log.warning("GeoIP databases unavailable: %s", exc)
		return {"city": False, "asn": False}, False
	return dict(result), result.confirmed


def ensure_geoip_databases(force: bool = False) -> dict[str, bool]:
	"""Blocking download/verify of both databases; returns which copies are usable."""
	return refresh_geoip_databases(force=force)[0]


def geolocate_ip(ip: str) -> GeoLocation | None:
	loc = _get_db().locate(ip)
	if not loc:
		return None
	return GeoLocation(lat=loc["lat"], lon=loc["lon"], city=loc["city"], country=loc["country"])


def lookup_asn(ip: str) -> tuple[int | None, str | None]:
	return _get_db().lookup_asn(ip)


def lookup_ip(ip: str) -> IPInfo | None:
	geo = geolocate_ip(ip)
	if not geo:
		return None
	asn, org = lookup_asn(ip)
	return IPInfo(lat=geo["lat"], lon=geo["lon"], city=geo["city"], country=geo["country"], asn=asn, as_org=org)


def eager_init() -> None:
	_get_db().open()


def resolve_speedtest_server_country(url: str) -> str | None:
	"""Blocking: lowercase ISO country of the first public address the URL host resolves to, within 3 s."""
	return _get_db().lookup_country_from_url(url, timeout=_ASYNC_DNS_TIMEOUT)
