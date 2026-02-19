#!/usr/bin/env python3
#
# app/utils/geoip.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""GeoIP lookup service using MaxMind GeoLite2 databases.

Provides IP → lat/lon/city/country + ASN resolution for WireGuard peer
endpoints.  Thread-safe with lazy-initialized readers and manual LRU
cache (512 entries).

Includes automatic database download and update checking via the
P3TERX GeoLite.mmdb mirror (derived from the JustUp bootstrap module).
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import tempfile
import time
from collections import OrderedDict
from datetime import datetime, timezone
from email.utils import formatdate, parsedate_to_datetime
from pathlib import Path
from threading import Lock
from typing import Any, Optional, TypedDict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

_log = logging.getLogger(__name__)

__all__ = [
	"GeoLocation", "IPInfo",
	"geolocate_ip", "lookup_asn", "lookup_ip",
	"ensure_geoip_databases", "get_geoip_build_info",
	"close_readers", "eager_init",
]

# ---------------------------------------------------------------------------
# GeoIP2 optional import
# ---------------------------------------------------------------------------
try:
	import geoip2.database

	_HAS_GEOIP = True
	_ReaderType = geoip2.database.Reader
except ImportError:
	_log.debug("geoip2 not installed – geolocation disabled")
	_HAS_GEOIP = False
	_ReaderType = Any  # type: ignore[misc, assignment]

# ---------------------------------------------------------------------------
# Database path resolution & download constants
# ---------------------------------------------------------------------------
_GEOIP_CITY_DB = "GeoLite2-City.mmdb"
_GEOIP_ASN_DB = "GeoLite2-ASN.mmdb"

# P3TERX mirror (updated regularly, no license key required)
GEOIP_CITY_DOWNLOAD_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
GEOIP_ASN_DOWNLOAD_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"

# MMDB format magic bytes – metadata section starts with this marker
MMDB_METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"

# Metadata lives at end of file – read last 128 KB for validation
_MMDB_TAIL_READ = 131_072

# Minimum file sizes (production: City ~60 MB, ASN ~8 MB)
_MIN_CITY_SIZE = 10_000_000   # 10 MB
_MIN_ASN_SIZE = 1_000_000     # 1 MB

# Hard floor for test environments (never accept files smaller than this)
_ABSOLUTE_MIN_SIZE = 100_000  # 100 KB


def _get_data_dir() -> Path:
	"""Return the data directory for GeoIP databases."""
	# Import here to avoid circular dependency at module load time
	from app.utils.config import get_config
	return get_config().data_dir


def _get_geoip_path() -> Path:
	"""Return the path to the MaxMind GeoLite2-City database."""
	explicit = os.getenv("WIREBUDDY_GEOIP_DB_PATH")
	if explicit:
		return Path(explicit)
	return _get_data_dir() / _GEOIP_CITY_DB


def _get_asn_path() -> Path:
	"""Return the path to the MaxMind GeoLite2-ASN database."""
	explicit = os.getenv("WIREBUDDY_ASN_DB_PATH")
	if explicit:
		return Path(explicit)
	return _get_data_dir() / _GEOIP_ASN_DB


# ---------------------------------------------------------------------------
# Database validation & auto-download (ported from JustUp bootstrap)
# ---------------------------------------------------------------------------

def _http_date_from_path(file_path: Path) -> str:
	"""Convert file mtime to HTTP date string for If-Modified-Since."""
	if not file_path.exists():
		return ""
	mtime = file_path.stat().st_mtime
	return formatdate(mtime, usegmt=True)


def get_geoip_build_info(data_dir: Path | None = None) -> tuple[str, int] | None:
	"""Return ``(database_type, build_epoch)`` for the City DB, or ``None``."""
	if not _HAS_GEOIP:
		return None
	try:
		if data_dir is None:
			data_dir = _get_data_dir()
		db_path = data_dir / _GEOIP_CITY_DB
		if not db_path.exists():
			return None
		with geoip2.database.Reader(str(db_path)) as reader:
			return (reader.metadata().database_type, reader.metadata().build_epoch)
	except Exception:
		return None


def _verify_mmdb(file_path: Path, *, expected_type: str = "City", min_size: int = _MIN_CITY_SIZE) -> bool:
	"""Verify that *file_path* is a valid MaxMind MMDB database.

	Checks: size ≥ *min_size*, MMDB metadata marker present, geoip2 can
	open it and *expected_type* appears in ``database_type``.
	"""
	if not file_path.exists():
		return False

	file_size = file_path.stat().st_size

	# Allow smaller files only in explicit test environments (with hard floor)
	if os.getenv("WIREBUDDY_TEST_MODE") == "1" or os.getenv("PYTEST_CURRENT_TEST") is not None:
		min_size = max(
			_ABSOLUTE_MIN_SIZE,
			int(os.getenv("WIREBUDDY_MIN_GEOIP_SIZE", str(min_size)))
		)

	if file_size < min_size:
		_log.warning("GeoIP database too small (%s): %d bytes (minimum: %d)", file_path.name, file_size, min_size)
		return False

	# Check for MMDB metadata marker in tail
	try:
		with open(file_path, "rb") as f:
			f.seek(max(0, file_size - _MMDB_TAIL_READ))
			tail = f.read()
			if MMDB_METADATA_MARKER not in tail:
				_log.warning("GeoIP database %s missing MMDB metadata marker", file_path.name)
				return False
	except Exception as exc:
		_log.warning("Failed to read GeoIP database %s: %s", file_path.name, exc)
		return False

	# Deep-verify with geoip2 library
	if _HAS_GEOIP:
		try:
			with geoip2.database.Reader(str(file_path)) as reader:
				db_type = reader.metadata().database_type
				build_epoch = reader.metadata().build_epoch
				if expected_type not in db_type:
					_log.warning("GeoIP database type mismatch: expected %s, got %s", expected_type, db_type)
					return False
				_log.info("GeoIP database verified: %s (type=%s, build=%d, date=%s)",
						  file_path.name, db_type, build_epoch, 
						  datetime.fromtimestamp(build_epoch, tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))
		except Exception as exc:
			_log.warning("GeoIP database verification failed for %s: %s", file_path.name, exc)
			return False

	return True


def _check_remote_modified(url: str, local_path: Path) -> tuple[bool, int | None, bool]:
	"""Check if remote resource is newer than local file.

	Returns ``(is_modified, content_length, network_error)``.  Uses ``If-Modified-Since``
	header if local file exists; a ``304 Not Modified`` indicates no change.
	If network check fails but local file exists, returns ``(False, None, True)``
	to signal "keep using local copy".
	"""
	headers = {"User-Agent": "WireBuddy/1.0"}
	if local_path.exists():
		headers["If-Modified-Since"] = _http_date_from_path(local_path)

	try:
		req = Request(url, method="HEAD", headers=headers)
		with urlopen(req, timeout=30) as response:
			# 304 means unchanged
			if response.status == 304:
				return False, None, False
			cl = response.headers.get("Content-Length")
			return True, int(cl) if cl else None, False
	except HTTPError as exc:
		if exc.code == 304:
			return False, None, False
		_log.debug("HTTP error checking remote GeoIP (%s): %s", url, exc)
	except URLError as exc:
		# Network error (DNS, timeout, etc.) but local file exists → keep using local
		if local_path.exists():
			return False, None, True
		_log.debug("Failed to check remote GeoIP (%s): %s", url, exc)
	except Exception as exc:
		_log.debug("Failed to check remote GeoIP (%s): %s", url, exc)

	# Assume modified if we can't determine and no local file
	return True, None, False


def _download_geoip_db(
	target_path: Path,
	download_url: str,
	*,
	expected_type: str = "City",
	min_size: int = _MIN_CITY_SIZE,
	force: bool = False,
) -> Path | None:
	"""Download a GeoLite2 MMDB if missing, invalid, or outdated.

	Returns the path on success, ``None`` on failure.
	Uses HTTP If-Modified-Since headers for efficient update detection.
	Enforces a 5-minute wall-clock download timeout.
	"""
	local_exists = target_path.exists()

	# Existing valid DB → check for updates via If-Modified-Since
	if local_exists and _verify_mmdb(target_path, expected_type=expected_type, min_size=min_size):
		if not force:
			is_modified, _, network_error = _check_remote_modified(download_url, target_path)
			if not is_modified:
				if network_error:
					_log.debug("GeoIP %s: using local copy (remote unreachable)", target_path.name)
				else:
					_log.debug("GeoIP %s up-to-date (HTTP 304 Not Modified)", target_path.name)
				return target_path
			_log.info("GeoIP %s has remote update, downloading…", target_path.name)
		else:
			_log.info("GeoIP %s force-update requested", target_path.name)
	elif local_exists:
		_log.warning("GeoIP %s exists but failed verification, re-downloading…", target_path.name)

	_log.info("Downloading GeoIP database %s from %s …", target_path.name, download_url)
	target_path.parent.mkdir(parents=True, exist_ok=True)

	temp_fd: int | None = None
	temp_path: Path | None = None
	try:
		temp_fd, temp_path_str = tempfile.mkstemp(
			suffix=".mmdb.tmp", prefix="geoip_", dir=str(target_path.parent),
		)
		temp_path = Path(temp_path_str)
		os.close(temp_fd)
		temp_fd = None

		req = Request(download_url, headers={"User-Agent": "WireBuddy/1.0"})
		
		# 5-minute wall-clock deadline
		deadline = time.monotonic() + 300

		with urlopen(req, timeout=120) as response:
			content_type = response.headers.get("Content-Type", "")
			if "text/html" in content_type.lower():
				_log.error("GeoIP download returned HTML instead of binary data")
				return None

			total_size = int(response.headers.get("Content-Length", 0))
			downloaded = 0
			hasher = hashlib.sha256()

			with open(temp_path, "wb") as f:
				while True:
					if time.monotonic() > deadline:
						raise TimeoutError("GeoIP download exceeded 5-minute limit")
					
					chunk = response.read(65536)
					if not chunk:
						break
					f.write(chunk)
					hasher.update(chunk)
					downloaded += len(chunk)

			_log.info("Downloaded %d bytes (SHA256=%s)", downloaded, hasher.hexdigest()[:16])

			# Verify total size if Content-Length was provided
			if total_size and downloaded != total_size:
				_log.error("Size mismatch for %s: expected %d, got %d", 
						   target_path.name, total_size, downloaded)
				return None

		if not _verify_mmdb(temp_path, expected_type=expected_type, min_size=min_size):
			_log.error("Downloaded GeoIP %s failed verification – possibly corrupted", target_path.name)
			return None

		# Extract metadata before installing
		db_info = ""
		if _HAS_GEOIP:
			try:
				with geoip2.database.Reader(str(temp_path)) as reader:
					meta = reader.metadata()
					build_date = datetime.fromtimestamp(meta.build_epoch, tz=timezone.utc).strftime('%Y-%m-%d')
					db_info = f" [{meta.database_type}, build {build_date}]"
			except Exception:
				pass

		# Atomic rename (same filesystem)
		temp_path.rename(target_path)
		temp_path = None
		_log.info("GeoIP database installed: %s%s", target_path, db_info)
		return target_path

	except TimeoutError as exc:
		_log.error("GeoIP download timeout for %s: %s", target_path.name, exc)
		return None
	except URLError as exc:
		_log.warning("Failed to download GeoIP %s: %s", target_path.name, exc)
		return None
	except Exception as exc:
		_log.error("GeoIP download error for %s: %s", target_path.name, exc)
		return None
	finally:
		if temp_fd is not None:
			try:
				os.close(temp_fd)
			except OSError:
				pass
		if temp_path and temp_path.exists():
			try:
				temp_path.unlink()
			except OSError:
				pass


def ensure_geoip_databases(data_dir: Path | None = None, *, force: bool = False) -> dict[str, bool]:
	"""Validate and download/update City + ASN databases.

	Called during application startup.  Returns a dict indicating success
	for each database: ``{"city": True/False, "asn": True/False}``.
	"""
	if data_dir is None:
		data_dir = _get_data_dir()

	city_path = data_dir / _GEOIP_CITY_DB
	asn_path = data_dir / _GEOIP_ASN_DB

	city_ok = _download_geoip_db(
		city_path, GEOIP_CITY_DOWNLOAD_URL,
		expected_type="City", min_size=_MIN_CITY_SIZE, force=force,
	) is not None

	asn_ok = _download_geoip_db(
		asn_path, GEOIP_ASN_DOWNLOAD_URL,
		expected_type="ASN", min_size=_MIN_ASN_SIZE, force=force,
	) is not None

	# If new databases were downloaded, reset the readers so they pick up fresh files
	if city_ok or asn_ok:
		_reset_readers_if_stale(city_path, asn_path)

	return {"city": city_ok, "asn": asn_ok}


def _reset_readers_if_stale(city_path: Path, asn_path: Path) -> None:
	"""Close existing readers if the underlying files have been replaced."""
	global _reader, _asn_reader, _db_not_found_logged, _asn_not_found_logged

	with _reader_lock:
		if _reader is not None:
			try:
				_reader.close()
			except Exception:
				pass
			_reader = None
			_db_not_found_logged = False
			_log.debug("GeoIP City reader reset (database may have been updated)")

	with _asn_reader_lock:
		if _asn_reader is not None:
			try:
				_asn_reader.close()
			except Exception:
				pass
			_asn_reader = None
			_asn_not_found_logged = False
			_log.debug("GeoIP ASN reader reset (database may have been updated)")

	# Also clear lookup cache since results may differ after DB update
	with _geo_cache_lock:
		_geo_cache.clear()


# ---------------------------------------------------------------------------
# City reader singleton (lazy, thread-safe, double-checked locking)
# ---------------------------------------------------------------------------
_reader: Optional[_ReaderType] = None
_db_not_found_logged = False
_reader_lock = Lock()

# ---------------------------------------------------------------------------
# ASN reader singleton
# ---------------------------------------------------------------------------
_asn_reader: Optional[_ReaderType] = None
_asn_not_found_logged = False
_asn_reader_lock = Lock()


def _get_reader() -> Optional[_ReaderType]:
	"""Get or initialise the GeoIP database reader.

	Uses double-checked locking so only one thread pays the init cost.
	If the DB file appears later (e.g. Docker volume mount), subsequent
	calls will pick it up and clear stale cache entries.
	"""
	global _reader, _db_not_found_logged

	if not _HAS_GEOIP:
		return None

	# Fast path
	if _reader is not None:
		return _reader

	# Slow path – acquire lock
	with _reader_lock:
		if _reader is not None:
			return _reader

		db_path = _get_geoip_path()
		if not db_path.exists():
			if not _db_not_found_logged:
				_db_not_found_logged = True
				_log.info(
					"GeoLite2-City.mmdb not found at %s – geolocation disabled. "
					"Will retry on next request.",
					db_path,
				)
			return None

		try:
			_reader = geoip2.database.Reader(str(db_path))
			_log.info("Initialised GeoIP reader from %s", db_path)
			with _geo_cache_lock:
				_geo_cache.clear()
		except Exception as exc:
			_log.warning("Failed to initialise GeoIP reader from %s: %s", db_path, exc)
			return None

	return _reader


def _get_asn_reader() -> Optional[_ReaderType]:
	"""Get or initialise the GeoLite2-ASN reader (lazy, thread-safe)."""
	global _asn_reader, _asn_not_found_logged

	if not _HAS_GEOIP:
		return None

	if _asn_reader is not None:
		return _asn_reader

	with _asn_reader_lock:
		if _asn_reader is not None:
			return _asn_reader

		db_path = _get_asn_path()
		if not db_path.exists():
			if not _asn_not_found_logged:
				_asn_not_found_logged = True
				_log.info(
					"GeoLite2-ASN.mmdb not found at %s – ASN lookups disabled.",
					db_path,
				)
			return None

		try:
			_asn_reader = geoip2.database.Reader(str(db_path))
			_log.info("Initialised ASN reader from %s", db_path)
		except Exception as exc:
			_log.warning("Failed to initialise ASN reader from %s: %s", db_path, exc)
			return None

	return _asn_reader


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------
class GeoLocation(TypedDict):
	lat: float
	lon: float
	city: Optional[str]
	country: Optional[str]


class IPInfo(TypedDict):
	"""Combined geo + ASN information for an IP address."""
	lat: float
	lon: float
	city: Optional[str]
	country: Optional[str]
	asn: Optional[int]
	as_org: Optional[str]


# ---------------------------------------------------------------------------
# Manual LRU cache (avoids caching None when reader is unavailable)
# ---------------------------------------------------------------------------
_geo_cache: OrderedDict[str, Optional[GeoLocation]] = OrderedDict()
_geo_cache_lock = Lock()
_GEO_CACHE_MAX = 512


def _cache_put(ip: str, result: Optional[GeoLocation]) -> None:
	"""Add or update cache entry with LRU eviction."""
	with _geo_cache_lock:
		if ip in _geo_cache:
			# Update existing entry and mark as recently used
			_geo_cache.move_to_end(ip)
			_geo_cache[ip] = result
		else:
			# Evict least recently used entry if cache is full
			if len(_geo_cache) >= _GEO_CACHE_MAX:
				_geo_cache.popitem(last=False)
			_geo_cache[ip] = result


# ---------------------------------------------------------------------------
# Eager initialisation (call once at startup after DBs are ensured)
# ---------------------------------------------------------------------------

def eager_init() -> None:
	"""Pre-load GeoIP readers so first request is instant.

	Safe to call even if databases are missing (returns silently).
	"""
	_get_reader()
	_get_asn_reader()
	_log.debug("GeoIP eager_init complete (city=%s, asn=%s)",
			   _reader is not None, _asn_reader is not None)


# ---------------------------------------------------------------------------
# Resource management
# ---------------------------------------------------------------------------

def close_readers() -> None:
	"""Close GeoIP readers and release file descriptors.

	Useful for graceful shutdown or when running with reload.
	Properly acquires locks to prevent race with active queries.
	"""
	global _reader, _asn_reader

	with _reader_lock:
		if _reader:
			try:
				_reader.close()
				_log.debug("Closed GeoIP City reader")
			except Exception as exc:
				_log.warning("Error closing GeoIP City reader: %s", exc)
			finally:
				_reader = None

	with _asn_reader_lock:
		if _asn_reader:
			try:
				_asn_reader.close()
				_log.debug("Closed GeoIP ASN reader")
			except Exception as exc:
				_log.warning("Error closing GeoIP ASN reader: %s", exc)
			finally:
				_asn_reader = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def geolocate_ip(ip: str) -> Optional[GeoLocation]:
	"""Resolve *ip* to geographic coordinates.

	Skips private / loopback / link-local / reserved / multicast addresses.
	Results are cached (up to 512 entries with LRU eviction).  When the
	GeoIP reader is not yet available the result is **not** cached so a
	later retry succeeds.

	Returns a ``GeoLocation`` dict or ``None``.
	"""
	# Normalize input
	ip = ip.strip()
	
	# 1. Cache hit?
	with _geo_cache_lock:
		if ip in _geo_cache:
			# Mark as recently used (LRU)
			_geo_cache.move_to_end(ip)
			return _geo_cache[ip]

	# 2. Skip non-routable IPs
	try:
		ip_obj = ipaddress.ip_address(ip)
		if (
			ip_obj.is_private
			or ip_obj.is_loopback
			or ip_obj.is_link_local
			or ip_obj.is_reserved
			or ip_obj.is_multicast
			or ip_obj.is_unspecified
		):
			_cache_put(ip, None)
			return None
	except ValueError:
		_log.debug("Invalid IP for geolocation: %s", ip)
		# Don't cache invalid IPs – prevents cache poisoning
		return None

	# 3. Get reader (double-checked locking lives inside _get_reader).
	#    MaxMind C extension is thread-safe for concurrent reads, so we
	#    do NOT hold the lock during the actual query.  If close_readers()
	#    races with a query the worst case is a single failed lookup which
	#    is caught below.
	reader = _get_reader()
	if not reader:
		return None  # do NOT cache – DB may appear later

	try:
		r = reader.city(ip)
		lat = r.location.latitude
		lon = r.location.longitude
		city_name = r.city.name if r.city else None
		country_iso = r.country.iso_code if r.country else None
	except Exception as exc:
		_log.debug("GeoIP lookup failed for %s: %s", ip, exc)
		_cache_put(ip, None)
		return None

	# 4. Validate (outside lock)
	if lat is None or lon is None:
		_cache_put(ip, None)
		return None

	if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
		_log.warning("GeoIP invalid types for %s: lat=%r lon=%r", ip, lat, lon)
		_cache_put(ip, None)
		return None

	if not (-90 <= lat <= 90 and -180 <= lon <= 180):
		_log.warning("GeoIP out-of-range for %s: lat=%s lon=%s", ip, lat, lon)
		_cache_put(ip, None)
		return None

	result: GeoLocation = {
		"lat": float(lat),
		"lon": float(lon),
		"city": city_name,
		"country": country_iso,
	}
	_cache_put(ip, result)
	return result


def lookup_asn(ip: str) -> tuple[Optional[int], Optional[str]]:
	"""Return ``(asn_number, as_org)`` for *ip*, or ``(None, None)``.

	MaxMind C extension is thread-safe for reads.  The lock only protects
	initialization inside ``_get_asn_reader()``.
	"""
	ip = ip.strip()

	reader = _get_asn_reader()
	if not reader:
		return None, None

	try:
		r = reader.asn(ip)
		return r.autonomous_system_number, r.autonomous_system_organization
	except Exception:
		return None, None


def lookup_ip(ip: str) -> Optional[IPInfo]:
	"""Combined geo + ASN lookup.  Returns ``IPInfo`` or ``None``.

	Uses the City DB for coordinates and the ASN DB for AS data.
	Private/reserved IPs are skipped.
	"""
	geo = geolocate_ip(ip)
	if not geo:
		return None

	asn_num, as_org = lookup_asn(ip)

	return IPInfo(
		lat=geo["lat"],
		lon=geo["lon"],
		city=geo["city"],
		country=geo["country"],
		asn=asn_num,
		as_org=as_org,
	)
