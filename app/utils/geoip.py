#!/usr/bin/env python3
#
# app/utils/geoip.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""GeoIP lookup service using MaxMind GeoLite2 databases.

Provides IP → lat/lon/city/country + ASN resolution for WireGuard peer
endpoints.  Thread-safe with lazy-initialized readers and C-optimized
LRU caching via functools.lru_cache.

Includes automatic database download and update checking via the
P3TERX GeoLite.mmdb mirror.
"""

from __future__ import annotations

import functools
import hashlib
import ipaddress
import logging
import os
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import formatdate
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, Any, Required, TypedDict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

if TYPE_CHECKING:
    import geoip2.database
    import geoip2.errors

_log = logging.getLogger(__name__)

__all__ = [
    "GeoLocation", "IPInfo",
    "geolocate_ip", "lookup_asn", "lookup_ip",
    "ensure_geoip_databases", "get_geoip_build_info",
    "close_readers", "eager_init",
]

# ---------------------------------------------------------------------------
# GeoIP2 initialization
# ---------------------------------------------------------------------------
try:
    import geoip2.database
    import geoip2.errors
    _HAS_GEOIP = True
except ImportError:
    _log.debug("geoip2 not installed – geolocation disabled")
    _HAS_GEOIP = False
    # Define as None to avoid NameError in inactive code paths
    geoip2 = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Constants & DB Specifications
# ---------------------------------------------------------------------------
_GEOIP_SUBDIR = "geolite2"

# P3TERX mirror (updated regularly, no license key required)
GEOIP_CITY_DOWNLOAD_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
GEOIP_ASN_DOWNLOAD_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"

# Minimum file sizes (production: City ~60 MB, ASN ~8 MB)
_MIN_CITY_SIZE = 10_000_000   # 10 MB
_MIN_ASN_SIZE = 1_000_000     # 1 MB
_ABSOLUTE_MIN_SIZE = 100_000  # 100 KB safety floor

# Update checking constraints
_MIN_UPDATE_INTERVAL_HOURS = 12
_LAST_CHECK_FILE = ".geoip_last_check"
_MAX_DOWNLOAD_SIZE = 200_000_000  # 200 MB hard safety cap

@dataclass(frozen=True, slots=True)
class _DBSpec:
    name: str
    env_var: str
    filename: str
    url: str
    min_size: int
    expected_type: str

_SPECS = {
    "city": _DBSpec("City", "WIREBUDDY_GEOIP_DB_PATH", "GeoLite2-City.mmdb",
                    GEOIP_CITY_DOWNLOAD_URL, _MIN_CITY_SIZE, "City"),
    "asn": _DBSpec("ASN", "WIREBUDDY_ASN_DB_PATH", "GeoLite2-ASN.mmdb",
                   GEOIP_ASN_DOWNLOAD_URL, _MIN_ASN_SIZE, "ASN"),
}

# ---------------------------------------------------------------------------
# Types (Python 3.11+ TypedDict)
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def _get_data_dir() -> Path:
    from app.utils.config import get_config
    return get_config().data_dir

def _get_geoip_dir(base_dir: Path | None = None) -> Path:
    """Return the GeoLite2 subdirectory, creating it if needed."""
    if base_dir is None:
        base_dir = _get_data_dir()
    d = base_dir / _GEOIP_SUBDIR
    d.mkdir(parents=True, exist_ok=True)
    return d

def _public_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return IP object if public, else None."""
    try:
        obj = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    if any((
        obj.is_private, obj.is_loopback, obj.is_link_local,
        obj.is_reserved, obj.is_multicast, obj.is_unspecified,
    )):
        return None
    return obj

def _get_http_date(path: Path) -> str:
    """Return HTTP-formatted date for If-Modified-Since."""
    if not path.exists():
        return ""
    # Try getting build epoch from MMDB first for better accuracy
    if _HAS_GEOIP:
        try:
            with geoip2.database.Reader(str(path)) as reader:
                return formatdate(reader.metadata().build_epoch, usegmt=True)
        except Exception:
            pass
    return formatdate(path.stat().st_mtime, usegmt=True)

# ---------------------------------------------------------------------------
# Reader Manager
# ---------------------------------------------------------------------------
class _ReaderManager:
    """Thread-safe, lazy-initialized GeoIP reader manager."""

    __slots__ = ("_spec", "_reader", "_lock", "_not_found_logged")

    def __init__(self, spec: _DBSpec) -> None:
        self._spec = spec
        self._reader: geoip2.database.Reader | None = None
        self._lock = RLock()
        self._not_found_logged = False

    def get(self, data_dir: Path | None = None) -> geoip2.database.Reader | None:
        """Get or initialize the reader. Thread-safe."""
        if not _HAS_GEOIP:
            return None
        if self._reader is not None:
            return self._reader
        with self._lock:
            if self._reader is not None:
                return self._reader
            
            p = self.resolve_path(data_dir)
            if not p.exists():
                if not self._not_found_logged:
                    self._not_found_logged = True
                    _log.info("%s database not found at %s – disabled.", self._spec.name, p)
                return None
            
            try:
                self._reader = geoip2.database.Reader(str(p))
                _log.info("Initialized %s reader from %s", self._spec.name, p)
                return self._reader
            except Exception as exc:
                _log.warning("Failed to initialize %s reader from %s: %s", self._spec.name, p, exc)
                return None

    def close(self) -> None:
        """Safely close the reader."""
        with self._lock:
            if self._reader is not None:
                try:
                    self._reader.close()
                except Exception as exc:
                    _log.warning("Error closing %s reader: %s", self._spec.name, exc)
                finally:
                    self._reader = None
                    self._not_found_logged = False

    def resolve_path(self, data_dir: Path | None = None) -> Path:
        explicit = os.getenv(self._spec.env_var)
        if explicit:
            return Path(explicit).resolve()
        return _get_geoip_dir(data_dir) / self._spec.filename

_city_mgr = _ReaderManager(_SPECS["city"])
_asn_mgr = _ReaderManager(_SPECS["asn"])

# ---------------------------------------------------------------------------
# Database Maintenance
# ---------------------------------------------------------------------------
def _verify_mmdb(path: Path, spec: _DBSpec) -> bool:
    """Verify MMDB size and type."""
    if not path.exists():
        return False
    
    size = path.stat().st_size
    min_size = spec.min_size
    if os.getenv("WIREBUDDY_TEST_MODE") == "1":
        min_size = max(_ABSOLUTE_MIN_SIZE, int(os.getenv("WIREBUDDY_MIN_GEOIP_SIZE", str(min_size))))
    
    if size < min_size:
        _log.warning("GeoIP %s too small: %d bytes", path.name, size)
        return False

    if _HAS_GEOIP:
        try:
            with geoip2.database.Reader(str(path)) as reader:
                db_type = reader.metadata().database_type
                if spec.expected_type not in db_type:
                    _log.warning("GeoIP %s type mismatch: expected %s, got %s", path.name, spec.expected_type, db_type)
                    return False
                _log.info("GeoIP %s verified: %s (build %s)", path.name, db_type, 
                          datetime.fromtimestamp(reader.metadata().build_epoch, tz=UTC).date())
        except Exception as exc:
            _log.warning("GeoIP %s verification failed: %s", path.name, exc)
            return False
    return True

def _download_db(spec: _DBSpec, data_dir: Path | None = None, force: bool = False) -> bool:
    """Download database if needed. Returns True if updated."""
    target = (_city_mgr if spec.name == "City" else _asn_mgr).resolve_path(data_dir)
    
    if target.exists() and not force:
        if _verify_mmdb(target, spec):
            return False

    _log.info("Downloading GeoIP %s from %s ...", spec.name, spec.url)
    target.parent.mkdir(parents=True, exist_ok=True)
    
    temp_path = None
    try:
        fd, temp_path_str = tempfile.mkstemp(suffix=".mmdb.tmp", dir=str(target.parent))
        temp_path = Path(temp_path_str)
        os.close(fd)
        
        req = Request(spec.url, headers={"User-Agent": "WireBuddy/1.0", "If-Modified-Since": _get_http_date(target)})
        with urlopen(req, timeout=60) as resp:
            if "text/html" in resp.headers.get("Content-Type", "").lower():
                _log.error("GeoIP download for %s returned HTML", spec.name)
                return False
            
            downloaded = 0
            with open(temp_path, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if downloaded > _MAX_DOWNLOAD_SIZE:
                        raise ValueError(f"Download exceeded safety limit ({_MAX_DOWNLOAD_SIZE} bytes)")
        
        if not _verify_mmdb(temp_path, spec):
            return False
            
        temp_path.replace(target)
        _log.info("GeoIP %s updated successfully (%d bytes)", spec.name, downloaded)
        return True
    except HTTPError as e:
        if e.code == 304:
            _log.debug("GeoIP %s is up-to-date (304)", spec.name)
            return False
        _log.warning("GeoIP download HTTP error %s: %s", e.code, spec.name)
    except Exception as e:
        if isinstance(e, ValueError) and "limit" in str(e):
            _log.error("GeoIP download safety violation: %s", e)
        else:
            _log.error("GeoIP download failed for %s: %s", spec.name, e)
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink()
    return False

def ensure_geoip_databases(data_dir: Path | None = None, force: bool = False) -> dict[str, bool]:
    """Startup check for databases."""
    geoip_dir = _get_geoip_dir(data_dir)
    check_file = geoip_dir / _LAST_CHECK_FILE
    
    if not force:
        try:
            if check_file.exists():
                last = float(check_file.read_text().strip())
                if (time.time() - last) / 3600 < _MIN_UPDATE_INTERVAL_HOURS:
                    c_ok = _verify_mmdb(_city_mgr.resolve_path(data_dir), _SPECS["city"])
                    a_ok = _verify_mmdb(_asn_mgr.resolve_path(data_dir), _SPECS["asn"])
                    if c_ok and a_ok:
                        return {"city": True, "asn": True}
        except Exception:
            pass

    c_up = _download_db(_SPECS["city"], data_dir, force=force)
    a_up = _download_db(_SPECS["asn"], data_dir, force=force)
    
    if c_up or a_up:
        close_readers()
        
    check_file.write_text(str(time.time()))
    return {
        "city": _city_mgr.resolve_path(data_dir).exists(),
        "asn": _asn_mgr.resolve_path(data_dir).exists()
    }

def get_geoip_build_info(data_dir: Path | None = None) -> tuple[str, int] | None:
    if not _HAS_GEOIP: return None
    try:
        p = _city_mgr.resolve_path(data_dir)
        with geoip2.database.Reader(str(p)) as r:
            return r.metadata().database_type, r.metadata().build_epoch
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Public Caching & API
# ---------------------------------------------------------------------------
@functools.lru_cache(maxsize=512)
def _cached_city_lookup(ip: str) -> GeoLocation | None:
    # Lock ONLY for getting the reference to the reader.
    # MaxMind C extension is thread-safe for parallel reads.
    reader = _city_mgr.get()
    if not reader: return None
    try:
        r = reader.city(ip)
        lat, lon = r.location.latitude, r.location.longitude
        if lat is None or lon is None or not (-90 <= lat <= 90 and -180 <= lon <= 180):
            return None
        return GeoLocation(
            lat=float(lat), lon=float(lon),
            city=r.city.name, country=r.country.iso_code
        )
    except (geoip2.errors.AddressNotFoundError, geoip2.errors.GeoIP2Error):
        return None
    except Exception as exc:
        _log.debug("GeoIP city lookup unexpected error for %s: %s", ip, exc)
        return None

@functools.lru_cache(maxsize=512)
def _cached_asn_lookup(ip: str) -> tuple[int | None, str | None]:
    reader = _asn_mgr.get()
    if not reader: return None, None
    try:
        r = reader.asn(ip)
        return r.autonomous_system_number, r.autonomous_system_organization
    except (geoip2.errors.AddressNotFoundError, geoip2.errors.GeoIP2Error):
        return None, None
    except Exception:
        return None, None

def geolocate_ip(ip: str) -> GeoLocation | None:
    if not _public_ip(ip): return None
    return _cached_city_lookup(ip)

def lookup_asn(ip: str) -> tuple[int | None, str | None]:
    if not _public_ip(ip): return None, None
    return _cached_asn_lookup(ip)

def lookup_ip(ip: str) -> IPInfo | None:
    geo = geolocate_ip(ip)
    if not geo: return None
    asn, org = lookup_asn(ip)
    return IPInfo(
        lat=geo["lat"], lon=geo["lon"],
        city=geo["city"], country=geo["country"],
        asn=asn, as_org=org
    )

def close_readers() -> None:
    _city_mgr.close()
    _asn_mgr.close()
    _cached_city_lookup.cache_clear()
    _cached_asn_lookup.cache_clear()

def eager_init() -> None:
    _city_mgr.get()
    _asn_mgr.get()


def resolve_country_from_url(url: str) -> str | None:
    """Synchronously resolve a URL's hostname to an ISO country code via GeoIP.

    Uses dual-stack DNS (IPv4 + IPv6) via :func:`socket.getaddrinfo`.
    Safe to call from a threadpool worker (blocking I/O, no event-loop needed).

    Returns the lowercase ISO 3166-1 alpha-2 country code, or ``None`` if the
    hostname cannot be resolved or has no GeoIP record.
    """
    import socket
    from urllib.parse import urlparse

    if not url:
        return None
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return None
        addrinfo = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addrinfo:
            return None
        ip = addrinfo[0][4][0]
        geo = geolocate_ip(ip)
        if geo and geo.get("country"):
            return str(geo["country"]).lower()
        return None
    except Exception:
        return None
