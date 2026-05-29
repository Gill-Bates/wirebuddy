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

import asyncio
import fcntl
import functools
import ipaddress
import logging
import os
import re
import stat
import tempfile
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import formatdate
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, Any, Required, TypedDict
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

if TYPE_CHECKING:
    import geoip2.database
    import geoip2.errors

_log = logging.getLogger(__name__)

__all__ = [
    "GeoLocation", "IPInfo",
    "geolocate_ip", "lookup_asn", "lookup_ip",
    "ensure_geoip_databases", "ensure_geoip_databases_async", "get_geoip_build_info",
    "close_readers", "eager_init",
    "resolve_country_from_url", "resolve_country_from_url_async",
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
_DEFAULT_GEOIP_CACHE_SIZE = 4096
_MAX_GEOIP_CACHE_SIZE = 65_536
_DEFAULT_GEOIP_ALLOWED_HOSTS = {
    "github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
}
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_GEOIP_DOWNLOAD_TOTAL_TIMEOUT_SECONDS = 120.0
_GEOIP_DOWNLOAD_LOCK = RLock()


def _read_geoip_cache_size() -> int:
    raw = os.getenv("WIREBUDDY_GEOIP_CACHE_SIZE", str(_DEFAULT_GEOIP_CACHE_SIZE))
    try:
        value = int(raw)
    except ValueError:
        _log.warning("Invalid WIREBUDDY_GEOIP_CACHE_SIZE=%r; using default", raw)
        return _DEFAULT_GEOIP_CACHE_SIZE
    return min(max(value, 128), _MAX_GEOIP_CACHE_SIZE)


_GEOIP_CACHE_SIZE = _read_geoip_cache_size()

@dataclass(frozen=True, slots=True)
class _DBSpec:
    name: str
    env_var: str
    url_env_var: str
    filename: str
    url: str
    min_size: int
    expected_type: str

_SPECS = {
    "city": _DBSpec("City", "WIREBUDDY_GEOIP_DB_PATH", "WIREBUDDY_GEOIP_CITY_DOWNLOAD_URL", "GeoLite2-City.mmdb",
                    GEOIP_CITY_DOWNLOAD_URL, _MIN_CITY_SIZE, "City"),
    "asn": _DBSpec("ASN", "WIREBUDDY_ASN_DB_PATH", "WIREBUDDY_GEOIP_ASN_DOWNLOAD_URL", "GeoLite2-ASN.mmdb",
                   GEOIP_ASN_DOWNLOAD_URL, _MIN_ASN_SIZE, "ASN"),
}

_cache_generation = 0
_HTTP_DATE_CACHE: dict[Path, tuple[int, str]] = {}

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


def _ensure_private_dir(path: Path) -> None:
    try:
        st = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700, parents=True)
        st = path.lstat()

    if path.is_symlink() or not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f"GeoIP directory is not safe: {path}")

    path.chmod(0o700)


def _fsync_dir(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    dir_fd = os.open(str(path), flags)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _resolve_download_url(spec: _DBSpec) -> str:
    return os.getenv(spec.url_env_var, spec.url).strip()


def _allowed_geoip_hosts() -> set[str]:
    """Return the explicit allowlist of GeoIP download hosts."""
    raw = os.getenv("WIREBUDDY_GEOIP_ALLOWED_HOSTS", "")
    hosts = {host.strip().lower() for host in raw.split(",") if host.strip()}
    return set(_DEFAULT_GEOIP_ALLOWED_HOSTS) | hosts


def _validate_download_response_target(url: str, *, requested_url: str) -> None:
    requested_host = (urlparse(requested_url).hostname or "").lower()
    parsed = urlparse(url)
    allowed_hosts = _allowed_geoip_hosts()
    if requested_host and requested_host not in allowed_hosts:
        raise ValueError(f"Unexpected GeoIP download source host: {requested_url}")
    if parsed.scheme != "https" or (parsed.hostname or "").lower() not in allowed_hosts:
        raise ValueError(f"Unexpected GeoIP download redirect target: {url}")


@contextmanager
def _acquire_geoip_file_lock(lock_path: Path):
    """Acquire an exclusive cross-process GeoIP update lock."""
    _ensure_private_dir(lock_path.parent)
    if lock_path.exists() and lock_path.is_symlink():
        raise RuntimeError(f"GeoIP lock path must not be a symlink: {lock_path}")

    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(lock_path, flags, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"GeoIP lock path is not a regular file: {lock_path}")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        with suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

def _get_geoip_dir(base_dir: Path | None = None) -> Path:
    """Return the GeoLite2 subdirectory, creating it if needed."""
    if base_dir is None:
        base_dir = _get_data_dir()
    d = base_dir / _GEOIP_SUBDIR
    _ensure_private_dir(d)
    return d

def _public_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return IP object if public, else None."""
    try:
        obj = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    if not obj.is_global:
        return None
    return obj

def _get_http_date(path: Path) -> str:
    """Return HTTP-formatted date for If-Modified-Since."""
    if not path.exists():
        return ""
    try:
        stat_result = path.stat()
    except OSError:
        return ""
    cached = _HTTP_DATE_CACHE.get(path)
    if cached is not None and cached[0] == stat_result.st_mtime_ns:
        return cached[1]
    # Try getting build epoch from MMDB first for better accuracy
    http_date = formatdate(stat_result.st_mtime, usegmt=True)
    if _HAS_GEOIP:
        try:
            with geoip2.database.Reader(str(path)) as reader:
                http_date = formatdate(reader.metadata().build_epoch, usegmt=True)
        except Exception:
            pass
    _HTTP_DATE_CACHE[path] = (stat_result.st_mtime_ns, http_date)
    return http_date


def _atomic_write_text(path: Path, content: str, *, mode: int = 0o644) -> None:
    """Atomically write small text files with fsync before replace."""
    _ensure_private_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.replace(path)
        os.chmod(path, mode)
        _fsync_dir(path.parent)
    finally:
        with suppress(OSError):
            tmp_path.unlink()

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

def _download_db(
    spec: _DBSpec,
    data_dir: Path | None = None,
    *,
    force: bool = False,
    check_remote: bool = True,
) -> bool:
    """Download database if needed. Returns True if the local file was replaced."""
    target = (_city_mgr if spec.name == "City" else _asn_mgr).resolve_path(data_dir)

    target_valid = False
    if target.exists():
        target_valid = _verify_mmdb(target, spec)
        if target_valid and not force and not check_remote:
            return False
        if not target_valid:
            _log.warning("GeoIP %s exists but failed verification; redownloading", spec.name)

    download_url = _resolve_download_url(spec)
    _log.info("Downloading GeoIP %s from %s ...", spec.name, download_url)
    _ensure_private_dir(target.parent)

    fd = -1
    temp_path: Path | None = None
    try:
        fd, temp_path_str = tempfile.mkstemp(suffix=".mmdb.tmp", dir=str(target.parent))
        temp_path = Path(temp_path_str)
        os.fchmod(fd, 0o644)

        headers = {"User-Agent": "WireBuddy/1.0"}
        if target.exists() and not force:
            http_date = _get_http_date(target)
            if http_date:
                headers["If-Modified-Since"] = http_date

        req = Request(download_url, headers=headers)
        deadline = time.monotonic() + _GEOIP_DOWNLOAD_TOTAL_TIMEOUT_SECONDS
        with urlopen(req, timeout=60) as resp:
            _validate_download_response_target(getattr(resp, "url", download_url), requested_url=download_url)
            if "text/html" in resp.headers.get("Content-Type", "").lower():
                _log.error("GeoIP download for %s returned HTML", spec.name)
                return False

            content_length = resp.headers.get("Content-Length")
            if content_length is not None:
                try:
                    parsed_length = int(content_length)
                except ValueError as exc:
                    raise ValueError("Invalid Content-Length for GeoIP download") from exc
                if parsed_length > _MAX_DOWNLOAD_SIZE:
                    raise ValueError(f"Download exceeded safety limit ({_MAX_DOWNLOAD_SIZE} bytes)")

            downloaded = 0
            with os.fdopen(fd, "wb") as f:
                fd = -1
                while True:
                    if time.monotonic() > deadline:
                        raise TimeoutError("GeoIP download exceeded total timeout")
                    chunk = resp.read(65_536)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if downloaded > _MAX_DOWNLOAD_SIZE:
                        raise ValueError(f"Download exceeded safety limit ({_MAX_DOWNLOAD_SIZE} bytes)")
                f.flush()
                os.fsync(f.fileno())
        
        if temp_path is None or not _verify_mmdb(temp_path, spec):
            return False

        temp_path.replace(target)
        os.chmod(target, 0o644)
        _fsync_dir(target.parent)
        _HTTP_DATE_CACHE.pop(target, None)
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
        if fd != -1:
            os.close(fd)
        if temp_path and temp_path.exists():
            with suppress(OSError):
                temp_path.unlink()
    return False

def _ensure_geoip_databases_locked(data_dir: Path | None = None, force: bool = False) -> dict[str, bool]:
    """Internal GeoIP update implementation guarded by locks."""
    geoip_dir = _get_geoip_dir(data_dir)
    check_file = geoip_dir / _LAST_CHECK_FILE
    should_check_remote = force

    if not force:
        try:
            if check_file.exists():
                last = float(check_file.read_text().strip())
                if (time.time() - last) / 3600 < _MIN_UPDATE_INTERVAL_HOURS:
                    c_ok = _verify_mmdb(_city_mgr.resolve_path(data_dir), _SPECS["city"])
                    a_ok = _verify_mmdb(_asn_mgr.resolve_path(data_dir), _SPECS["asn"])
                    if c_ok and a_ok:
                        return {"city": True, "asn": True}
                else:
                    should_check_remote = True
            else:
                should_check_remote = True
        except Exception:
            should_check_remote = True

    c_up = _download_db(_SPECS["city"], data_dir, force=force, check_remote=should_check_remote)
    a_up = _download_db(_SPECS["asn"], data_dir, force=force, check_remote=should_check_remote)

    if c_up or a_up:
        close_readers()

    result = {
        "city": _verify_mmdb(_city_mgr.resolve_path(data_dir), _SPECS["city"]),
        "asn": _verify_mmdb(_asn_mgr.resolve_path(data_dir), _SPECS["asn"]),
    }

    if result["city"] and result["asn"]:
        _atomic_write_text(check_file, str(time.time()))

    return result


def ensure_geoip_databases(data_dir: Path | None = None, force: bool = False) -> dict[str, bool]:
    """Blocking startup check for GeoIP databases.

    Do not call directly from an asyncio event loop; use
    ensure_geoip_databases_async() instead.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise RuntimeError(
            "ensure_geoip_databases() must not run on an active event loop; "
            "use ensure_geoip_databases_async() instead."
        )

    geoip_dir = _get_geoip_dir(data_dir)
    lock_path = geoip_dir / ".geoip-update.lock"
    with _GEOIP_DOWNLOAD_LOCK:
        with _acquire_geoip_file_lock(lock_path):
            return _ensure_geoip_databases_locked(data_dir, force)


async def ensure_geoip_databases_async(data_dir: Path | None = None, force: bool = False) -> dict[str, bool]:
    """Async wrapper for ensure_geoip_databases()."""
    return await asyncio.to_thread(ensure_geoip_databases, data_dir, force)

def get_geoip_build_info(data_dir: Path | None = None) -> tuple[str, int] | None:
    if not _HAS_GEOIP:
        return None
    try:
        p = _city_mgr.resolve_path(data_dir)
        with geoip2.database.Reader(str(p)) as r:
            return r.metadata().database_type, r.metadata().build_epoch
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Public Caching & API
# ---------------------------------------------------------------------------
@functools.lru_cache(maxsize=_GEOIP_CACHE_SIZE)
def _cached_city_lookup(ip: str, generation: int) -> GeoLocation | None:
    # Lock ONLY for getting the reference to the reader.
    # MaxMind C extension is thread-safe for parallel reads.
    _ = generation
    reader = _city_mgr.get()
    if not reader:
        return None
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

@functools.lru_cache(maxsize=_GEOIP_CACHE_SIZE)
def _cached_asn_lookup(ip: str, generation: int) -> tuple[int | None, str | None]:
    _ = generation
    reader = _asn_mgr.get()
    if not reader:
        return None, None
    try:
        r = reader.asn(ip)
        return r.autonomous_system_number, r.autonomous_system_organization
    except (geoip2.errors.AddressNotFoundError, geoip2.errors.GeoIP2Error):
        return None, None
    except Exception:
        return None, None

def geolocate_ip(ip: str) -> GeoLocation | None:
    if not _public_ip(ip):
        return None
    return _cached_city_lookup(ip, _cache_generation)

def lookup_asn(ip: str) -> tuple[int | None, str | None]:
    if not _public_ip(ip):
        return None, None
    return _cached_asn_lookup(ip, _cache_generation)

def lookup_ip(ip: str) -> IPInfo | None:
    geo = geolocate_ip(ip)
    if not geo:
        return None
    asn, org = lookup_asn(ip)
    return IPInfo(
        lat=geo["lat"], lon=geo["lon"],
        city=geo["city"], country=geo["country"],
        asn=asn, as_org=org
    )

def close_readers() -> None:
    global _cache_generation
    _cache_generation += 1
    _city_mgr.close()
    _asn_mgr.close()
    _cached_city_lookup.cache_clear()
    _cached_asn_lookup.cache_clear()

def eager_init() -> None:
    _city_mgr.get()
    _asn_mgr.get()


def resolve_country_from_url(url: str) -> str | None:
    """Blocking helper that resolves a URL hostname to an ISO country code.

    Uses dual-stack DNS (IPv4 + IPv6) via :func:`socket.getaddrinfo`.
    Safe to call from a threadpool worker (blocking I/O, no event-loop needed).

    Returns the lowercase ISO 3166-1 alpha-2 country code, or ``None`` if the
    hostname cannot be resolved or has no GeoIP record.
    """
    import socket

    if not url:
        return None
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return None
        hostname = hostname.rstrip(".").lower()
        if len(hostname) > 253 or not _HOSTNAME_RE.fullmatch(hostname):
            return None
        if "." not in hostname:
            return None
        addrinfo = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addrinfo:
            return None
        seen_ips: set[str] = set()
        for entry in addrinfo:
            ip = entry[4][0]
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            if not _public_ip(ip):
                continue
            geo = geolocate_ip(ip)
            if geo and geo.get("country"):
                return str(geo["country"]).lower()
        return None
    except Exception:
        return None


async def resolve_country_from_url_async(url: str) -> str | None:
    """Async wrapper that isolates blocking DNS resolution in a worker thread."""
    loop = asyncio.get_running_loop()
    sem = getattr(loop, "_wirebuddy_geoip_dns_semaphore", None)
    if sem is None:
        sem = asyncio.Semaphore(8)
        setattr(loop, "_wirebuddy_geoip_dns_semaphore", sem)
    try:
        async with sem:
            return await asyncio.wait_for(asyncio.to_thread(resolve_country_from_url, url), timeout=3.0)
    except TimeoutError:
        return None
