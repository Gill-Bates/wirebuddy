#!/usr/bin/env python3
#
# app/api/network_stats.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Network interface statistics API for real-time bandwidth monitoring.

Reads kernel network counters from /sys/class/net/<interface>/statistics/
to provide host and WireGuard interface throughput data.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, Request
from starlette.concurrency import run_in_threadpool

from .auth import get_current_user
from .response import ok_response
from ..db.sqlite_interfaces import list_interfaces
from ..utils.deps import get_conn, get_config

_log = logging.getLogger(__name__)

router = APIRouter(tags=["network"])

__all__ = ["router", "NETWORK_STATS_KEY", "sample_network_stats"]

# TSDB synthetic key for network stats
NETWORK_STATS_KEY = "__network_stats__"
NETWORK_STATS_RETENTION_DAYS = 7  # 7 days default retention

# Time range mapping for history queries
NETWORK_RANGE_TO_HOURS = {
    "1h": 1,
    "6h": 6,
    "24h": 24,
    "7d": 7 * 24,
}

# Cache for previous readings (interface -> (timestamp, rx_bytes, tx_bytes))
_prev_stats: dict[str, tuple[float, int, int]] = {}
_prev_stats_lock = threading.Lock()

# Response cache to prevent hammering sysfs
_cache: dict[str, Any] = {"interfaces": []}
_cache_ts: float = 0.0
_CACHE_TTL = 0.5  # seconds - minimum interval between sysfs reads

# Cache for primary interface detection (changes rarely)
_primary_iface_cache: str | None = None
_primary_iface_cache_ts: float = 0.0
_PRIMARY_IFACE_CACHE_TTL = 30.0  # seconds

# Interfaces to skip (virtual/docker/bridge)
_SKIP_PREFIXES = frozenset(("lo", "docker", "br-", "br", "veth", "virbr"))


def _get_primary_interface() -> str | None:
    """Detect the system's primary outbound network interface (default route).

    Reads /proc/net/route for the entry with Destination=0.0.0.0 and
    Mask=0.0.0.0 (all values in hex). Caches results for performance.

    Returns:
        Interface name (e.g., 'eth0', 'enp0s3') or None if detection fails.
    """
    global _primary_iface_cache, _primary_iface_cache_ts
    now = time.monotonic()

    if _primary_iface_cache is not None and (now - _primary_iface_cache_ts) < _PRIMARY_IFACE_CACHE_TTL:
        return _primary_iface_cache

    primary = None
    try:
        with open("/proc/net/route") as fh:
            next(fh)  # skip header line
            for line in fh:
                parts = line.split()
                # Columns: Iface Dest Gateway Flags RefCnt Use Metric Mask ...
                if len(parts) >= 8 and parts[1] == "00000000" and parts[7] == "00000000":
                    primary = parts[0]
                    break
    except (OSError, StopIteration, IndexError):
        _log.debug("Could not detect default route interface")

    _primary_iface_cache = primary
    _primary_iface_cache_ts = now
    return primary


def _is_physical_or_wg(name: str) -> bool:
    """Check if interface is physical or WireGuard (not loopback/docker/veth)."""
    for prefix in _SKIP_PREFIXES:
        if name.startswith(prefix):
            return False
    return True


def _read_interface_stats(name: str) -> tuple[int, int] | None:
    """Read RX/TX bytes from /sys/class/net/<name>/statistics/."""
    stats_dir = Path(f"/sys/class/net/{name}/statistics")
    try:
        rx_bytes = int((stats_dir / "rx_bytes").read_text().strip())
        tx_bytes = int((stats_dir / "tx_bytes").read_text().strip())
        return rx_bytes, tx_bytes
    except (FileNotFoundError, ValueError, PermissionError):
        return None


def _is_wg_interface(name: str) -> bool:
    """Check if interface is a WireGuard interface.
    
    Primary check: Look for DEVTYPE=wireguard in uevent (kernel >= 5.6).
    Fallback: Check naming convention (wg*) and absence of physical device.
    """
    uevent_path = Path(f"/sys/class/net/{name}/uevent")
    try:
        content = uevent_path.read_text()
        if "DEVTYPE=wireguard" in content:
            return True
    except (FileNotFoundError, PermissionError):
        pass
    
    # Fallback for older kernels: wg* naming + no physical device
    # (WireGuard virtual interfaces lack /sys/class/net/<name>/device)
    if name.startswith("wg"):
        device_path = Path(f"/sys/class/net/{name}/device")
        return not device_path.exists()
    
    return False


def _get_all_interface_stats(wg_visibility: dict[str, bool] | None = None) -> dict[str, Any]:
    """Get statistics for all relevant interfaces.
    
    Thread-safe: Uses lock to protect shared _prev_stats dict.
    Caches results for _CACHE_TTL seconds to prevent hammering sysfs.
    
    Args:
        wg_visibility: Optional dict mapping WG interface names to their
            show_on_dashboard setting. If None, all WG interfaces are shown.
    """
    now = time.monotonic()
    
    # Note: We can't cache when wg_visibility filtering is applied
    # since visibility settings may change. Only cache raw stats.
    cache_valid = (now - _cache_ts < _CACHE_TTL) and wg_visibility is None
    if cache_valid:
        return _cache.copy()
    
    net_path = Path("/sys/class/net")
    if not net_path.is_dir():
        return {"interfaces": [], "error": "Network stats unavailable"}
    
    # Get primary interface for marking
    primary_iface = _get_primary_interface()
    
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    
    for iface_path in net_path.iterdir():
        name = iface_path.name
        
        # Skip virtual interfaces
        if not _is_physical_or_wg(name):
            continue
        
        # Read current stats
        stats = _read_interface_stats(name)
        if stats is None:
            continue
        
        seen.add(name)
        rx_bytes, tx_bytes = stats
        is_wg = _is_wg_interface(name)
        
        # Filter WG interfaces based on visibility setting
        if is_wg and wg_visibility is not None:
            if not wg_visibility.get(name, True):
                continue
        
        # For non-WG interfaces, only include the primary interface
        if not is_wg and primary_iface and name != primary_iface:
            continue
        
        # Calculate rates with thread-safe access to previous data
        rx_rate = 0.0
        tx_rate = 0.0
        
        with _prev_stats_lock:
            if name in _prev_stats:
                prev_ts, prev_rx, prev_tx = _prev_stats[name]
                elapsed = now - prev_ts
                
                if elapsed > 0.1:  # At least 100ms between samples
                    # Calculate deltas
                    rx_delta = rx_bytes - prev_rx
                    tx_delta = tx_bytes - prev_tx
                    
                    # Handle 32-bit counter wraps (rare on modern kernels but possible)
                    # 64-bit counters effectively never wrap (584 years at 1 Gbps)
                    if rx_delta < 0:
                        rx_delta += 2**32
                    if tx_delta < 0:
                        tx_delta += 2**32
                    
                    rx_rate = rx_delta / elapsed  # bytes/sec
                    tx_rate = tx_delta / elapsed  # bytes/sec
            
            # Store current reading for next calculation
            _prev_stats[name] = (now, rx_bytes, tx_bytes)
        
        iface_data = {
            "name": name,
            "is_wg": is_wg,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "rx_rate": round(rx_rate, 1),  # bytes/sec
            "tx_rate": round(tx_rate, 1),  # bytes/sec
        }
        
        # Mark primary host interface
        if not is_wg and name == primary_iface:
            iface_data["is_primary"] = True
        
        results.append(iface_data)
    
    # Prune stale entries (interfaces that disappeared)
    with _prev_stats_lock:
        stale = set(_prev_stats.keys()) - seen
        for key in stale:
            del _prev_stats[key]
            _log.debug("Pruned stale interface from stats cache: %s", key)
    
    # Sort: WireGuard interfaces first, then by name
    results.sort(key=lambda x: (not x["is_wg"], x["name"]))
    
    # Update cache
    result = {"interfaces": results}
    _cache.clear()
    _cache.update(result)
    # Note: We use assignment not rebinding, so no global declaration needed
    
    return result


@router.get("/network/stats")
async def get_network_stats(
    user: Any = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_conn),
):
    """Get real-time network interface statistics.
    
    Returns RX/TX byte counters and calculated rates (bytes/sec) for:
    - Primary host interface (the default route interface)
    - WireGuard interfaces (filtered by show_on_dashboard setting)
    
    Call this endpoint repeatedly (~1-2s intervals) to get accurate rate data.
    The first call returns rates of 0 as no previous sample exists.
    
    Results are cached for 500ms to prevent excessive sysfs reads under load.
    """
    # Fetch WG interface visibility settings from database
    def get_wg_visibility() -> dict[str, bool]:
        interfaces = list_interfaces(conn)
        return {
            iface["name"]: bool(iface["show_on_dashboard"] if "show_on_dashboard" in iface.keys() else 1)
            for iface in interfaces
        }
    
    wg_visibility = await run_in_threadpool(get_wg_visibility)
    data = await run_in_threadpool(_get_all_interface_stats, wg_visibility)
    return ok_response(data=data)


def sample_network_stats(tsdb_dir: Path) -> int:
    """Sample current network stats and persist to TSDB.
    
    Called by scheduled task every 30 seconds. Stores combined rate
    (rx_rate + tx_rate) per interface as metric: `iface_{name}`.
    
    Returns:
        Number of points written.
    """
    from ..db import tsdb
    
    # Get raw stats without visibility filter for persistence
    data = _get_all_interface_stats(wg_visibility=None)
    interfaces = data.get("interfaces", [])
    
    points = 0
    for iface in interfaces:
        name = iface["name"]
        rx_rate = iface.get("rx_rate", 0)
        tx_rate = iface.get("tx_rate", 0)
        total_rate = rx_rate + tx_rate
        
        # Only store if there's actual traffic (avoid storing mostly zeros)
        # Store both individual rates and total for flexibility
        metric_name = f"iface_{name}"
        tsdb.append_point(
            tsdb_dir,
            peer_key=NETWORK_STATS_KEY,
            metric=metric_name,
            value={
                "rx": round(rx_rate, 1),
                "tx": round(tx_rate, 1),
                "total": round(total_rate, 1),
            },
            retention_days=NETWORK_STATS_RETENTION_DAYS,
        )
        points += 1
    
    return points


@router.get("/network/stats/history")
async def get_network_stats_history(
    request: Request,
    interface: str = Query(..., description="Interface name (e.g., wg0, eth0)"),
    range: str = Query("1h", description="Time range: 1h, 6h, 24h, 7d"),
    user: Any = Depends(get_current_user),
):
    """Get historical network stats for sparkline display.
    
    Returns time-series data points for the specified interface within
    the given time range. Data is sampled every 30 seconds.
    
    Response format:
    ```json
    {
        "data": {
            "interface": "wg0",
            "range": "1h",
            "points": [
                {"ts": "2026-03-18T10:00:00Z", "rx": 1234.5, "tx": 567.8, "total": 1802.3},
                ...
            ]
        }
    }
    ```
    """
    from ..db import tsdb
    
    cfg = get_config(request)
    
    # Validate range
    hours = NETWORK_RANGE_TO_HOURS.get(range, 1)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    
    # Query TSDB
    metric_name = f"iface_{interface}"
    
    def query_history():
        try:
            points = tsdb.query(
                cfg.tsdb_dir,
                peer_key=NETWORK_STATS_KEY,
                metric=metric_name,
                since=since,
                limit=7200,  # 1h @ 30s = 120, 7d @ 30s = 20160 - cap at reasonable limit
            )
            return [
                {
                    "ts": pt.ts.isoformat(),
                    "rx": pt.value.get("rx", 0) if isinstance(pt.value, dict) else 0,
                    "tx": pt.value.get("tx", 0) if isinstance(pt.value, dict) else 0,
                    "total": pt.value.get("total", 0) if isinstance(pt.value, dict) else pt.value,
                }
                for pt in points
            ]
        except Exception as e:
            _log.warning("Failed to query network stats history: %s", e)
            return []
    
    points = await run_in_threadpool(query_history)
    
    return ok_response(data={
        "interface": interface,
        "range": range,
        "points": points,
    })
