#!/usr/bin/env python3
#
# app/api/wireguard_stats.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard traffic and connection statistics API routes.

SECURITY NOTE: These endpoints require admin privileges as they expose
traffic metadata (volumes, connection times, patterns) for all peers.
"""

from __future__ import annotations

import logging
import sqlite3
import time as _time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from starlette.concurrency import run_in_threadpool

from ..db import tsdb
from ..db.sqlite_nodes import get_all_tunnel_peer_ids
from ..db.sqlite_peers import get_all_peers
from ..db.sqlite_settings import get_tsdb_retention_days
from ..utils.deps import get_conn, get_tsdb_dir
from ..utils.time import utcnow
from .auth import require_admin
from .frontend_shared import CONNECTED_THRESHOLD_S as HANDSHAKE_THRESHOLD
from .response import ok_response
from .wireguard_utils import bytes_to_unit, parse_wg_show_dump, run_wg_command, select_display_unit

_log = logging.getLogger(__name__)

router = APIRouter(tags=["wireguard"])

__all__ = ["router"]

WG_BIN = "wg"

# Time range presets for traffic queries
TRAFFIC_RANGE_TO_HOURS = {
    "6h": 6,
    "24h": 24,
    "7d": 168,
    "30d": 720,
    "90d": 2160,
    "180d": 4320,
    "y1": 8760,
}

# Reverse mapping: hours -> preset key (used for response labels)
_HOURS_TO_RANGE: dict[int, str] = {v: k for k, v in TRAFFIC_RANGE_TO_HOURS.items()}

# Resource limits to prevent DoS
MAX_PEERS_TRAFFIC = 100  # Max peers to include in traffic stats
MAX_POINTS_PER_PEER = 5000  # Cap per-peer TSDB points to bound memory and query time.


def _bucket_counter_delta(
    points: list[tsdb.MetricPoint],
    since: datetime,
    bucket_seconds: int,
) -> dict[str, float]:
    """Aggregate counter deltas into time buckets (consumption per bucket).

    Points are sorted defensively (TSDB contract guarantees chronological
    order, but we guard against future regressions). If consecutive points
    have a time gap wider than ``2 * bucket_seconds``, we reset the baseline.
    The delta spanning that gap is discarded to avoid unreliable spikes.

    Args:
        points: Time-series data points (expected to be counter values).
        since: Only include deltas from points after this time.
        bucket_seconds: Bucket size in seconds.

    Returns:
        Dict mapping ISO timestamp labels to summed byte deltas.
    """
    if __debug__:
        assert all(
            points[i].ts <= points[i + 1].ts for i in range(len(points) - 1)
        ), "TSDB returned points out of chronological order"

    buckets: dict[str, float] = {}
    prev: float | None = None
    prev_ts: datetime | None = None
    gap_limit = bucket_seconds * 2

    for pt in points:
        if not isinstance(pt.value, (int, float)):
            continue
        value = pt.value

        if prev is None:
            prev = value
            prev_ts = pt.ts
            continue

        # Guard: if the gap between consecutive points is too large the
        # delta would attribute an unreliable amount of traffic to one
        # bucket.  Reset the baseline instead.
        gap = (pt.ts - prev_ts).total_seconds() if prev_ts else 0
        if gap > gap_limit:
            prev = value
            prev_ts = pt.ts
            continue

        delta = value - prev
        prev = value
        prev_ts = pt.ts

        # Counter reset (e.g., WireGuard restart): discard this delta.
        # The next sample will establish a new baseline from the reset value.
        if delta < 0:
            continue

        if pt.ts < since:
            continue

        ts_epoch = pt.ts.timestamp()
        bucket_ts = int(ts_epoch // bucket_seconds) * bucket_seconds
        label = datetime.fromtimestamp(bucket_ts, UTC).isoformat()
        buckets[label] = buckets.get(label, 0) + delta

    return dict(sorted(buckets.items()))


def _downsample_buckets(
    labels: list[str],
    peer_data: list[dict],
    target_points: int,
) -> tuple[list[str], list[dict]]:
    """Downsample pre-bucketed data to at most *target_points* via summation.

    Adjacent label groups are merged.  Each group's traffic value is the
    **sum** of the raw values in that group so that total traffic volume is
    preserved.  This avoids the problem where median aggregation combined
    with zero-filled gaps would silently drop sparse peer traffic.

    Args:
        labels: Sorted ISO-timestamp labels.
        peer_data: List of per-peer dicts with 'rx' and 'tx' bucket dicts.
        target_points: Maximum number of output labels.

    Returns:
        (new_labels, new_peer_data) with len(new_labels) <= target_points.
    """
    n = len(labels)
    if n <= target_points or target_points <= 0:
        return labels, peer_data

    # Distribute labels evenly into *target_points* groups
    group_size = n / target_points  # float for even distribution
    groups: list[list[str]] = []
    for i in range(target_points):
        start = int(round(i * group_size))
        end = int(round((i + 1) * group_size))
        groups.append(labels[start:end])

    new_labels: list[str] = []
    new_peer_data: list[dict] = [{**entry, "rx": {}, "tx": {}} for entry in peer_data]

    for group in groups:
        if not group:
            continue
        # Use the midpoint label as representative timestamp
        representative = group[len(group) // 2]
        new_labels.append(representative)

        for idx, entry in enumerate(peer_data):
            # Sum preserves total traffic volume in the merged window
            rx_total = sum(entry["rx"].get(lbl, 0) for lbl in group)
            tx_total = sum(entry["tx"].get(lbl, 0) for lbl in group)

            new_peer_data[idx]["rx"][representative] = rx_total
            new_peer_data[idx]["tx"][representative] = tx_total

    return new_labels, new_peer_data


def _empty_traffic_response(hours: int, range_key: str | None, bucket_seconds: int = 3600) -> dict:
    """Build a zero-data traffic response (logging disabled or no peers)."""
    return {
        "retention_days": 0,
        "logging_disabled": True,
        "range": range_key or "24h",
        "hours": hours,
        "labels": [],
        "peers": [],
        "all_peers": [],
        "display_unit": "B",
        "bucket_seconds": bucket_seconds,
    }


# Default target data points for different display sizes
DEFAULT_MAX_POINTS = 60  # Desktop
MIN_MAX_POINTS = 10  # Minimum allowed (small mobile screens)
MAX_MAX_POINTS = 200  # Maximum allowed (prevents DoS)


def _query_peer_metrics(
    key: str,
    tsdb_dir: Path,
    query_since: datetime,
    since: datetime,
    bucket_seconds: int,
) -> tuple[str, dict[str, float], dict[str, float]]:
    """Query RX and TX metrics for one peer and bucket them."""
    rx_points = tsdb.query(
        tsdb_dir,
        peer_key=key,
        metric="rx_bytes",
        since=query_since,
        limit=MAX_POINTS_PER_PEER,
    )
    rx_buckets = _bucket_counter_delta(rx_points, since, bucket_seconds)

    tx_points = tsdb.query(
        tsdb_dir,
        peer_key=key,
        metric="tx_bytes",
        since=query_since,
        limit=MAX_POINTS_PER_PEER,
    )
    tx_buckets = _bucket_counter_delta(tx_points, since, bucket_seconds)
    return key, rx_buckets, tx_buckets


def _compute_traffic_stats(
    conn: sqlite3.Connection,
    tsdb_dir: Path,
    hours: int,
    max_points: int = DEFAULT_MAX_POINTS,
) -> dict:
    """Compute traffic statistics (blocking operation for threadpool).

    Args:
        conn: Database connection (check_same_thread=False, safe for threadpool).
        tsdb_dir: TSDB directory path.
        hours: Number of hours of history to include (pre-validated 1-8760).
        max_points: Target number of data points (buckets) to return.

    Returns:
        Dict with traffic data ready for JSON response.
    """
    since = utcnow() - timedelta(hours=hours)
    resolved_range = _HOURS_TO_RANGE.get(hours, f"{hours}h")

    # Determine bucket size based on max_points (responsive design support)
    target_points = max(MIN_MAX_POINTS, min(max_points, MAX_MAX_POINTS))
    bucket_seconds = max((hours * 3600) // target_points, 60)

    # Pre-query window: fetch one extra bucket before `since` so that
    # _bucket_counter_delta has a baseline for the first visible delta.
    # Using bucket_seconds (instead of a fixed 1 hour) ensures the
    # window scales properly for all range sizes.
    query_since = since - timedelta(seconds=bucket_seconds)

    # Fetch all peers (blocking DB query)
    all_peers = list(get_all_peers(conn))
    tunnel_peer_ids = get_all_tunnel_peer_ids(conn)
    
    # Filter out node tunnel peers (inter-node connections)
    all_peers = [p for p in all_peers if p["id"] not in tunnel_peer_ids]
    
    # Sort by recent activity before truncating (most active peers first)
    # sqlite3.Row doesn't have .get(), so access column directly with fallback
    all_peers.sort(key=lambda p: p["last_handshake_at"] or 0, reverse=True)
    peer_keys = [peer["public_key"] for peer in all_peers if peer["public_key"]]

    # Early exit if no peers exist
    if not peer_keys:
        return {
            "range": resolved_range,
            "hours": hours,
            "labels": [],
            "peers": [],
            "all_peers": [],
            "display_unit": "B",
            "bucket_seconds": bucket_seconds,
            "actual_points": 0,
            "requested_points": target_points,
        }

    # Apply peer limit to prevent DoS
    if len(peer_keys) > MAX_PEERS_TRAFFIC:
        _log.warning(
            "TRAFFIC_STATS peer count (%d) exceeds limit (%d), showing most active peers",
            len(peer_keys),
            MAX_PEERS_TRAFFIC,
        )
        peer_keys = peer_keys[:MAX_PEERS_TRAFFIC]

    # Build name map only for the (possibly truncated) peer set
    active_keys = set(peer_keys)
    peer_name_map: dict[str, str] = {
        peer["public_key"]: (peer["name"] or peer["public_key"][:8])
        for peer in all_peers
        if peer["public_key"] and peer["public_key"] in active_keys
    }

    # Parallelize per-peer TSDB I/O with a bounded thread pool.
    # This function already runs inside run_in_threadpool(), so spawning
    # additional threads here is safe and avoids the N+1 sequential query
    # pattern (2 queries × up to 100 peers = up to 200 sequential reads).
    with ThreadPoolExecutor(max_workers=min(8, len(peer_keys))) as executor:
        results = list(executor.map(
            lambda k: _query_peer_metrics(k, tsdb_dir, query_since, since, bucket_seconds),
            peer_keys,
        ))
    
    # Process results
    peer_data: list[dict] = []
    all_labels: set[str] = set()
    
    for key, rx_buckets, tx_buckets in results:
        # Only include peers with actual data
        if rx_buckets or tx_buckets:
            peer_name = peer_name_map.get(key, key[:8])
            peer_data.append({
                "key": key,  # Full public key
                "key_short": key[:8],  # Truncated for display
                "name": peer_name,
                "rx": rx_buckets,
                "tx": tx_buckets,
            })
            all_labels.update(rx_buckets.keys())
            all_labels.update(tx_buckets.keys())

    labels = sorted(all_labels)

    # Downsample via summation if we still have more labels than max_points
    # (can happen when peers have data at slightly offset timestamps)
    if len(labels) > target_points:
        labels, peer_data = _downsample_buckets(labels, peer_data, target_points)

    # Build datasets for each peer (display-ready values only)
    max_bytes = 0.0
    for entry in peer_data:
        max_bytes = max(
            max_bytes,
            max(entry["rx"].values(), default=0),
            max(entry["tx"].values(), default=0),
        )

    display_unit = select_display_unit(max_bytes)

    peers_display = [
        {
            "key": entry["key"],
            "key_short": entry["key_short"],
            "name": entry["name"],
            "rx": [round(bytes_to_unit(entry["rx"].get(label, 0), display_unit), 4) for label in labels],
            "tx": [round(bytes_to_unit(entry["tx"].get(label, 0), display_unit), 4) for label in labels],
        }
        for entry in peer_data
    ]

    # Build list of ALL peers for filter dropdown (even those without traffic data)
    all_peers_for_filter = [
        {
            "key": key,
            "name": peer_name_map.get(key, key[:8]),
        }
        for key in peer_keys
    ]

    return {
        "range": resolved_range,
        "hours": hours,
        "labels": labels,
        "peers": peers_display,
        "all_peers": all_peers_for_filter,  # All peers for filter dropdown
        "display_unit": display_unit,
        "bucket_seconds": bucket_seconds,
        "actual_points": len(labels),
        "requested_points": target_points,
    }


@router.get("/stats/traffic")
async def get_traffic_stats(
    hours: int = Query(24, ge=1, le=8760, description="Number of hours of history (1-8760)"),
    range_key: str | None = Query(None, pattern="^(6h|24h|7d|30d|90d|180d|y1)$"),
    max_points: int = Query(DEFAULT_MAX_POINTS, ge=MIN_MAX_POINTS, le=MAX_MAX_POINTS, description="Target number of data points (10-200)"),
    conn: sqlite3.Connection = Depends(get_conn),
    tsdb_dir: Path = Depends(get_tsdb_dir),
    _: sqlite3.Row = Depends(require_admin),
):
    """Get per-peer RX/TX traffic over time (admin only).

    Returns bucketed data suitable for charting, with each peer as a separate dataset.

    Args:
        hours: Number of hours of history (1-8760, validated at API boundary).
        range_key: Preset time range (6h, 24h, 7d, 30d, 90d, 180d, y1). Overrides hours if provided.
        max_points: Target number of data points/buckets (20-200). Lower values for mobile displays.

    Returns:
        Traffic statistics with display-ready values and unit metadata.
    """
    # Range key overrides hours parameter (regex already ensures valid values)
    if range_key:
        hours = TRAFFIC_RANGE_TO_HOURS[range_key]

    # Check if logging is disabled (retention_days = 0)
    retention_days = await run_in_threadpool(get_tsdb_retention_days, conn)
    if retention_days == 0:
        return ok_response(data=_empty_traffic_response(hours, range_key))

    # Offload blocking I/O to threadpool (conn uses check_same_thread=False)
    t0 = _time.monotonic()
    data = await run_in_threadpool(_compute_traffic_stats, conn, tsdb_dir, hours, max_points)
    elapsed = _time.monotonic() - t0
    if elapsed > 5.0:
        _log.warning(
            "TRAFFIC_STATS took %.1fs for %d peers",
            elapsed, len(data.get("peers", [])),
        )

    data["retention_days"] = retention_days
    data["logging_disabled"] = False

    # Signal to the client when the query window exceeds data retention
    if retention_days and hours > retention_days * 24:
        data["effective_hours"] = retention_days * 24
        data["truncated"] = True
    else:
        data["effective_hours"] = hours
        data["truncated"] = False

    return ok_response(data=data)


@router.get("/stats/connections")
async def get_connection_stats(
    _: sqlite3.Row = Depends(require_admin),
):
    """Get current connected peers per interface (admin only).

    A peer is considered "connected" if its latest handshake was within the last 3 minutes.

    Returns:
        Connection statistics including per-interface and total counts.
    """
    try:
        code, stdout, stderr = await run_wg_command(WG_BIN, "show", "all", "dump")
        if code != 0:
            _log.warning("WG_SHOW_DUMP failed: code=%d stderr=%s", code, stderr)
            raise HTTPException(status_code=500, detail="Failed to query WireGuard interfaces")

        now = _time.time()
        interfaces: dict[str, dict] = {}

        # Use shared parser for consistency with other endpoints
        peers = await run_in_threadpool(parse_wg_show_dump, stdout)
        
        for peer in peers:
            if not peer.interface:
                continue
                
            connected = (now - peer.handshake_ts) < HANDSHAKE_THRESHOLD if peer.handshake_ts else False
            
            if peer.interface not in interfaces:
                interfaces[peer.interface] = {"connected": 0, "total": 0, "rx": 0, "tx": 0}
            
            interfaces[peer.interface]["total"] += 1
            interfaces[peer.interface]["rx"] += peer.rx
            interfaces[peer.interface]["tx"] += peer.tx
            if connected:
                interfaces[peer.interface]["connected"] += 1

        total_connected = sum(v["connected"] for v in interfaces.values())
        total_peers = sum(v["total"] for v in interfaces.values())
        max_bytes = max((max(v["rx"], v["tx"]) for v in interfaces.values()), default=0)
        display_unit = select_display_unit(max_bytes)
        for iface_data in interfaces.values():
            iface_data["rx"] = round(bytes_to_unit(iface_data["rx"], display_unit), 2)
            iface_data["tx"] = round(bytes_to_unit(iface_data["tx"], display_unit), 2)

        data = {
            "interfaces": interfaces,
            "total_connected": total_connected,
            "total_peers": total_peers,
            "display_unit": display_unit,
        }
        return ok_response(data=data)

    except HTTPException:
        raise  # Re-raise HTTP errors
    except Exception as exc:
        # Log the full exception for debugging, but don't expose internals to client
        _log.exception("Failed to parse WireGuard connection stats")
        raise HTTPException(status_code=500, detail="Failed to retrieve connection statistics") from exc
