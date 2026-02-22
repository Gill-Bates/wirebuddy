#!/usr/bin/env python3
#
# app/api/wireguard_stats.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard traffic and connection statistics API routes.

SECURITY NOTE: These endpoints require admin privileges as they expose
traffic metadata (volumes, connection times, patterns) for all peers.
"""

from __future__ import annotations

from ..db.sqlite_peers import (
	get_all_peers,
)

import logging
import sqlite3
import time as _time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from starlette.concurrency import run_in_threadpool

from ..db import tsdb
from ..utils.deps import get_conn, get_tsdb_dir
from ..utils.time import utcnow
from .auth import require_admin
from .response import ok_response
from .wireguard_utils import bytes_to_unit, parse_wg_show_dump, run_wg_command, safe_int, select_display_unit

_log = logging.getLogger(__name__)

router = APIRouter(tags=["wireguard"])

__all__ = ["router"]

# Time range presets for traffic queries
TRAFFIC_RANGE_TO_HOURS = {
    "6h": 6,
    "24h": 24,
    "3d": 72,
    "7d": 168,
}

# Reverse mapping for O(1) lookup
_HOURS_TO_RANGE = {v: k for k, v in TRAFFIC_RANGE_TO_HOURS.items()}

# Resource limits to prevent DoS
MAX_PEERS_TRAFFIC = 100  # Max peers to include in traffic stats
MAX_POINTS_PER_PEER = 5000  # Reduced from 10000

# Handshake freshness threshold (seconds) — peers with handshake < 3 min are "connected"
# NOTE: Uses system clock (time.time()). Clock jumps (NTP adjustments) may cause
# temporary inaccuracy in connection status reporting.
HANDSHAKE_THRESHOLD = 180


def _bucket_counter_delta(
    points: list[tsdb.MetricPoint],
    since: datetime,
    bucket_seconds: int,
) -> dict[str, float]:
    """Aggregate counter deltas into time buckets (consumption per bucket).

    Args:
        points: Time-series data points (expected to be counter values).
        since: Only include deltas from points after this time.
        bucket_seconds: Bucket size in seconds.

    Returns:
        Dict mapping ISO timestamp labels to summed byte deltas.
    """
    buckets: dict[str, float] = {}
    prev: float | None = None

    for pt in points:
        if not isinstance(pt.value, (int, float)):
            continue
        value = float(pt.value)

        if prev is None:
            prev = value
            continue

        delta = value - prev
        prev = value

        # Counter reset (e.g., WireGuard restart): discard this delta.
        # The next sample will establish a new baseline from the reset value.
        if delta < 0:
            continue

        if pt.ts < since:
            continue

        ts_epoch = pt.ts.timestamp()
        bucket_ts = int(ts_epoch // bucket_seconds) * bucket_seconds
        label = datetime.fromtimestamp(bucket_ts, timezone.utc).isoformat()
        buckets[label] = buckets.get(label, 0) + delta

    return dict(sorted(buckets.items()))


def _compute_traffic_stats(
    conn: sqlite3.Connection,
    tsdb_dir: Path,
    hours: int,
) -> dict:
    """Compute traffic statistics (blocking operation for threadpool).

    Args:
        conn: Database connection (check_same_thread=False, safe for threadpool).
        tsdb_dir: TSDB directory path.
        hours: Number of hours of history to include (pre-validated 1-168).

    Returns:
        Dict with traffic data ready for JSON response.
    """
    since = utcnow() - timedelta(hours=hours)
    query_since = since - timedelta(hours=1)
    resolved_range = _HOURS_TO_RANGE.get(hours, f"{hours}h")

    # Determine bucket size (aim for ~60 data points)
    bucket_seconds = max((hours * 3600) // 60, 60)

    # Fetch all peers (blocking DB query)
    all_peers = list(get_all_peers(conn))
    
    # Sort by recent activity before truncating (most active peers first)
    # sqlite3.Row doesn't have .get(), so access column directly with fallback
    all_peers.sort(key=lambda p: p["last_handshake_at"] or 0, reverse=True)
    peer_keys = [peer["public_key"] for peer in all_peers if peer["public_key"]]

    # Apply peer limit to prevent DoS
    if len(peer_keys) > MAX_PEERS_TRAFFIC:
        _log.warning(
            "TRAFFIC_STATS peer count (%d) exceeds limit (%d), showing most active peers",
            len(peer_keys),
            MAX_PEERS_TRAFFIC,
        )
        peer_keys = peer_keys[:MAX_PEERS_TRAFFIC]

    peer_name_map: dict[str, str] = {
        peer["public_key"]: (peer["name"] or peer["public_key"][:8])
        for peer in all_peers
        if peer["public_key"]
    }

    # Collect per-peer traffic data (blocking file I/O)
    peer_data: list[dict] = []
    all_labels: set[str] = set()

    for key in peer_keys:
        # Blocking TSDB reads
        rx_points = tsdb.query(
            tsdb_dir,
            peer_key=key,
            metric="rx_bytes",
            since=query_since,
            limit=MAX_POINTS_PER_PEER,
        )
        rx_buckets = _bucket_counter_delta(rx_points, since, bucket_seconds)
        del rx_points  # Free memory before loading tx data
        
        tx_points = tsdb.query(
            tsdb_dir,
            peer_key=key,
            metric="tx_bytes",
            since=query_since,
            limit=MAX_POINTS_PER_PEER,
        )
        tx_buckets = _bucket_counter_delta(tx_points, since, bucket_seconds)
        del tx_points  # Free memory before next peer

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
            "rx": [round(bytes_to_unit(float(entry["rx"].get(label, 0)), display_unit), 4) for label in labels],
            "tx": [round(bytes_to_unit(float(entry["tx"].get(label, 0)), display_unit), 4) for label in labels],
        }
        for entry in peer_data
    ]

    return {
        "range": resolved_range,
        "hours": hours,
        "labels": labels,
        "peers": peers_display,
        "display_unit": display_unit,
        "bucket_seconds": bucket_seconds,
    }


@router.get("/stats/traffic")
async def get_traffic_stats(
    hours: int = Query(24, ge=1, le=168, description="Number of hours of history (1-168)"),
    range_key: str | None = Query(None, pattern="^(6h|24h|3d|7d)$"),
    conn: sqlite3.Connection = Depends(get_conn),
    tsdb_dir: Path = Depends(get_tsdb_dir),
    _: sqlite3.Row = Depends(require_admin),
):
    """Get per-peer RX/TX traffic over time (admin only).

    Returns bucketed data suitable for charting, with each peer as a separate dataset.

    Args:
        hours: Number of hours of history (1-168, validated at API boundary).
        range_key: Preset time range (6h, 24h, 3d, 7d). Overrides hours if provided.

    Returns:
        Traffic statistics with display-ready values and unit metadata.
    """
    # Range key overrides hours parameter (regex already ensures valid values)
    if range_key:
        hours = TRAFFIC_RANGE_TO_HOURS[range_key]

    # Offload blocking I/O to threadpool (conn uses check_same_thread=False)
    data = await run_in_threadpool(_compute_traffic_stats, conn, tsdb_dir, hours)

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
        code, stdout, stderr = await run_wg_command("wg", "show", "all", "dump")
        if code != 0:
            _log.warning("WG_SHOW_DUMP failed: code=%d stderr=%s", code, stderr)
            raise HTTPException(status_code=500, detail="Failed to query WireGuard interfaces")

        now = _time.time()
        interfaces: dict[str, dict] = {}

        # Use shared parser for consistency with other endpoints
        peers = parse_wg_show_dump(stdout)
        
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

        data = {
            "interfaces": interfaces,
            "total_connected": total_connected,
            "total_peers": total_peers,
        }
        return ok_response(data=data)

    except HTTPException:
        raise  # Re-raise HTTP errors
    except Exception as exc:
        # Log the full exception for debugging, but don't expose internals to client
        _log.exception("Failed to parse WireGuard connection stats")
        raise HTTPException(status_code=500, detail="Failed to retrieve connection statistics") from exc
