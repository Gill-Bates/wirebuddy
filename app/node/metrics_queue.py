#!/usr/bin/env python3
#
# app/node/metrics_queue.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Local SQLite queue for reliable metric delivery to master.

Architecture
------------
This module implements an embedded message queue for the Node daemon that
provides **at-least-once delivery** guarantees with **idempotency** through
sequence numbers. It acts as a buffer between local metric collection and
remote master synchronization.

    ┌─────────────────────────────────────────────────────────────────┐
    │                         NODE DAEMON                             │
    │  ┌──────────┐     ┌──────────────────┐     ┌────────────────┐  │
    │  │ WG Sample│────►│ metrics_queue.db │────►│ Heartbeat POST │──┼──► Master
    │  │  (30s)   │     │  (SQLite WAL)    │     │ + batch + seq  │  │
    │  └──────────┘     └──────────────────┘     └────────────────┘  │
    │                           ▲                        │           │
    │                           └────────────────────────┘           │
    │                             DELETE on ACK                      │
    └─────────────────────────────────────────────────────────────────┘

Delivery Guarantees
-------------------
- **At-least-once**: Metrics remain in queue until master acknowledges receipt
- **Idempotency**: Master tracks `last_metric_seq` per node, skips duplicates
- **Crash-safe**: SQLite WAL mode ensures durability across restarts
- **Offline-tolerant**: Queue grows up to MAX_QUEUE_SIZE during disconnection

Thread Safety
-------------
All public functions are thread-safe via a module-level lock. The SQLite
connection is created with `check_same_thread=False` but all operations
are serialized to prevent race conditions.

Schema
------
::

    metrics_queue(
        seq          INTEGER PRIMARY KEY AUTOINCREMENT,  -- Sequence number
        ts           TEXT NOT NULL,                      -- ISO 8601 UTC timestamp
        metric_type  TEXT NOT NULL,                      -- 'peer_traffic' | 'peer_handshake'
        data         TEXT NOT NULL                       -- JSON payload
    )

    sync_state(
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )

Performance Notes
-----------------
- Queue size estimation uses O(1) seq difference instead of COUNT(*)
- DELETE operations use direct seq comparison (indexed via PRIMARY KEY)
- WAL mode with synchronous=NORMAL balances durability and speed
- Batch size limited to 500 metrics per heartbeat

Usage Example
-------------
::

    from app.node.metrics_queue import (
        init_queue, close_queue, enqueue_peer_traffic,
        get_pending_batch, ack_up_to_seq, serialize_batch_for_api
    )

    # Initialize
    conn = init_queue(Path("/app/data"))

    # Enqueue metrics from WG dump
    peer_stats = [{"public_key": "abc...", "transfer_rx": 1000, "transfer_tx": 500}]
    enqueue_peer_traffic(conn, peer_stats)

    # Send to master
    batch = get_pending_batch(conn)
    payload = serialize_batch_for_api(batch)
    response = send_heartbeat(payload)

    # ACK received metrics
    if response.acked_seq:
        ack_up_to_seq(conn, response.acked_seq)

    # Cleanup
    close_queue(conn)
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_QUEUE_SIZE = 10000  # Max pending metrics before oldest are dropped
MAX_BATCH_SIZE = 500    # Max metrics per heartbeat
QUEUE_DB_NAME = "metrics_queue.db"

# Metric types
METRIC_PEER_TRAFFIC = "peer_traffic"
METRIC_PEER_HANDSHAKE = "peer_handshake"

# Thread safety: all public functions acquire this lock
_lock = threading.Lock()


@dataclass(frozen=True)
class QueuedMetric:
    """A metric waiting to be sent to master."""
    seq: int
    ts: str
    metric_type: str
    data: dict[str, Any]


def _get_queue_path(data_dir: Path) -> Path:
    """Return the path to the metrics queue database."""
    return data_dir / QUEUE_DB_NAME


def _init_schema(conn: sqlite3.Connection) -> None:
    """Initialize the queue schema if not exists."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS metrics_queue (
            seq          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT NOT NULL,
            metric_type  TEXT NOT NULL,
            data         TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_metrics_queue_ts
            ON metrics_queue(ts);

        CREATE TABLE IF NOT EXISTS sync_state (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)


def init_queue(data_dir: Path) -> sqlite3.Connection:
    """Initialize and return a connection to the metrics queue.

    Creates the database and schema if they don't exist.
    Uses WAL mode for better concurrency.

    Args:
        data_dir: Directory to store the queue database

    Returns:
        SQLite connection (thread-safe via module lock)
    """
    with _lock:
        db_path = _get_queue_path(data_dir)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")  # Faster, still durable with WAL

        _init_schema(conn)
        _log.debug("Metrics queue initialized: %s", db_path)
        return conn


def close_queue(conn: sqlite3.Connection) -> None:
    """Close the queue connection cleanly.

    Performs a WAL checkpoint before closing to ensure all data is flushed.
    """
    with _lock:
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.close()
        except Exception as exc:
            _log.warning("Error closing metrics queue: %s", exc)


def _get_queue_size_estimate(conn: sqlite3.Connection) -> int:
    """Estimate queue size using sequence number difference (O(1)).

    More efficient than COUNT(*) for large queues. May slightly overestimate
    if sequences were deleted, but accurate enough for limit enforcement.
    """
    row = conn.execute("""
        SELECT
            (SELECT seq FROM metrics_queue ORDER BY seq DESC LIMIT 1) as max_seq,
            (SELECT seq FROM metrics_queue ORDER BY seq ASC LIMIT 1) as min_seq
    """).fetchone()

    if row["max_seq"] is None or row["min_seq"] is None:
        return 0
    return row["max_seq"] - row["min_seq"] + 1


def _enforce_queue_limit(conn: sqlite3.Connection) -> None:
    """Drop oldest metrics if queue exceeds size limit.

    Uses O(1) size estimation and efficient DELETE query.
    """
    size = _get_queue_size_estimate(conn)
    if size < MAX_QUEUE_SIZE:
        return

    # Calculate cutoff sequence
    drop_count = size - MAX_QUEUE_SIZE + MAX_BATCH_SIZE  # Make room for a batch
    row = conn.execute(
        "SELECT seq FROM metrics_queue ORDER BY seq ASC LIMIT 1 OFFSET ?",
        (drop_count,)
    ).fetchone()

    if row:
        cutoff_seq = row["seq"]
        conn.execute("DELETE FROM metrics_queue WHERE seq < ?", (cutoff_seq,))
        conn.commit()
        _log.warning("Queue overflow: dropped metrics with seq < %d (~%d items)", cutoff_seq, drop_count)


def enqueue_peer_traffic(
    conn: sqlite3.Connection,
    peer_stats: list[dict[str, Any]],
) -> int:
    """Enqueue peer traffic metrics for later sync.

    Thread-safe. Metrics are persisted locally and only deleted after
    master ACK, ensuring at-least-once delivery.

    Args:
        conn: Queue database connection
        peer_stats: List of peer stat dicts with keys:
            - public_key (str, required)
            - transfer_rx (int, bytes received)
            - transfer_tx (int, bytes transmitted)
            - latest_handshake (int, unix timestamp, optional)
            - endpoint (str, IP:port, optional)

    Returns:
        Number of metrics enqueued
    """
    if not peer_stats:
        return 0

    with _lock:
        ts = datetime.now(timezone.utc).isoformat()
        enqueued = 0

        # Enforce queue size limit (before adding new metrics)
        _enforce_queue_limit(conn)

        cursor = conn.cursor()
        try:
            for ps in peer_stats:
                public_key = ps.get("public_key")
                if not public_key:
                    continue

                # Traffic metrics
                rx = ps.get("transfer_rx", 0)
                tx = ps.get("transfer_tx", 0)
                if rx > 0 or tx > 0:
                    cursor.execute(
                        "INSERT INTO metrics_queue (ts, metric_type, data) VALUES (?, ?, ?)",
                        (ts, METRIC_PEER_TRAFFIC, json.dumps({
                            "public_key": public_key,
                            "rx_bytes": rx,
                            "tx_bytes": tx,
                        }))
                    )
                    enqueued += 1

                # Handshake metrics (for connection state)
                latest_handshake = ps.get("latest_handshake")
                if latest_handshake and latest_handshake > 0:
                    cursor.execute(
                        "INSERT INTO metrics_queue (ts, metric_type, data) VALUES (?, ?, ?)",
                        (ts, METRIC_PEER_HANDSHAKE, json.dumps({
                            "public_key": public_key,
                            "latest_handshake": latest_handshake,
                            "endpoint": ps.get("endpoint"),
                        }))
                    )
                    enqueued += 1

            conn.commit()
        except Exception:
            conn.rollback()
            raise

        if enqueued > 0:
            _log.debug("Enqueued %d metrics", enqueued)
        return enqueued


def get_pending_batch(conn: sqlite3.Connection) -> list[QueuedMetric]:
    """Get a batch of pending metrics to send to master.

    Thread-safe. Returns metrics ordered by sequence number for reliable
    delivery ordering.

    Args:
        conn: Queue database connection

    Returns:
        List of QueuedMetric up to MAX_BATCH_SIZE, ordered by seq ASC
    """
    with _lock:
        cursor = conn.execute(
            "SELECT seq, ts, metric_type, data FROM metrics_queue "
            "ORDER BY seq ASC LIMIT ?",
            (MAX_BATCH_SIZE,)
        )
        return [
            QueuedMetric(
                seq=row["seq"],
                ts=row["ts"],
                metric_type=row["metric_type"],
                data=json.loads(row["data"]),
            )
            for row in cursor
        ]


def ack_up_to_seq(conn: sqlite3.Connection, acked_seq: int) -> int:
    """Delete all metrics up to and including acked_seq.

    Thread-safe. Called after master confirms receipt. Includes safety
    check to prevent accidental deletion with invalid sequence numbers.

    Args:
        conn: Queue database connection
        acked_seq: Highest sequence number acknowledged by master

    Returns:
        Number of metrics deleted (0 if acked_seq is invalid)
    """
    with _lock:
        # Safety check: verify acked_seq is within valid range
        row = conn.execute(
            "SELECT MIN(seq) as min_seq, MAX(seq) as max_seq FROM metrics_queue"
        ).fetchone()

        if row["min_seq"] is None:
            return 0  # Queue is empty

        if acked_seq < row["min_seq"]:
            _log.warning(
                "ACK rejected: acked_seq=%d is below min_seq=%d (already processed?)",
                acked_seq, row["min_seq"]
            )
            return 0

        if acked_seq > row["max_seq"]:
            _log.warning(
                "ACK adjusted: acked_seq=%d exceeds max_seq=%d, capping",
                acked_seq, row["max_seq"]
            )
            acked_seq = row["max_seq"]

        cursor = conn.execute(
            "DELETE FROM metrics_queue WHERE seq <= ?",
            (acked_seq,)
        )
        conn.commit()
        deleted = cursor.rowcount
        if deleted > 0:
            _log.debug("ACK received: deleted %d metrics (up to seq %d)", deleted, acked_seq)
        return deleted


def get_queue_stats(conn: sqlite3.Connection) -> dict[str, Any]:
    """Get queue statistics for debugging and monitoring.

    Thread-safe. Returns current queue state including pending count,
    sequence range, and age of oldest metric.

    Args:
        conn: Queue database connection

    Returns:
        Dict with keys: pending, min_seq, max_seq, oldest_ts
    """
    with _lock:
        row = conn.execute("""
            SELECT
                COUNT(*) as pending,
                MIN(seq) as min_seq,
                MAX(seq) as max_seq,
                MIN(ts) as oldest_ts
            FROM metrics_queue
        """).fetchone()

        return {
            "pending": row["pending"] or 0,
            "min_seq": row["min_seq"],
            "max_seq": row["max_seq"],
            "oldest_ts": row["oldest_ts"],
        }


def get_last_acked_seq(conn: sqlite3.Connection) -> int | None:
    """Get the last acknowledged sequence number.

    For debugging and state recovery. Not required for normal operation
    since idempotency is handled by the master.

    Args:
        conn: Queue database connection

    Returns:
        Last ACKed sequence number, or None if never ACKed
    """
    with _lock:
        row = conn.execute(
            "SELECT value FROM sync_state WHERE key = 'last_acked_seq'"
        ).fetchone()
        return int(row["value"]) if row else None


def set_last_acked_seq(conn: sqlite3.Connection, seq: int) -> None:
    """Store the last acknowledged sequence number.

    For debugging and state recovery.

    Args:
        conn: Queue database connection
        seq: Sequence number to store
    """
    with _lock:
        conn.execute(
            "INSERT OR REPLACE INTO sync_state (key, value) VALUES ('last_acked_seq', ?)",
            (str(seq),)
        )
        conn.commit()


def serialize_batch_for_api(metrics: list[QueuedMetric]) -> dict[str, Any]:
    """Serialize a batch of metrics for the heartbeat API.

    Pure function, no database access required.

    Args:
        metrics: List of QueuedMetric from get_pending_batch()

    Returns:
        Dict with keys:
            - seq_from: First sequence in batch (None if empty)
            - seq_to: Last sequence in batch (None if empty)
            - metrics: List of metric dicts with seq, ts, type, data
    """
    if not metrics:
        return {"seq_from": None, "seq_to": None, "metrics": []}

    return {
        "seq_from": metrics[0].seq,
        "seq_to": metrics[-1].seq,
        "metrics": [
            {
                "seq": m.seq,
                "ts": m.ts,
                "type": m.metric_type,
                "data": m.data,
            }
            for m in metrics
        ]
    }
