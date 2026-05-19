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
All public functions are thread-safe via a per-connection lock registry.
The SQLite connection is created with `check_same_thread=False` but
operations are serialized per connection to prevent race conditions.

Schema
------
::

    metrics_queue(
        seq          INTEGER PRIMARY KEY AUTOINCREMENT,  -- Sequence number
        ts           TEXT NOT NULL,                      -- ISO 8601 UTC timestamp
        metric_type  TEXT NOT NULL,                      -- 'peer_traffic' | 'peer_handshake'
        data         TEXT NOT NULL                       -- JSON payload
    )

Performance Notes
-----------------
- Queue size enforcement uses exact COUNT(*) on the PRIMARY KEY table
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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_QUEUE_SIZE = 10000  # Max pending metrics before oldest are dropped
MAX_BATCH_SIZE = 500    # Max metrics per heartbeat
QUEUE_DB_NAME = "metrics_queue.db"
QUEUE_SCHEMA_VERSION = 1

# Metric types
METRIC_PEER_TRAFFIC = "peer_traffic"
METRIC_PEER_HANDSHAKE = "peer_handshake"

# Lock registry: one lock per queue database file
_registry_lock = threading.Lock()
_connection_locks: dict[str, threading.Lock] = {}


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

        CREATE TABLE IF NOT EXISTS metrics_queue_meta (
            id                INTEGER PRIMARY KEY CHECK (id = 1),
            pending_count     INTEGER NOT NULL DEFAULT 0,
            dropped_count     INTEGER NOT NULL DEFAULT 0,
            last_overflow_ts   TEXT
        );

        INSERT OR IGNORE INTO metrics_queue_meta (id, pending_count, dropped_count, last_overflow_ts)
        VALUES (1, 0, 0, NULL);
    """)


def _ensure_schema_version(conn: sqlite3.Connection) -> None:
    """Ensure the queue schema version is initialized."""
    current_version = int(conn.execute("PRAGMA user_version").fetchone()[0] or 0)
    if current_version == 0:
        conn.execute(f"PRAGMA user_version = {QUEUE_SCHEMA_VERSION}")
        return
    if current_version > QUEUE_SCHEMA_VERSION:
        raise RuntimeError(
            f"Queue schema version {current_version} is newer than supported version {QUEUE_SCHEMA_VERSION}"
        )


def _reconcile_meta(conn: sqlite3.Connection) -> None:
    """Reconcile the cached queue size after opening the database."""
    pending_count = _get_queue_size_exact(conn)
    conn.execute(
        "UPDATE metrics_queue_meta SET pending_count = ? WHERE id = 1",
        (pending_count,),
    )


def _get_queue_size_exact(conn: sqlite3.Connection) -> int:
    """Return the exact queue size from the table."""
    row = conn.execute("SELECT COUNT(*) as pending FROM metrics_queue").fetchone()
    return int(row["pending"] or 0)


def _get_queue_size(conn: sqlite3.Connection) -> int:
    """Return the cached queue size, falling back to an exact count if needed."""
    row = conn.execute("SELECT pending_count FROM metrics_queue_meta WHERE id = 1").fetchone()
    if row is not None and row["pending_count"] is not None:
        return int(row["pending_count"])
    return _get_queue_size_exact(conn)


def _get_connection_key(conn: sqlite3.Connection) -> str:
    """Return a stable key for the underlying queue database file."""
    row = conn.execute("PRAGMA database_list").fetchone()
    if row is None:
        return f"<unknown:{id(conn)}>"

    database_path = row[2]
    if not database_path:
        return f"<memory:{id(conn)}>"

    return str(Path(database_path).resolve())


def _register_connection_lock(connection_key: str) -> threading.Lock:
    """Register and return the lock for a queue database file."""
    lock = threading.Lock()
    with _registry_lock:
        _connection_locks[connection_key] = lock
    return lock


def _get_connection_lock(conn: sqlite3.Connection) -> threading.Lock:
    """Return the lock for a queue database file."""
    connection_key = _get_connection_key(conn)
    with _registry_lock:
        lock = _connection_locks.get(connection_key)
        if lock is None:
            lock = threading.Lock()
            _connection_locks[connection_key] = lock
        return lock


def _unregister_connection_lock(connection_key: str) -> None:
    """Remove the lock for a queue database file."""
    with _registry_lock:
        _connection_locks.pop(connection_key, None)


def init_queue(data_dir: Path) -> sqlite3.Connection:
    """Initialize and return a connection to the metrics queue.

    Creates the database and schema if they don't exist.
    Uses WAL mode for better concurrency.

    Args:
        data_dir: Directory to store the queue database

    Returns:
        SQLite connection (thread-safe via a per-connection lock)
    """
    db_path = _get_queue_path(data_dir)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")  # Faster, still durable with WAL

    _init_schema(conn)
    _ensure_schema_version(conn)
    _reconcile_meta(conn)
    _register_connection_lock(str(db_path.resolve()))
    _log.debug("Metrics queue initialized: %s", db_path)
    return conn


def close_queue(conn: sqlite3.Connection) -> None:
    """Close the queue connection cleanly.

    Performs a WAL checkpoint before closing to ensure all data is flushed.
    """
    connection_key = _get_connection_key(conn)
    with _get_connection_lock(conn):
        try:
            conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
            conn.close()
        except Exception as exc:
            _log.warning("Error closing metrics queue: %s", exc)
        finally:
            _unregister_connection_lock(connection_key)


def _enforce_queue_limit(conn: sqlite3.Connection) -> None:
    """Drop oldest metrics if queue exceeds size limit.

    Uses exact size measurement and an indexed cutoff query.
    """
    size = _get_queue_size(conn)
    if size <= MAX_QUEUE_SIZE:
        return

    # Calculate cutoff sequence
    drop_count = size - MAX_QUEUE_SIZE + MAX_BATCH_SIZE  # Make room for a batch
    row = conn.execute(
        "SELECT seq FROM metrics_queue ORDER BY seq ASC LIMIT 1 OFFSET ?",
        (drop_count,)
    ).fetchone()

    if row:
        cutoff_seq = row["seq"]
        deleted = conn.execute("DELETE FROM metrics_queue WHERE seq < ?", (cutoff_seq,)).rowcount
        if deleted > 0:
            conn.execute(
                "UPDATE metrics_queue_meta SET pending_count = MAX(pending_count - ?, 0), dropped_count = dropped_count + ?, last_overflow_ts = ? WHERE id = 1",
                (deleted, deleted, datetime.now(UTC).isoformat()),
            )
            _log.warning("Queue overflow: dropped metrics with seq < %d (~%d items)", cutoff_seq, deleted)


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

    with _get_connection_lock(conn), conn:
        ts = datetime.now(UTC).isoformat()
        rows: list[tuple[str, str, str]] = []

        # Enforce queue size limit (before adding new metrics)
        _enforce_queue_limit(conn)

        for ps in peer_stats:
            public_key = ps.get("public_key")
            if not public_key:
                continue

            rx = ps.get("transfer_rx", 0)
            tx = ps.get("transfer_tx", 0)
            if rx > 0 or tx > 0:
                rows.append((
                    ts,
                    METRIC_PEER_TRAFFIC,
                    json.dumps({
                        "public_key": public_key,
                        "rx_bytes": rx,
                        "tx_bytes": tx,
                    }),
                ))

            latest_handshake = ps.get("latest_handshake")
            if latest_handshake and latest_handshake > 0:
                rows.append((
                    ts,
                    METRIC_PEER_HANDSHAKE,
                    json.dumps({
                        "public_key": public_key,
                        "latest_handshake": latest_handshake,
                        "endpoint": ps.get("endpoint"),
                    }),
                ))

        if not rows:
            return 0

        try:
            conn.executemany(
                "INSERT INTO metrics_queue (ts, metric_type, data) VALUES (?, ?, ?)",
                rows,
            )
            conn.execute(
                "UPDATE metrics_queue_meta SET pending_count = pending_count + ? WHERE id = 1",
                (len(rows),),
            )
        except Exception:
            raise

        _log.debug("Enqueued %d metrics", len(rows))
        return len(rows)


def get_pending_batch(conn: sqlite3.Connection) -> list[QueuedMetric]:
    """Get a batch of pending metrics to send to master.

    Thread-safe. Returns metrics ordered by sequence number for reliable
    delivery ordering.

    Args:
        conn: Queue database connection

    Returns:
        List of QueuedMetric up to MAX_BATCH_SIZE, ordered by seq ASC
    """
    with _get_connection_lock(conn), conn:
        cursor = conn.execute(
            "SELECT seq, ts, metric_type, data FROM metrics_queue "
            "ORDER BY seq ASC LIMIT ?",
            (MAX_BATCH_SIZE,)
        )
        metrics: list[QueuedMetric] = []
        corrupt_seqs: list[int] = []
        for row in cursor:
            try:
                metrics.append(
                    QueuedMetric(
                        seq=row["seq"],
                        ts=row["ts"],
                        metric_type=row["metric_type"],
                        data=json.loads(row["data"]),
                    )
                )
            except (TypeError, ValueError, json.JSONDecodeError):
                corrupt_seqs.append(int(row["seq"]))
                _log.warning("Corrupt metrics queue row skipped: seq=%s", row["seq"])

        if corrupt_seqs:
            conn.executemany(
                "DELETE FROM metrics_queue WHERE seq = ?",
                [(seq,) for seq in corrupt_seqs],
            )
            conn.execute(
                "UPDATE metrics_queue_meta SET pending_count = MAX(pending_count - ?, 0), dropped_count = dropped_count + ? WHERE id = 1",
                (len(corrupt_seqs), len(corrupt_seqs)),
            )

        return metrics


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
    with _get_connection_lock(conn), conn:
        if isinstance(acked_seq, bool) or not isinstance(acked_seq, int) or acked_seq < 1:
            return 0

        row = conn.execute(
            "SELECT MIN(seq) as min_seq, MAX(seq) as max_seq FROM metrics_queue"
        ).fetchone()
        max_seq = row["max_seq"] if row is not None else None
        if max_seq is None:
            return 0

        if acked_seq > max_seq:
            _log.warning("ACK seq %d exceeds queue max seq %d, clamping", acked_seq, max_seq)
            acked_seq = int(max_seq)

        cursor = conn.execute(
            "DELETE FROM metrics_queue WHERE seq <= ?",
            (acked_seq,)
        )
        deleted = cursor.rowcount
        if deleted > 0:
            conn.execute(
                "UPDATE metrics_queue_meta SET pending_count = MAX(pending_count - ?, 0) WHERE id = 1",
                (deleted,),
            )
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
    with _get_connection_lock(conn):
        row = conn.execute("""
            SELECT
                MIN(seq) as min_seq,
                MAX(seq) as max_seq,
                MIN(ts) as oldest_ts
            FROM metrics_queue
        """).fetchone()
        meta = conn.execute(
            "SELECT pending_count, dropped_count, last_overflow_ts FROM metrics_queue_meta WHERE id = 1"
        ).fetchone()

        return {
            "pending": int(meta["pending_count"] or 0) if meta is not None else 0,
            "min_seq": row["min_seq"],
            "max_seq": row["max_seq"],
            "oldest_ts": row["oldest_ts"],
            "dropped": int(meta["dropped_count"] or 0) if meta is not None else 0,
            "last_overflow_ts": meta["last_overflow_ts"] if meta is not None else None,
        }


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
