#!/usr/bin/env python3
#
# app/node/metrics_queue.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Local SQLite queue for reliable metric delivery to master.

Provides at-least-once delivery guarantees with idempotency through sequence
numbers. Metrics are persisted locally and only deleted after master ACK.

Schema:
    metrics_queue(
        seq          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts           TEXT NOT NULL,      -- ISO 8601 UTC timestamp
        metric_type  TEXT NOT NULL,      -- 'peer_traffic' | 'peer_handshake'
        data         TEXT NOT NULL       -- JSON payload
    )

    sync_state(
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# Queue limits
MAX_QUEUE_SIZE = 10000  # Max pending metrics before oldest are dropped
MAX_BATCH_SIZE = 500    # Max metrics per heartbeat
QUEUE_DB_NAME = "metrics_queue.db"

# Metric types
METRIC_PEER_TRAFFIC = "peer_traffic"
METRIC_PEER_HANDSHAKE = "peer_handshake"


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
    """
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
    """Close the queue connection cleanly."""
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
    except Exception as exc:
        _log.warning("Error closing metrics queue: %s", exc)


def enqueue_peer_traffic(
    conn: sqlite3.Connection,
    peer_stats: list[dict[str, Any]],
) -> int:
    """Enqueue peer traffic metrics for later sync.

    Args:
        conn: Queue database connection
        peer_stats: List of peer stat dicts with public_key, transfer_rx, transfer_tx

    Returns:
        Number of metrics enqueued
    """
    if not peer_stats:
        return 0

    ts = datetime.now(timezone.utc).isoformat()
    enqueued = 0

    # Enforce queue size limit
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


def _enforce_queue_limit(conn: sqlite3.Connection) -> None:
    """Drop oldest metrics if queue exceeds size limit."""
    count = conn.execute("SELECT COUNT(*) FROM metrics_queue").fetchone()[0]
    if count >= MAX_QUEUE_SIZE:
        drop_count = count - MAX_QUEUE_SIZE + MAX_BATCH_SIZE  # Make room for a batch
        conn.execute(
            "DELETE FROM metrics_queue WHERE seq IN "
            "(SELECT seq FROM metrics_queue ORDER BY seq ASC LIMIT ?)",
            (drop_count,)
        )
        conn.commit()
        _log.warning("Queue overflow: dropped %d oldest metrics", drop_count)


def get_pending_batch(conn: sqlite3.Connection) -> list[QueuedMetric]:
    """Get a batch of pending metrics to send to master.

    Returns:
        List of QueuedMetric up to MAX_BATCH_SIZE, ordered by seq ASC
    """
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

    Called after master confirms receipt.

    Args:
        conn: Queue database connection
        acked_seq: Highest sequence number acknowledged by master

    Returns:
        Number of metrics deleted
    """
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
    """Get queue statistics for debugging."""
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
    """Get the last acknowledged sequence number (for debugging)."""
    row = conn.execute(
        "SELECT value FROM sync_state WHERE key = 'last_acked_seq'"
    ).fetchone()
    return int(row["value"]) if row else None


def set_last_acked_seq(conn: sqlite3.Connection, seq: int) -> None:
    """Store the last acknowledged sequence number."""
    conn.execute(
        "INSERT OR REPLACE INTO sync_state (key, value) VALUES ('last_acked_seq', ?)",
        (str(seq),)
    )
    conn.commit()


def serialize_batch_for_api(metrics: list[QueuedMetric]) -> dict[str, Any]:
    """Serialize a batch of metrics for the heartbeat API.

    Returns:
        Dict with seq_from, seq_to, and metrics list
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
