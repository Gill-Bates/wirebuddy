#!/usr/bin/env python3
#
# tests/test_node_metrics_sync.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Regression tests for reliable node-metric ingestion in ``_process_heartbeat``.

Locks the sequence-gap handling (P2.2), the per-metric idempotent checkpoint
(P2.3) and the node-supplied observation timestamp threading (P3.2).
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.api import nodes_sync
from app.api.nodes_sync import HeartbeatRequest, MetricEntry, MetricsBatch, _process_heartbeat
from app.db import tsdb
from app.db.sqlite_nodes import (
	create_node,
	enroll_node,
	get_node,
	get_node_last_metric_seq,
	set_node_last_metric_seq,
)

_PEER_KEY = "A" * 43 + "="


def _node(conn: sqlite3.Connection) -> sqlite3.Row:
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	enroll_node(conn, "n1", "f" * 64)
	return get_node(conn, "n1")


def _traffic(seq: int, ts: str, rx: int = 10, tx: int = 20) -> MetricEntry:
	return MetricEntry(seq=seq, ts=ts, type="peer_traffic", data={"public_key": _PEER_KEY, "rx_bytes": rx, "tx_bytes": tx})


def _batch(metrics: list[MetricEntry], *, seq_from: int | None = None, seq_to: int | None = None) -> HeartbeatRequest:
	return HeartbeatRequest(metrics_batch=MetricsBatch(seq_from=seq_from, seq_to=seq_to, metrics=metrics))


def _now_iso() -> str:
	return datetime.now(UTC).isoformat()


# ─── P2.2 sequence-gap handling ──────────────────────────────────────────────


def test_transient_gap_is_rejected_without_advancing(conn, tmp_path):
	node = _node(conn)
	set_node_last_metric_seq(conn, "n1", 10)

	# Batch starts at 12 but does not declare its queue start (seq_from=None),
	# so this is treated as a transient/reordered gap (seq 11 may still exist)
	# and rejected rather than re-anchored.
	result = _process_heartbeat(conn, tmp_path, node, _batch([_traffic(12, _now_iso()), _traffic(13, _now_iso())], seq_to=13))

	assert result == {"acked_seq": None, "failed": True}
	assert get_node_last_metric_seq(conn, "n1") == 10


def test_overflow_gap_is_reanchored(conn, tmp_path):
	node = _node(conn)
	set_node_last_metric_seq(conn, "n1", 10)

	# Node dropped 11 on overflow and now starts its queue at 12 (seq_from == 12).
	# The gap is unrecoverable, so the master must re-anchor rather than deadlock.
	result = _process_heartbeat(conn, tmp_path, node, _batch([_traffic(12, _now_iso()), _traffic(13, _now_iso())], seq_from=12, seq_to=13))

	assert result == {"acked_seq": 13, "failed": False}
	assert get_node_last_metric_seq(conn, "n1") == 13


def test_internally_non_contiguous_batch_rejected(conn, tmp_path):
	node = _node(conn)
	set_node_last_metric_seq(conn, "n1", 10)

	result = _process_heartbeat(conn, tmp_path, node, _batch([_traffic(11, _now_iso()), _traffic(13, _now_iso())], seq_from=11, seq_to=13))

	assert result == {"acked_seq": None, "failed": True}
	assert get_node_last_metric_seq(conn, "n1") == 10


@pytest.mark.parametrize(
	("seq_from", "seq_to"),
	[(12, 13), (11, 14)],
)
def test_envelope_mismatch_rejected(conn, tmp_path, seq_from, seq_to):
	node = _node(conn)
	set_node_last_metric_seq(conn, "n1", 10)

	# Actual new metrics are 11..13; a declared envelope that disagrees is rejected.
	result = _process_heartbeat(
		conn, tmp_path, node, _batch([_traffic(11, _now_iso()), _traffic(12, _now_iso()), _traffic(13, _now_iso())], seq_from=seq_from, seq_to=seq_to)
	)

	assert result == {"acked_seq": None, "failed": True}
	assert get_node_last_metric_seq(conn, "n1") == 10


def test_contiguous_first_batch_accepted(conn, tmp_path):
	node = _node(conn)

	result = _process_heartbeat(conn, tmp_path, node, _batch([_traffic(1, _now_iso()), _traffic(2, _now_iso())], seq_from=1, seq_to=2))

	assert result == {"acked_seq": 2, "failed": False}
	assert get_node_last_metric_seq(conn, "n1") == 2


# ─── P2.3 idempotent per-metric checkpoint ───────────────────────────────────


def test_partial_write_failure_checkpoints_confirmed_prefix(conn, tmp_path, monkeypatch):
	node = _node(conn)

	calls = {"n": 0}
	real_writer = nodes_sync._write_peer_traffic_metric

	def flaky(tsdb_dir: Path, data: dict, at: datetime) -> int:
		calls["n"] += 1
		if calls["n"] == 2:
			raise RuntimeError("tsdb append failed")
		return real_writer(tsdb_dir, data, at)

	monkeypatch.setitem(nodes_sync._METRIC_WRITERS, "peer_traffic", flaky)

	result = _process_heartbeat(conn, tmp_path, node, _batch([_traffic(1, _now_iso()), _traffic(2, _now_iso())], seq_from=1, seq_to=2))

	# First metric persisted and checkpointed; second raised.
	assert result == {"acked_seq": 1, "failed": True}
	assert get_node_last_metric_seq(conn, "n1") == 1


def test_retry_does_not_reappend_checkpointed_prefix(conn, tmp_path, monkeypatch):
	node = _node(conn)

	calls = {"n": 0}
	real_writer = nodes_sync._write_peer_traffic_metric

	def flaky(tsdb_dir: Path, data: dict, at: datetime) -> int:
		calls["n"] += 1
		if calls["n"] == 2:
			raise RuntimeError("tsdb append failed")
		return real_writer(tsdb_dir, data, at)

	monkeypatch.setitem(nodes_sync._METRIC_WRITERS, "peer_traffic", flaky)

	ts1, ts2 = _now_iso(), _now_iso()
	# First delivery: seq 1 persists and checkpoints, seq 2 raises mid-batch.
	first = _process_heartbeat(conn, tmp_path, node, _batch([_traffic(1, ts1), _traffic(2, ts2)], seq_from=1, seq_to=2))
	assert first == {"acked_seq": 1, "failed": True}
	# Exactly seq 1's single rx point so far.
	assert len(tsdb.query(tmp_path, peer_key=_PEER_KEY, metric="rx_bytes")) == 1

	# Restore the working writer and retry the FULL batch (the node may resend
	# the whole window). The already-checkpointed seq 1 must be skipped, so its
	# point is not re-appended; only seq 2 is written.
	monkeypatch.setitem(nodes_sync._METRIC_WRITERS, "peer_traffic", real_writer)
	node = get_node(conn, "n1")
	result = _process_heartbeat(conn, tmp_path, node, _batch([_traffic(1, ts1), _traffic(2, ts2)], seq_from=1, seq_to=2))
	assert result == {"acked_seq": 2, "failed": False}

	# One point for seq 1 (not duplicated) + one for seq 2 = two total.
	rx_points = tsdb.query(tmp_path, peer_key=_PEER_KEY, metric="rx_bytes")
	assert len(rx_points) == 2
	assert get_node_last_metric_seq(conn, "n1") == 2


# ─── P3.2 observation timestamp threading ────────────────────────────────────


def test_buffered_metric_keeps_its_measurement_time(conn, tmp_path):
	node = _node(conn)
	old = datetime.now(UTC) - timedelta(days=3)
	old_iso = old.isoformat()

	result = _process_heartbeat(conn, tmp_path, node, _batch([_traffic(1, old_iso)], seq_from=1, seq_to=1))
	assert result == {"acked_seq": 1, "failed": False}

	points = tsdb.query(tmp_path, peer_key=_PEER_KEY, metric="rx_bytes")
	assert len(points) == 1
	# Stored at the node-supplied observation time, not master receive time.
	assert abs((points[0].ts - old).total_seconds()) < 1.0


def test_invalid_timestamp_rejects_batch(conn, tmp_path):
	node = _node(conn)

	result = _process_heartbeat(conn, tmp_path, node, _batch([_traffic(1, "not-a-timestamp")], seq_from=1, seq_to=1))

	assert result == {"acked_seq": None, "failed": True}
	assert get_node_last_metric_seq(conn, "n1") is None
	# Nothing written when the batch is rejected up-front.
	assert tsdb.query(tmp_path, peer_key=_PEER_KEY, metric="rx_bytes") == []
