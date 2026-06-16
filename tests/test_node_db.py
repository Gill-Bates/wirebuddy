#!/usr/bin/env python3
#
# tests/test_node_db.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Unit tests for node/auth DB-helper boundaries.

Locks the security/reliability behaviors hardened after review: heartbeat must
not enliven pending nodes, command payloads must be finite JSON, the command
claim limit is clamped and returns the fresh delivered_at, and the stale-node /
token-refresh helpers reject non-positive durations.
"""

from __future__ import annotations

import sqlite3

import pytest

from app.db import sqlite_runtime as rt
from app.db.sqlite_auth import refresh_auth_token
from app.db.sqlite_nodes import (
	STATUS_ERROR,
	STATUS_OFFLINE,
	STATUS_ONLINE,
	STATUS_PENDING,
	VALID_NODE_COMMANDS,
	_MAX_COMMAND_CLAIM_LIMIT,
	_serialize_command_payload,
	claim_pending_node_commands,
	create_node,
	enqueue_node_command,
	enroll_node,
	mark_stale_nodes_offline,
	update_node_heartbeat,
)
from app.db.sqlite_schema import init_schema

_A_COMMAND = next(iter(VALID_NODE_COMMANDS))


@pytest.fixture()
def conn():
	rt._ensure_sqlite_adapters()
	connection = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
	connection.row_factory = sqlite3.Row
	init_schema(connection)
	try:
		yield connection
	finally:
		connection.close()


def _status(conn: sqlite3.Connection, node_id: str) -> str:
	return conn.execute("SELECT status FROM nodes WHERE id = ?", (node_id,)).fetchone()["status"]


# ─── _serialize_command_payload (Finding 3) ──────────────────────────────────


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_serialize_command_payload_rejects_non_finite(bad):
	with pytest.raises(ValueError):
		_serialize_command_payload({"value": bad})


def test_serialize_command_payload_accepts_finite_and_sorts_keys():
	assert _serialize_command_payload({"b": 1, "a": 2}) == '{"a":2,"b":1}'
	assert _serialize_command_payload(None) == "{}"


# ─── update_node_heartbeat status transitions (Finding 2) ─────────────────────


def test_heartbeat_does_not_enliven_pending(conn):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	assert _status(conn, "n1") == STATUS_PENDING

	assert update_node_heartbeat(conn, "n1") is True
	# Enrollment, not heartbeat, owns the pending -> online transition.
	assert _status(conn, "n1") == STATUS_PENDING


def test_heartbeat_re_enlivens_offline(conn):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	enroll_node(conn, "n1", "f" * 64)
	conn.execute("UPDATE nodes SET status = ? WHERE id = ?", (STATUS_OFFLINE, "n1"))

	update_node_heartbeat(conn, "n1")
	assert _status(conn, "n1") == STATUS_ONLINE


def test_heartbeat_leaves_error_untouched(conn):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	conn.execute("UPDATE nodes SET status = ? WHERE id = ?", (STATUS_ERROR, "n1"))

	update_node_heartbeat(conn, "n1")
	assert _status(conn, "n1") == STATUS_ERROR


def test_enroll_then_heartbeat_keeps_online(conn):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	assert enroll_node(conn, "n1", "a" * 64) is True
	assert _status(conn, "n1") == STATUS_ONLINE

	update_node_heartbeat(conn, "n1")
	assert _status(conn, "n1") == STATUS_ONLINE


# ─── claim_pending_node_commands (Findings 4 & 10) ────────────────────────────


def test_claim_clamps_limit_and_returns_fresh_delivered_at(conn):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	for _ in range(_MAX_COMMAND_CLAIM_LIMIT + 25):
		enqueue_node_command(conn, "n1", _A_COMMAND)

	claimed = claim_pending_node_commands(conn, "n1", limit=10_000)

	assert len(claimed) == _MAX_COMMAND_CLAIM_LIMIT
	# Returned delivered_at must reflect the in-transaction update, not the
	# stale pre-update NULL.
	assert all(cmd["delivered_at"] is not None for cmd in claimed)


def test_claim_non_positive_limit_returns_empty(conn):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	enqueue_node_command(conn, "n1", _A_COMMAND)
	assert claim_pending_node_commands(conn, "n1", limit=0) == []


# ─── input validation (Findings 6 & 9) ───────────────────────────────────────


@pytest.mark.parametrize("bad", [0, -1, -90])
def test_mark_stale_nodes_offline_rejects_non_positive(conn, bad):
	with pytest.raises(ValueError):
		mark_stale_nodes_offline(conn, stale_seconds=bad)


@pytest.mark.parametrize("bad", [0, -1])
def test_refresh_auth_token_rejects_non_positive_hours(conn, bad):
	with pytest.raises(ValueError):
		refresh_auth_token(conn, "some-token", hours=bad)
