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
	_MAX_COMMAND_CLAIM_LIMIT,
	STATUS_ERROR,
	STATUS_OFFLINE,
	STATUS_ONLINE,
	STATUS_PENDING,
	VALID_NODE_COMMANDS,
	_serialize_command_payload,
	ack_node_command,
	claim_pending_node_commands,
	create_node,
	enqueue_node_command,
	enroll_node,
	mark_stale_nodes_offline,
	set_node_tunnel_peer,
	update_node_api_secret,
	update_node_heartbeat,
)
from app.db.sqlite_schema import init_schema
from app.utils.time import utcnow

_A_COMMAND = next(iter(VALID_NODE_COMMANDS))


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


@pytest.mark.parametrize("bad_limit", [0, -1, -100])
def test_claim_non_positive_limit_returns_empty(conn, bad_limit):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	enqueue_node_command(conn, "n1", _A_COMMAND)
	assert claim_pending_node_commands(conn, "n1", limit=bad_limit) == []


def test_claim_is_exclusive_across_concurrent_connections(tmp_path):
	"""Two workers racing to claim must never be handed the same command.

	`:memory:` databases are private per connection, so this needs a real file
	on disk to exercise the BEGIN IMMEDIATE exclusion `claim_pending_node_commands`
	relies on for its claim guarantee.
	"""
	db_path = tmp_path / "nodes.db"

	def _open() -> sqlite3.Connection:
		rt._ensure_sqlite_adapters()
		connection = sqlite3.connect(str(db_path), detect_types=sqlite3.PARSE_DECLTYPES)
		connection.row_factory = sqlite3.Row
		connection.execute("PRAGMA journal_mode=WAL")
		return connection

	conn_a = _open()
	init_schema(conn_a)
	create_node(conn_a, "n1", "N1", "example.com", 51820, "hash")
	for _ in range(10):
		enqueue_node_command(conn_a, "n1", _A_COMMAND)

	conn_b = _open()
	try:
		claimed_a = claim_pending_node_commands(conn_a, "n1", limit=10)
		# conn_a's BEGIN IMMEDIATE transaction has already committed by the time
		# claim_pending_node_commands() returns, so this must not block forever.
		claimed_b = claim_pending_node_commands(conn_b, "n1", limit=10)

		ids_a = {cmd["id"] for cmd in claimed_a}
		ids_b = {cmd["id"] for cmd in claimed_b}
		assert ids_a, "first claim should have found the freshly enqueued commands"
		assert ids_a.isdisjoint(ids_b), "the same command must not be claimed twice"
	finally:
		conn_a.close()
		conn_b.close()


# ─── input validation (Findings 6 & 9) ───────────────────────────────────────


@pytest.mark.parametrize("bad", [0, -1, -90])
def test_mark_stale_nodes_offline_rejects_non_positive(conn, bad):
	with pytest.raises(ValueError):
		mark_stale_nodes_offline(conn, stale_seconds=bad)


@pytest.mark.parametrize("bad", [0, -1])
def test_refresh_auth_token_rejects_non_positive_hours(conn, bad):
	with pytest.raises(ValueError):
		refresh_auth_token(conn, "some-token", hours=bad)


# ─── update_node_api_secret re-enrollment boundary (P2.2) ─────────────────────


def _make_tunnel_peer(conn: sqlite3.Connection, node_id: str) -> int:
	"""Create an enabled peer and bind it as the node's tunnel peer."""
	now = utcnow()
	cur = conn.execute(
		"""
		INSERT INTO peers (public_key, allowed_ips, is_enabled, created_at, updated_at)
		VALUES (?, ?, 1, ?, ?)
		""",
		(f"pk-{node_id}", "10.0.0.2/32", now, now),
	)
	peer_id = cur.lastrowid
	assert set_node_tunnel_peer(conn, node_id, peer_id) is True
	return peer_id


def _peer_enabled(conn: sqlite3.Connection, peer_id: int) -> int:
	return conn.execute("SELECT is_enabled FROM peers WHERE id = ?", (peer_id,)).fetchone()["is_enabled"]


def test_token_regen_disables_tunnel_peer(conn):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	enroll_node(conn, "n1", "f" * 64)
	peer_id = _make_tunnel_peer(conn, "n1")
	assert _peer_enabled(conn, peer_id) == 1

	assert update_node_api_secret(conn, "n1", "new-hash") is True

	# Boundary: old WireGuard key is disabled in the DB; node is pending again.
	assert _peer_enabled(conn, peer_id) == 0
	assert _status(conn, "n1") == STATUS_PENDING


def test_token_regen_purges_unacked_commands_but_keeps_acked(conn):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	# One command that will be delivered + acked, one left unacked.
	enqueue_node_command(conn, "n1", _A_COMMAND)
	enqueue_node_command(conn, "n1", _A_COMMAND)
	claimed = claim_pending_node_commands(conn, "n1", limit=1)
	assert len(claimed) == 1
	assert ack_node_command(conn, "n1", claimed[0]["id"]) is True

	update_node_api_secret(conn, "n1", "new-hash")

	rows = conn.execute("SELECT id, acked_at FROM node_commands WHERE node_id = ?", ("n1",)).fetchall()
	# Unacked command is purged; the acked one survives (audit trail).
	assert len(rows) == 1
	assert rows[0]["acked_at"] is not None


def test_enroll_re_enables_tunnel_peer_after_regen(conn):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	enroll_node(conn, "n1", "f" * 64)
	peer_id = _make_tunnel_peer(conn, "n1")

	update_node_api_secret(conn, "n1", "new-hash")
	assert _peer_enabled(conn, peer_id) == 0

	# Successful re-enrollment re-enables the reused tunnel peer.
	assert enroll_node(conn, "n1", "a" * 64) is True
	assert _peer_enabled(conn, peer_id) == 1


# ─── SSE session validity across token regeneration ───────────────────────────


def test_node_session_is_current_ends_after_token_regeneration(conn):
	from app.api.nodes_sync import node_session_is_current

	create_node(conn, "n1", "N1", "example.com", 51820, "hash-old")
	enroll_node(conn, "n1", "a" * 64)
	assert node_session_is_current(conn, "n1", "hash-old") is True

	# Regeneration swaps the secret and resets the node to pending: the SSE
	# stream that authenticated with the old secret must be told to close.
	assert update_node_api_secret(conn, "n1", "hash-new") is True
	assert node_session_is_current(conn, "n1", "hash-old") is False
	assert node_session_is_current(conn, "n1", "hash-new") is False  # still pending
	enroll_node(conn, "n1", "b" * 64)
	assert node_session_is_current(conn, "n1", "hash-new") is True
	assert node_session_is_current(conn, "n1", "hash-old") is False


def test_node_session_is_current_false_for_deleted_node(conn):
	from app.api.nodes_sync import node_session_is_current

	assert node_session_is_current(conn, "missing", "x") is False
