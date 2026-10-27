#!/usr/bin/env python3
#
# tests/test_node_delete.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Node-deletion durability (P3.1).

The removal signal to the node is irreversible (the node wipes its local
enrollment state on receipt). If the final DB delete then fails, the node must
not keep showing as online: it is flagged 'error' so the operator can retry.
"""

from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime

import pytest

from app.api import nodes as nodes_api
from app.db import sqlite_nodes
from app.db.sqlite_nodes import STATUS_ERROR, create_node, enroll_node, get_node


def _enrolled_node(conn: sqlite3.Connection) -> sqlite3.Row:
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	enroll_node(conn, "n1", "f" * 64)
	return get_node(conn, "n1")


def _call_delete(conn: sqlite3.Connection) -> None:
	user = {"id": 1, "username": "admin"}
	asyncio.run(nodes_api.delete_node_endpoint("n1", conn=conn, user=user))


def test_delete_db_failure_flags_node_error(conn, monkeypatch):
	_enrolled_node(conn)

	notified = {"called": False}

	async def fake_notify(node_id: str) -> int:
		notified["called"] = True
		return 1

	def boom(_conn, _node_id):
		raise sqlite3.OperationalError("database is locked")

	monkeypatch.setattr(nodes_api.node_notifier, "notify_node_removed", fake_notify)
	monkeypatch.setattr(nodes_api, "delete_node", boom)

	with pytest.raises(nodes_api.HTTPException) as exc:
		_call_delete(conn)

	assert exc.value.status_code == 500
	assert notified["called"] is True
	# Node is flagged error instead of silently kept online.
	assert get_node(conn, "n1")["status"] == STATUS_ERROR


def test_delete_happy_path_removes_row(conn, monkeypatch):
	_enrolled_node(conn)

	async def fake_notify(node_id: str) -> int:
		return 0

	monkeypatch.setattr(nodes_api.node_notifier, "notify_node_removed", fake_notify)

	_call_delete(conn)

	assert get_node(conn, "n1") is None


def test_mark_node_delete_failed_sets_error(conn):
	_enrolled_node(conn)
	assert sqlite_nodes.mark_node_delete_failed(conn, "n1") is True
	assert get_node(conn, "n1")["status"] == STATUS_ERROR


def _node_with_tunnel_peer(conn: sqlite3.Connection) -> None:
	_enrolled_node(conn)
	now = datetime.now(UTC)
	conn.execute(
		"INSERT INTO peers (public_key, allowed_ips, interface, is_enabled, created_at, updated_at) VALUES ('PUB', '10.0.0.2/32', 'wg0', 1, ?, ?)",
		(now, now),
	)
	peer_id = conn.execute("SELECT id FROM peers WHERE public_key = 'PUB'").fetchone()["id"]
	sqlite_nodes.set_node_tunnel_peer(conn, "n1", peer_id)
	conn.commit()


def _regenerate(conn: sqlite3.Connection, monkeypatch) -> None:
	# Token minting needs a configured master URL; it is not under test here.
	monkeypatch.setattr(nodes_api, "_generate_node_token", lambda _c, _i, _n: ("tok", "newhash"))
	user = {"id": 1, "username": "admin"}
	asyncio.run(nodes_api.regenerate_token("n1", conn=conn, user=user))


def _patch_wg(monkeypatch, results: dict[str, int]) -> list[tuple[str, ...]]:
	calls: list[tuple[str, ...]] = []

	async def fake_wg(*args, **_kwargs):
		calls.append(args)
		return results.get(args[1], 0), "", "boom"

	monkeypatch.setattr(nodes_api, "run_wg_command", fake_wg)
	return calls


def _peer_enabled(conn: sqlite3.Connection) -> int:
	return conn.execute("SELECT is_enabled FROM peers WHERE public_key = 'PUB'").fetchone()["is_enabled"]


def test_regenerate_token_revokes_peer_disables_it_and_syncs_config(conn, monkeypatch):
	_node_with_tunnel_peer(conn)
	calls = _patch_wg(monkeypatch, {})
	synced: list[str] = []
	monkeypatch.setattr(nodes_api, "sync_interface_config", lambda _p, iface, _c, **_k: synced.append(iface))

	old_hash = get_node(conn, "n1")["api_secret_hash"]
	_regenerate(conn, monkeypatch)

	assert ("wg", "set", "wg0", "peer", "PUB", "remove") in calls
	assert _peer_enabled(conn) == 0
	assert get_node(conn, "n1")["api_secret_hash"] != old_hash
	assert synced == ["wg0"]


def test_regenerate_token_refuses_with_503_when_live_revoke_fails(conn, monkeypatch):
	from fastapi import HTTPException

	_node_with_tunnel_peer(conn)
	# "set" fails while "show" succeeds: the interface is up, access is still live.
	_patch_wg(monkeypatch, {"set": 1, "show": 0})
	synced: list[str] = []
	monkeypatch.setattr(nodes_api, "sync_interface_config", lambda _p, iface, _c, **_k: synced.append(iface))

	old = get_node(conn, "n1")
	with pytest.raises(HTTPException) as exc:
		_regenerate(conn, monkeypatch)

	assert exc.value.status_code == 503
	assert get_node(conn, "n1")["api_secret_hash"] == old["api_secret_hash"]
	assert get_node(conn, "n1")["status"] == old["status"]
	assert _peer_enabled(conn) == 1
	assert synced == []


def test_regenerate_token_proceeds_when_interface_is_down(conn, monkeypatch):
	_node_with_tunnel_peer(conn)
	_patch_wg(monkeypatch, {"set": 1, "show": 1})
	monkeypatch.setattr(nodes_api, "sync_interface_config", lambda *_a, **_k: None)

	_regenerate(conn, monkeypatch)

	assert _peer_enabled(conn) == 0


def test_regenerate_token_returns_404_when_node_vanished(conn, monkeypatch):
	from fastapi import HTTPException

	_enrolled_node(conn)
	# The node disappears between the lookup and the secret update.
	monkeypatch.setattr(nodes_api, "update_node_api_secret", lambda *_a, **_k: False)

	with pytest.raises(HTTPException) as exc:
		_regenerate(conn, monkeypatch)

	assert exc.value.status_code == 404
