#!/usr/bin/env python3
#
# tests/test_peer_policy_invariants.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Peer policy invariants must hold against the effective persisted state.

PeerUpdate's Pydantic validators only see fields present in a single
request. A partial update (e.g. only ``node_id``) can silently combine with
an unrelated value already stored on the row (e.g. an existing
``allow_all_nodes=True``) to violate an invariant the API model appears to
guarantee. The DB mutation layer (create_peer/update_peer) is the actual
authority: it must reject any effective state — request values merged with
what is already stored — that violates:

- allow_all_nodes and node_id are mutually exclusive
- allowed_ips_mode='full' requires 0.0.0.0/0 and ::/0 in allowed_ips
"""

from __future__ import annotations

import sqlite3

import pytest

from app.db.sqlite_interfaces import create_interface
from app.db.sqlite_nodes import create_node
from app.db.sqlite_peers import get_peer_by_id
from app.db.sqlite_peers_mutations import create_peer, update_peer

_PUBKEY_A = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI="
_PUBKEY_B = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBI="
_FULL_TUNNEL = "0.0.0.0/0, ::/0"
_SPLIT_TUNNEL = "10.0.0.0/8"


@pytest.fixture()
def iface(conn: sqlite3.Connection) -> str:
	create_interface(
		conn,
		name="wg0",
		private_key="a" * 44,
		public_key="b" * 44,
		address="10.13.13.1/24",
	)
	return "wg0"


@pytest.fixture()
def node_id(conn: sqlite3.Connection) -> str:
	nid = "1" * 32
	create_node(
		conn,
		node_id=nid,
		name="node-a",
		fqdn="node-a.example.com",
		wg_port=51820,
		api_secret_hash="x" * 64,
	)
	return nid


def _make_peer(conn: sqlite3.Connection, iface: str, **overrides) -> int:
	kwargs = {
		"public_key": _PUBKEY_A,
		"allowed_ips": _FULL_TUNNEL,
		"interface": iface,
		"allowed_ips_mode": "full",
	}
	kwargs.update(overrides)
	return create_peer(conn, **kwargs)


# ---------------------------------------------------------------------------
# create_peer(): direct DB callers cannot bypass the invariant either
# ---------------------------------------------------------------------------


def test_create_peer_rejects_allow_all_nodes_with_node_id(conn: sqlite3.Connection, iface: str, node_id: str):
	with pytest.raises(ValueError, match="allow_all_nodes"):
		create_peer(
			conn,
			public_key=_PUBKEY_A,
			allowed_ips=_FULL_TUNNEL,
			interface=iface,
			node_id=node_id,
			allow_all_nodes=True,
		)
	assert conn.execute("SELECT 1 FROM peers WHERE public_key = ?", (_PUBKEY_A,)).fetchone() is None


def test_create_peer_rejects_full_mode_with_split_allowed_ips(conn: sqlite3.Connection, iface: str):
	with pytest.raises(ValueError, match="allowed_ips_mode='full'"):
		create_peer(
			conn,
			public_key=_PUBKEY_A,
			allowed_ips=_SPLIT_TUNNEL,
			allowed_ips_mode="full",
			interface=iface,
		)


def test_create_peer_allows_consistent_full_tunnel(conn: sqlite3.Connection, iface: str):
	peer_id = _make_peer(conn, iface)
	assert get_peer_by_id(conn, peer_id) is not None


# ---------------------------------------------------------------------------
# update_peer(): effective (merged) state must be validated, not the
# request in isolation
# ---------------------------------------------------------------------------


def test_update_rejects_node_id_when_existing_allow_all_nodes(conn: sqlite3.Connection, iface: str, node_id: str):
	peer_id = _make_peer(conn, iface, allow_all_nodes=True)

	with pytest.raises(ValueError, match="allow_all_nodes"):
		update_peer(conn, peer_id, node_id=node_id)

	row = get_peer_by_id(conn, peer_id)
	assert row["node_id"] is None
	assert bool(row["allow_all_nodes"]) is True


def test_update_rejects_allow_all_nodes_when_existing_node_id(conn: sqlite3.Connection, iface: str, node_id: str):
	peer_id = _make_peer(conn, iface, node_id=node_id)

	with pytest.raises(ValueError, match="allow_all_nodes"):
		update_peer(conn, peer_id, allow_all_nodes=True)

	row = get_peer_by_id(conn, peer_id)
	assert row["node_id"] == node_id
	assert bool(row["allow_all_nodes"]) is False


def test_update_allows_clearing_node_id_when_existing_allow_all_nodes(
	conn: sqlite3.Connection, iface: str, node_id: str
):
	peer_id = _make_peer(conn, iface, allow_all_nodes=True)

	assert update_peer(conn, peer_id, node_id=None) is True

	row = get_peer_by_id(conn, peer_id)
	assert row["node_id"] is None
	assert bool(row["allow_all_nodes"]) is True


def test_update_allows_disabling_allow_all_nodes_when_existing_node_id(
	conn: sqlite3.Connection, iface: str, node_id: str
):
	peer_id = _make_peer(conn, iface, node_id=node_id)

	assert update_peer(conn, peer_id, allow_all_nodes=False) is True

	row = get_peer_by_id(conn, peer_id)
	assert row["node_id"] == node_id
	assert bool(row["allow_all_nodes"]) is False


def test_update_rejects_split_allowed_ips_when_existing_mode_full(conn: sqlite3.Connection, iface: str):
	peer_id = _make_peer(conn, iface, allowed_ips_mode="full")

	with pytest.raises(ValueError, match="allowed_ips_mode='full'"):
		update_peer(conn, peer_id, allowed_ips=_SPLIT_TUNNEL)

	row = get_peer_by_id(conn, peer_id)
	assert row["allowed_ips"] == _FULL_TUNNEL


def test_update_rejects_mode_full_when_existing_split_allowed_ips(conn: sqlite3.Connection, iface: str):
	peer_id = _make_peer(conn, iface, allowed_ips=_SPLIT_TUNNEL, allowed_ips_mode="split")

	with pytest.raises(ValueError, match="allowed_ips_mode='full'"):
		update_peer(conn, peer_id, allowed_ips_mode="full")

	row = get_peer_by_id(conn, peer_id)
	assert row["allowed_ips_mode"] == "split"


def test_update_allows_full_tunnel_routes_together(conn: sqlite3.Connection, iface: str):
	peer_id = _make_peer(conn, iface, allowed_ips=_SPLIT_TUNNEL, allowed_ips_mode="split")

	assert update_peer(conn, peer_id, allowed_ips=_FULL_TUNNEL, allowed_ips_mode="full") is True

	row = get_peer_by_id(conn, peer_id)
	assert row["allowed_ips_mode"] == "full"
	assert row["allowed_ips"] == _FULL_TUNNEL


def test_update_name_only_does_not_trigger_policy_check(conn: sqlite3.Connection, iface: str, node_id: str):
	"""A field unrelated to the policy invariant must succeed even on an otherwise consistent row, and must not require loading/merging state."""
	peer_id = _make_peer(conn, iface, node_id=node_id)

	assert update_peer(conn, peer_id, name="renamed") is True

	row = get_peer_by_id(conn, peer_id)
	assert row["name"] == "renamed"
	assert row["node_id"] == node_id
