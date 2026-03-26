#!/usr/bin/env python3
#
# app/db/sqlite_nodes.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Database operations for remote node management (Master-Node architecture)."""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from typing import Any

from ..utils.config import get_config
from ..utils.time import utcnow
from ..utils import vault
from .sqlite_runtime import transaction

_log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Node CRUD
# ─────────────────────────────────────────────────────────────────────────────


def create_node(
	conn: sqlite3.Connection,
	node_id: str,
	name: str,
	fqdn: str,
	wg_port: int,
	api_secret_hash: str,
) -> None:
	"""Insert a new node record (status='pending')."""
	now = utcnow()
	with transaction(conn, immediate=True):
		conn.execute(
			"""
			INSERT INTO nodes (id, name, fqdn, wg_port, api_secret_hash, status, created_at)
			VALUES (?, ?, ?, ?, ?, 'pending', ?)
			""",
			(node_id, name, fqdn, wg_port, api_secret_hash, now),
		)


def get_node(conn: sqlite3.Connection, node_id: str) -> sqlite3.Row | None:
	"""Fetch a single node by ID."""
	return conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()


def get_node_by_name(conn: sqlite3.Connection, name: str) -> sqlite3.Row | None:
	"""Fetch a single node by display name."""
	return conn.execute("SELECT * FROM nodes WHERE name = ?", (name,)).fetchone()


def get_all_nodes(conn: sqlite3.Connection) -> list[sqlite3.Row]:
	"""Return all nodes ordered by creation date."""
	return conn.execute("SELECT * FROM nodes ORDER BY created_at DESC").fetchall()


def get_node_by_api_secret(conn: sqlite3.Connection, secret_hash: str) -> sqlite3.Row | None:
	"""Look up a node by its hashed API secret (for authentication)."""
	return conn.execute(
		"SELECT * FROM nodes WHERE api_secret_hash = ?", (secret_hash,)
	).fetchone()


def update_node(
	conn: sqlite3.Connection,
	node_id: str,
	*,
	name: str | None = None,
	fqdn: str | None = None,
	wg_port: int | None = None,
) -> bool:
	"""Update mutable node fields. Returns True if found and updated."""
	updates: list[str] = []
	params: list[Any] = []

	if name is not None:
		updates.append("name = ?")
		params.append(name)
	if fqdn is not None:
		updates.append("fqdn = ?")
		params.append(fqdn)
	if wg_port is not None:
		updates.append("wg_port = ?")
		params.append(wg_port)

	if not updates:
		return get_node(conn, node_id) is not None

	params.append(node_id)
	sql = f"UPDATE nodes SET {', '.join(updates)} WHERE id = ?"
	with transaction(conn, immediate=True):
		cur = conn.execute(sql, params)
		return cur.rowcount > 0


def delete_node(conn: sqlite3.Connection, node_id: str) -> bool:
	"""Delete a node and unassign its peers (ON DELETE SET NULL).

	Also removes node_interfaces rows (ON DELETE CASCADE).
	Returns True if the node existed.
	"""
	with transaction(conn, immediate=True):
		# Peers: node_id set to NULL via FK ON DELETE SET NULL
		cur = conn.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
		return cur.rowcount > 0


# ─────────────────────────────────────────────────────────────────────────────
# Enrollment
# ─────────────────────────────────────────────────────────────────────────────


def enroll_node(
	conn: sqlite3.Connection,
	node_id: str,
	cert_fingerprint: str,
) -> bool:
	"""Mark a node as enrolled by storing its certificate fingerprint.

	Returns True if the node was found and updated.
	"""
	now = utcnow()
	with transaction(conn, immediate=True):
		cur = conn.execute(
			"""
			UPDATE nodes
			SET cert_fingerprint = ?, status = 'online', enrolled_at = ?, last_seen = ?
			WHERE id = ? AND status = 'pending'
			""",
			(cert_fingerprint, now, now, node_id),
		)
		return cur.rowcount > 0


def update_node_api_secret(
	conn: sqlite3.Connection,
	node_id: str,
	api_secret_hash: str,
) -> bool:
	"""Replace the API secret hash (for token regeneration / re-enrollment).

	Also resets status to 'pending' and clears the cert fingerprint.
	"""
	with transaction(conn, immediate=True):
		cur = conn.execute(
			"""
			UPDATE nodes
			SET api_secret_hash = ?, cert_fingerprint = NULL, status = 'pending',
			    enrolled_at = NULL
			WHERE id = ?
			""",
			(api_secret_hash, node_id),
		)
		return cur.rowcount > 0


# ─────────────────────────────────────────────────────────────────────────────
# Heartbeat & Status
# ─────────────────────────────────────────────────────────────────────────────


def update_node_heartbeat(
	conn: sqlite3.Connection,
	node_id: str,
	metadata: dict | None = None,
) -> bool:
	"""Update node heartbeat timestamp and optional metadata JSON."""
	now = utcnow()
	meta_json = json.dumps(metadata) if metadata else None
	with transaction(conn, immediate=True):
		cur = conn.execute(
			"UPDATE nodes SET last_seen = ?, metadata = COALESCE(?, metadata), status = 'online' WHERE id = ?",
			(now, meta_json, node_id),
		)
		return cur.rowcount > 0


def mark_stale_nodes_offline(
	conn: sqlite3.Connection,
	stale_seconds: int = 90,
) -> int:
	"""Mark enrolled nodes as 'offline' if last_seen exceeds threshold.

	Returns the number of nodes marked offline.
	"""
	from datetime import timedelta
	cutoff = utcnow() - timedelta(seconds=stale_seconds)
	with transaction(conn, immediate=True):
		cur = conn.execute(
			"""
			UPDATE nodes SET status = 'offline'
			WHERE status = 'online' AND last_seen < ?
			""",
			(cutoff,),
		)
		return cur.rowcount


# ─────────────────────────────────────────────────────────────────────────────
# Config Version
# ─────────────────────────────────────────────────────────────────────────────


def bump_node_config_version(
	conn: sqlite3.Connection,
	node_id: str,
) -> str:
	"""Compute and store a new config_version hash for the node.

	The version is a SHA-256 hash of all peer public keys assigned to this
	node, concatenated with a timestamp to guarantee uniqueness.
	"""
	now = utcnow()
	rows = conn.execute(
		"SELECT public_key FROM peers WHERE node_id = ? AND is_enabled = 1 ORDER BY public_key",
		(node_id,),
	).fetchall()
	payload = "|".join(r["public_key"] for r in rows) + "|" + now.isoformat()
	version = hashlib.sha256(payload.encode()).hexdigest()
	conn.execute(
		"UPDATE nodes SET config_version = ? WHERE id = ?",
		(version, node_id),
	)
	return version


# ─────────────────────────────────────────────────────────────────────────────
# Node Config (what the node needs to apply)
# ─────────────────────────────────────────────────────────────────────────────


def get_node_config(
	conn: sqlite3.Connection,
	node_id: str,
) -> dict:
	"""Build the full configuration payload for a node.

	Returns a dict with interfaces (+ keypairs) and assigned peers.
	"""
	pepper = get_config().secret_key
	node = get_node(conn, node_id)
	if node is None:
		return {}

	# Node interfaces (keypairs)
	ni_rows = conn.execute(
		"SELECT * FROM node_interfaces WHERE node_id = ?", (node_id,)
	).fetchall()
	interfaces = []
	for ni in ni_rows:
		iface = conn.execute(
			"SELECT * FROM interfaces WHERE name = ?", (ni["interface_name"],)
		).fetchone()
		if iface is None:
			continue
		interfaces.append({
			"name": ni["interface_name"],
			"private_key": vault.decrypt_if_needed(ni["private_key"], pepper),
			"public_key": ni["public_key"],
			"address": iface["address"],
			"address6": iface["address6"],
			"listen_port": iface["listen_port"],
			"dns": iface["dns"],
			"post_up": iface["post_up"],
			"post_down": iface["post_down"],
		})

	# Assigned peers
	peer_rows = conn.execute(
		"SELECT * FROM peers WHERE node_id = ? AND is_enabled = 1",
		(node_id,),
	).fetchall()
	peers = []
	for p in peer_rows:
		peers.append({
			"public_key": p["public_key"],
			"preshared_key": vault.decrypt_if_needed(p["preshared_key"], pepper) if p["preshared_key"] else None,
			"peer_address": p["peer_address"],
			"allowed_ips": p["allowed_ips"],
		})

	return {
		"config_version": node["config_version"],
		"interfaces": interfaces,
		"peers": peers,
	}


# ─────────────────────────────────────────────────────────────────────────────
# Node Interface Keypairs
# ─────────────────────────────────────────────────────────────────────────────


def create_node_interface(
	conn: sqlite3.Connection,
	node_id: str,
	interface_name: str,
	private_key: str,
	public_key: str,
) -> None:
	"""Store an encrypted WireGuard keypair for a node's interface."""
	pepper = get_config().secret_key
	now = utcnow()
	with transaction(conn, immediate=True):
		conn.execute(
			"""
			INSERT OR REPLACE INTO node_interfaces
				(node_id, interface_name, private_key, public_key, created_at)
			VALUES (?, ?, ?, ?, ?)
			""",
			(node_id, interface_name, vault.encrypt_if_needed(private_key, pepper), public_key, now),
		)


def get_node_interfaces(
	conn: sqlite3.Connection,
	node_id: str,
) -> list[sqlite3.Row]:
	"""Return all interface keypairs for a node."""
	return conn.execute(
		"SELECT * FROM node_interfaces WHERE node_id = ?", (node_id,)
	).fetchall()


def get_node_interface_public_key(
	conn: sqlite3.Connection,
	node_id: str,
	interface_name: str,
) -> str | None:
	"""Return the public key for a specific node + interface, or None."""
	row = conn.execute(
		"SELECT public_key FROM node_interfaces WHERE node_id = ? AND interface_name = ?",
		(node_id, interface_name),
	).fetchone()
	return row["public_key"] if row else None


def get_peers_count_by_node(conn: sqlite3.Connection) -> dict[str | None, int]:
	"""Return {node_id: peer_count} for all nodes (None key = local/master)."""
	rows = conn.execute(
		"SELECT node_id, COUNT(*) AS cnt FROM peers GROUP BY node_id"
	).fetchall()
	return {r["node_id"]: r["cnt"] for r in rows}
