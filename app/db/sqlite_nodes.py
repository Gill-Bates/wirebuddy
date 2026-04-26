#!/usr/bin/env python3
#
# app/db/sqlite_nodes.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Database operations for remote node management (Master-Node architecture)."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from ..utils.config import get_config
from ..utils.time import parse_utc, utcnow
from ..utils import vault
from .sqlite_interfaces import get_interface, list_interfaces
from .sqlite_settings import get_setting
from .sqlite_runtime import transaction

_log = logging.getLogger(__name__)

# Input validation constants
_MAX_METADATA_SIZE = 4096  # bytes
_MAX_PORT = 65535
_MIN_PORT = 1

# Node status constants
STATUS_PENDING = "pending"
STATUS_ONLINE = "online"
STATUS_OFFLINE = "offline"

# FQDN validation: RFC 1123 compliant hostname/domain
_FQDN_RE = re.compile(
	r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
	r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


def _parse_ip_or_none(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
	"""Parse a bare or bracketed IP address, or return None."""
	try:
		return ipaddress.ip_address(value.strip("[]"))
	except ValueError:
		return None


def _parse_db_timestamp(value: Any) -> datetime | None:
	"""Normalize a DB timestamp value to a UTC-aware datetime."""
	if value is None:
		return None
	if isinstance(value, datetime):
		return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
	if isinstance(value, str):
		return parse_utc(value)
	return None


def _validate_fqdn_or_ip(fqdn: str) -> None:
	"""Validate FQDN or IP address (v4 / bracketed v6).

	Accepts: RFC 1123 hostnames, IPv4 addresses, and bracketed IPv6 addresses
	(e.g., ``[::1]`` as stored by the API layer).
	Rejects: invalid hostnames, malformed IPs, empty values.
	"""
	fqdn = fqdn.strip()
	if not fqdn:
		raise ValueError("FQDN cannot be empty")
	if _parse_ip_or_none(fqdn) is not None:
		return
	if not _FQDN_RE.match(fqdn):
		raise ValueError(f"Invalid FQDN: {fqdn!r}")


def _canonicalize_fqdn_or_ip(fqdn: str) -> str:
	"""Return canonical storage form for host values.

	- Hostnames are lowercased (DNS is case-insensitive).
	- IPv4 is stored compressed.
	- IPv6 is stored bracketed and compressed.
	"""
	fqdn = fqdn.strip()
	_validate_fqdn_or_ip(fqdn)
	addr = _parse_ip_or_none(fqdn)
	if addr is None:
		return fqdn.lower()
	return f"[{addr.compressed}]" if addr.version == 6 else addr.compressed


def _validate_port(port: int) -> None:
	"""Validate port is in valid range."""
	if not (_MIN_PORT <= port <= _MAX_PORT):
		raise ValueError(f"Port out of valid range: {port}")


def _validate_name(name: str) -> None:
	"""Validate node name is non-empty and properly formatted."""
	name = name.strip()
	if not name:
		raise ValueError("Node name cannot be empty")
	if len(name) > 63:
		raise ValueError("Node name exceeds 63 characters")


def _split_addresses(raw: str) -> list[str]:
	"""Split a comma-separated address list into clean non-empty entries."""
	return [part.strip() for part in str(raw or "").split(",") if part.strip()]


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
	name = name.strip()
	fqdn = _canonicalize_fqdn_or_ip(fqdn)
	_validate_name(name)
	_validate_port(wg_port)
	now = utcnow()
	with transaction(conn, immediate=True):
		conn.execute(
			"""
			INSERT INTO nodes (id, name, fqdn, wg_port, api_secret_hash, status, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			""",
			(node_id, name, fqdn, wg_port, api_secret_hash, STATUS_PENDING, now),
		)


def get_node(conn: sqlite3.Connection, node_id: str) -> sqlite3.Row | None:
	"""Fetch a single node by ID."""
	return conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()


def get_node_by_name(conn: sqlite3.Connection, name: str) -> sqlite3.Row | None:
	"""Fetch a single node by display name."""
	return conn.execute("SELECT * FROM nodes WHERE name = ?", (name,)).fetchone()


def get_node_by_fqdn(conn: sqlite3.Connection, fqdn: str) -> sqlite3.Row | None:
	"""Fetch a single node by FQDN."""
	normalized = _canonicalize_fqdn_or_ip(fqdn)
	return conn.execute(
		"SELECT * FROM nodes WHERE fqdn = ? COLLATE NOCASE",
		(normalized,),
	).fetchone()


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
		name = name.strip()
		_validate_name(name)
		updates.append("name = ?")
		params.append(name)
	if fqdn is not None:
		fqdn = _canonicalize_fqdn_or_ip(fqdn)
		updates.append("fqdn = ?")
		params.append(fqdn)
	if wg_port is not None:
		_validate_port(wg_port)
		updates.append("wg_port = ?")
		params.append(wg_port)

	if not updates:
		return False  # No changes requested

	params.append(node_id)
	sql = f"UPDATE nodes SET {', '.join(updates)} WHERE id = ?"
	with transaction(conn, immediate=True):
		cur = conn.execute(sql, params)
		return cur.rowcount > 0


def delete_node(conn: sqlite3.Connection, node_id: str) -> int | None:
	"""Delete a node and return the number of peer assignments removed.

	The tunnel peer (created during enrollment for Node→Master DNS routing)
	is deleted along with the node. Regular peers assigned to this node have
	their node_id set to NULL (ON DELETE SET NULL).

	Also removes node_interfaces rows (ON DELETE CASCADE).
	Returns:
		- int: number of peers that had this node assigned before deletion
		- None: node does not exist
	"""
	with transaction(conn, immediate=True):
		row = conn.execute(
			"SELECT tunnel_peer_id FROM nodes WHERE id = ?",
			(node_id,),
		).fetchone()
		if not row:
			return None

		assigned_peer_count_row = conn.execute(
			"SELECT COUNT(*) AS cnt FROM peers WHERE node_id = ?",
			(node_id,),
		).fetchone()
		assigned_peer_count = int(assigned_peer_count_row["cnt"]) if assigned_peer_count_row else 0

		if row["tunnel_peer_id"]:
			cur = conn.execute(
				"DELETE FROM peers WHERE id = ?",
				(row["tunnel_peer_id"],),
			)
			if cur.rowcount > 0:
				_log.info("Deleted tunnel peer for node=%s", node_id)

		conn.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
		return assigned_peer_count
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
			SET cert_fingerprint = ?, status = ?, enrolled_at = ?, last_seen = ?
			WHERE id = ? AND status = ?
			""",
			(cert_fingerprint, STATUS_ONLINE, now, now, node_id, STATUS_PENDING),
		)
		return cur.rowcount > 0


def rotate_node_session_secret(
	conn: sqlite3.Connection,
	node_id: str,
	api_secret_hash: str,
) -> bool:
	"""Replace the API secret hash after successful enrollment.

	This invalidates the enrollment token's api_secret so the token
	becomes single-use. Works on any enrolled node (status != 'pending').
	Returns True if the row was updated.
	"""
	with transaction(conn, immediate=True):
		cur = conn.execute(
			"UPDATE nodes SET api_secret_hash = ? WHERE id = ? AND status != ?",
			(api_secret_hash, node_id, STATUS_PENDING),
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
			SET api_secret_hash = ?, cert_fingerprint = NULL, status = ?,
			    enrolled_at = NULL, last_seen = NULL, sse_connected_at = NULL,
			    pending_command = NULL, last_metric_seq = NULL
			WHERE id = ?
			""",
			(api_secret_hash, STATUS_PENDING, node_id),
		)
		return cur.rowcount > 0


def set_node_tunnel_peer(
	conn: sqlite3.Connection,
	node_id: str,
	tunnel_peer_id: int,
) -> bool:
	"""Store the peer ID that represents this node's tunnel to the master.

	The tunnel peer allows the node to route DNS traffic to the master's Unbound.
	"""
	with transaction(conn, immediate=True):
		cur = conn.execute(
			"UPDATE nodes SET tunnel_peer_id = ? WHERE id = ?",
			(tunnel_peer_id, node_id),
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
	"""Update node heartbeat timestamp and optional metadata JSON.

	If ``metadata`` is None, existing metadata is preserved.
	"""
	now = utcnow()
	meta_json = None
	if metadata is not None:
		meta_json = json.dumps(metadata, default=str)
		if len(meta_json.encode("utf-8")) > _MAX_METADATA_SIZE:
			raise ValueError(f"Metadata exceeds maximum size ({_MAX_METADATA_SIZE} bytes)")
	with transaction(conn, immediate=True):
		# Only set status to 'online' if not in error state
		cur = conn.execute(
			"""
			UPDATE nodes
			SET last_seen = ?,
			    metadata = COALESCE(?, metadata),
			    status = CASE WHEN status != 'error' THEN ? ELSE status END
			WHERE id = ?
			""",
			(now, meta_json, STATUS_ONLINE, node_id),
		)
		return cur.rowcount > 0


def get_node_last_metric_seq(conn: sqlite3.Connection, node_id: str) -> int | None:
	"""Get the last processed metric sequence for a node."""
	row = conn.execute(
		"SELECT last_metric_seq FROM nodes WHERE id = ?",
		(node_id,),
	).fetchone()
	if not row:
		return None
	value = row["last_metric_seq"]
	if value is None:
		return None
	try:
		return int(value)
	except (TypeError, ValueError):
		_log.warning("Invalid last_metric_seq for node=%s: %r", node_id, value)
		return None


def set_node_last_metric_seq(conn: sqlite3.Connection, node_id: str, seq: int) -> None:
	"""Update the last processed metric sequence for a node."""
	seq = int(seq)
	if seq < 0:
		raise ValueError("seq must be >= 0")
	with transaction(conn, immediate=True):
		conn.execute(
			"UPDATE nodes SET last_metric_seq = ? WHERE id = ?",
			(seq, node_id),
		)


def mark_stale_nodes_offline(
	conn: sqlite3.Connection,
	stale_seconds: int = 90,
) -> int:
	"""Mark enrolled nodes as 'offline' if last_seen exceeds threshold.

	Returns the number of nodes marked offline.
	"""
	cutoff = utcnow() - timedelta(seconds=stale_seconds)
	with transaction(conn, immediate=True):
		cur = conn.execute(
			"""
			UPDATE nodes SET status = ?
			WHERE status = ? AND last_seen < ?
			""",
			(STATUS_OFFLINE, STATUS_ONLINE, cutoff),
		)
		return cur.rowcount


# ─────────────────────────────────────────────────────────────────────────────
# SSE Connection Tracking (multi-worker safe)
# ─────────────────────────────────────────────────────────────────────────────


def update_node_sse_connected(conn: sqlite3.Connection, node_id: str) -> None:
	"""Record that a node connected via SSE. Thread/worker-safe via DB."""
	now = utcnow()
	with transaction(conn, immediate=True):
		conn.execute(
			"UPDATE nodes SET sse_connected_at = ? WHERE id = ?",
			(now, node_id),
		)


def clear_node_sse_connected(conn: sqlite3.Connection, node_id: str) -> None:
	"""Clear SSE connection timestamp when node disconnects."""
	with transaction(conn, immediate=True):
		conn.execute(
			"UPDATE nodes SET sse_connected_at = NULL WHERE id = ?",
			(node_id,),
		)


def is_node_sse_connected(conn: sqlite3.Connection, node_id: str, max_age_seconds: int = 45) -> bool:
	"""Check if node has an active SSE connection (multi-worker safe).

	A node is considered connected if sse_connected_at is within max_age_seconds.
	Default 45s accounts for 25s keepalive interval + margin.
	"""
	cutoff = utcnow() - timedelta(seconds=max_age_seconds)
	row = conn.execute(
		"SELECT sse_connected_at FROM nodes WHERE id = ?",
		(node_id,),
	).fetchone()
	if not row:
		return False
	ts = _parse_db_timestamp(row["sse_connected_at"])
	if ts is None:
		return False
	return ts >= cutoff


# ─────────────────────────────────────────────────────────────────────────────
# Pending Commands (Multi-Worker Safe)
# ─────────────────────────────────────────────────────────────────────────────

# Valid commands for node control
VALID_NODE_COMMANDS = frozenset({"config_changed", "restart", "shutdown", "removed", "speedtest"})


def set_node_pending_command(conn: sqlite3.Connection, node_id: str, command: str) -> bool:
	"""Set a pending command for a node (multi-worker safe).
	
	Returns True if command was set, False if node doesn't exist.
	
	Raises:
		ValueError: If command is not in VALID_NODE_COMMANDS.
	"""
	if command not in VALID_NODE_COMMANDS:
		raise ValueError(f"Invalid node command: {command!r}. Valid: {sorted(VALID_NODE_COMMANDS)}")
	
	with transaction(conn, immediate=True):
		result = conn.execute(
			"UPDATE nodes SET pending_command = ? WHERE id = ?",
			(command, node_id),
		)
		return result.rowcount > 0


def get_and_clear_node_pending_command(conn: sqlite3.Connection, node_id: str) -> str | None:
	"""Atomically get and clear any pending command for a node.
	
	Returns the command string if one was pending, None otherwise.
	Uses SELECT-then-UPDATE within a transaction to ensure atomicity
	across multiple workers.
	"""
	with transaction(conn, immediate=True):
		# SELECT first to get the current value
		row = conn.execute(
			"SELECT pending_command FROM nodes WHERE id = ?",
			(node_id,),
		).fetchone()
		
		if not row or not row["pending_command"]:
			return None
		
		command = row["pending_command"]
		_clear_node_pending_command_locked(conn, node_id)
		
		return command


def clear_node_pending_command(conn: sqlite3.Connection, node_id: str) -> None:
	"""Clear any pending command for a node without returning it."""
	with transaction(conn, immediate=True):
		_clear_node_pending_command_locked(conn, node_id)


def _clear_node_pending_command_locked(conn: sqlite3.Connection, node_id: str) -> None:
	"""Clear pending command while the caller already holds a transaction."""
	conn.execute(
		"UPDATE nodes SET pending_command = NULL WHERE id = ?",
		(node_id,),
	)


# ─────────────────────────────────────────────────────────────────────────────
# Config Version
# ─────────────────────────────────────────────────────────────────────────────


def bump_node_config_version(
	conn: sqlite3.Connection,
	node_id: str,
) -> str:
	"""Compute and store a new config_version hash for the node.

	The version is a deterministic SHA-256 hash of the full peer configuration
	assigned to this node (public_key, allowed_ips, preshared_key presence).
	Timestamp is NOT included to ensure idempotency.
	"""
	with transaction(conn, immediate=True):
		rows = conn.execute(
			"""
			SELECT
				public_key,
				allowed_ips,
				interface,
				(preshared_key IS NOT NULL AND preshared_key != '') AS has_psk
			FROM peers
			WHERE node_id = ? AND is_enabled = 1
			ORDER BY public_key
			""",
			(node_id,),
		).fetchall()
		# Include full peer config (but not decrypted keys) for version hash
		payload = json.dumps(
			[
				{
					"public_key": r["public_key"],
					"allowed_ips": r["allowed_ips"],
					"has_psk": bool(r["has_psk"]),
					"interface": r["interface"],
				}
				for r in rows
			],
			separators=(",", ":"),
		)
		version = hashlib.sha256(payload.encode("utf-8")).hexdigest()
		conn.execute(
			"UPDATE nodes SET config_version = ? WHERE id = ?",
			(version, node_id),
		)
	return version


# ─────────────────────────────────────────────────────────────────────────────
# Node Config (what the node needs to apply)
# ─────────────────────────────────────────────────────────────────────────────


def _get_tunnel_peer(conn: sqlite3.Connection, tunnel_peer_id: int | None) -> sqlite3.Row | None:
	"""Fetch tunnel peer row for a node if present."""
	if not tunnel_peer_id:
		return None
	return conn.execute("SELECT * FROM peers WHERE id = ?", (tunnel_peer_id,)).fetchone()


def _build_interfaces_config(
	conn: sqlite3.Connection,
	node_id: str,
	tunnel_peer: sqlite3.Row | None,
	pepper: str,
) -> list[dict[str, Any]]:
	"""Decrypt and assemble WireGuard interface configs for a node."""
	interfaces_map = {row["name"]: row for row in list_interfaces(conn)}
	tunnel_interface = tunnel_peer["interface"] if tunnel_peer else None

	ni_rows = conn.execute(
		"SELECT * FROM node_interfaces WHERE node_id = ?", (node_id,)
	).fetchall()
	interfaces: list[dict[str, Any]] = []
	for ni in ni_rows:
		iface = interfaces_map.get(ni["interface_name"])
		if iface is None:
			_log.warning("Orphaned node_interface: node=%s interface=%s", node_id, ni["interface_name"])
			continue

		interface_address = iface["address"]
		interface_address6 = iface["address6"]
		if tunnel_peer and ni["interface_name"] == tunnel_interface:
			address_parts = _split_addresses(tunnel_peer["peer_address"])
			if address_parts:
				interface_address = address_parts[0]
			interface_address6 = address_parts[1] if len(address_parts) >= 2 else None

		interfaces.append({
			"name": ni["interface_name"],
			"private_key": vault.decrypt_if_needed(ni["private_key"], pepper),
			"public_key": ni["public_key"],
			"address": interface_address,
			"address6": interface_address6,
			"listen_port": iface["listen_port"],
			"dns": iface["dns"],
			"post_up": iface["post_up"],
			"post_down": iface["post_down"],
		})

	return interfaces


def _build_peers_config(conn: sqlite3.Connection, node_id: str, pepper: str) -> list[dict[str, Any]]:
	"""Assemble peers assigned to a node for config delivery."""
	peer_rows = conn.execute(
		"SELECT * FROM peers WHERE node_id = ? AND is_enabled = 1",
		(node_id,),
	).fetchall()
	return [
		{
			"interface": p["interface"],
			"name": p["name"],
			"public_key": p["public_key"],
			"preshared_key": vault.decrypt_if_needed(p["preshared_key"], pepper) if p["preshared_key"] else None,
			"peer_address": p["peer_address"],
			"allowed_ips": p["allowed_ips"],
		}
		for p in peer_rows
	]


def _build_master_peer_config(conn: sqlite3.Connection, tunnel_peer: sqlite3.Row | None) -> dict[str, Any] | None:
	"""Build master peer configuration for the node tunnel."""
	if not tunnel_peer:
		return None

	master_iface = get_interface(conn, tunnel_peer["interface"])
	if not master_iface:
		return None

	master_fqdn = (get_setting(conn, "wg_fqdn") or "").strip() or None
	master_port = master_iface["listen_port"] or 51820
	if master_fqdn:
		try:
			addr = ipaddress.ip_address(master_fqdn)
			host = f"[{addr.compressed}]" if addr.version == 6 else addr.compressed
		except ValueError:
			host = master_fqdn
		master_endpoint = f"{host}:{master_port}"
	else:
		master_endpoint = None
		_log.warning("wg_fqdn not configured — master_peer endpoint will be empty")

	try:
		master_ip = str(ipaddress.ip_interface(master_iface["address"]).ip)
	except ValueError:
		master_ip = master_iface["address"].split("/")[0]
	allowed_ips = f"{master_ip}/32"

	if master_iface["address6"]:
		try:
			master_ip6 = str(ipaddress.ip_interface(master_iface["address6"]).ip)
			allowed_ips += f", {master_ip6}/128"
		except ValueError:
			pass

	return {
		"interface": tunnel_peer["interface"],
		"public_key": master_iface["public_key"],
		"endpoint": master_endpoint,
		"allowed_ips": allowed_ips,
		"tunnel_address": tunnel_peer["peer_address"],
	}


def get_node_config(
	conn: sqlite3.Connection,
	node_id: str,
	*,
	pepper: str | None = None,
) -> dict:
	"""Build the full configuration payload for a node.

	Returns a dict with interfaces (+ keypairs), assigned peers, and master_peer
	for the Node→Master DNS tunnel.
	
	Raises ValueError if node not found.
	"""
	pepper = pepper if pepper is not None else get_config().secret_key
	node = get_node(conn, node_id)
	if node is None:
		raise ValueError(f"Node not found: {node_id}")

	tunnel_peer = _get_tunnel_peer(conn, node["tunnel_peer_id"])
	interfaces = _build_interfaces_config(conn, node_id, tunnel_peer, pepper)
	peers = _build_peers_config(conn, node_id, pepper)

	master_peer = _build_master_peer_config(conn, tunnel_peer)

	_log.info(
		"NODE_CONFIG built for node=%s: interfaces=%d peers=%d master_peer=%s",
		node_id, len(interfaces), len(peers), master_peer is not None,
	)

	return {
		"config_version": node["config_version"],
		"interfaces": interfaces,
		"peers": peers,
		"master_peer": master_peer,
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
	pepper: str | None = None,
) -> None:
	"""Store an encrypted WireGuard keypair for a node's interface."""
	pepper = pepper if pepper is not None else get_config().secret_key
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


def get_all_tunnel_peer_ids(conn: sqlite3.Connection) -> set[int]:
	"""Return all peer IDs that serve as node tunnel peers.

	These peers are auto-created during node enrollment and should not
	be editable or deletable by users.
	"""
	rows = conn.execute(
		"SELECT tunnel_peer_id FROM nodes WHERE tunnel_peer_id IS NOT NULL"
	).fetchall()
	return {r["tunnel_peer_id"] for r in rows}


def get_peers_count_by_node(conn: sqlite3.Connection) -> dict[str | None, int]:
	"""Return peer counts for all nodes in one query (None key = local/master).

	Use this for list/bulk views. For a single node, prefer
	``get_peer_count_for_node``.
	"""
	rows = conn.execute(
		"SELECT node_id, COUNT(*) AS cnt FROM peers GROUP BY node_id"
	).fetchall()
	return {r["node_id"]: r["cnt"] for r in rows}


def get_peer_count_for_node(conn: sqlite3.Connection, node_id: str) -> int:
	"""Return peer count for one node.

	Use this for targeted checks; for bulk views use
	``get_peers_count_by_node``.
	"""
	row = conn.execute(
		"SELECT COUNT(*) AS cnt FROM peers WHERE node_id = ?",
		(node_id,),
	).fetchone()
	return int(row["cnt"] or 0) if row else 0


def get_tunnel_peer_info(conn: sqlite3.Connection, tunnel_peer_id: int) -> dict | None:
	"""Return tunnel peer's public_key and interface for WireGuard sync."""
	row = conn.execute(
		"SELECT public_key, interface FROM peers WHERE id = ?",
		(tunnel_peer_id,),
	).fetchone()
	if not row:
		return None
	return {"public_key": row["public_key"], "interface": row["interface"]}


def get_tunnel_peer_allowed_ips(conn: sqlite3.Connection, node_id: str) -> str | None:
	"""Compute the complete allowed-ips for a node's tunnel peer.

	Returns a comma-separated list of IPs including:
	- The node's own tunnel address
	- All peer addresses assigned to this node

	This allows the master to accept DNS traffic from all peers connected
	to the node, not just the node itself.
	"""
	node = get_node(conn, node_id)
	if not node or not node["tunnel_peer_id"]:
		return None
	return _compute_tunnel_allowed_ips(conn, node_id, node["tunnel_peer_id"])


def _compute_tunnel_allowed_ips(conn: sqlite3.Connection, node_id: str, tunnel_peer_id: int) -> str | None:
	"""Compute canonical allowed-ips list for a node tunnel peer."""
	tunnel_peer = conn.execute(
		"SELECT peer_address FROM peers WHERE id = ?",
		(tunnel_peer_id,),
	).fetchone()
	if not tunnel_peer:
		return None

	addresses: set[str] = set(_split_addresses(tunnel_peer["peer_address"]))
	peer_rows = conn.execute(
		"SELECT peer_address FROM peers WHERE node_id = ? AND is_enabled = 1",
		(node_id,),
	).fetchall()
	for row in peer_rows:
		addresses.update(_split_addresses(row["peer_address"]))

	return ", ".join(sorted(addresses)) if addresses else None


def update_tunnel_peer_allowed_ips(conn: sqlite3.Connection, node_id: str) -> bool:
	"""Update the tunnel peer's allowed_ips to include all node peer addresses.

	Should be called when:
	- A peer is assigned to this node
	- A peer is removed/reassigned from this node
	- A peer's address changes

	NOTE: Only `allowed_ips` is updated (what master accepts from this peer).
	`peer_address` remains unchanged (the node's own tunnel address).

	Returns True if the tunnel peer was updated.
	"""
	with transaction(conn, immediate=True):
		# Read, compute, and write inside one transaction to avoid stale data
		# from concurrent peer assignment changes.
		node = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
		if not node or not node["tunnel_peer_id"]:
			return False

		tunnel_peer_id = node["tunnel_peer_id"]
		new_allowed_ips = _compute_tunnel_allowed_ips(conn, node_id, tunnel_peer_id)
		if not new_allowed_ips:
			return False
		conn.execute(
			"UPDATE peers SET allowed_ips = ? WHERE id = ?",
			(new_allowed_ips, tunnel_peer_id),
		)

	_log.info(
		"Updated tunnel peer allowed_ips for node=%s: %s",
		node_id, new_allowed_ips,
	)
	return True
