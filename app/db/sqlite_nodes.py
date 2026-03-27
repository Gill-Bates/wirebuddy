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


def _validate_fqdn(fqdn: str) -> None:
	"""Validate FQDN format per RFC 1123.

	Rejects: consecutive dots, leading/trailing hyphens, empty labels,
	invalid characters, and domains exceeding 253 chars.
	"""
	fqdn = fqdn.strip()
	if not fqdn:
		raise ValueError("FQDN cannot be empty")
	if not _FQDN_RE.match(fqdn):
		raise ValueError(f"Invalid FQDN: {fqdn!r}")


def _validate_port(port: int) -> None:
	"""Validate port is in valid range."""
	if not (_MIN_PORT <= port <= _MAX_PORT):
		raise ValueError(f"Port out of valid range: {port}")


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
	_validate_fqdn(fqdn)
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
		_validate_fqdn(fqdn)
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


def delete_node(conn: sqlite3.Connection, node_id: str) -> bool:
	"""Delete a node, its tunnel peer, and unassign regular peers.

	The tunnel peer (created during enrollment for Node→Master DNS routing)
	is deleted along with the node. Regular peers assigned to this node have
	their node_id set to NULL (ON DELETE SET NULL).

	Also removes node_interfaces rows (ON DELETE CASCADE).
	Returns True if the node existed.
	"""
	with transaction(conn, immediate=True):
		# Delete tunnel peer first (by subquery) to avoid FK race
		cur = conn.execute(
			"DELETE FROM peers WHERE id IN (SELECT tunnel_peer_id FROM nodes WHERE id = ? AND tunnel_peer_id IS NOT NULL)",
			(node_id,),
		)
		if cur.rowcount > 0:
			_log.info("Deleted tunnel peer for node=%s", node_id)

		# Delete the node (peers.node_id set to NULL via FK ON DELETE SET NULL)
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
	becomes single-use. Only works on pending nodes to prevent race conditions.
	Returns True if the row was updated.
	"""
	with transaction(conn, immediate=True):
		cur = conn.execute(
			"UPDATE nodes SET api_secret_hash = ? WHERE id = ? AND status = ?",
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
			    enrolled_at = NULL
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
	"""Update node heartbeat timestamp and optional metadata JSON."""
	now = utcnow()
	meta_json = None
	if metadata:
		meta_json = json.dumps(metadata, default=str)
		if len(meta_json.encode("utf-8")) > _MAX_METADATA_SIZE:
			raise ValueError(f"Metadata exceeds maximum size ({_MAX_METADATA_SIZE} bytes)")
	with transaction(conn, immediate=True):
		cur = conn.execute(
			"UPDATE nodes SET last_seen = ?, metadata = COALESCE(?, metadata), status = ? WHERE id = ?",
			(now, meta_json, STATUS_ONLINE, node_id),
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
			UPDATE nodes SET status = ?
			WHERE status = ? AND last_seen < ?
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

	The version is a deterministic SHA-256 hash of all enabled peer public keys
	assigned to this node. Timestamp is NOT included to ensure idempotency.
	"""
	rows = conn.execute(
		"SELECT public_key FROM peers WHERE node_id = ? AND is_enabled = 1 ORDER BY public_key",
		(node_id,),
	).fetchall()
	payload = json.dumps(
		[r["public_key"] for r in rows],
		separators=(",", ":"),
	)
	version = hashlib.sha256(payload.encode("utf-8")).hexdigest()
	with transaction(conn, immediate=True):
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

	Returns a dict with interfaces (+ keypairs), assigned peers, and master_peer
	for the Node→Master DNS tunnel.
	
	Raises ValueError if node not found.
	"""
	import ipaddress  # Local import to avoid circular imports
	pepper = get_config().secret_key
	node = get_node(conn, node_id)
	if node is None:
		raise ValueError(f"Node not found: {node_id}")

	# Get tunnel peer info first (needed for interface address)
	tunnel_peer_id = node["tunnel_peer_id"]
	tunnel_peer = None
	tunnel_interface = None
	if tunnel_peer_id:
		tunnel_peer = conn.execute(
			"SELECT * FROM peers WHERE id = ?", (tunnel_peer_id,)
		).fetchone()
		if tunnel_peer:
			tunnel_interface = tunnel_peer["interface"]

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
			_log.warning("Orphaned node_interface: node=%s interface=%s", node_id, ni["interface_name"])
			continue

		# For the tunnel interface, use the tunnel_address instead of master's address
		# This allows the node to route DNS to the master
		interface_address = iface["address"]
		interface_address6 = iface["address6"]
		if tunnel_peer and ni["interface_name"] == tunnel_interface:
			# Use tunnel_address for this interface
			interface_address = tunnel_peer["peer_address"]
			# peer_address may contain both v4 and v6, parse correctly
			address_parts = [a.strip() for a in interface_address.split(",")]
			if len(address_parts) >= 1:
				interface_address = address_parts[0]  # First is IPv4
			if len(address_parts) >= 2:
				interface_address6 = address_parts[1]  # Second is IPv6
			else:
				interface_address6 = None

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

	# Assigned peers
	peer_rows = conn.execute(
		"SELECT * FROM peers WHERE node_id = ? AND is_enabled = 1",
		(node_id,),
	).fetchall()
	peers = []
	for p in peer_rows:
		peers.append({
			"interface": p["interface"],
			"name": p["name"],
			"public_key": p["public_key"],
			"preshared_key": vault.decrypt_if_needed(p["preshared_key"], pepper) if p["preshared_key"] else None,
			"peer_address": p["peer_address"],
			"allowed_ips": p["allowed_ips"],
		})

	_log.info(
		"NODE_CONFIG built for node=%s: interfaces=%d peers=%d",
		node_id, len(interfaces), len(peers),
	)

	# Master peer info for Node→Master DNS tunnel
	master_peer = None
	if tunnel_peer:
		# Get master interface info for this peer
		master_iface = conn.execute(
			"SELECT * FROM interfaces WHERE name = ?", (tunnel_peer["interface"],)
		).fetchone()
		if master_iface:
			# Build master endpoint from wg_fqdn + interface listen port
			fqdn_row = conn.execute(
				"SELECT value FROM settings WHERE key = 'wg_fqdn'"
			).fetchone()
			master_fqdn = fqdn_row["value"].strip() if fqdn_row and fqdn_row["value"] else None
			master_port = master_iface["listen_port"] or 51820
			if master_fqdn:
				# IPv6 addresses get brackets, hostnames stay as-is
				try:
					addr = ipaddress.ip_address(master_fqdn)
					host = f"[{addr.compressed}]" if addr.version == 6 else addr.compressed
				except ValueError:
					host = master_fqdn  # Hostname
				master_endpoint = f"{host}:{master_port}"
			else:
				master_endpoint = None
				_log.warning("wg_fqdn not configured — master_peer endpoint will be empty")

			# Extract gateway IP from interface address (e.g., "10.13.13.1/24" → "10.13.13.1")
			try:
				master_ip = str(ipaddress.ip_interface(master_iface["address"]).ip)
			except ValueError:
				master_ip = master_iface["address"].split("/")[0]
			# AllowedIPs = just the master's gateway IP for DNS routing
			allowed_ips = f"{master_ip}/32"
			# Add IPv6 if available
			if master_iface["address6"]:
				try:
					master_ip6 = str(ipaddress.ip_interface(master_iface["address6"]).ip)
					allowed_ips += f", {master_ip6}/128"
				except ValueError:
					pass
			master_peer = {
				"interface": tunnel_peer["interface"],
				"public_key": master_iface["public_key"],
				"endpoint": master_endpoint,
				"allowed_ips": allowed_ips,
				"tunnel_address": tunnel_peer["peer_address"],  # Node's address on master
			}

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
	"""Return {node_id: peer_count} for all nodes (None key = local/master)."""
	rows = conn.execute(
		"SELECT node_id, COUNT(*) AS cnt FROM peers GROUP BY node_id"
	).fetchall()
	return {r["node_id"]: r["cnt"] for r in rows}


def get_peer_count_for_node(conn: sqlite3.Connection, node_id: str) -> int:
	"""Return the number of peers currently assigned to ``node_id``."""
	row = conn.execute(
		"SELECT COUNT(*) AS cnt FROM peers WHERE node_id = ?",
		(node_id,),
	).fetchone()
	return int(row["cnt"] or 0) if row else 0
