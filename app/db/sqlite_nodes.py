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
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any

from ..node.events import NodeCommandType
from ..utils.config import get_config
from ..utils.time import parse_utc, utcnow
from ..utils import vault
from .sqlite_interfaces import get_interface, list_interfaces
from .sqlite_settings import get_setting
from .sqlite_runtime import transaction

_log = logging.getLogger(__name__)

# Input validation constants
_MAX_METADATA_SIZE = 4096  # bytes
_MAX_COMMAND_PAYLOAD_SIZE = 16_384  # bytes
_MAX_PORT = 65535
_MIN_PORT = 1

# Node status constants
STATUS_PENDING = "pending"
STATUS_ONLINE = "online"
STATUS_OFFLINE = "offline"
STATUS_ERROR = "error"

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
	- Bracketed IPv6 input is accepted and normalized.
	"""
	fqdn = fqdn.strip()
	_validate_fqdn_or_ip(fqdn)
	addr = _parse_ip_or_none(fqdn)
	if addr is None:
		return fqdn.lower()
	return f"[{addr.compressed}]" if addr.version == 6 else addr.compressed


def _resolve_pepper(pepper: str | None) -> str:
	"""Return the provided pepper or fall back to the configured secret key."""
	return pepper if pepper is not None else get_config().secret_key


def _validate_port(port: int) -> None:
	"""Validate port is in valid range."""
	if not (_MIN_PORT <= port <= _MAX_PORT):
		raise ValueError(f"Port out of valid range: {port}")


def _validate_name(name: str) -> None:
	"""Validate a normalized node name."""
	if not name:
		raise ValueError("Node name cannot be empty")
	if len(name) > 63:
		raise ValueError("Node name exceeds 63 characters")


def _normalize_name(name: str) -> str:
	"""Normalize node names consistently before lookup or persistence."""
	normalized = unicodedata.normalize("NFKC", str(name)).strip()
	_validate_name(normalized)
	return normalized


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
	name = _normalize_name(name)
	fqdn = _canonicalize_fqdn_or_ip(fqdn)
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
	name = _normalize_name(name)
	return conn.execute("SELECT * FROM nodes WHERE name = ?", (name,)).fetchone()


def get_node_by_fqdn(conn: sqlite3.Connection, fqdn: str) -> sqlite3.Row | None:
	"""Fetch a single node by FQDN."""
	normalized = _canonicalize_fqdn_or_ip(fqdn)
	return conn.execute("SELECT * FROM nodes WHERE fqdn = ?", (normalized,)).fetchone()


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
	show_on_dashboard: bool | None = None,
) -> bool:
	"""Update mutable node fields. Returns True if found and updated."""
	updates: list[str] = []
	params: list[Any] = []

	if name is not None:
		name = _normalize_name(name)
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
	if show_on_dashboard is not None:
		updates.append("show_on_dashboard = ?")
		params.append(int(show_on_dashboard))

	if not updates:
		raise ValueError("No fields provided for update")

	params.append(node_id)
	sql = f"UPDATE nodes SET {', '.join(updates)} WHERE id = ?"
	with transaction(conn, immediate=True):
		cur = conn.execute(sql, params)
		return cur.rowcount > 0


def delete_node(conn: sqlite3.Connection, node_id: str) -> int | None:
	"""Delete a node and return the prior number of assigned peers.

	Schema-side effects:
	- ``node_interfaces`` rows are removed via ``ON DELETE CASCADE``.
	- ``peers.node_id`` is set to ``NULL`` via ``ON DELETE SET NULL``.

	The node tunnel peer, if present, is explicitly deleted before the node.
	Returns ``None`` if the node does not exist.
	"""
	with transaction(conn, immediate=True):
		row = conn.execute(
			"SELECT tunnel_peer_id FROM nodes WHERE id = ?",
			(node_id,),
		).fetchone()
		if not row:
			return None

		assigned_peer_count = conn.execute(
			"SELECT COUNT(*) FROM peers WHERE node_id = ?",
			(node_id,),
		).fetchone()[0]

		if row["tunnel_peer_id"]:
			cur = conn.execute(
				"""
				DELETE FROM peers
				WHERE id = ?
				  AND id IN (
					SELECT tunnel_peer_id
					FROM nodes
					WHERE id = ?
				  )
				""",
				(row["tunnel_peer_id"], node_id),
			)
			if cur.rowcount > 0:
				_log.info("Deleted tunnel peer for node=%s", node_id)

		conn.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
		_log.info("Deleted node=%s (assigned_peers=%d)", node_id, assigned_peer_count)
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
	"""Rotate the session API secret hash for an enrolled node.

	Called after enrollment to replace the one-time enrollment secret with the
	node's session credential. Only applies to non-pending nodes.
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
	metadata: dict[str, Any] | None = None,
) -> bool:
	"""Update node heartbeat timestamp and optional metadata JSON.

	If ``metadata`` is None, existing metadata is preserved.
	"""
	now = utcnow()
	meta_json = None
	if metadata is not None:
		try:
			meta_json = json.dumps(metadata)
		except TypeError as exc:
			raise ValueError("Metadata must be JSON-serializable") from exc
		if len(meta_json.encode("utf-8")) > _MAX_METADATA_SIZE:
			raise ValueError(f"Metadata exceeds maximum size ({_MAX_METADATA_SIZE} bytes)")
	with transaction(conn, immediate=True):
		# Only set status to 'online' if not in error state
		cur = conn.execute(
			"""
			UPDATE nodes
			SET last_seen = ?,
			    metadata = COALESCE(?, metadata),
			    status = CASE WHEN status != ? THEN ? ELSE status END
			WHERE id = ?
			""",
			(now, meta_json, STATUS_ERROR, STATUS_ONLINE, node_id),
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
	now = utcnow()
	if ts > now + timedelta(minutes=1):
		_log.warning("Ignoring future sse_connected_at for node=%s: %s", node_id, ts.isoformat())
		return False
	return ts >= cutoff


# ─────────────────────────────────────────────────────────────────────────────
# Pending Commands (Multi-Worker Safe)
# ─────────────────────────────────────────────────────────────────────────────

# Valid commands for node control
VALID_NODE_COMMANDS = frozenset(command.value for command in NodeCommandType)


def _serialize_command_payload(payload: dict[str, Any] | None) -> str:
	"""Serialize command payload as compact JSON."""
	if payload is None:
		return "{}"
	try:
		raw = json.dumps(payload, separators=(",", ":"), sort_keys=True)
	except TypeError as exc:
		raise ValueError("Command payload must be JSON-serializable") from exc
	if len(raw.encode("utf-8")) > _MAX_COMMAND_PAYLOAD_SIZE:
		raise ValueError("Command payload too large")
	return raw


def _parse_command_payload(raw: Any) -> dict[str, Any]:
	"""Parse a stored JSON command payload defensively."""
	if not raw:
		return {}
	try:
		parsed = json.loads(str(raw))
	except (TypeError, ValueError, json.JSONDecodeError):
		_log.warning("Invalid node command payload: %r", raw)
		return {}
	return parsed if isinstance(parsed, dict) else {}


def enqueue_node_command(
	conn: sqlite3.Connection,
	node_id: str,
	command: str,
	*,
	payload: dict[str, Any] | None = None,
) -> int | None:
	"""Persist a durable command for one node and return its row ID."""
	if command not in VALID_NODE_COMMANDS:
		raise ValueError(f"Invalid node command: {command!r}. Valid: {sorted(VALID_NODE_COMMANDS)}")

	now = utcnow()
	with transaction(conn, immediate=True):
		row = conn.execute("SELECT 1 FROM nodes WHERE id = ?", (node_id,)).fetchone()
		if row is None:
			return None
		cur = conn.execute(
			"""
			INSERT INTO node_commands (node_id, command_type, payload, created_at)
			VALUES (?, ?, ?, ?)
			""",
			(node_id, command, _serialize_command_payload(payload), now),
		)
		return int(cur.lastrowid)


def claim_pending_node_commands(
	conn: sqlite3.Connection,
	node_id: str,
	*,
	replay_after_seconds: int = 30,
	limit: int = 20,
) -> list[dict[str, Any]]:
	"""Claim replayable commands for SSE delivery and mark them as delivered."""
	if limit <= 0:
		return []

	threshold = utcnow() - timedelta(seconds=max(0, replay_after_seconds))
	now = utcnow()
	with transaction(conn, immediate=True):
		candidate_rows = conn.execute(
			"""
			SELECT id, node_id, command_type, payload, created_at, delivered_at, acked_at
			FROM node_commands
			WHERE node_id = ?
			  AND acked_at IS NULL
			  AND (delivered_at IS NULL OR delivered_at < ?)
			ORDER BY created_at ASC, id ASC
			LIMIT ?
			""",
			(node_id, threshold, limit),
		).fetchall()
		if not candidate_rows:
			return []

		claimed_rows: list[sqlite3.Row] = []
		for row in candidate_rows:
			cur = conn.execute(
				"""
				UPDATE node_commands
				SET delivered_at = ?
				WHERE id = ?
				  AND node_id = ?
				  AND acked_at IS NULL
				  AND (delivered_at IS NULL OR delivered_at < ?)
				""",
				(now, int(row["id"]), node_id, threshold),
			)
			if cur.rowcount > 0:
				claimed_rows.append(row)

		if not claimed_rows:
			return []

		return [
			{
				"id": int(row["id"]),
				"node_id": row["node_id"],
				"command_type": str(row["command_type"]),
				"payload": _parse_command_payload(row["payload"]),
				"created_at": row["created_at"],
				"delivered_at": row["delivered_at"],
				"acked_at": row["acked_at"],
			}
			for row in claimed_rows
		]


def ack_node_command(conn: sqlite3.Connection, node_id: str, command_id: int) -> bool:
	"""Acknowledge one delivered command."""
	now = utcnow()
	with transaction(conn, immediate=True):
		cur = conn.execute(
			"""
			UPDATE node_commands
			SET acked_at = ?
			WHERE id = ? AND node_id = ? AND acked_at IS NULL
			""",
			(now, int(command_id), node_id),
		)
		return cur.rowcount > 0


def mark_node_command_delivered(conn: sqlite3.Connection, node_id: str, command_id: int) -> bool:
	"""Stamp one durable command as delivered to an active SSE stream."""
	now = utcnow()
	with transaction(conn, immediate=True):
		cur = conn.execute(
			"""
			UPDATE node_commands
			SET delivered_at = ?
			WHERE id = ? AND node_id = ? AND acked_at IS NULL
			""",
			(now, int(command_id), node_id),
		)
		return cur.rowcount > 0


def set_node_pending_command(conn: sqlite3.Connection, node_id: str, command: str) -> bool:
	"""Compatibility wrapper for the legacy single-slot pending command field."""
	command_id = enqueue_node_command(conn, node_id, command)
	return command_id is not None


def get_and_clear_node_pending_command(conn: sqlite3.Connection, node_id: str) -> str | None:
	"""Compatibility wrapper that returns one unacked durable command."""
	commands = claim_pending_node_commands(conn, node_id, replay_after_seconds=0, limit=1)
	if not commands:
		return None
		
	return str(commands[0]["command_type"])


def clear_node_pending_command(conn: sqlite3.Connection, node_id: str) -> None:
	"""Compatibility helper that acks all currently replayable commands."""
	commands = claim_pending_node_commands(conn, node_id, replay_after_seconds=0, limit=100)
	for command in commands:
		ack_node_command(conn, node_id, int(command["id"]))


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
	assigned to this node, including roaming peers served on all nodes.
	Timestamp is NOT included to ensure idempotency.
	"""
	with transaction(conn, immediate=True):
		cursor = conn.execute(
			"""
			SELECT
				public_key,
				allowed_ips,
				interface,
				peer_address,
				name,
				COALESCE(preshared_key, '') AS preshared_key
			FROM peers
			WHERE (node_id = ? OR allow_all_nodes = 1) AND is_enabled = 1
			ORDER BY public_key
			""",
			(node_id,),
		)
		hasher = hashlib.sha256()
		for row in cursor:
			hasher.update(b"\x1e")
			hasher.update(
				json.dumps(
					{
						"allowed_ips": row["allowed_ips"],
						"interface": row["interface"],
						"name": row["name"],
						"peer_address": row["peer_address"],
						"preshared_key": row["preshared_key"],
						"public_key": row["public_key"],
					},
					separators=(",", ":"),
					sort_keys=True,
				).encode("utf-8")
			)
		version = hasher.hexdigest()
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
) -> list[dict[str, Any]]:
	"""Assemble interface configs for a node with encrypted private keys intact."""
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
			"private_key_enc": ni["private_key"],
			"public_key": ni["public_key"],
			"address": interface_address,
			"address6": interface_address6,
			"listen_port": iface["listen_port"],
			"dns": iface["dns"],
			"post_up": iface["post_up"],
			"post_down": iface["post_down"],
		})

	return interfaces


def _build_peers_config(conn: sqlite3.Connection, node_id: str) -> list[dict[str, Any]]:
	"""Assemble peers assigned to a node for config delivery.
	
	Includes:
	- Peers explicitly assigned to this node (node_id = ?)
	- Peers with allow_all_nodes=1 (roaming peers available on all nodes)
	"""
	peer_rows = conn.execute(
		"SELECT * FROM peers WHERE (node_id = ? OR allow_all_nodes = 1) AND is_enabled = 1",
		(node_id,),
	).fetchall()
	return [
		{
			"interface": p["interface"],
			"name": p["name"],
			"public_key": p["public_key"],
			"preshared_key_enc": p["preshared_key"],
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
		_log.warning(
			"Invalid master interface address %r; using fallback value %r",
			master_iface["address"],
			master_ip,
		)
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
) -> dict[str, Any]:
	"""Build the full configuration payload for a node.

	Args:
		conn: Active SQLite connection.
		node_id: Node identifier.
		pepper: Encryption pepper for private-key decryption. Defaults to the
			configured application secret key.

	Returns a dict with interfaces (+ keypairs), assigned peers, and master_peer
	for the Node→Master DNS tunnel.
	
	Raises ValueError if node not found.
	"""
	pepper = _resolve_pepper(pepper)
	with transaction(conn):
		node = get_node(conn, node_id)
		if node is None:
			raise ValueError(f"Node not found: {node_id}")

		tunnel_peer = _get_tunnel_peer(conn, node["tunnel_peer_id"])
		interfaces_enc = _build_interfaces_config(conn, node_id, tunnel_peer)
		peers_enc = _build_peers_config(conn, node_id)
		master_peer = _build_master_peer_config(conn, tunnel_peer)

		interfaces = [
			{
				**item,
				"private_key": vault.decrypt_required(str(item.pop("private_key_enc")), pepper),
			}
			for item in interfaces_enc
		]
		peers = [
			{
				**item,
				"preshared_key": vault.decrypt_required(item.pop("preshared_key_enc"), pepper)
				if item.get("preshared_key_enc")
				else None,
			}
			for item in peers_enc
		]

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
	pepper = _resolve_pepper(pepper)
	now = utcnow()
	with transaction(conn, immediate=True):
		conn.execute(
			"""
			INSERT INTO node_interfaces
				(node_id, interface_name, private_key, public_key, created_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(node_id, interface_name) DO UPDATE SET
				private_key = excluded.private_key,
				public_key = excluded.public_key,
				created_at = excluded.created_at
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
	"""Return a mapping of node_id to peer count for all nodes.

	The ``None`` key represents peers assigned to the master/local node.
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
	with transaction(conn):
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
		"SELECT peer_address FROM peers WHERE (node_id = ? OR allow_all_nodes = 1) AND is_enabled = 1",
		(node_id,),
	).fetchall()
	for row in peer_rows:
		addresses.update(_split_addresses(row["peer_address"]))

	def _sort_key(value: str) -> tuple[int, bytes, int, str]:
		try:
			iface = ipaddress.ip_interface(value)
			return (iface.version, iface.ip.packed, iface.network.prefixlen, iface.compressed)
		except ValueError:
			return (99, value.encode("utf-8"), 0, value)

	return ", ".join(sorted(addresses, key=_sort_key)) if addresses else None


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
		node = conn.execute("SELECT tunnel_peer_id FROM nodes WHERE id = ?", (node_id,)).fetchone()
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
