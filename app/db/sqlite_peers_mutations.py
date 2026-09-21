#!/usr/bin/env python3
#
# app/db/sqlite_peers_mutations.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Peer mutation (create/update/delete) helpers."""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import sqlite3

from ..utils import vault
from ..utils.config import get_config
from ..utils.time import utcnow
from .sqlite_interfaces import get_interface
from .sqlite_runtime import UNSET, UnsetType, transaction

_VALID_ALLOWED_IPS_MODES = frozenset({"full", "split", "custom"})
_ALLOWED_UPDATE_ASSIGNMENTS = frozenset({
	"name = ?",
	"private_key = ?",
	"preshared_key = ?",
	"allowed_ips = ?",
	"allowed_ips_mode = ?",
	"endpoint = ?",
	"is_enabled = ?",
	"use_adblocker = ?",
	"dns_logging_enabled = ?",
	"blocklist_ids = ?",
	"client_isolation = ?",
	"node_id = ?",
	"allow_all_nodes = ?",
	"updated_at = ?",
})

_log = logging.getLogger(__name__)
_MAX_BLOCKLIST_IDS = 128
_MAX_BLOCKLIST_ID_LENGTH = 128
_MAX_BLOCKLIST_IDS_BYTES = 8192
_MAX_ALLOWED_IPS_ENTRIES = 64
_MAX_PEER_ADDRESS_ENTRIES = 8


def _normalize_cidr_csv(value: str, *, field: str, max_entries: int, interface_mode: bool = False) -> str:
	"""Validate and normalize a comma-separated CIDR/interface list."""
	parts = [part.strip() for part in str(value or "").split(",") if part.strip()]
	if not parts:
		raise ValueError(f"{field} must not be empty")
	if len(parts) > max_entries:
		raise ValueError(f"{field} exceeds maximum entry count")
	normalized: list[str] = []
	for part in parts:
		try:
			if interface_mode:
				normalized.append(ipaddress.ip_interface(part).with_prefixlen)
			else:
				normalized.append(ipaddress.ip_network(part, strict=False).with_prefixlen)
		except ValueError as exc:
			raise ValueError(f"Invalid {field} entry: {part!r}") from exc
	return ", ".join(normalized)


def _validate_allowed_ips_mode(allowed_ips_mode: str) -> str:
	"""Validate the allowed-IPs mode before writing it to the database."""
	if allowed_ips_mode not in _VALID_ALLOWED_IPS_MODES:
		raise ValueError(f"Invalid allowed_ips_mode: {allowed_ips_mode!r}")
	return allowed_ips_mode


def _maybe_encrypt(value: str | None, pepper: str) -> str | None:
	"""Encrypt a value if present; preserve None for nullable DB fields."""
	if value is None:
		return None
	return vault.encrypt_if_needed(value, pepper)


def _require_not_none(value: object, field: str) -> None:
	"""Raise ValueError for explicit None on NOT NULL update fields."""
	if value is None:
		raise ValueError(f"{field} cannot be None")


def _serialize_blocklist_ids(blocklist_ids: list[str] | None) -> str | None:
	"""Serialize blocklist IDs; NULL means all blocklists enabled."""
	if blocklist_ids is None:
		return None
	if not isinstance(blocklist_ids, list) or not all(isinstance(item, str) for item in blocklist_ids):
		raise ValueError("blocklist_ids must be a list of strings")
	if len(blocklist_ids) > _MAX_BLOCKLIST_IDS:
		raise ValueError("blocklist_ids exceeds maximum entry count")
	normalized: list[str] = []
	for item in blocklist_ids:
		value = item.strip()
		if not value:
			raise ValueError("blocklist_ids entries must be non-empty strings")
		if len(value) > _MAX_BLOCKLIST_ID_LENGTH:
			raise ValueError("blocklist_id too long")
		normalized.append(value)
	payload = json.dumps(normalized, separators=(",", ":"))
	if len(payload.encode("utf-8")) > _MAX_BLOCKLIST_IDS_BYTES:
		raise ValueError("blocklist_ids payload too large")
	return payload


def _assert_safe_update_assignments(assignments: list[str]) -> None:
	"""Ensure UPDATE assignments are from the fixed set of supported columns."""
	if not all(item in _ALLOWED_UPDATE_ASSIGNMENTS for item in assignments):
		raise ValueError("Unsafe SQL assignment in update list")


def _validate_peer_policy_state(
	*,
	allowed_ips: str,
	allowed_ips_mode: str,
	node_id: str | None,
	allow_all_nodes: bool,
) -> None:
	"""Validate cross-field policy invariants against a concrete, fully-resolved state.

	Single source of truth for both create_peer() and update_peer(): the
	Pydantic models (PeerCreate/PeerUpdate) enforce the same invariants, but
	only over fields present in a single request. A direct DB caller, or a
	partial PeerUpdate that combines with an already-stored value on the
	row, can bypass that. This must always be called with already-merged,
	effective values — never with UNSET/omitted fields.
	"""
	if allow_all_nodes and node_id is not None:
		raise ValueError("allow_all_nodes cannot be combined with node_id")

	if allowed_ips_mode == "full":
		actual = {ip.strip() for ip in str(allowed_ips or "").split(",")}
		if not actual.issuperset({"0.0.0.0/0", "::/0"}):
			raise ValueError("allowed_ips_mode='full' requires both 0.0.0.0/0 and ::/0 in allowed_ips")


def _assert_effective_state_consistent(
	conn: sqlite3.Connection,
	peer_id: int,
	*,
	node_id: str | UnsetType | None,
	allow_all_nodes: bool | UnsetType | None,
	allowed_ips_mode: str | UnsetType | None,
	allowed_ips: str | UnsetType | None,
) -> None:
	"""Validate policy invariants against the effective post-update state.

	PeerUpdate's Pydantic validators only see fields present in a single
	request; a partial update (e.g. only ``node_id``) can silently combine
	with an unrelated field already stored on the row (e.g. an existing
	``allow_all_nodes=True``) to violate an invariant the model appears to
	guarantee. This loads the current row inside the caller's IMMEDIATE
	transaction (no separate read before the lock, so no TOCTOU window),
	merges it with the requested changes, and validates the merged
	(effective) state — the same values the UPDATE below is about to
	persist — instead of validating the request in isolation.
	"""
	if node_id is UNSET and allow_all_nodes is UNSET and allowed_ips_mode is UNSET and allowed_ips is UNSET:
		return

	row = conn.execute(
		"SELECT node_id, allow_all_nodes, allowed_ips_mode, allowed_ips FROM peers WHERE id = ?",
		(peer_id,),
	).fetchone()
	if row is None:
		return  # Peer missing; UPDATE below will affect 0 rows and the caller handles that.

	_validate_peer_policy_state(
		allowed_ips=row["allowed_ips"] if allowed_ips is UNSET else allowed_ips,
		allowed_ips_mode=row["allowed_ips_mode"] if allowed_ips_mode is UNSET else allowed_ips_mode,
		node_id=row["node_id"] if node_id is UNSET else node_id,
		allow_all_nodes=bool(row["allow_all_nodes"]) if allow_all_nodes is UNSET else bool(allow_all_nodes),
	)


def _require_bool(value: object, field: str) -> bool:
	"""Require a strict bool value and return it."""
	if type(value) is not bool:
		raise ValueError(f"{field} must be a boolean")
	return value


def _extract_ips(cidr_csv: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
	"""Extract the bare IP addresses from a comma-separated CIDR/interface list."""
	ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
	for raw_part in cidr_csv.split(","):
		part = raw_part.strip()
		if not part:
			continue
		try:
			ips.append(ipaddress.ip_interface(part).ip)
		except ValueError:
			continue
	return ips


def _assert_peer_address_not_in_use(
	conn: sqlite3.Connection,
	*,
	interface: str,
	peer_address: str,
	exclude_peer_id: int | None = None,
) -> None:
	"""Reject peer_address values whose individual IPs collide with another peer.

	The unique index on (peer_address, interface) only protects the exact
	normalized string; two peers can still hold the same single IP inside
	differently-composed CSV lists (e.g. IPv4-only vs. dual-stack), which
	would create overlapping WireGuard routes. Compares parsed IPs, not raw
	strings, and runs inside the caller's IMMEDIATE transaction.
	"""
	candidate_ips = set(_extract_ips(peer_address))
	if not candidate_ips:
		return
	rows = conn.execute(
		"SELECT id, peer_address FROM peers WHERE interface = ? AND peer_address IS NOT NULL",
		(interface,),
	).fetchall()
	for row in rows:
		if exclude_peer_id is not None and int(row["id"]) == exclude_peer_id:
			continue
		if candidate_ips & set(_extract_ips(str(row["peer_address"] or ""))):
			raise ValueError(
				f"peer_address overlaps with an IP already assigned to peer {row['id']} on interface {interface!r}"
			)


def _validate_public_key(public_key: str) -> str:
	"""Validate a WireGuard public key before persisting it."""
	public_key = public_key.strip()
	if len(public_key) != 44:
		raise ValueError("Invalid WireGuard public key format")
	try:
		decoded = base64.b64decode(public_key, validate=True)
	except Exception as exc:
		raise ValueError("Invalid WireGuard public key format") from exc
	if len(decoded) != 32:
		raise ValueError("Invalid WireGuard public key format")
	return public_key


def create_peer(
	conn: sqlite3.Connection,
	public_key: str,
	allowed_ips: str,
	name: str | None = None,
	endpoint: str | None = None,
	interface: str = "wg0",
	private_key: str | None = None,
	preshared_key: str | None = None,
	peer_address: str | None = None,
	allowed_ips_mode: str = "full",
	use_adblocker: bool = True,
	dns_logging_enabled: bool = True,
	blocklist_ids: list[str] | None = None,
	client_isolation: bool = False,
	node_id: str | None = None,
	allow_all_nodes: bool = False,
) -> int:
	"""Create a new peer and return the peer ID.

	blocklist_ids: JSON array of enabled blocklist IDs (e.g., ["ads", "porn"]).
	               None means all blocklists enabled.
	client_isolation: If True, peer cannot communicate with other peers (iptables isolation).
	node_id: If set, peer is assigned to a remote node (not local WireGuard).
	allow_all_nodes: If True, peer can connect to all nodes (roaming mode).
	"""
	now = utcnow()
	public_key = _validate_public_key(public_key)
	allowed_ips = _normalize_cidr_csv(allowed_ips, field="allowed_ips", max_entries=_MAX_ALLOWED_IPS_ENTRIES)
	peer_address = (
		_normalize_cidr_csv(peer_address, field="peer_address", max_entries=_MAX_PEER_ADDRESS_ENTRIES, interface_mode=True)
		if peer_address is not None
		else None
	)
	blocklist_ids_json = _serialize_blocklist_ids(blocklist_ids)
	pepper = get_config().secret_key
	private_key_stored = _maybe_encrypt(private_key, pepper)
	preshared_key_stored = _maybe_encrypt(preshared_key, pepper)
	allowed_ips_mode = _validate_allowed_ips_mode(allowed_ips_mode)
	use_adblocker = _require_bool(use_adblocker, "use_adblocker")
	dns_logging_enabled = _require_bool(dns_logging_enabled, "dns_logging_enabled")
	client_isolation = _require_bool(client_isolation, "client_isolation")
	allow_all_nodes = _require_bool(allow_all_nodes, "allow_all_nodes")
	_validate_peer_policy_state(
		allowed_ips=allowed_ips,
		allowed_ips_mode=allowed_ips_mode,
		node_id=node_id,
		allow_all_nodes=allow_all_nodes,
	)
	peer_id: int
	with transaction(conn, immediate=True):
		if conn.execute("SELECT 1 FROM peers WHERE public_key = ?", (public_key,)).fetchone():
			raise ValueError(f"Peer with public_key {public_key!r} already exists")
		if get_interface(conn, interface) is None:
			raise ValueError(f"Unknown interface: {interface!r}")
		if peer_address is not None:
			_assert_peer_address_not_in_use(conn, interface=interface, peer_address=peer_address)
		cur = conn.execute(
			"""
			INSERT INTO peers (
				public_key, private_key, preshared_key, name,
				allowed_ips, endpoint, interface, peer_address, allowed_ips_mode,
				use_adblocker, dns_logging_enabled, blocklist_ids, client_isolation,
				node_id, allow_all_nodes, created_at, updated_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			""",
			(
				public_key,
				private_key_stored,
				preshared_key_stored,
				name,
				allowed_ips,
				endpoint,
				interface,
				peer_address,
				allowed_ips_mode,
				int(use_adblocker),
				int(dns_logging_enabled),
				blocklist_ids_json,
				int(client_isolation),
				node_id,
				int(allow_all_nodes),
				now,
				now,
			),
		)
		peer_id = int(cur.lastrowid)
	return peer_id


def update_peer(
	conn: sqlite3.Connection,
	peer_id: int,
	name: str | UnsetType | None = UNSET,
	allowed_ips: str | UnsetType | None = UNSET,
	allowed_ips_mode: str | UnsetType | None = UNSET,
	endpoint: str | UnsetType | None = UNSET,
	is_enabled: bool | UnsetType | None = UNSET,
	use_adblocker: bool | UnsetType | None = UNSET,
	dns_logging_enabled: bool | UnsetType | None = UNSET,
	blocklist_ids: list[str] | UnsetType | None = UNSET,
	client_isolation: bool | UnsetType | None = UNSET,
	private_key: str | UnsetType | None = UNSET,
	preshared_key: str | UnsetType | None = UNSET,
	node_id: str | UnsetType | None = UNSET,
	allow_all_nodes: bool | UnsetType | None = UNSET,
) -> bool:
	"""Update a peer by ID. Returns True if peer was found and updated.

	Parameters:
		name, endpoint: Can be set to None (NULL in database).
		private_key, preshared_key: Use UNSET to leave unchanged, None to clear,
			or a plaintext/encrypted value to persist.
		allowed_ips, allowed_ips_mode: Cannot be None (NOT NULL constraint).
			Pass UNSET to leave unchanged, or a string value to update.
		is_enabled, use_adblocker, dns_logging_enabled, client_isolation: Cannot be None.
			Pass UNSET to leave unchanged, False to disable, or True to enable.
		blocklist_ids: Use UNSET to leave unchanged, None to reset to all,
			or a list of IDs to set specific blocklists.
	"""
	pepper = get_config().secret_key
	updates: list[str] = []
	params: list[object] = []

	if name is not UNSET:
		updates.append("name = ?")
		params.append(name)
	if private_key is not UNSET:
		updates.append("private_key = ?")
		params.append(_maybe_encrypt(private_key, pepper))
	if preshared_key is not UNSET:
		updates.append("preshared_key = ?")
		params.append(_maybe_encrypt(preshared_key, pepper))
	if allowed_ips is not UNSET:
		_require_not_none(allowed_ips, "allowed_ips")
		updates.append("allowed_ips = ?")
		params.append(_normalize_cidr_csv(allowed_ips, field="allowed_ips", max_entries=_MAX_ALLOWED_IPS_ENTRIES))
	if allowed_ips_mode is not UNSET:
		_require_not_none(allowed_ips_mode, "allowed_ips_mode")
		updates.append("allowed_ips_mode = ?")
		params.append(_validate_allowed_ips_mode(allowed_ips_mode))
	if endpoint is not UNSET:
		updates.append("endpoint = ?")
		params.append(endpoint)
	if is_enabled is not UNSET:
		_require_not_none(is_enabled, "is_enabled")
		updates.append("is_enabled = ?")
		params.append(int(_require_bool(is_enabled, "is_enabled")))
	if use_adblocker is not UNSET:
		_require_not_none(use_adblocker, "use_adblocker")
		updates.append("use_adblocker = ?")
		params.append(int(_require_bool(use_adblocker, "use_adblocker")))
	if dns_logging_enabled is not UNSET:
		_require_not_none(dns_logging_enabled, "dns_logging_enabled")
		updates.append("dns_logging_enabled = ?")
		params.append(int(_require_bool(dns_logging_enabled, "dns_logging_enabled")))
	if blocklist_ids is not UNSET:
		updates.append("blocklist_ids = ?")
		params.append(_serialize_blocklist_ids(blocklist_ids))
	if client_isolation is not UNSET:
		_require_not_none(client_isolation, "client_isolation")
		updates.append("client_isolation = ?")
		params.append(int(_require_bool(client_isolation, "client_isolation")))
	if node_id is not UNSET:
		updates.append("node_id = ?")
		params.append(node_id)
	if allow_all_nodes is not UNSET:
		_require_not_none(allow_all_nodes, "allow_all_nodes")
		updates.append("allow_all_nodes = ?")
		params.append(int(_require_bool(allow_all_nodes, "allow_all_nodes")))

	if not updates:
		return False

	updates.append("updated_at = ?")
	_assert_safe_update_assignments(updates)
	params.append(utcnow())
	params.append(peer_id)
	sql = f"UPDATE peers SET {', '.join(updates)} WHERE id = ?"

	with transaction(conn, immediate=True):
		_assert_effective_state_consistent(
			conn,
			peer_id,
			node_id=node_id,
			allow_all_nodes=allow_all_nodes,
			allowed_ips_mode=allowed_ips_mode,
			allowed_ips=allowed_ips,
		)
		cur = conn.execute(sql, params)
		return cur.rowcount > 0


def delete_peer(conn: sqlite3.Connection, peer_id: int) -> bool:
	"""Delete a peer by ID.

	Note: This only removes the database row. Callers are responsible for
	removing the peer from the live WireGuard interface first.
	"""
	deleted = False
	with transaction(conn, immediate=True):
		if conn.execute("SELECT 1 FROM nodes WHERE tunnel_peer_id = ?", (peer_id,)).fetchone():
			raise ValueError(f"Peer {peer_id} is an active node tunnel peer; remove the node first")
		cur = conn.execute("DELETE FROM peers WHERE id = ?", (peer_id,))
		deleted = cur.rowcount > 0

	if deleted:
		_log.info("PEER_DELETE peer_id=%d", peer_id)
	else:
		_log.debug("PEER_DELETE peer_id=%d not found", peer_id)
	return deleted
