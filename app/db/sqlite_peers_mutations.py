#!/usr/bin/env python3
#
# app/db/sqlite_peers_mutations.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Peer mutation (create/update/delete) helpers."""

from __future__ import annotations

import json
import logging
import re
import sqlite3

from ..utils.config import get_config
from ..utils.time import utcnow
from ..utils import vault
from .sqlite_runtime import UNSET, UnsetType, transaction

_VALID_ALLOWED_IPS_MODES = frozenset({"full", "split", "custom"})
_UPDATE_ASSIGNMENT_RE = re.compile(r"^[a-z_]+ = \?$")

_log = logging.getLogger(__name__)


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
	return json.dumps(blocklist_ids)


def _assert_safe_update_assignments(assignments: list[str]) -> None:
	"""Ensure UPDATE assignments are static `column = ?` fragments only."""
	if not all(_UPDATE_ASSIGNMENT_RE.fullmatch(item) for item in assignments):
		raise ValueError("Unsafe SQL assignment in update list")


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
) -> int:
	"""Create a new peer and return the peer ID.

	blocklist_ids: JSON array of enabled blocklist IDs (e.g., ["ads", "porn"]).
	               None means all blocklists enabled.
	client_isolation: If True, peer cannot communicate with other peers (iptables isolation).
	node_id: If set, peer is assigned to a remote node (not local WireGuard).
	"""
	now = utcnow()
	blocklist_ids_json = _serialize_blocklist_ids(blocklist_ids)
	pepper = get_config().secret_key
	private_key_stored = _maybe_encrypt(private_key, pepper)
	preshared_key_stored = _maybe_encrypt(preshared_key, pepper)
	allowed_ips_mode = _validate_allowed_ips_mode(allowed_ips_mode)
	peer_id: int
	with transaction(conn, immediate=True):
		cur = conn.execute(
			"""
			INSERT INTO peers (
				public_key, private_key, preshared_key, name,
				allowed_ips, endpoint, interface, peer_address, allowed_ips_mode,
				use_adblocker, dns_logging_enabled, blocklist_ids, client_isolation,
				node_id, created_at, updated_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
				now,
				now,
			),
		)
		peer_id = int(cur.lastrowid)
	return peer_id


def update_peer(
	conn: sqlite3.Connection,
	peer_id: int,
	name: str | None | UnsetType = UNSET,
	allowed_ips: str | None | UnsetType = UNSET,
	allowed_ips_mode: str | None | UnsetType = UNSET,
	endpoint: str | None | UnsetType = UNSET,
	is_enabled: bool | None | UnsetType = UNSET,
	use_adblocker: bool | None | UnsetType = UNSET,
	dns_logging_enabled: bool | None | UnsetType = UNSET,
	blocklist_ids: list[str] | None | UnsetType = UNSET,
	client_isolation: bool | None | UnsetType = UNSET,
	private_key: str | None | UnsetType = UNSET,
	preshared_key: str | None | UnsetType = UNSET,
	node_id: str | None | UnsetType = UNSET,
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
		params.append(allowed_ips)
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
		params.append(int(is_enabled))
	if use_adblocker is not UNSET:
		_require_not_none(use_adblocker, "use_adblocker")
		updates.append("use_adblocker = ?")
		params.append(int(use_adblocker))
	if dns_logging_enabled is not UNSET:
		_require_not_none(dns_logging_enabled, "dns_logging_enabled")
		updates.append("dns_logging_enabled = ?")
		params.append(int(dns_logging_enabled))
	if blocklist_ids is not UNSET:
		updates.append("blocklist_ids = ?")
		params.append(_serialize_blocklist_ids(blocklist_ids))
	if client_isolation is not UNSET:
		_require_not_none(client_isolation, "client_isolation")
		updates.append("client_isolation = ?")
		params.append(int(client_isolation))
	if node_id is not UNSET:
		updates.append("node_id = ?")
		params.append(node_id)

	if not updates:
		row = conn.execute("SELECT 1 FROM peers WHERE id = ?", (peer_id,)).fetchone()
		return row is not None

	updates.append("updated_at = ?")
	_assert_safe_update_assignments(updates)
	params.append(utcnow())
	params.append(peer_id)
	sql = f"UPDATE peers SET {', '.join(updates)} WHERE id = ?"

	updated = False
	with transaction(conn, immediate=True):
		cur = conn.execute(sql, params)
		updated = cur.rowcount > 0
	return updated


def delete_peer(conn: sqlite3.Connection, peer_id: int) -> bool:
	"""Delete a peer by ID.

	Note: This only removes the database row. Callers are responsible for
	removing the peer from the live WireGuard interface first.
	"""
	deleted = False
	with transaction(conn, immediate=True):
		cur = conn.execute("DELETE FROM peers WHERE id = ?", (peer_id,))
		deleted = cur.rowcount > 0

	if deleted:
		_log.info("PEER_DELETE peer_id=%d", peer_id)
	else:
		_log.debug("PEER_DELETE peer_id=%d not found", peer_id)
	return deleted
