#!/usr/bin/env python3
#
# app/db/sqlite_peers_mutations.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Peer mutation (create/update/delete) helpers."""

from __future__ import annotations

import json
import sqlite3

from ..utils.config import get_config
from ..utils.time import utcnow
from ..utils import vault
from .sqlite_runtime import UNSET, UnsetType, transaction

_VALID_ALLOWED_IPS_MODES = frozenset({"full", "split", "custom"})


def _validate_allowed_ips_mode(allowed_ips_mode: str) -> str:
	"""Validate the allowed-IPs mode before writing it to the database."""
	if allowed_ips_mode not in _VALID_ALLOWED_IPS_MODES:
		raise ValueError(f"Invalid allowed_ips_mode: {allowed_ips_mode!r}")
	return allowed_ips_mode


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
) -> int:
	"""Create a new peer and return the peer ID.

	blocklist_ids: JSON array of enabled blocklist IDs (e.g., ["ads", "porn"]).
	               None means all blocklists enabled.
	client_isolation: If True, peer cannot communicate with other peers (iptables isolation).
	"""
	now = utcnow()
	blocklist_ids_json = json.dumps(blocklist_ids) if blocklist_ids is not None else None
	pepper = get_config().secret_key
	private_key_stored = vault.encrypt_if_needed(private_key, pepper)
	preshared_key_stored = vault.encrypt_if_needed(preshared_key, pepper)
	allowed_ips_mode = _validate_allowed_ips_mode(allowed_ips_mode)
	with transaction(conn, immediate=True):
		cur = conn.execute(
			"""
			INSERT INTO peers (
				public_key, private_key, preshared_key, name,
				allowed_ips, endpoint, interface, peer_address, allowed_ips_mode,
				use_adblocker, dns_logging_enabled, blocklist_ids, client_isolation, created_at, updated_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
				now,
				now,
			),
		)
		return cur.lastrowid


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
	with transaction(conn, immediate=True):
		updates = []
		params = []

		if name is not UNSET:
			updates.append("name = ?")
			params.append(name)
		if private_key is not UNSET:
			updates.append("private_key = ?")
			params.append(vault.encrypt_if_needed(private_key, pepper))
		if preshared_key is not UNSET:
			updates.append("preshared_key = ?")
			params.append(vault.encrypt_if_needed(preshared_key, pepper))
		if allowed_ips is not UNSET:
			if allowed_ips is None:
				raise ValueError("allowed_ips cannot be None")
			updates.append("allowed_ips = ?")
			params.append(allowed_ips)
		if allowed_ips_mode is not UNSET:
			if allowed_ips_mode is None:
				raise ValueError("allowed_ips_mode cannot be None")
			updates.append("allowed_ips_mode = ?")
			params.append(_validate_allowed_ips_mode(allowed_ips_mode))
		if endpoint is not UNSET:
			updates.append("endpoint = ?")
			params.append(endpoint)
		if is_enabled is not UNSET:
			if is_enabled is None:
				raise ValueError("is_enabled cannot be None")
			updates.append("is_enabled = ?")
			params.append(int(is_enabled))
		if use_adblocker is not UNSET:
			if use_adblocker is None:
				raise ValueError("use_adblocker cannot be None")
			updates.append("use_adblocker = ?")
			params.append(int(use_adblocker))
		if dns_logging_enabled is not UNSET:
			if dns_logging_enabled is None:
				raise ValueError("dns_logging_enabled cannot be None")
			updates.append("dns_logging_enabled = ?")
			params.append(int(dns_logging_enabled))
		if blocklist_ids is not UNSET:
			updates.append("blocklist_ids = ?")
			params.append(json.dumps(blocklist_ids) if blocklist_ids is not None else None)
		if client_isolation is not UNSET:
			if client_isolation is None:
				raise ValueError("client_isolation cannot be None")
			updates.append("client_isolation = ?")
			params.append(int(client_isolation))

		if not updates:
			row = conn.execute("SELECT 1 FROM peers WHERE id = ?", (peer_id,)).fetchone()
			return row is not None

		updates.append("updated_at = ?")
		params.append(utcnow())
		params.append(peer_id)

		sql = f"UPDATE peers SET {', '.join(updates)} WHERE id = ?"
		cur = conn.execute(sql, params)
		return cur.rowcount > 0


def delete_peer(conn: sqlite3.Connection, peer_id: int) -> bool:
	"""Delete a peer by ID.

	Note: This only removes the database row. Callers are responsible for
	removing the peer from the live WireGuard interface first.
	"""
	with transaction(conn, immediate=True):
		cur = conn.execute("DELETE FROM peers WHERE id = ?", (peer_id,))
		return cur.rowcount > 0
