#!/usr/bin/env python3
#
# app/db/sqlite_peers_mutations.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Peer mutation (create/update/delete) helpers."""

from __future__ import annotations

import json
import sqlite3
from typing import Optional

from ..utils.time import utcnow
from .sqlite_peers import get_peer_by_id
from .sqlite_runtime import UNSET, transaction


def create_peer(
	conn: sqlite3.Connection,
	public_key: str,
	allowed_ips: str,
	name: Optional[str] = None,
	description: Optional[str] = None,
	endpoint: Optional[str] = None,
	interface: str = "wg0",
	private_key: Optional[str] = None,
	preshared_key: Optional[str] = None,
	peer_address: Optional[str] = None,
	allowed_ips_mode: str = "full",
	use_adblocker: bool = True,
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
	with transaction(conn):
		cur = conn.execute(
			"""
			INSERT INTO peers (
				public_key, private_key, preshared_key, name, description,
				allowed_ips, endpoint, interface, peer_address, allowed_ips_mode,
				use_adblocker, blocklist_ids, client_isolation, created_at, updated_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			""",
			(
				public_key,
				private_key,
				preshared_key,
				name,
				description,
				allowed_ips,
				endpoint,
				interface,
				peer_address,
				allowed_ips_mode,
				int(use_adblocker),
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
	name: str | None | object = UNSET,
	description: str | None | object = UNSET,
	allowed_ips: str | None | object = UNSET,
	allowed_ips_mode: str | None | object = UNSET,
	endpoint: str | None | object = UNSET,
	is_enabled: bool | None | object = UNSET,
	use_adblocker: bool | None | object = UNSET,
	blocklist_ids: list[str] | None | object = UNSET,
	client_isolation: bool | None | object = UNSET,
) -> bool:
	"""Update a peer by ID. Returns True if peer was found and updated.

	Parameters:
		name, description, endpoint: Can be set to None (NULL in database).
		allowed_ips, allowed_ips_mode: Cannot be None (NOT NULL constraint).
			Pass UNSET to leave unchanged, or a string value to update.
		is_enabled, use_adblocker, client_isolation: Cannot be None.
			Pass UNSET to leave unchanged, False to disable, or True to enable.
		blocklist_ids: Use UNSET to leave unchanged, None to reset to all,
			or a list of IDs to set specific blocklists.
	"""
	try:
		conn.execute("BEGIN IMMEDIATE")

		# Check if peer exists
		peer = get_peer_by_id(conn, peer_id)
		if not peer:
			conn.rollback()
			return False

		updates = []
		params = []

		if name is not UNSET:
			updates.append("name = ?")
			params.append(name)
		if description is not UNSET:
			updates.append("description = ?")
			params.append(description)
		if allowed_ips is not UNSET and allowed_ips is not None:
			updates.append("allowed_ips = ?")
			params.append(allowed_ips)
		if allowed_ips_mode is not UNSET and allowed_ips_mode is not None:
			updates.append("allowed_ips_mode = ?")
			params.append(allowed_ips_mode)
		if endpoint is not UNSET:
			updates.append("endpoint = ?")
			params.append(endpoint)
		if is_enabled is not UNSET and is_enabled is not None:
			updates.append("is_enabled = ?")
			params.append(int(is_enabled))
		if use_adblocker is not UNSET and use_adblocker is not None:
			updates.append("use_adblocker = ?")
			params.append(int(use_adblocker))
		if blocklist_ids is not UNSET:
			updates.append("blocklist_ids = ?")
			params.append(json.dumps(blocklist_ids) if blocklist_ids is not None else None)
		if client_isolation is not UNSET and client_isolation is not None:
			updates.append("client_isolation = ?")
			params.append(int(client_isolation))

		if not updates:
			conn.rollback()
			return True

		updates.append("updated_at = ?")
		params.append(utcnow())
		params.append(peer_id)

		sql = f"UPDATE peers SET {', '.join(updates)} WHERE id = ?"
		cur = conn.execute(sql, params)
		conn.commit()
		# Verify update actually affected a row
		return cur.rowcount > 0
	except Exception:
		conn.rollback()
		raise


def delete_peer(conn: sqlite3.Connection, peer_id: int) -> bool:
	"""Delete a peer by ID. Returns True if peer was found and deleted."""
	with transaction(conn):
		cur = conn.execute("DELETE FROM peers WHERE id = ?", (peer_id,))
		return cur.rowcount > 0
