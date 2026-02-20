#!/usr/bin/env python3
#
# app/db/sqlite_interfaces.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard interface CRUD operations."""

from __future__ import annotations

import sqlite3

from ..utils.time import utcnow
from .sqlite_runtime import transaction


# ─────────────────────────────────────────────────────────────────────────────
# Interface CRUD functions
# ─────────────────────────────────────────────────────────────────────────────


def create_interface(
	conn: sqlite3.Connection,
	name: str,
	private_key: str,
	public_key: str,
	address: str,
	listen_port: int = 51820,
	dns: str | None = None,
	post_up: str | None = None,
	post_down: str | None = None,
	address6: str | None = None,
) -> int:
	"""Create a new WireGuard interface in the database."""
	now = utcnow()
	with transaction(conn):
		cur = conn.execute(
			"""
			INSERT INTO interfaces (
				name, private_key, public_key, address, address6, listen_port,
				dns, post_up, post_down, is_enabled, created_at, updated_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
			""",
			(name, private_key, public_key, address, address6, listen_port, dns, post_up, post_down, now, now),
		)
		return cur.lastrowid


def get_interface(conn: sqlite3.Connection, name: str) -> sqlite3.Row | None:
	"""Get an interface by name."""
	cur = conn.execute("SELECT * FROM interfaces WHERE name = ?", (name,))
	return cur.fetchone()


def update_interface(
	conn: sqlite3.Connection,
	name: str,
	address: str,
	address6: str | None,
	listen_port: int,
	dns: str | None,
	post_up: str | None,
	post_down: str | None,
) -> bool:
	"""Update mutable settings of an existing WireGuard interface."""
	now = utcnow()
	with transaction(conn):
		cur = conn.execute(
			"""
			UPDATE interfaces
			SET address = ?, address6 = ?, listen_port = ?, dns = ?, post_up = ?, post_down = ?, updated_at = ?
			WHERE name = ?
			""",
			(address, address6, listen_port, dns, post_up, post_down, now, name),
		)
		return cur.rowcount > 0


def list_interfaces(conn: sqlite3.Connection) -> list[sqlite3.Row]:
	"""List all interfaces."""
	cur = conn.execute("SELECT * FROM interfaces ORDER BY name")
	return cur.fetchall()


def delete_interface(conn: sqlite3.Connection, name: str) -> bool:
	"""Delete an interface from the database."""
	with transaction(conn):
		cur = conn.execute("DELETE FROM interfaces WHERE name = ?", (name,))
		return cur.rowcount > 0
