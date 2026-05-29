#!/usr/bin/env python3
#
# app/db/sqlite_interfaces.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard interface CRUD operations."""

from __future__ import annotations

import ipaddress
import re
import sqlite3

from ..utils.config import get_config
from ..utils.time import utcnow
from ..utils import vault
from .sqlite_runtime import transaction


_INTERFACE_NAME_RE = re.compile(r"^[A-Za-z0-9_.=-]{1,32}$")


def _validate_interface_name(name: str) -> str:
	"""Validate an interface name before persisting or querying."""
	normalized = str(name or "").strip()
	if not _INTERFACE_NAME_RE.fullmatch(normalized):
		raise ValueError("Invalid interface name")
	return normalized


def _validate_interface_address(value: str, field: str) -> str:
	"""Validate and normalize an interface address with prefix."""
	text = str(value or "").strip()
	if not text:
		raise ValueError(f"{field} must not be empty")
	try:
		return ipaddress.ip_interface(text).with_prefixlen
	except ValueError as exc:
		raise ValueError(f"Invalid {field}") from exc


def _normalize_optional_interface_address(value: str | None, field: str) -> str | None:
	"""Normalize an optional interface address; blank values become None."""
	if value is None:
		return None
	text = str(value).strip()
	if not text:
		return None
	return _validate_interface_address(text, field)


def _validate_listen_port(listen_port: int) -> int:
	"""Validate a WireGuard listen port."""
	port = int(listen_port)
	if not 1 <= port <= 65535:
		raise ValueError("listen_port must be between 1 and 65535")
	return port


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
	name = _validate_interface_name(name)
	address = _validate_interface_address(address, "address")
	address6 = _normalize_optional_interface_address(address6, "address6")
	listen_port = _validate_listen_port(listen_port)
	private_key_stored = vault.encrypt_if_needed(private_key, get_config().secret_key)
	with transaction(conn, immediate=True):
		cur = conn.execute(
			"""
			INSERT INTO interfaces (
				name, private_key, public_key, address, address6, listen_port,
				client_endpoint_port, dns, post_up, post_down, is_enabled, created_at, updated_at
			)
			VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, 1, ?, ?)
			""",
			(
				name,
				private_key_stored,
				public_key,
				address,
				address6,
				listen_port,
				dns,
				post_up,
				post_down,
				now,
				now,
			),
		)
		return cur.lastrowid


def get_interface(conn: sqlite3.Connection, name: str) -> sqlite3.Row | None:
	"""Get an interface by name."""
	name = _validate_interface_name(name)
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
	show_on_dashboard: bool | None = None,
) -> bool:
	"""Update mutable settings of an existing WireGuard interface."""
	now = utcnow()
	name = _validate_interface_name(name)
	address = _validate_interface_address(address, "address")
	address6 = _normalize_optional_interface_address(address6, "address6")
	listen_port = _validate_listen_port(listen_port)
	with transaction(conn, immediate=True):
		columns = "address = ?, address6 = ?, listen_port = ?, dns = ?, post_up = ?, post_down = ?"
		params: list = [address, address6, listen_port, dns, post_up, post_down]
		if show_on_dashboard is not None:
			columns += ", show_on_dashboard = ?"
			params.append(int(show_on_dashboard))
		columns += ", updated_at = ?"
		params.append(now)
		params.append(name)
		cur = conn.execute(
			f"UPDATE interfaces SET {columns} WHERE name = ?",
			params,
		)
		return cur.rowcount > 0


def list_interfaces(conn: sqlite3.Connection) -> list[sqlite3.Row]:
	"""List all interfaces."""
	cur = conn.execute("SELECT * FROM interfaces ORDER BY name")
	return cur.fetchall()


def get_first_listen_port(conn: sqlite3.Connection, default: int = 51820) -> int:
	"""Return the first interface listen port or a fallback default."""
	try:
		row = conn.execute("SELECT listen_port FROM interfaces LIMIT 1").fetchone()
	except sqlite3.OperationalError:
		return default
	if not row:
		return default
	try:
		return int(row["listen_port"])
	except (TypeError, ValueError, KeyError, IndexError):
		return default


def delete_interface(conn: sqlite3.Connection, name: str) -> bool:
	"""Delete an interface from the database."""
	name = _validate_interface_name(name)
	with transaction(conn, immediate=True):
		peer_refs = conn.execute(
			"SELECT COUNT(*) FROM peers WHERE interface = ?",
			(name,),
		).fetchone()[0]
		node_refs = conn.execute(
			"SELECT COUNT(*) FROM node_interfaces WHERE interface_name = ?",
			(name,),
		).fetchone()[0]
		if peer_refs or node_refs:
			raise ValueError("Cannot delete interface while peers or nodes still reference it")
		cur = conn.execute("DELETE FROM interfaces WHERE name = ?", (name,))
		return cur.rowcount > 0


def delete_peers_by_interface(conn: sqlite3.Connection, interface: str) -> int:
	"""Delete all peers belonging to an interface. Returns number of deleted rows."""
	with transaction(conn):
		cur = conn.execute("DELETE FROM peers WHERE interface = ?", (interface,))
		return cur.rowcount
