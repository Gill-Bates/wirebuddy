#!/usr/bin/env python3
#
# app/db/sqlite_users.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""User CRUD and profile-related operations."""

from __future__ import annotations

import sqlite3
from typing import Optional

from ..utils.crypto import hash_password
from ..utils.time import utcnow
from .sqlite_runtime import transaction


# ---------------------------------------------------------------------------
# User operations
# ---------------------------------------------------------------------------

def get_user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
	"""Get a user by username (case-insensitive).

	Note: create_user normalizes usernames to lowercase, so we can use
	a simple equality check instead of LOWER() to allow index use.
	"""
	cur = conn.execute("SELECT * FROM users WHERE username = ?", (username.strip().lower(),))
	return cur.fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[sqlite3.Row]:
	"""Get a user by ID."""
	cur = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
	return cur.fetchone()


def get_all_users(conn: sqlite3.Connection) -> list[sqlite3.Row]:
	"""Get all users."""
	cur = conn.execute("SELECT * FROM users ORDER BY username")
	return cur.fetchall()


def count_admins(conn: sqlite3.Connection) -> int:
	"""Count the number of active admin users."""
	cur = conn.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1 AND is_active = 1")
	return cur.fetchone()[0]


def create_user(
	conn: sqlite3.Connection,
	username: str,
	password: str,
	is_admin: bool = False,
) -> int:
	"""Create a new user and return the user ID."""
	now = utcnow()
	# Normalize username to lowercase for consistent storage
	normalized_username = username.strip().lower()
	with transaction(conn):
		cur = conn.execute(
			"""
			INSERT INTO users (username, password_hash, is_admin, is_active, created_at)
			VALUES (?, ?, ?, 1, ?)
			""",
			(normalized_username, hash_password(password), int(is_admin), now),
		)
		return cur.lastrowid


def update_user(
	conn: sqlite3.Connection,
	user_id: int,
	username: str | None = None,
	password: str | None = None,
	is_admin: bool | None = None,
	is_active: bool | None = None,
) -> bool:
	"""Update a user. Returns True if successful, False if user not found or username conflict."""
	# Manual transaction management here because we need different behavior for
	# "not found" (rollback + False) vs "success" (commit + True) vs "integrity error" (rollback + False)
	try:
		conn.execute("BEGIN IMMEDIATE")

		# Check if user exists
		user = get_user_by_id(conn, user_id)
		if not user:
			conn.rollback()
			return False

		updates = []
		params = []

		if username is not None:
			updates.append("username = ?")
			# Normalize username to lowercase
			params.append(username.strip().lower())
		if password is not None:
			updates.append("password_hash = ?")
			params.append(hash_password(password))
		if is_admin is not None:
			updates.append("is_admin = ?")
			params.append(int(is_admin))
		if is_active is not None:
			updates.append("is_active = ?")
			params.append(int(is_active))

		if not updates:
			conn.rollback()
			return True

		params.append(user_id)
		sql = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"

		cur = conn.execute(sql, params)
		conn.commit()
		# Verify update actually affected a row
		return cur.rowcount > 0
	except sqlite3.IntegrityError:
		conn.rollback()
		# Username already exists
		return False
	except Exception:
		conn.rollback()
		raise


def delete_user(conn: sqlite3.Connection, user_id: int) -> bool:
	"""Delete a user. Returns True if user was found and deleted."""
	with transaction(conn):
		cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
		return cur.rowcount > 0


def update_last_login(conn: sqlite3.Connection, user_id: int, ip_address: str) -> None:
	"""Update the last login timestamp and IP for a user."""
	now = utcnow()
	with transaction(conn):
		conn.execute(
			"UPDATE users SET last_login_at = ?, last_login_ip = ? WHERE id = ?",
			(now, ip_address, user_id),
		)
