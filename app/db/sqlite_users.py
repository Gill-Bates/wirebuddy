#!/usr/bin/env python3
#
# app/db/sqlite_users.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""User CRUD and profile-related operations."""

from __future__ import annotations

import enum
import sqlite3

from ..utils.config import get_config
from ..utils.crypto import hash_password
from ..utils.time import utcnow
from ..utils import vault
from .sqlite_runtime import transaction


class UpdateResult(enum.Enum):
	"""Result of user update operations."""
	SUCCESS = "success"
	NOT_FOUND = "not_found"
	CONFLICT = "conflict"
	LAST_ADMIN = "last_admin"


class LastAdminError(Exception):
	"""Raised when attempting to remove/demote the last admin."""


# ---------------------------------------------------------------------------
# OTP Secret Encryption Helpers
# ---------------------------------------------------------------------------

def _encrypt_otp_secret(secret: str) -> str:
	"""Encrypt OTP secret for storage at rest."""
	pepper = get_config().secret_key
	return vault.encrypt(secret, pepper)


def decrypt_otp_secret(encrypted: str | None) -> str | None:
	"""Decrypt OTP secret from storage. Returns None if not set."""
	if not encrypted:
		return None
	# Handle legacy unencrypted secrets (migration window)
	if not vault.is_encrypted(encrypted):
		return encrypted
	pepper = get_config().secret_key
	return vault.decrypt(encrypted, pepper)


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


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
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
) -> int | None:
	"""Create a new user and return the user ID.

	Returns:
		User ID on success, None if username already exists.

	Raises:
		ValueError: If username or password is empty/blank.
	"""
	normalized_username = username.strip().lower()
	if not normalized_username:
		raise ValueError("Username must not be blank")
	if not password:
		raise ValueError("Password must not be blank")

	now = utcnow()
	try:
		with transaction(conn):
			cur = conn.execute(
				"""
				INSERT INTO users (username, password_hash, is_admin, is_active, created_at)
				VALUES (?, ?, ?, 1, ?)
				""",
				(normalized_username, hash_password(password), int(is_admin), now),
			)
			row_id = cur.lastrowid
			if row_id is None:
				raise RuntimeError("INSERT did not return a rowid")
			return row_id
	except sqlite3.IntegrityError:
		return None


def update_user(
	conn: sqlite3.Connection,
	user_id: int,
	username: str | None = None,
	password: str | None = None,
	is_admin: bool | None = None,
	is_active: bool | None = None,
) -> UpdateResult:
	"""Update a user.

	Returns:
		UpdateResult.SUCCESS: User updated
		UpdateResult.NOT_FOUND: User ID does not exist
		UpdateResult.CONFLICT: Username already taken
		UpdateResult.LAST_ADMIN: Cannot demote/deactivate last admin
	"""
	try:
		conn.execute("BEGIN IMMEDIATE")

		user = get_user_by_id(conn, user_id)
		if not user:
			conn.rollback()
			return UpdateResult.NOT_FOUND

		# Last-admin protection: prevent demoting or deactivating the last admin
		is_currently_admin = bool(user["is_admin"]) and bool(user["is_active"])
		will_lose_admin = (is_admin is False) or (is_active is False)
		if is_currently_admin and will_lose_admin:
			if count_admins(conn) <= 1:
				conn.rollback()
				return UpdateResult.LAST_ADMIN

		updates = []
		params = []

		if username is not None:
			normalized = username.strip().lower()
			if not normalized:
				conn.rollback()
				raise ValueError("Username must not be blank")
			updates.append("username = ?")
			params.append(normalized)
		if password is not None:
			if not password:
				conn.rollback()
				raise ValueError("Password must not be blank")
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
			return UpdateResult.SUCCESS

		params.append(user_id)
		sql = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"

		cur = conn.execute(sql, params)
		conn.commit()
		return UpdateResult.SUCCESS if cur.rowcount > 0 else UpdateResult.NOT_FOUND
	except sqlite3.IntegrityError:
		conn.rollback()
		return UpdateResult.CONFLICT
	except ValueError:
		raise
	except BaseException:
		conn.rollback()
		raise


def delete_user(conn: sqlite3.Connection, user_id: int) -> bool:
	"""Delete a user. Returns True if user was found and deleted.

	Raises:
		LastAdminError: If this is the last active admin user.
	"""
	with transaction(conn):
		# Last-admin protection
		user = get_user_by_id(conn, user_id)
		if user and bool(user["is_admin"]) and bool(user["is_active"]):
			if count_admins(conn) <= 1:
				raise LastAdminError("Cannot delete the last admin user")
		cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
		return cur.rowcount > 0


def update_last_login(conn: sqlite3.Connection, user_id: int, ip_address: str) -> bool:
	"""Update the last login timestamp and IP for a user.

	Returns:
		True if user was found and updated, False otherwise.
	"""
	now = utcnow()
	with transaction(conn):
		cur = conn.execute(
			"UPDATE users SET last_login_at = ?, last_login_ip = ? WHERE id = ?",
			(now, ip_address, user_id),
		)
		return cur.rowcount > 0


def set_user_otp_secret(conn: sqlite3.Connection, user_id: int, otp_secret: str) -> bool:
	"""Set OTP secret (encrypted at rest) and keep OTP disabled until confirmation."""
	encrypted_secret = _encrypt_otp_secret(otp_secret)
	with transaction(conn):
		cur = conn.execute(
			"""
			UPDATE users
			SET otp_secret = ?, otp_enabled = 0, otp_recovery_codes = NULL
			WHERE id = ?
			""",
			(encrypted_secret, user_id),
		)
		return cur.rowcount > 0


def confirm_user_otp(conn: sqlite3.Connection, user_id: int, otp_recovery_codes: str) -> bool:
	"""Enable OTP and persist fresh recovery codes."""
	with transaction(conn):
		cur = conn.execute(
			"""
			UPDATE users
			SET otp_enabled = 1, otp_recovery_codes = ?
			WHERE id = ?
			""",
			(otp_recovery_codes, user_id),
		)
		return cur.rowcount > 0


def update_user_recovery_codes(conn: sqlite3.Connection, user_id: int, otp_recovery_codes: str) -> bool:
	"""Update persisted recovery code list after one-time code consumption."""
	with transaction(conn):
		cur = conn.execute(
			"UPDATE users SET otp_recovery_codes = ? WHERE id = ?",
			(otp_recovery_codes, user_id),
		)
		return cur.rowcount > 0


def disable_user_otp(conn: sqlite3.Connection, user_id: int) -> bool:
	"""Disable OTP and clear all OTP-related fields."""
	with transaction(conn):
		cur = conn.execute(
			"""
			UPDATE users
			SET otp_enabled = 0, otp_secret = NULL, otp_recovery_codes = NULL
			WHERE id = ?
			""",
			(user_id,),
		)
		return cur.rowcount > 0
