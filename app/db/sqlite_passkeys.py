#!/usr/bin/env python3
#
# app/db/sqlite_passkeys.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Passkey (WebAuthn credential) database operations."""

from __future__ import annotations

import logging
import sqlite3

import hashlib
import time

from ..utils.time import utcnow
from .sqlite_runtime import transaction

_log = logging.getLogger(__name__)


def get_passkeys_for_user(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
	"""Get all passkeys for a user."""
	if conn.row_factory is not sqlite3.Row:
		raise TypeError("row_factory must be sqlite3.Row")
	cur = conn.execute(
		"""
		SELECT id, user_id, credential_id, public_key, sign_count,
			   device_name, transports, created_at
		FROM passkeys
		WHERE user_id = ?
		ORDER BY created_at DESC
		""",
		(user_id,),
	)
	return cur.fetchall()


def get_passkey_by_credential_id(
	conn: sqlite3.Connection,
	credential_id: str,
) -> sqlite3.Row | None:
	"""Get a passkey by credential ID (for usernameless login)."""
	if conn.row_factory is not sqlite3.Row:
		raise TypeError("row_factory must be sqlite3.Row")
	cur = conn.execute(
		"""
		SELECT p.id, p.user_id, p.credential_id, p.public_key, p.sign_count,
			   p.device_name, p.transports, p.created_at,
			   u.username, u.is_active, u.auth_method, u.passkey_enabled
		FROM passkeys p
		JOIN users u ON p.user_id = u.id
		WHERE p.credential_id = ?
		""",
		(credential_id,),
	)
	return cur.fetchone()


def get_passkey_by_id(conn: sqlite3.Connection, passkey_id: int) -> sqlite3.Row | None:
	"""Get a passkey by its ID."""
	if conn.row_factory is not sqlite3.Row:
		raise TypeError("row_factory must be sqlite3.Row")
	cur = conn.execute(
		"""
		SELECT id, user_id, credential_id, public_key, sign_count,
			   device_name, transports, created_at
		FROM passkeys
		WHERE id = ?
		""",
		(passkey_id,),
	)
	return cur.fetchone()


def create_passkey(
	conn: sqlite3.Connection,
	user_id: int,
	credential_id: str,
	public_key: bytes,
	sign_count: int,
	device_name: str | None = None,
	transports: str | None = None,
) -> int:
	"""Create a new passkey credential.
	
	Returns:
		The new passkey ID.
		
	Raises:
		ValueError: If credential_id is already registered
		RuntimeError: If INSERT did not return a row ID
	"""
	now = utcnow()
	with transaction(conn):
		try:
			cur = conn.execute(
				"""
				INSERT INTO passkeys (user_id, credential_id, public_key, sign_count,
									  device_name, transports, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)
				""",
				(user_id, credential_id, public_key, sign_count, device_name, transports, now),
			)
		except sqlite3.IntegrityError as e:
			_log.warning("Passkey creation failed for user_id=%d: %s", user_id, e)
			raise ValueError("Credential ID already registered") from e
		
		row_id = cur.lastrowid
		
		_log.info(
			"Passkey created: id=%d user_id=%d device=%s",
			row_id,
			user_id,
			device_name or "unnamed",
		)
		return row_id


def update_passkey_sign_count(
	conn: sqlite3.Connection,
	passkey_id: int,
	new_sign_count: int,
) -> None:
	"""Update the sign count for replay protection.
	
	Enforces monotonicity: new_sign_count must be greater than current value.
	
	Note: Consider adding last_used_at column to passkeys table for better
	credential hygiene tracking.
	
	Raises:
		ValueError: If sign count regression is detected (potential cloned authenticator)
	"""
	with transaction(conn):
		if new_sign_count == 0:
			existing = conn.execute("SELECT sign_count FROM passkeys WHERE id = ?", (passkey_id,)).fetchone()
			if existing is None:
				raise ValueError(f"Passkey {passkey_id} not found")
			if existing[0] > 0:
				_log.error(
					"Sign count regression blocked for passkey_id=%d: current=%d, attempted=0",
					passkey_id,
					existing[0],
				)
				raise ValueError(f"Sign count regression blocked for passkey {passkey_id}")
			_log.debug("Sign count is 0 for passkey_id=%d (non-incrementing authenticator)", passkey_id)
			return
			
		cur = conn.execute(
			"UPDATE passkeys SET sign_count = ? WHERE id = ? AND sign_count < ?",
			(new_sign_count, passkey_id, new_sign_count),
		)
		if cur.rowcount == 0:
			existing = conn.execute("SELECT sign_count FROM passkeys WHERE id = ?", (passkey_id,)).fetchone()
			if existing is None:
				raise ValueError(f"Passkey {passkey_id} not found")
			
			_log.error(
				"Sign count regression blocked for passkey_id=%d: current=%d, attempted=%d",
				passkey_id, existing[0], new_sign_count,
			)
			raise ValueError(
				f"Sign count regression blocked for passkey {passkey_id}"
			)
		_log.debug("Sign count updated for passkey_id=%d: %d", passkey_id, new_sign_count)


def delete_passkey(conn: sqlite3.Connection, passkey_id: int, user_id: int) -> bool:
	"""Delete a passkey by ID, scoped to the owning user.
	
	Args:
		passkey_id: The passkey ID to delete
		user_id: The user ID that owns the passkey (ownership verification)
	
	Returns:
		True if deleted, False if not found or not owned by user.
	"""
	with transaction(conn):
		existing = conn.execute("SELECT user_id FROM passkeys WHERE id = ?", (passkey_id,)).fetchone()
		
		if existing is None:
			_log.warning("Passkey delete: id=%d not found (user_id=%d)", passkey_id, user_id)
			return False
			
		if existing[0] != user_id:
			_log.error("Passkey delete: ownership mismatch id=%d owner=%d requester=%d", passkey_id, existing[0], user_id)
			return False

		cur = conn.execute("DELETE FROM passkeys WHERE id = ? AND user_id = ?", (passkey_id, user_id))
		if cur.rowcount != 1:
			_log.error("Passkey delete: delete failed id=%d user_id=%d", passkey_id, user_id)
			return False
		_log.info("Passkey deleted: id=%d user_id=%d", passkey_id, user_id)
		return True
def count_user_passkeys(conn: sqlite3.Connection, user_id: int) -> int:
	"""Count passkeys for a user."""
	cur = conn.execute(
		"SELECT COUNT(*) FROM passkeys WHERE user_id = ?",
		(user_id,),
	)
	return cur.fetchone()[0]


def any_passkeys_exist(conn: sqlite3.Connection) -> bool:
	"""Check if any passkeys exist in the system."""
	cur = conn.execute("SELECT EXISTS(SELECT 1 FROM passkeys)")
	return bool(cur.fetchone()[0])


def get_credential_ids_for_user(conn: sqlite3.Connection, user_id: int) -> list[str]:
	"""Get all credential IDs for a user (for exclude list during registration)."""
	cur = conn.execute(
		"SELECT credential_id FROM passkeys WHERE user_id = ?",
		(user_id,),
	)
	return [row[0] for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# Passkey Challenge Storage (SQLite-backed for multi-worker support)
# ---------------------------------------------------------------------------

# Challenge TTL in seconds
_CHALLENGE_TTL_SECONDS = 120


def store_challenge(
	conn: sqlite3.Connection,
	challenge: str,
	ceremony_type: str,
	user_id: int | None,
	username: str | None,
) -> None:
	"""Store a WebAuthn challenge in the database.
	
	Args:
		challenge: Base64url-encoded challenge string
		ceremony_type: 'registration' or 'authentication'
		user_id: User ID (required for registration, optional for auth)
		username: Username (required for registration)
		
	Raises:
		ValueError: If ceremony_type is invalid
		sqlite3.IntegrityError: If challenge already exists (replay)
	"""

	if ceremony_type not in ("registration", "authentication"):
		raise ValueError(f"Invalid ceremony_type: {ceremony_type}")
	
	now = time.time()
	expires_at = now + _CHALLENGE_TTL_SECONDS
	
	with transaction(conn):
		
		# Insert new challenge
		conn.execute(
			"""
			INSERT INTO passkey_challenges (challenge, ceremony_type, user_id, username, expires_at, created_at)
			VALUES (?, ?, ?, ?, ?, ?)
			""",
			(challenge, ceremony_type, user_id, username, expires_at, now),
		)
	
	_log.debug(
		"Stored %s challenge for user_id=%s (expires in %ds)",
		ceremony_type,
		user_id,
		_CHALLENGE_TTL_SECONDS,
	)


def consume_challenge(
	conn: sqlite3.Connection,
	challenge: str,
	expected_ceremony_type: str,
) -> tuple[int | None, str | None]:
	"""Consume a WebAuthn challenge from the database.
	
	Args:
		challenge: Base64url-encoded challenge string
		expected_ceremony_type: 'registration' or 'authentication'
		
	Returns:
		(user_id, username) tuple. user_id may be None for usernameless auth.
		
	Raises:
		KeyError: If challenge not found (expired, used, or invalid)
		ValueError: If ceremony_type doesn't match
	"""
	now = time.time()
	
	with transaction(conn):
		cur = conn.execute(
			"""
			DELETE FROM passkey_challenges
			WHERE challenge = ? AND expires_at > ?
			RETURNING ceremony_type, user_id, username
			""",
			(challenge, now),
		)
		row = cur.fetchone()
		
		if not row:
			challenge_ref = hashlib.sha256(challenge.encode()).hexdigest()[:12]
			_log.warning("Challenge not found (expired or already consumed): ref=%s", challenge_ref)
			raise KeyError("Challenge not found")
		
		ceremony_type, user_id, username = row
		
		if ceremony_type != expected_ceremony_type:
			_log.error(
				"Challenge ceremony type mismatch: expected %s, got %s",
				expected_ceremony_type,
				ceremony_type,
			)
			raise ValueError(f"Challenge was not issued for {expected_ceremony_type}")

		_log.info("Consumed %s challenge for user_id=%s", ceremony_type, user_id)
	return (user_id, username)


def cleanup_expired_challenges(conn: sqlite3.Connection) -> int:
	"""Remove expired challenges from the database.
	
	Returns:
		Number of challenges removed.
	"""

	now = time.time()
	with transaction(conn):
		cur = conn.execute("DELETE FROM passkey_challenges WHERE expires_at <= ?", (now,))
		count = cur.rowcount
	
	if count > 0:
		_log.debug("Cleaned up %d expired challenge(s)", count)
	return count
