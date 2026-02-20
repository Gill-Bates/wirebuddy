#!/usr/bin/env python3
#
# app/db/sqlite_auth.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Auth-token handling and login-attempt lockout tracking."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta

from ..utils.crypto import hash_token
from ..utils.time import utcnow
from .sqlite_runtime import transaction


# ---------------------------------------------------------------------------
# Token operations
# ---------------------------------------------------------------------------

def create_auth_token(
	conn: sqlite3.Connection,
	user_id: int,
	token: str,
	expires_at: datetime,
	max_expires_at: datetime,
) -> int:
	"""Store a new auth token (hashed) and return the token ID."""
	now = utcnow()
	token_hash = hash_token(token)
	with transaction(conn):
		cur = conn.execute(
			"""
			INSERT INTO auth_tokens (user_id, token_hash, expires_at, max_expires_at, created_at)
			VALUES (?, ?, ?, ?, ?)
			""",
			(user_id, token_hash, expires_at, max_expires_at, now),
		)
		return cur.lastrowid


def get_user_by_token(conn: sqlite3.Connection, token: str) -> sqlite3.Row | None:
	"""Get a user by their auth token (validates expiry).

	Pure read operation - does NOT refresh the token.
	Call refresh_auth_token() explicitly if needed.
	"""
	token_hash = hash_token(token)
	now = utcnow()

	cur = conn.execute(
		"""
		SELECT u.* FROM users u
		JOIN auth_tokens t ON u.id = t.user_id
		WHERE t.token_hash = ? AND t.expires_at > ? AND u.is_active = 1
		""",
		(token_hash, now),
	)
	return cur.fetchone()


def refresh_auth_token(conn: sqlite3.Connection, token: str, hours: int = 1) -> None:
	"""Extend token expiry by the given hours, but not beyond max_expires_at."""
	token_hash = hash_token(token)
	now = utcnow()
	new_expires = now + timedelta(hours=hours)

	with transaction(conn):
		conn.execute(
			"""
			UPDATE auth_tokens
			SET expires_at = MIN(?, max_expires_at)
			WHERE token_hash = ?
			""",
			(new_expires, token_hash),
		)


def delete_auth_token(conn: sqlite3.Connection, token: str) -> None:
	"""Delete an auth token (logout)."""
	token_hash = hash_token(token)
	with transaction(conn):
		conn.execute("DELETE FROM auth_tokens WHERE token_hash = ?", (token_hash,))


def delete_expired_tokens(conn: sqlite3.Connection) -> int:
	"""Delete all expired tokens. Returns count of deleted tokens."""
	now = utcnow()
	with transaction(conn):
		cur = conn.execute("DELETE FROM auth_tokens WHERE expires_at <= ?", (now,))
		return cur.rowcount


def delete_user_tokens(conn: sqlite3.Connection, user_id: int) -> None:
	"""Delete all tokens for a user (logout all sessions)."""
	with transaction(conn):
		conn.execute("DELETE FROM auth_tokens WHERE user_id = ?", (user_id,))


# ---------------------------------------------------------------------------
# Login attempt tracking (exponential backoff)
# ---------------------------------------------------------------------------

MIN_FAILURES_FOR_LOCKOUT = 3  # Start lockout after 3 failed attempts
BASE_LOCKOUT_SECONDS = 15  # First lockout: 15 seconds
MAX_LOCKOUT_SECONDS = 86400  # Maximum lockout: 24 hours


def _calculate_lockout_seconds(failed_count: int) -> int:
	"""Calculate exponential backoff lockout duration.

	Formula: BASE * 2^(attempts - MIN_FAILURES)
	- 3 failures: 15s
	- 4 failures: 30s
	- 5 failures: 60s (1 min)
	- 6 failures: 120s (2 min)
	- 7 failures: 240s (4 min)
	- 8 failures: 480s (8 min)
	- 9 failures: 960s (16 min)
	- 10 failures: 1920s (32 min)
	- 11 failures: 3840s (64 min)
	- 12+ failures: capped at 24 hours
	"""
	if failed_count < MIN_FAILURES_FOR_LOCKOUT:
		return 0

	exponent = failed_count - MIN_FAILURES_FOR_LOCKOUT
	if exponent > 16:
		return MAX_LOCKOUT_SECONDS
	lockout = BASE_LOCKOUT_SECONDS * (2**exponent)
	return min(lockout, MAX_LOCKOUT_SECONDS)


def is_ip_locked(conn: sqlite3.Connection, ip_address: str) -> tuple[bool, int]:
	"""Check if an IP is locked out from login attempts.

	Returns:
		Tuple of (is_locked, seconds_remaining)
	"""
	cur = conn.execute(
		"SELECT failed_count, locked_until FROM login_attempts WHERE ip_address = ?",
		(ip_address,),
	)
	row = cur.fetchone()
	if not row:
		return (False, 0)

	locked_until = row["locked_until"]
	if not locked_until:
		return (False, 0)

	now = utcnow()
	if now < locked_until:
		remaining = int((locked_until - now).total_seconds())
		return (True, remaining)

	return (False, 0)


def record_failed_login(conn: sqlite3.Connection, ip_address: str) -> None:
	"""Record a failed login attempt for an IP with exponential backoff.

	Uses immediate transaction to prevent race conditions.
	"""
	now = utcnow()

	with transaction(conn, immediate=True):
		# Get current failed_count to calculate the new lockout
		cur = conn.execute(
			"SELECT failed_count FROM login_attempts WHERE ip_address = ?",
			(ip_address,),
		)
		row = cur.fetchone()
		current_count = row["failed_count"] if row else 0
		new_count = current_count + 1

		# Calculate lockout duration based on NEW count
		lockout_seconds = _calculate_lockout_seconds(new_count)
		locked_until = now + timedelta(seconds=lockout_seconds) if lockout_seconds > 0 else None

		# Upsert with calculated lockout
		conn.execute(
			"""
			INSERT INTO login_attempts (ip_address, failed_count, last_attempt_at, created_at, locked_until)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(ip_address) DO UPDATE SET
				failed_count = ?,
				last_attempt_at = excluded.last_attempt_at,
				locked_until = excluded.locked_until
			""",
			(ip_address, new_count, now, now, locked_until, new_count),
		)


def clear_login_attempts(conn: sqlite3.Connection, ip_address: str) -> None:
	"""Clear failed login attempts for an IP after successful login."""
	with transaction(conn):
		conn.execute("DELETE FROM login_attempts WHERE ip_address = ?", (ip_address,))
