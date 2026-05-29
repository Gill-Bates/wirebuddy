#!/usr/bin/env python3
#
# app/db/sqlite_auth.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Auth-token handling and login-attempt lockout tracking."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import math
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from ..utils.crypto import hash_token
from ..utils.time import ensure_utc, utcnow
from .sqlite_runtime import transaction

_log = logging.getLogger(__name__)


def _parse_db_timestamp(value: object) -> datetime | None:
	"""Normalize a database timestamp value to a timezone-aware UTC datetime."""
	if value is None:
		return None
	if isinstance(value, datetime):
		return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
	if isinstance(value, str):
		text = value.strip()
		if not text:
			return None
		if text.endswith("Z"):
			text = text[:-1] + "+00:00"
		try:
			dt = datetime.fromisoformat(text)
		except ValueError:
			return None
		return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
	return None


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
	if int(user_id) <= 0:
		raise ValueError("user_id must be > 0")
	now = utcnow()
	expires_at = ensure_utc(expires_at)
	max_expires_at = ensure_utc(max_expires_at)
	if expires_at is None or max_expires_at is None:
		raise ValueError("expires_at and max_expires_at must be timezone-aware datetimes")
	if expires_at <= now:
		raise ValueError("expires_at must be in the future")
	if max_expires_at < expires_at:
		raise ValueError("max_expires_at must be >= expires_at")
	token_hash = hash_token(token)
	with transaction(conn):
		cur = conn.execute(
			"""
			INSERT INTO auth_tokens (user_id, token_hash, expires_at, max_expires_at, created_at)
			VALUES (?, ?, ?, ?, ?)
			""",
			(int(user_id), token_hash, expires_at, max_expires_at, now),
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


def refresh_auth_token(conn: sqlite3.Connection, token: str, hours: int = 1) -> bool:
	"""Extend token expiry by the given hours, but not beyond max_expires_at.

	Returns True if a non-expired token was found and refreshed.
	"""
	token_hash = hash_token(token)
	now = utcnow()
	new_expires = now + timedelta(hours=hours)

	with transaction(conn):
		cur = conn.execute(
			"""
			UPDATE auth_tokens
			SET expires_at = MIN(?, max_expires_at)
			WHERE token_hash = ? AND expires_at > ?
			""",
			(new_expires, token_hash, now),
		)
		return cur.rowcount > 0


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
		deleted = cur.rowcount
	if deleted:
		_log.info("Deleted %d expired auth tokens", deleted)
	return deleted


def delete_user_tokens(conn: sqlite3.Connection, user_id: int) -> None:
	"""Delete all tokens for a user (logout all sessions)."""
	with transaction(conn):
		conn.execute("DELETE FROM auth_tokens WHERE user_id = ?", (user_id,))


# ---------------------------------------------------------------------------
# Login attempt tracking (exponential backoff)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class _LockoutPolicy:
	key_prefix: str
	min_failures: int
	base_seconds: int
	max_seconds: int


def _int_env(name: str, default: int, *, minimum: int = 1) -> int:
	"""Read a positive integer from env, falling back safely on invalid values."""
	raw = os.environ.get(name)
	if raw is None:
		return default
	try:
		value = int(raw)
	except ValueError:
		_log.warning("Ignoring invalid %s=%r; using %d", name, raw, default)
		return default
	if value < minimum:
		_log.warning("Ignoring %s=%r below minimum %d; using %d", name, raw, minimum, default)
		return default
	return value


_IP_LOCKOUT_POLICY = _LockoutPolicy(
	key_prefix="ip",
	min_failures=_int_env("WIREBUDDY_LOGIN_IP_MIN_FAILURES", 5),
	base_seconds=_int_env("WIREBUDDY_LOGIN_IP_BASE_LOCKOUT_SECONDS", 30),
	max_seconds=_int_env("WIREBUDDY_LOGIN_IP_MAX_LOCKOUT_SECONDS", 86400),
)
_USER_IP_LOCKOUT_POLICY = _LockoutPolicy(
	key_prefix="userip",
	min_failures=_int_env("WIREBUDDY_LOGIN_USER_IP_MIN_FAILURES", 3),
	base_seconds=_int_env("WIREBUDDY_LOGIN_USER_IP_BASE_LOCKOUT_SECONDS", 30),
	max_seconds=_int_env("WIREBUDDY_LOGIN_USER_IP_MAX_LOCKOUT_SECONDS", 3600),
)


def _normalize_login_subject(username: str | None) -> str | None:
	"""Return a normalized username token for composite lockout keys."""
	if username is None:
		return None
	normalized = username.strip().casefold()
	return normalized[:128] or None


def _build_attempt_keys(ip_address: str, username: str | None) -> list[tuple[str, _LockoutPolicy]]:
	"""Return all storage keys participating in login throttling."""
	keys = [(f"{_IP_LOCKOUT_POLICY.key_prefix}:{ip_address}", _IP_LOCKOUT_POLICY)]
	normalized_username = _normalize_login_subject(username)
	if normalized_username is not None:
		keys.append(
			(
				f"{_USER_IP_LOCKOUT_POLICY.key_prefix}:{normalized_username}:{ip_address}",
				_USER_IP_LOCKOUT_POLICY,
			)
		)
	return keys


def _calculate_lockout_seconds(failed_count: int, policy: _LockoutPolicy) -> int:
	"""Calculate exponential backoff lockout duration.

	Formula: BASE * 2^(attempts - MIN_FAILURES)
	- first lockout starts at the configured base seconds
	- each subsequent failure doubles the duration
	- higher failures are capped at 24 hours
	"""
	if failed_count < policy.min_failures:
		return 0

	exponent = failed_count - policy.min_failures
	max_exponent = math.floor(math.log2(policy.max_seconds / policy.base_seconds))
	if exponent > max_exponent:
		return policy.max_seconds
	lockout = policy.base_seconds * (2**exponent)
	return min(lockout, policy.max_seconds)


def is_ip_locked(conn: sqlite3.Connection, ip_address: str, username: str | None = None) -> tuple[bool, int]:
	"""Check if an IP or username+IP pair is locked out from login attempts.

	Returns:
		Tuple of (is_locked, seconds_remaining)
	"""
	now = utcnow()
	max_remaining = 0
	for key, _policy in _build_attempt_keys(ip_address, username):
		cur = conn.execute(
			"SELECT locked_until FROM login_attempts WHERE ip_address = ?",
			(key,),
		)
		row = cur.fetchone()
		if not row:
			continue
		locked_until = _parse_db_timestamp(row["locked_until"])
		if locked_until is None or now >= locked_until:
			continue
		max_remaining = max(max_remaining, int((locked_until - now).total_seconds()))

	return (max_remaining > 0, max_remaining)


def record_failed_login(conn: sqlite3.Connection, ip_address: str, username: str | None = None) -> None:
	"""Record failed login attempts for the IP and username+IP lockout keys.

	Uses immediate transaction to prevent race conditions.
	"""
	now = utcnow()

	with transaction(conn, immediate=True):
		for key, policy in _build_attempt_keys(ip_address, username):
			cur = conn.execute(
				"SELECT failed_count, last_attempt_at FROM login_attempts WHERE ip_address = ?",
				(key,),
			)
			row = cur.fetchone()
			current_count = 0
			if row is not None:
				last_attempt_at = _parse_db_timestamp(row["last_attempt_at"])
				if last_attempt_at is not None and now - last_attempt_at <= timedelta(seconds=policy.max_seconds):
					current_count = int(row["failed_count"] or 0)
			new_count = current_count + 1
			lockout_seconds = _calculate_lockout_seconds(new_count, policy)
			locked_until = now + timedelta(seconds=lockout_seconds) if lockout_seconds > 0 else None

			conn.execute(
				"""
				INSERT INTO login_attempts (ip_address, failed_count, last_attempt_at, created_at, locked_until)
				VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(ip_address) DO UPDATE SET
					failed_count = ?,
					last_attempt_at = excluded.last_attempt_at,
					locked_until = excluded.locked_until
				""",
				(key, new_count, now, now, locked_until, new_count),
			)


def clear_login_attempts(conn: sqlite3.Connection, ip_address: str, username: str | None = None) -> None:
	"""Clear failed login attempts for all keys after successful login."""
	with transaction(conn):
		for key, _policy in _build_attempt_keys(ip_address, username):
			conn.execute("DELETE FROM login_attempts WHERE ip_address = ?", (key,))
