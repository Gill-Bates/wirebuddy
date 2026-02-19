#!/usr/bin/env python3
#
# app/db/sqlite.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""SQLite database access layer and schema initialization."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from ..utils.time import utcnow
from ..utils.crypto import hash_password, hash_token

_log = logging.getLogger(__name__)

# Sentinel value to distinguish "not provided" from "set to None" in update functions.
# Use `is UNSET` to check if a parameter was not provided.
# The type annotation `object` is intentionally broad; stricter typing would require
# a dedicated Enum or Literal type, which adds complexity without runtime benefit.
UNSET: object = object()


def _adapt_datetime(value: datetime) -> str:
	if value.tzinfo is None:
		raise ValueError("Naive datetime not allowed in SQLite")
	return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _convert_datetime(value: bytes) -> datetime:
	s = value.decode("utf-8")
	if s.endswith("Z"):
		s = s[:-1] + "+00:00"
	try:
		dt = datetime.fromisoformat(s)
		if dt.tzinfo is None:
			dt = dt.replace(tzinfo=timezone.utc)
		return dt.astimezone(timezone.utc)
	except ValueError:
		_log.error(
			"Corrupt timestamp in database: %r - returning epoch",
			value.decode("utf-8", errors="replace"),
		)
		return datetime(1970, 1, 1, tzinfo=timezone.utc)


# NOTE: sqlite3 adapter/converter registration is process-global.
sqlite3.register_adapter(datetime, _adapt_datetime)
sqlite3.register_converter("timestamp", _convert_datetime)


# ---------------------------------------------------------------------------
# Connection Registry
# ---------------------------------------------------------------------------

_OPEN_CONNECTIONS: set[sqlite3.Connection] = set()
_CONNECTIONS_LOCK = threading.Lock()


def connect(db_path: Path) -> sqlite3.Connection:
	"""Create a SQLite connection configured for this application."""
	db_path.parent.mkdir(parents=True, exist_ok=True)
	conn = sqlite3.connect(
		str(db_path),
		detect_types=sqlite3.PARSE_DECLTYPES,
		check_same_thread=False,
		timeout=30.0,  # Busy timeout for multi-process access
	)
	conn.row_factory = sqlite3.Row
	conn.execute("PRAGMA journal_mode=WAL")
	conn.execute("PRAGMA foreign_keys=ON")
	
	with _CONNECTIONS_LOCK:
		_OPEN_CONNECTIONS.add(conn)
	
	return conn


def close_connection(conn: sqlite3.Connection) -> None:
	"""Close and untrack a SQLite connection."""
	with _CONNECTIONS_LOCK:
		_OPEN_CONNECTIONS.discard(conn)
	conn.close()


def close_all_connections() -> int:
	"""Close all tracked connections for graceful shutdown."""
	with _CONNECTIONS_LOCK:
		connections = list(_OPEN_CONNECTIONS)
		_OPEN_CONNECTIONS.clear()
	
	success_count = 0
	for conn in connections:
		try:
			conn.close()
			success_count += 1
		except Exception as e:
			_log.warning("Failed to close SQLite connection: %s", e)
	
	return success_count


def checkpoint_wal(db_path: Path, mode: str = "TRUNCATE") -> dict[str, int | str]:
	"""Run a WAL checkpoint using a dedicated short-lived connection.

	Returns checkpoint counters in SQLite's ``wal_checkpoint`` format:
	``busy``, ``log_frames``, ``checkpointed_frames``.
	"""
	mode_upper = mode.strip().upper()
	if mode_upper not in {"PASSIVE", "FULL", "RESTART", "TRUNCATE"}:
		mode_upper = "TRUNCATE"

	conn: sqlite3.Connection | None = None
	try:
		conn = sqlite3.connect(
			str(db_path),
			timeout=30.0,
			check_same_thread=False,
		)
		conn.execute("PRAGMA busy_timeout=30000")
		row = conn.execute(f"PRAGMA wal_checkpoint({mode_upper})").fetchone()
		if not row:
			return {
				"mode": mode_upper,
				"busy": -1,
				"log_frames": -1,
				"checkpointed_frames": -1,
			}
		return {
			"mode": mode_upper,
			"busy": int(row[0]),
			"log_frames": int(row[1]),
			"checkpointed_frames": int(row[2]),
		}
	except Exception as e:
		_log.warning("WAL checkpoint failed (%s): %s", mode_upper, e)
		return {
			"mode": mode_upper,
			"busy": -1,
			"log_frames": -1,
			"checkpointed_frames": -1,
		}
	finally:
		if conn is not None:
			try:
				conn.close()
			except Exception:
				pass


@contextmanager
def transaction(conn: sqlite3.Connection, *, immediate: bool = False):
	"""Transaction context manager that commits or rolls back on error.
	
	If already inside a transaction, this is a no-op (the outer transaction
	controls commit/rollback). This enables composability but means inner
	functions MUST NOT catch and suppress exceptions that the outer transaction
	needs to see for rollback.
	"""
	started_tx = False
	if not conn.in_transaction:
		conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
		started_tx = True
	try:
		yield
		if started_tx:
			conn.commit()
	except Exception:
		if started_tx and conn.in_transaction:
			conn.rollback()
		raise


# ─────────────────────────────────────────────────────────────────────────────
# Leader Election (multi-worker safety)
# ─────────────────────────────────────────────────────────────────────────────

def try_acquire_leader_lock(conn: sqlite3.Connection) -> bool:
	"""Attempt to acquire the leader lock for this process.
	
	Returns True if this process is now the leader (should run scheduler/init tasks).
	Uses INSERT OR REPLACE with a CHECK that only one row can exist.
	"""
	pid = os.getpid()
	now = utcnow()
	stale_threshold = now - timedelta(seconds=60)
	force_takeover = 0
	started_tx = False
	
	try:
		if not conn.in_transaction:
			conn.execute("BEGIN IMMEDIATE")
			started_tx = True

		# Fast stale-lock recovery: if lock owner PID no longer exists, steal lock now.
		cur = conn.execute("SELECT pid FROM app_lock WHERE id = 1")
		row = cur.fetchone()
		if row is not None:
			try:
				owner_pid = int(row["pid"])
			except (TypeError, ValueError):
				owner_pid = -1
			if owner_pid > 0 and owner_pid != pid:
				try:
					os.kill(owner_pid, 0)
				except ProcessLookupError:
					force_takeover = 1
				except PermissionError:
					# Different UID/process namespace: do not steal lock aggressively.
					force_takeover = 0
				except Exception:
					force_takeover = 0

		# Try to insert/update the lock
		# Use Python-generated timestamp for comparison to avoid ISO 8601 'T' vs space mismatch
		conn.execute(
			"""
			INSERT INTO app_lock (id, pid, acquired_at)
			VALUES (1, ?, ?)
			ON CONFLICT(id) DO UPDATE SET pid = excluded.pid, acquired_at = excluded.acquired_at
			WHERE pid = ? OR acquired_at < ? OR ? = 1
			""",
			(pid, now, pid, stale_threshold, force_takeover),
		)
		
		# Check if we got it (same transaction to avoid TOCTOU gap)
		cur = conn.execute("SELECT pid FROM app_lock WHERE id = 1")
		row = cur.fetchone()
		success = row is not None and row["pid"] == pid
		if started_tx:
			conn.commit()
		return success
	except Exception as e:
		if started_tx and conn.in_transaction:
			conn.rollback()
		_log.warning("Failed to acquire leader lock: %s", e)
		return False


def release_leader_lock(conn: sqlite3.Connection) -> bool:
	"""Release the leader lock if held by this process."""
	pid = os.getpid()
	try:
		conn.execute("DELETE FROM app_lock WHERE id = 1 AND pid = ?", (pid,))
		conn.commit()
		return True
	except Exception as e:
		_log.warning("Failed to release leader lock: %s", e)
		return False


def is_leader(conn: sqlite3.Connection) -> bool:
	"""Check if this process currently holds the leader lock."""
	pid = os.getpid()
	try:
		cur = conn.execute("SELECT pid FROM app_lock WHERE id = 1")
		row = cur.fetchone()
		return row is not None and row["pid"] == pid
	except Exception:
		return False


# ─────────────────────────────────────────────────────────────────────────────
# Schema Initialization
# ─────────────────────────────────────────────────────────────────────────────


def init_schema(conn: sqlite3.Connection) -> None:
	"""Create the required database schema (factory default).
	
	This defines the complete schema for fresh installs.
	"""
	with transaction(conn):
		# Users table
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				username TEXT NOT NULL UNIQUE,
				password_hash TEXT NOT NULL,
				is_admin INTEGER NOT NULL DEFAULT 0,
				is_active INTEGER NOT NULL DEFAULT 1,
				last_login_at timestamp,
				last_login_ip TEXT,
				created_at timestamp NOT NULL
			)
			"""
		)

		# Auth tokens
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS auth_tokens (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id INTEGER NOT NULL,
				token_hash TEXT NOT NULL UNIQUE,
				expires_at timestamp NOT NULL,
				max_expires_at timestamp NOT NULL,
				created_at timestamp NOT NULL,
				FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
			)
			"""
		)
		conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires_at ON auth_tokens(expires_at)")
		conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_tokens_user_id ON auth_tokens(user_id)")

		# Settings
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS settings (
				key TEXT PRIMARY KEY,
				value TEXT NOT NULL,
				updated_at timestamp NOT NULL
			)
			"""
		)

		# Login attempts (for brute-force protection)
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS login_attempts (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				ip_address TEXT NOT NULL UNIQUE,
				failed_count INTEGER NOT NULL DEFAULT 0,
				last_attempt_at timestamp NOT NULL,
				locked_until timestamp,
				created_at timestamp NOT NULL
			)
			"""
		)
		# Index not needed - UNIQUE already creates an index

		# WireGuard peers
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS peers (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				public_key TEXT NOT NULL UNIQUE,
				private_key TEXT,
				preshared_key TEXT,
				name TEXT,
				description TEXT,
				allowed_ips TEXT NOT NULL,
				allowed_ips_mode TEXT NOT NULL DEFAULT 'full',
				client_isolation INTEGER NOT NULL DEFAULT 0,
				peer_address TEXT,
				endpoint TEXT,
				interface TEXT NOT NULL DEFAULT 'wg0',
				is_enabled INTEGER NOT NULL DEFAULT 1,
				use_adblocker INTEGER NOT NULL DEFAULT 1,
				blocklist_ids TEXT,
				last_client_ip TEXT,
				last_handshake_at INTEGER,
				created_at timestamp NOT NULL,
				updated_at timestamp NOT NULL
			)
			"""
		)
		conn.execute("CREATE INDEX IF NOT EXISTS idx_peers_interface ON peers(interface)")
		conn.execute("CREATE INDEX IF NOT EXISTS idx_peers_peer_address ON peers(peer_address)")
		# Enforce uniqueness for assigned peer VPN address per interface.
		# Safe rollout: if legacy duplicates exist, keep startup running and warn.
		duplicate = conn.execute(
			"""
			SELECT interface, peer_address, COUNT(*) AS cnt
			FROM peers
			WHERE peer_address IS NOT NULL
			GROUP BY interface, peer_address
			HAVING COUNT(*) > 1
			LIMIT 1
			"""
		).fetchone()
		if duplicate is None:
			conn.execute(
				"""
				CREATE UNIQUE INDEX IF NOT EXISTS idx_peers_address_interface_unique
				ON peers(peer_address, interface)
				WHERE peer_address IS NOT NULL
				"""
			)
		else:
			_log.warning(
				"Skipping unique peer_address index due to legacy duplicates (interface=%s, peer_address=%s, count=%s)",
				duplicate[0],
				duplicate[1],
				duplicate[2],
			)

		# WireGuard interfaces
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS interfaces (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL UNIQUE,
				private_key TEXT NOT NULL,
				public_key TEXT NOT NULL,
				address TEXT NOT NULL,
				address6 TEXT,
				listen_port INTEGER NOT NULL DEFAULT 51820,
				dns TEXT,
				post_up TEXT,
				post_down TEXT,
				is_enabled INTEGER NOT NULL DEFAULT 1,
				created_at timestamp NOT NULL,
				updated_at timestamp NOT NULL
			)
			"""
		)

		# App lock table for leader election (multi-worker safety)
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS app_lock (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				pid INTEGER NOT NULL,
				acquired_at timestamp NOT NULL
			)
			"""
		)

def ensure_default_admin(conn: sqlite3.Connection) -> None:
	"""Create a default admin user if no users exist."""
	now = utcnow()
	default_password = "admin"  # Should be changed on first login
	try:
		conn.execute("BEGIN IMMEDIATE")
		cur = conn.execute("SELECT COUNT(*) FROM users")
		count = cur.fetchone()[0]
		if count == 0:
			conn.execute(
				"""
				INSERT INTO users (username, password_hash, is_admin, is_active, created_at)
				VALUES (?, ?, 1, 1, ?)
				""",
				("admin", hash_password(default_password), now),
			)
			_log.warning("Created default admin user (username: admin, password: admin) - CHANGE THIS!")
		conn.commit()
	except sqlite3.IntegrityError:
		conn.rollback()  # another worker beat us
	except Exception:
		conn.rollback()
		raise

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
BASE_LOCKOUT_SECONDS = 15     # First lockout: 15 seconds
MAX_LOCKOUT_SECONDS = 86400   # Maximum lockout: 24 hours


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
	lockout = BASE_LOCKOUT_SECONDS * (2 ** exponent)
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


# ---------------------------------------------------------------------------
# Settings operations
# ---------------------------------------------------------------------------

def get_setting(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
	"""Get a setting value by key."""
	cur = conn.execute("SELECT value FROM settings WHERE key = ?", (key,))
	row = cur.fetchone()
	return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
	"""Set a setting value."""
	now = utcnow()
	with transaction(conn):
		conn.execute(
			"""
			INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
			""",
			(key, value, now),
		)


DNS_LOG_RETENTION_OPTIONS = {0, 7, 30, 90, 180, 365}
DEFAULT_DNS_LOG_RETENTION_DAYS = 30
DEFAULT_DNS_UPSTREAM_SERVERS = [
	"1.1.1.1@853#cloudflare-dns.com",
	"9.9.9.9@853#dns.quad9.net",
	"91.239.100.100@853#unicast.censurfridns.dk",
	"45.90.28.0@853#dns.nextdns.io",
	"194.242.2.2@853#dns.mullvad.net",
]


def _setting_is_truthy(value: Any, default: bool = False) -> bool:
	"""Parse boolean-ish setting values from strings."""
	if value is None:
		return default
	return str(value).strip().lower() in {"1", "true", "yes", "on"}


def get_enabled_blocklists(conn: sqlite3.Connection) -> list[str]:
	"""Get list of enabled blocklist URLs from settings."""
	value = get_setting(conn, "dns_blocklists")
	if value:
		try:
			return json.loads(value)
		except Exception:
			pass
	# Return default blocklists if not set
	from ..dns.unbound import DEFAULT_BLOCKLISTS
	return DEFAULT_BLOCKLISTS


def set_enabled_blocklists(conn: sqlite3.Connection, urls: list[str]) -> None:
	"""Save list of enabled blocklist URLs to settings."""
	set_setting(conn, "dns_blocklists", json.dumps(urls))


def get_dns_upstream_servers(conn: sqlite3.Connection) -> list[str]:
	"""Get list of custom upstream DNS servers from settings."""
	value = get_setting(conn, "dns_upstream_servers")
	if value:
		try:
			parsed = json.loads(value)
			if isinstance(parsed, list) and parsed:
				return parsed
		except Exception:
			pass
	# Return default upstream servers if not set
	return list(DEFAULT_DNS_UPSTREAM_SERVERS)


def set_dns_upstream_servers(conn: sqlite3.Connection, servers: list[str]) -> None:
	"""Save list of custom upstream DNS servers to settings."""
	set_setting(conn, "dns_upstream_servers", json.dumps(servers))


def get_dns_log_retention_days(conn: sqlite3.Connection) -> int:
	"""Return DNS query log retention period in days.

	Allowed values:
	- 0 (disabled / keep no DNS logs)
	- 7
	- 30
	- 90
	- 180
	- 365
	"""
	raw = get_setting(conn, "dns_log_retention_days", str(DEFAULT_DNS_LOG_RETENTION_DAYS))
	try:
		parsed = int(str(raw).strip())
	except (TypeError, ValueError):
		return DEFAULT_DNS_LOG_RETENTION_DAYS
	return parsed if parsed in DNS_LOG_RETENTION_OPTIONS else DEFAULT_DNS_LOG_RETENTION_DAYS


def set_dns_log_retention_days(conn: sqlite3.Connection, days: int) -> None:
	"""Persist DNS query log retention period in days."""
	if days not in DNS_LOG_RETENTION_OPTIONS:
		raise ValueError(f"Invalid DNS log retention days: {days}")
	set_setting(conn, "dns_log_retention_days", str(days))


def get_dnssec_enabled(conn: sqlite3.Connection) -> bool:
	"""Get whether DNSSEC validation should be enabled."""
	return _setting_is_truthy(get_setting(conn, "dnssec_enabled", "1"), default=True)


def set_dnssec_enabled(conn: sqlite3.Connection, enabled: bool) -> None:
	"""Persist DNSSEC enabled setting."""
	set_setting(conn, "dnssec_enabled", "1" if enabled else "0")


def get_dns_query_logging_enabled(conn: sqlite3.Connection) -> bool:
	"""Get whether Unbound query logging is enabled."""
	return _setting_is_truthy(get_setting(conn, "dns_enable_logging", "1"), default=True)


def set_dns_query_logging_enabled(conn: sqlite3.Connection, enabled: bool) -> None:
	"""Persist Unbound query logging enabled setting."""
	set_setting(conn, "dns_enable_logging", "1" if enabled else "0")


def get_dns_blocklist_enabled(conn: sqlite3.Connection) -> bool:
	"""Get whether DNS blocklist include is enabled in Unbound config."""
	return _setting_is_truthy(get_setting(conn, "dns_enable_blocklist", "1"), default=True)


def set_dns_blocklist_enabled(conn: sqlite3.Connection, enabled: bool) -> None:
	"""Persist DNS blocklist enabled setting."""
	set_setting(conn, "dns_enable_blocklist", "1" if enabled else "0")


# ---------------------------------------------------------------------------
# Peer operations
# ---------------------------------------------------------------------------

def get_all_peers(conn: sqlite3.Connection, interface: Optional[str] = None) -> list[sqlite3.Row]:
	"""Get all peers, optionally filtered by interface."""
	if interface:
		cur = conn.execute(
			"SELECT * FROM peers WHERE interface = ? ORDER BY name",
			(interface,),
		)
	else:
		cur = conn.execute("SELECT * FROM peers ORDER BY interface, name")
	return cur.fetchall()


def count_peers(conn: sqlite3.Connection, interface: Optional[str] = None) -> int:
	"""Count peers, optionally filtered by interface."""
	if interface:
		cur = conn.execute("SELECT COUNT(*) FROM peers WHERE interface = ?", (interface,))
	else:
		cur = conn.execute("SELECT COUNT(*) FROM peers")
	row = cur.fetchone()
	return int(row[0]) if row else 0


def get_peers_paginated(
	conn: sqlite3.Connection,
	*,
	page: int = 1,
	page_size: int = 50,
	interface: Optional[str] = None,
) -> list[sqlite3.Row]:
	"""Get peers paginated, optionally filtered by interface."""
	page = max(1, page)
	page_size = max(1, page_size)
	offset = (page - 1) * page_size
	if interface:
		cur = conn.execute(
			"SELECT * FROM peers WHERE interface = ? ORDER BY interface, name LIMIT ? OFFSET ?",
			(interface, page_size, offset),
		)
	else:
		cur = conn.execute(
			"SELECT * FROM peers ORDER BY interface, name LIMIT ? OFFSET ?",
			(page_size, offset),
		)
	return cur.fetchall()


def get_peer_by_public_key(conn: sqlite3.Connection, public_key: str) -> Optional[sqlite3.Row]:
	"""Get a peer by public key."""
	cur = conn.execute("SELECT * FROM peers WHERE public_key = ?", (public_key,))
	return cur.fetchone()


def update_peer_last_seen(
	conn: sqlite3.Connection,
	public_key: str,
	client_ip: str,
	handshake_at: int,
) -> None:
	"""Persist the client's last observed public IP and handshake timestamp."""
	with transaction(conn):
		conn.execute(
			"UPDATE peers SET last_client_ip = ?, last_handshake_at = ? WHERE public_key = ?",
			(client_ip, handshake_at, public_key),
		)


def update_peers_last_seen_batch(
	conn: sqlite3.Connection,
	updates: list[tuple[str, int, str]],
) -> None:
	"""Batch-persist last_client_ip and last_handshake_at for multiple peers.

	*updates* is a list of ``(client_ip, handshake_at, public_key)`` tuples.
	"""
	if not updates:
		return
	with transaction(conn):
		conn.executemany(
			"UPDATE peers SET last_client_ip = ?, last_handshake_at = ? WHERE public_key = ?",
			updates,
		)


def get_peer_by_id(conn: sqlite3.Connection, peer_id: int) -> Optional[sqlite3.Row]:
	"""Get a peer by ID."""
	cur = conn.execute("SELECT * FROM peers WHERE id = ?", (peer_id,))
	return cur.fetchone()


def allocate_peer_ip(conn: sqlite3.Connection, interface_name: str) -> Optional[str]:
	"""Allocate the next available dual-stack IP address for a peer.
	
	Returns:
		The address string (e.g. "10.13.13.2/32, fd13:13:13::2/128"),
		or None if the pool is exhausted.

	Note:
		Allocation is optimistic and NOT atomic. A concurrent writer may reserve
		the same address between this read and the subsequent peer insert, causing
		sqlite3.IntegrityError due to the unique index on (peer_address, interface).
		Callers SHOULD catch IntegrityError and retry allocation + insert.
	"""
	import ipaddress
	
	iface = get_interface(conn, interface_name)
	if not iface:
		return None
	
	# Parse IPv4 subnet
	try:
		ipv4_iface = ipaddress.ip_interface(iface["address"].strip())
		ipv4_network = ipv4_iface.network
		ipv4_server = ipv4_iface.ip
	except ValueError as e:
		_log.error("Invalid interface IPv4 address %s: %s", iface["address"], e)
		return None
	
	# Parse IPv6 subnet (optional)
	ipv6_network = None
	ipv6_server = None
	if iface["address6"]:
		try:
			ipv6_iface = ipaddress.ip_interface(iface["address6"].strip())
			ipv6_network = ipv6_iface.network
			ipv6_server = ipv6_iface.ip
		except ValueError:
			_log.warning("Invalid interface IPv6 address %s, skipping", iface["address6"])
	
	# Collect already-used IPs from existing peers
	cur = conn.execute(
		"SELECT peer_address FROM peers WHERE interface = ? AND peer_address IS NOT NULL",
		(interface_name,),
	)
	used_v4: set[ipaddress.IPv4Address] = {ipv4_server}
	used_v6: set[ipaddress.IPv6Address] = set()
	if ipv6_server:
		used_v6.add(ipv6_server)
	
	for row in cur.fetchall():
		for part in row[0].split(","):
			part = part.strip()
			if not part:
				continue
			try:
				used_ip = ipaddress.ip_interface(part).ip
				if isinstance(used_ip, ipaddress.IPv4Address):
					used_v4.add(used_ip)
				else:
					used_v6.add(used_ip)
			except ValueError:
				pass
	
	# Find next free IPv4
	next_v4 = None
	for ip in ipv4_network.hosts():
		if ip not in used_v4:
			next_v4 = ip
			break
	
	if next_v4 is None:
		return None  # Pool exhausted
	
	# Find matching IPv6 (mirror host part from IPv4)
	result = f"{next_v4}/32"
	if ipv6_network:
		# Use same host offset for IPv6
		v4_offset = int(next_v4) - int(ipv4_network.network_address)
		next_v6 = ipv6_network.network_address + v4_offset
		if next_v6 not in used_v6 and next_v6 in ipv6_network:
			result += f", {next_v6}/128"
	
	return result


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
				public_key, private_key, preshared_key, name, description,
				allowed_ips, endpoint, interface, peer_address, allowed_ips_mode,
				int(use_adblocker), blocklist_ids_json, int(client_isolation), now, now
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
