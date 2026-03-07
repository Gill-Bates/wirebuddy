#!/usr/bin/env python3
#
# app/utils/migration.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""
Database schema migrations for WireBuddy.

Migration Framework
-------------------
This module provides a versioned migration system for schema updates.

How it works:
1. `schema_version` table tracks the current schema version
2. Each migration has a unique version number (monotonically increasing)
3. On startup, `run_pending_migrations()` applies all migrations with
   version > current_version, in order
4. Migrations are idempotent – safe to re-run if interrupted

Adding a new migration:
1. Create a function `_migrate_NNNN_description(conn)` where NNNN is the version
2. Add it to _MIGRATIONS list with its version number
3. Test on both fresh DB and existing DB

Factory-default baseline note:
The current schema baseline is fully defined in `init_schema()`.
Migration history up to this baseline was intentionally absorbed into
factory defaults, so migration versioning is reset to 0.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from typing import Callable

from ..db.sqlite_runtime import transaction

_log = logging.getLogger(__name__)
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Current schema version.
# Baseline is reset to v0 because all previous schema changes are now
# integrated into init_schema() factory defaults.
SCHEMA_VERSION = 3


def _ensure_schema_version_table(conn: sqlite3.Connection) -> None:
	"""Create schema_version table if it doesn't exist.

	Uses transaction() to avoid standalone commit() calls that
	conflict with outer transactions or concurrent workers.
	"""
	with transaction(conn, immediate=True):
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS schema_version (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				version INTEGER NOT NULL DEFAULT 0,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)
			"""
		)
		# Ensure exactly one row exists
		conn.execute(
			"""
			INSERT OR IGNORE INTO schema_version (id, version) VALUES (1, 0)
			"""
		)


def get_schema_version(conn: sqlite3.Connection) -> int:
	"""Get the current schema version from the database.
	
	Note: Assumes schema_version table already exists.
	Call run_pending_migrations() at startup to ensure table creation.
	"""
	cur = conn.execute("SELECT version FROM schema_version WHERE id = 1")
	row = cur.fetchone()
	return row[0] if row else 0


def _set_schema_version(conn: sqlite3.Connection, version: int) -> None:
	"""Update the schema version in the database."""
	conn.execute(
		"UPDATE schema_version SET version = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
		(version,),
	)


# ---------------------------------------------------------------------------
# Helper functions for migrations
# ---------------------------------------------------------------------------


def _validate_identifier(name: str) -> str:
	"""Validate that *name* is a safe SQL identifier."""
	if not _IDENT_RE.fullmatch(name):
		raise ValueError(f"Invalid SQL identifier: {name!r}")
	return name


def _quote_identifier(name: str) -> str:
	"""Return a safely quoted SQL identifier.
	
	Note: Relies on _validate_identifier to reject names containing quotes.
	Does not perform quote escaping.
	"""
	validated = _validate_identifier(name)
	return f'"{validated}"'


def _get_columns(conn: sqlite3.Connection, table: str) -> set[str]:
	"""Return the set of column names for a table."""
	table_ident = _quote_identifier(table)
	cur = conn.execute(f"PRAGMA table_info({table_ident})")
	return {row[1] for row in cur.fetchall()}


def _add_column_if_missing(
	conn: sqlite3.Connection,
	table: str,
	column: str,
	definition: str,
	columns: set[str] | None = None,
) -> bool:
	"""Add a column to *table* if it does not exist yet.  Returns True if added.
	
	Note: This only checks column presence, not schema correctness (type, default, constraints).
	If a migration is partially applied with wrong column type, re-running will skip it silently.
	
	Warning: The *definition* parameter is unsanitized SQL interpolated directly.
	Callers MUST ensure it contains only trusted, validated SQL (e.g. "TEXT NOT NULL DEFAULT ''").
	This is internal-only and assumes migration functions are trusted code.
	"""
	table_ident = _quote_identifier(table)
	column_ident = _quote_identifier(column)
	if columns is None:
		columns = _get_columns(conn, table)
	if column not in columns:
		conn.execute(f"ALTER TABLE {table_ident} ADD COLUMN {column_ident} {definition}")
		_log.info("Migration: %s.%s column added", table, column)
		return True
	return False


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
	"""Check if a table exists in the database."""
	validated_table = _validate_identifier(table)
	cur = conn.execute(
		"SELECT name FROM sqlite_master WHERE type='table' AND name=?",
		(validated_table,),
	)
	return cur.fetchone() is not None


# ---------------------------------------------------------------------------
# Migration registry
# ---------------------------------------------------------------------------

# Historical migrations are now part of the factory-default schema.
# Start a new migration history from 0 for future schema changes.
#
# Migration naming convention: _migrate_NNNN_description(conn: sqlite3.Connection) -> None
# where NNNN is the version number (must match version in tuple).


def _migrate_0001_passkey_support(conn: sqlite3.Connection) -> None:
	"""Add passkey (WebAuthn) support: passkeys table and users columns."""
	# Create passkeys table
	conn.execute(
		"""
		CREATE TABLE IF NOT EXISTS passkeys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			credential_id TEXT NOT NULL UNIQUE,
			public_key BLOB NOT NULL,
			sign_count INTEGER NOT NULL DEFAULT 0,
			device_name TEXT,
			transports TEXT,
			created_at TIMESTAMP NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		)
		"""
	)
	conn.execute("CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON passkeys(user_id)")
	conn.execute("CREATE INDEX IF NOT EXISTS idx_passkeys_credential_id ON passkeys(credential_id)")

	# Add new columns to users table
	columns = _get_columns(conn, "users")
	_add_column_if_missing(conn, "users", "auth_method", "TEXT DEFAULT 'password'", columns)
	_add_column_if_missing(conn, "users", "passkey_enabled", "INTEGER DEFAULT 0", columns)

	_log.info("Migration 0001: Added passkey support")


def _migrate_0002_passkey_pending(conn: sqlite3.Connection) -> None:
	"""Add passkey_pending column for user onboarding flow."""
	columns = _get_columns(conn, "users")
	_add_column_if_missing(conn, "users", "passkey_pending", "INTEGER DEFAULT 0", columns)
	_log.info("Migration 0002: Added passkey_pending column")


def _migrate_0003_passkey_challenges(conn: sqlite3.Connection) -> None:
	"""Add passkey_challenges table for multi-worker WebAuthn challenge storage."""
	if not _table_exists(conn, "passkey_challenges"):
		conn.execute(
			"""
			CREATE TABLE passkey_challenges (
				challenge TEXT PRIMARY KEY,
				ceremony_type TEXT NOT NULL CHECK (ceremony_type IN ('registration', 'authentication')),
				user_id INTEGER,
				username TEXT,
				expires_at REAL NOT NULL,
				created_at REAL NOT NULL
			)
			"""
		)
		conn.execute("CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expires ON passkey_challenges(expires_at)")
		_log.info("Migration 0003: Added passkey_challenges table")
	else:
		_log.info("Migration 0003: passkey_challenges table already exists")


_MIGRATIONS: list[tuple[int, Callable[[sqlite3.Connection], None]]] = [
	(1, _migrate_0001_passkey_support),
	(2, _migrate_0002_passkey_pending),
	(3, _migrate_0003_passkey_challenges),
]


def _validate_migration_registry() -> None:
	"""Validate migration registry integrity at import time."""
	versions = [version for version, _ in _MIGRATIONS]
	if len(versions) != len(set(versions)):
		raise RuntimeError("Duplicate migration versions in _MIGRATIONS")
	if versions != sorted(versions):
		raise RuntimeError("Migrations must be listed in ascending version order")
	
	# Validate migration function naming convention
	for version, func in _MIGRATIONS:
		if not func.__name__.startswith("_migrate_"):
			raise RuntimeError(
				f"Migration function {func.__name__} must follow _migrate_NNNN_ naming convention"
			)
	
	if versions:
		max_version = max(versions)
		if max_version != SCHEMA_VERSION:
			raise RuntimeError(
				f"SCHEMA_VERSION ({SCHEMA_VERSION}) must match highest migration version ({max_version})"
			)
	elif SCHEMA_VERSION != 0:
		# Empty migration registry but SCHEMA_VERSION > 0 is inconsistent
		raise RuntimeError(
			f"SCHEMA_VERSION is {SCHEMA_VERSION} but no migrations are registered"
		)


_validate_migration_registry()


# ---------------------------------------------------------------------------
# Migration runner
# ---------------------------------------------------------------------------


def run_pending_migrations(conn: sqlite3.Connection) -> int:
	"""Execute all pending migrations.

	Each migration runs in its own transaction() block so that
	partial progress is preserved on failure and no standalone
	commit()/rollback() calls are needed.

	When no migrations are registered, schema_version is normalized to
	SCHEMA_VERSION (currently 0) so baseline resets are applied.

	Returns:
		Number of migrations applied

	Raises:
		RuntimeError: If any migration fails (transaction is rolled back)
	"""
	# Ensure schema_version table exists before reading
	_ensure_schema_version_table(conn)
	current_version = get_schema_version(conn)

	# Handle version downgrade scenarios
	if current_version > SCHEMA_VERSION:
		# Special case: Allow downgrade to v0 (baseline reset)
		# This happens when migration history is absorbed into init_schema() factory defaults
		if SCHEMA_VERSION == 0:
			_log.warning(
				"MIGRATION baseline reset: database at v%d, normalizing to v0 "
				"(all schema changes now in factory defaults)",
				current_version,
			)
			with transaction(conn, immediate=True):
				_set_schema_version(conn, 0)
			return 0
		else:
			# Refuse downgrade in all other cases (application rollback detected)
			_log.error(
				"MIGRATION database is at v%d but application only knows v%d — "
				"refusing to downgrade. Was the application rolled back?",
				current_version,
				SCHEMA_VERSION,
			)
			raise RuntimeError(
				f"Schema version {current_version} is ahead of application version {SCHEMA_VERSION}. "
				f"Database may have been modified by a newer version of the application."
			)

	# Filter and sort migrations that need to run
	pending = [
		(ver, func) for ver, func in _MIGRATIONS
		if ver > current_version
	]
	pending.sort(key=lambda x: x[0])

	if not pending:
		# Normalize version metadata if needed (idempotent)
		if current_version != SCHEMA_VERSION:
			with transaction(conn, immediate=True):
				_set_schema_version(conn, SCHEMA_VERSION)
			_log.info(
				"MIGRATION normalized schema version from v%d to v%d",
				current_version,
				SCHEMA_VERSION,
			)
		else:
			_log.debug("MIGRATION no pending migrations (schema version: %d)", current_version)
		return 0

	_log.info(
		"MIGRATION %d pending migration(s) to apply (current: v%d, target: v%d)",
		len(pending),
		current_version,
		pending[-1][0],
	)

	applied = 0
	for version, func in pending:
		try:
			_log.info("MIGRATION applying v%d: %s", version, func.__name__)
			with transaction(conn, immediate=True):
				func(conn)
				_set_schema_version(conn, version)
			applied += 1
			_log.info("MIGRATION v%d applied successfully", version)
		except Exception as exc:
			_log.error("MIGRATION v%d failed: %s", version, exc)
			raise RuntimeError(f"Migration v{version} failed: {exc}") from exc

	_log.info("MIGRATION completed: %d migration(s) applied", applied)
	return applied


def check_migration_status(conn: sqlite3.Connection) -> dict:
	"""Check migration status without applying changes.
	
	Returns:
		Dict with schema version info and pending migrations
	"""
	current_version = get_schema_version(conn)
	
	pending = [
		{"version": ver, "name": func.__name__}
		for ver, func in _MIGRATIONS
		if ver > current_version
	]
	
	return {
		"current_version": current_version,
		"target_version": SCHEMA_VERSION,
		"pending_count": len(pending),
		"pending_migrations": pending,
		"up_to_date": len(pending) == 0 and current_version == SCHEMA_VERSION,
	}
