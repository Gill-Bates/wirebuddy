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

Pre-release note:
Since there's no public release yet, all schema definitions are in
`init_schema()` in sqlite.py. This migration system is set up for
post-release schema changes.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from typing import Callable

from ..db.sqlite_runtime import transaction

_log = logging.getLogger(__name__)
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Current schema version – reflects the baseline absorbed into init_schema().
# Increment this AND add a new _migrate_NNNN_* function when a future
# schema change is needed.
SCHEMA_VERSION = 6  # v6: enable ad-blocker for existing peers


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
	"""Get the current schema version from the database."""
	with transaction(conn, immediate=True):
		_ensure_schema_version_table(conn)
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
	"""Return a safely quoted SQL identifier."""
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
	"""Add a column to *table* if it does not exist yet.  Returns True if added."""
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
# Migration functions
# ---------------------------------------------------------------------------
# Each migration function takes a Connection and must be idempotent.
# Version numbers must be unique and monotonically increasing.
#
# Template for future migrations:
#
#   def _migrate_0006_description(conn: sqlite3.Connection) -> None:
#       """Short description of what changes."""
#       _add_column_if_missing(conn, "table", "column", "TYPE DEFAULT x")
#
# Then register it below:
#   (6, _migrate_0006_description),


def _migrate_0005_baseline_catchup(conn: sqlite3.Connection) -> None:
	"""Idempotent baseline migration for v1-v5 schema changes.

	This migration exists so that older database backups can be upgraded
	to the current schema. All operations are idempotent - they check if
	columns/tables exist before adding them, so this is safe to run on
	fresh databases as well.

	If you're adding new columns in future versions, add a new migration
	function (e.g., _migrate_0006_*) rather than modifying this one.
	"""
	for required_table in ("peers", "interfaces", "users"):
		if not _table_exists(conn, required_table):
			raise RuntimeError(
				f"Migration v5 expects table '{required_table}' to exist. "
				"Database may be too old or corrupted."
			)

	# -- peers table columns --
	peers_cols = _get_columns(conn, "peers")

	_add_column_if_missing(conn, "peers", "description", "TEXT", peers_cols)
	_add_column_if_missing(conn, "peers", "allowed_ips_mode", "TEXT NOT NULL DEFAULT 'full'", peers_cols)
	_add_column_if_missing(conn, "peers", "client_isolation", "INTEGER NOT NULL DEFAULT 0", peers_cols)
	_add_column_if_missing(conn, "peers", "use_adblocker", "INTEGER NOT NULL DEFAULT 1", peers_cols)
	_add_column_if_missing(conn, "peers", "blocklist_ids", "TEXT", peers_cols)
	_add_column_if_missing(conn, "peers", "last_client_ip", "TEXT", peers_cols)
	_add_column_if_missing(conn, "peers", "cumulative_rx", "INTEGER NOT NULL DEFAULT 0", peers_cols)
	_add_column_if_missing(conn, "peers", "cumulative_tx", "INTEGER NOT NULL DEFAULT 0", peers_cols)
	_add_column_if_missing(conn, "peers", "last_wg_rx", "INTEGER NOT NULL DEFAULT 0", peers_cols)
	_add_column_if_missing(conn, "peers", "last_wg_tx", "INTEGER NOT NULL DEFAULT 0", peers_cols)

	# -- interfaces table columns --
	iface_cols = _get_columns(conn, "interfaces")

	_add_column_if_missing(conn, "interfaces", "address6", "TEXT", iface_cols)
	_add_column_if_missing(conn, "interfaces", "client_endpoint_port", "INTEGER", iface_cols)

	# -- users table columns --
	users_cols = _get_columns(conn, "users")

	_add_column_if_missing(conn, "users", "otp_secret", "TEXT", users_cols)
	_add_column_if_missing(conn, "users", "otp_enabled", "INTEGER NOT NULL DEFAULT 0", users_cols)
	_add_column_if_missing(conn, "users", "otp_recovery_codes", "TEXT", users_cols)

	# -- auth_tokens table (may not exist in very old DBs) --
	if not _table_exists(conn, "auth_tokens"):
		conn.execute(
			"""
			CREATE TABLE auth_tokens (
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
		_log.info("Migration: auth_tokens table created")

	# -- login_attempts table (may not exist in very old DBs) --
	if not _table_exists(conn, "login_attempts"):
		conn.execute(
			"""
			CREATE TABLE login_attempts (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				ip_address TEXT NOT NULL UNIQUE,
				failed_count INTEGER NOT NULL DEFAULT 0,
				last_attempt_at timestamp NOT NULL,
				locked_until timestamp,
				created_at timestamp NOT NULL
			)
			"""
		)
		_log.info("Migration: login_attempts table created")

	# -- app_lock table (may not exist in very old DBs) --
	if not _table_exists(conn, "app_lock"):
		conn.execute(
			"""
			CREATE TABLE app_lock (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				pid INTEGER NOT NULL,
				acquired_at timestamp NOT NULL
			)
			"""
		)
		_log.info("Migration: app_lock table created")

	_log.info("Migration: v5 baseline catchup complete")


def _migrate_0006_enable_adblocker_for_peers(conn: sqlite3.Connection) -> None:
	"""Migration v6: Enable ad-blocker for all existing peers.
	
	The use_adblocker column was added with DEFAULT 0, but the intended
	default is 1 (peers use ad-blocker when globally enabled).
	This migration sets use_adblocker = 1 for all existing peers.
	"""
	result = conn.execute("UPDATE peers SET use_adblocker = 1 WHERE use_adblocker = 0")
	_log.info("Migration: v6 enabled ad-blocker for %d peer(s)", result.rowcount)


# ---------------------------------------------------------------------------
# Migration registry
# ---------------------------------------------------------------------------

# List of (version: int, function: Callable) tuples.
# Migrations are applied in version order for versions > the DB's current version.
_MIGRATIONS: list[tuple[int, Callable[[sqlite3.Connection], None]]] = [
	(5, _migrate_0005_baseline_catchup),
	(6, _migrate_0006_enable_adblocker_for_peers),
	# Future migrations go here, e.g.:
	# (7, _migrate_0007_description),
]


def _validate_migration_registry() -> None:
	"""Validate migration registry integrity at import time."""
	versions = [version for version, _ in _MIGRATIONS]
	if len(versions) != len(set(versions)):
		raise RuntimeError("Duplicate migration versions in _MIGRATIONS")
	if versions != sorted(versions):
		raise RuntimeError("Migrations must be listed in ascending version order")
	if versions:
		max_version = max(versions)
		if max_version != SCHEMA_VERSION:
			raise RuntimeError(
				f"SCHEMA_VERSION ({SCHEMA_VERSION}) must match highest migration version ({max_version})"
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

	Fresh databases (version 0 with no pending migrations) are
	stamped to SCHEMA_VERSION so version tracking stays in sync.

	Returns:
		Number of migrations applied

	Raises:
		RuntimeError: If any migration fails (transaction is rolled back)
	"""
	current_version = get_schema_version(conn)

	# Filter and sort migrations that need to run
	pending = [
		(ver, func) for ver, func in _MIGRATIONS
		if ver > current_version
	]
	pending.sort(key=lambda x: x[0])

	if not pending:
		# Only stamp fresh databases (version 0) to SCHEMA_VERSION.
		# A backup from an older version (e.g. v3) would have version > 0
		# but < SCHEMA_VERSION — that requires actual migrations, not stamping.
		# If _MIGRATIONS is empty but the DB is old, we cannot auto-upgrade;
		# the admin must use a version that still has those migrations.
		if current_version == 0:
			# Fresh database: init_schema() created the full v5 schema,
			# so we can safely stamp it without running migrations.
			with transaction(conn, immediate=True):
				_set_schema_version(conn, SCHEMA_VERSION)
			_log.info(
				"MIGRATION stamped fresh database to schema version %d",
				SCHEMA_VERSION,
			)
		elif current_version < SCHEMA_VERSION:
			raise RuntimeError(
				f"Database schema v{current_version} is older than code v{SCHEMA_VERSION} "
				"and no pending migrations are available. Restore from a compatible backup "
				"or provide the missing migrations."
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
		"up_to_date": len(pending) == 0,
	}
