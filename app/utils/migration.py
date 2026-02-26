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
import sqlite3
from typing import Callable

_log = logging.getLogger(__name__)

# Current schema version – reflects the baseline absorbed into init_schema().
# Increment this AND add a new _migrate_NNNN_* function when a future
# schema change is needed.
SCHEMA_VERSION = 5  # baseline: all v1–v5 columns are in init_schema()


def _ensure_schema_version_table(conn: sqlite3.Connection) -> None:
	"""Create schema_version table if it doesn't exist."""
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
	conn.commit()


def get_schema_version(conn: sqlite3.Connection) -> int:
	"""Get the current schema version from the database."""
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


def _get_columns(conn: sqlite3.Connection, table: str) -> set[str]:
	"""Return the set of column names for a table."""
	cur = conn.execute(f"PRAGMA table_info({table})")
	return {row[1] for row in cur.fetchall()}


def _add_column_if_missing(
	conn: sqlite3.Connection,
	table: str,
	column: str,
	definition: str,
	columns: set[str] | None = None,
) -> bool:
	"""Add a column to *table* if it does not exist yet.  Returns True if added."""
	if columns is None:
		columns = _get_columns(conn, table)
	if column not in columns:
		conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
		_log.info("Migration: %s.%s column added", table, column)
		return True
	return False


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
	"""Check if a table exists in the database."""
	cur = conn.execute(
		"SELECT name FROM sqlite_master WHERE type='table' AND name=?",
		(table,),
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
#
# All migrations up to and including v5 have been absorbed into init_schema()
# and are no longer needed here.


# ---------------------------------------------------------------------------
# Migration registry
# ---------------------------------------------------------------------------

# List of (version: int, function: Callable) tuples.
# Migrations are applied in version order for versions > the DB's current version.
_MIGRATIONS: list[tuple[int, Callable[[sqlite3.Connection], None]]] = [
	# Future migrations go here, e.g.:
	# (6, _migrate_0006_description),
]


# ---------------------------------------------------------------------------
# Migration runner
# ---------------------------------------------------------------------------


def run_pending_migrations(conn: sqlite3.Connection) -> int:
	"""Execute all pending migrations.
	
	Returns:
		Number of migrations applied
	
	Raises:
		Exception: If any migration fails (transaction is rolled back)
	"""
	current_version = get_schema_version(conn)
	
	# Filter and sort migrations that need to run
	pending = [
		(ver, func) for ver, func in _MIGRATIONS
		if ver > current_version
	]
	pending.sort(key=lambda x: x[0])
	
	if not pending:
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
			func(conn)
			_set_schema_version(conn, version)
			conn.commit()
			applied += 1
			_log.info("MIGRATION v%d applied successfully", version)
		except Exception as exc:
			conn.rollback()
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
		"target_version": max((v for v, _ in _MIGRATIONS), default=current_version),
		"pending_count": len(pending),
		"pending_migrations": pending,
		"up_to_date": len(pending) == 0,
	}
