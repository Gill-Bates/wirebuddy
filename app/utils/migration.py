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
import sqlite3
from typing import Callable

from ..db.sqlite_runtime import transaction

_log = logging.getLogger(__name__)

# Current schema version.
# Baseline is reset to v0 because all previous schema changes are now
# integrated into init_schema() factory defaults.
SCHEMA_VERSION = 2


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


# Historical migrations are now part of the factory-default schema.
# Start a new migration history from 0 for future schema changes.


def _migrate_0001_add_show_on_dashboard(conn: sqlite3.Connection) -> None:
	"""Add show_on_dashboard column to interfaces table.

	This column controls whether a WireGuard interface appears in the
	dashboard's network throughput gauges. Defaults to 1 (shown).
	"""
	# Check if column already exists (idempotent)
	cur = conn.execute("PRAGMA table_info(interfaces)")
	columns = [row[1] for row in cur.fetchall()]
	if "show_on_dashboard" not in columns:
		conn.execute(
			"ALTER TABLE interfaces ADD COLUMN show_on_dashboard INTEGER NOT NULL DEFAULT 1"
		)
		_log.info("Added show_on_dashboard column to interfaces table")


def _migrate_0002_drop_peers_description(conn: sqlite3.Connection) -> None:
	"""Remove description column from peers table.

	SQLite doesn't support DROP COLUMN before 3.35.0, so we
	check the runtime version and use ALTER TABLE DROP COLUMN
	when available, otherwise recreate the table.
	"""
	cur = conn.execute("PRAGMA table_info(peers)")
	columns = [row[1] for row in cur.fetchall()]
	if "description" not in columns:
		return  # already removed

	sqlite_version = tuple(int(x) for x in sqlite3.sqlite_version.split("."))
	if sqlite_version >= (3, 35, 0):
		conn.execute("ALTER TABLE peers DROP COLUMN description")
		_log.info("Dropped description column from peers table")
	else:
		# Rebuild without the column
		keep = [c for c in columns if c != "description"]
		cols = ", ".join(keep)
		conn.execute(f"CREATE TABLE peers_backup AS SELECT {cols} FROM peers")
		conn.execute("DROP TABLE peers")
		conn.execute(f"ALTER TABLE peers_backup RENAME TO peers")
		_log.info("Rebuilt peers table without description column (SQLite < 3.35)")


_MIGRATIONS: list[tuple[int, Callable[[sqlite3.Connection], None]]] = [
	(1, _migrate_0001_add_show_on_dashboard),
	(2, _migrate_0002_drop_peers_description),
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

	Fresh installs skip migrations: If schema_version is 0 and no users exist,
	set version to SCHEMA_VERSION directly (all columns already in init_schema).

	Returns:
		Number of migrations applied

	Raises:
		RuntimeError: If any migration fails (transaction is rolled back)
	"""
	# Ensure schema_version table exists before reading
	_ensure_schema_version_table(conn)
	current_version = get_schema_version(conn)

	# Fresh install detection: If version is 0 and no users exist, skip migrations
	# (init_schema already created tables with all current columns)
	if current_version == 0:
		user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
		if user_count == 0:
			_log.info(
				"MIGRATION Fresh installation detected, setting schema_version to v%d (skipping migrations)",
				SCHEMA_VERSION,
			)
			with transaction(conn, immediate=True):
				_set_schema_version(conn, SCHEMA_VERSION)
			return 0

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
	_ensure_schema_version_table(conn)
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
