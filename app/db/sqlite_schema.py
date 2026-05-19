#!/usr/bin/env python3
#
# app/db/sqlite_schema.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""SQLite schema initialization and bootstrap routines."""

from __future__ import annotations

import logging
import sqlite3

from ..utils.crypto import hash_password
from ..utils.time import utcnow
from .sqlite_runtime import transaction

_log = logging.getLogger(__name__)

_KNOWN_SCHEMA_TABLES = frozenset({
	"auth_tokens",
	"interfaces",
	"login_attempts",
	"node_commands",
	"node_interfaces",
	"nodes",
	"passkey_challenges",
	"passkeys",
	"peers",
	"schema_version",
	"settings",
	"users",
})


# ─────────────────────────────────────────────────────────────────────────────
# Default Settings (called AFTER key validation)
# ─────────────────────────────────────────────────────────────────────────────


def insert_default_settings(conn: sqlite3.Connection) -> None:
	"""Insert factory default settings if not already present.
	
	MUST be called AFTER validate_secret_key() to avoid key validation failures.
	"""
	now = utcnow()
	with transaction(conn):
		conn.executemany(
			"""
			INSERT OR IGNORE INTO settings (key, value, updated_at)
			VALUES (?, ?, ?)
			""",
			[
				("gui_port", "8000", now),
				("wg_mtu", "1420", now),
				("wg_persistent_keepalive", "25", now),
				("wg_use_psk", "1", now),  # PresharedKey enabled by default
				("traffic_analysis_enabled", "0", now),
			],
		)


# ─────────────────────────────────────────────────────────────────────────────
# Schema Initialization
# ─────────────────────────────────────────────────────────────────────────────


def init_schema(conn: sqlite3.Connection) -> None:
	"""Create tables for a fresh installation, then apply pending migrations.

	Fresh databases are created with the current baseline schema. Existing
	databases are then brought forward via ``_run_migrations``.
	"""
	with transaction(conn, immediate=True):
		# Users table
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				username TEXT NOT NULL UNIQUE,
				password_hash TEXT NOT NULL,
				is_admin INTEGER NOT NULL DEFAULT 0,
				is_active INTEGER NOT NULL DEFAULT 1,
				otp_secret TEXT,
				otp_enabled INTEGER NOT NULL DEFAULT 0,
				otp_recovery_codes TEXT,
				auth_method TEXT DEFAULT 'password',
				passkey_enabled INTEGER DEFAULT 0,
				passkey_pending INTEGER DEFAULT 0,
				last_login_at timestamp,
				last_login_ip TEXT,
				created_at timestamp NOT NULL
			)
			"""
		)

		# Passkeys table (WebAuthn credentials)
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

		# Passkey challenges (ephemeral, supports multi-worker deployments)
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS passkey_challenges (
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

		# Migration framework bookkeeping
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS schema_version (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				version INTEGER NOT NULL DEFAULT 0,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)
			"""
		)
		conn.execute("INSERT OR IGNORE INTO schema_version (id, version) VALUES (1, 0)")

		# Login attempts (IP-level brute-force protection)
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

		# WireGuard peers
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS peers (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				public_key TEXT NOT NULL UNIQUE,
				private_key TEXT,
				preshared_key TEXT,
				name TEXT,
				allowed_ips TEXT NOT NULL,
				allowed_ips_mode TEXT NOT NULL DEFAULT 'full',
				client_isolation INTEGER NOT NULL DEFAULT 0,
				peer_address TEXT,
				endpoint TEXT,
				interface TEXT NOT NULL DEFAULT 'wg0',
				is_enabled INTEGER NOT NULL DEFAULT 1,
				use_adblocker INTEGER NOT NULL DEFAULT 1,
				dns_logging_enabled INTEGER NOT NULL DEFAULT 1,
				blocklist_ids TEXT,
				last_client_ip TEXT,
				last_handshake_at INTEGER,
				cumulative_rx INTEGER NOT NULL DEFAULT 0,
				cumulative_tx INTEGER NOT NULL DEFAULT 0,
				last_wg_rx INTEGER NOT NULL DEFAULT 0,
				last_wg_tx INTEGER NOT NULL DEFAULT 0,
				node_id TEXT REFERENCES nodes(id) ON DELETE SET NULL,
				allow_all_nodes INTEGER NOT NULL DEFAULT 0,
				created_at timestamp NOT NULL,
				updated_at timestamp NOT NULL
			)
			"""
		)
		conn.execute("CREATE INDEX IF NOT EXISTS idx_peers_interface ON peers(interface)")
		conn.execute("CREATE INDEX IF NOT EXISTS idx_peers_peer_address ON peers(peer_address)")
		conn.execute("CREATE INDEX IF NOT EXISTS idx_peers_node_id ON peers(node_id)")
		# Enforce uniqueness for assigned peer VPN address per interface.
		# If duplicates already exist, keep startup running and warn.
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
				"Skipping unique peer_address index because duplicate values already exist (interface=%s, peer_address=%s, count=%s)",
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
				client_endpoint_port INTEGER,
				dns TEXT,
				post_up TEXT,
				post_down TEXT,
				is_enabled INTEGER NOT NULL DEFAULT 1,
				show_on_dashboard INTEGER NOT NULL DEFAULT 1,
				created_at timestamp NOT NULL,
				updated_at timestamp NOT NULL
			)
			"""
		)

		# Remote nodes (Master-Node architecture)
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS nodes (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL UNIQUE,
				fqdn TEXT NOT NULL,
				wg_port INTEGER NOT NULL DEFAULT 51820,
				show_on_dashboard INTEGER NOT NULL DEFAULT 1,
				api_secret_hash TEXT NOT NULL,
				cert_fingerprint TEXT,
				status TEXT NOT NULL DEFAULT 'pending'
					CHECK (status IN ('pending', 'online', 'offline', 'error')),
				last_seen timestamp,
				enrolled_at timestamp,
				created_at timestamp NOT NULL,
				config_version TEXT,
				metadata TEXT,
				tunnel_peer_id INTEGER REFERENCES peers(id) ON DELETE SET NULL,
				last_metric_seq INTEGER,
				sse_connected_at TIMESTAMP,
				pending_command TEXT
			)
			"""
		)
		conn.execute("CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status)")
		conn.execute("CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen)")
		conn.execute("CREATE INDEX IF NOT EXISTS idx_nodes_api_secret_hash ON nodes(api_secret_hash)")

		# Durable node command queue for replay-safe control-plane delivery
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS node_commands (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				node_id TEXT NOT NULL,
				command_type TEXT NOT NULL,
				payload TEXT NOT NULL DEFAULT '{}',
				created_at timestamp NOT NULL,
				delivered_at timestamp,
				acked_at timestamp,
				FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
			)
			"""
		)
		conn.execute("CREATE INDEX IF NOT EXISTS idx_node_commands_pending ON node_commands(node_id, acked_at, delivered_at, created_at)")
		conn.execute("CREATE INDEX IF NOT EXISTS idx_node_commands_acked_at ON node_commands(acked_at)")

		# Per-node WireGuard interface keypairs
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS node_interfaces (
				node_id TEXT NOT NULL,
				interface_name TEXT NOT NULL,
				private_key TEXT NOT NULL,
				public_key TEXT NOT NULL,
				created_at timestamp NOT NULL,
				PRIMARY KEY (node_id, interface_name),
				FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
			)
			"""
		)
		_run_migrations(conn)


def _get_columns(conn: sqlite3.Connection, table: str) -> set[str]:
	"""Return the set of column names currently defined on *table*."""
	if table not in _KNOWN_SCHEMA_TABLES:
		raise ValueError(f"Unknown table: {table!r}")
	return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _add_column_if_missing(
	conn: sqlite3.Connection,
	*,
	table: str,
	column: str,
	definition: str,
	existing_columns: set[str],
	log_message: str,
) -> bool:
	"""Add a column if absent.

	Returns ``True`` when the column was added so callers can update any local
	column snapshot explicitly.
	"""
	if column in existing_columns:
		return False
	_log.info(log_message)
	conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
	return True


def _find_duplicate_value(
	conn: sqlite3.Connection,
	*,
	table: str,
	column: str,
) -> sqlite3.Row | None:
	"""Return one duplicate value for ``table.column`` if present."""
	return conn.execute(
		f"""
		SELECT {column} AS value, COUNT(*) AS cnt
		FROM {table}
		WHERE {column} IS NOT NULL
		GROUP BY {column}
		HAVING COUNT(*) > 1
		LIMIT 1
		"""
	).fetchone()


def _create_unique_index_if_no_duplicates(
	conn: sqlite3.Connection,
	*,
	table: str,
	column: str,
	ddl: str,
	label: str,
) -> None:
	"""Create a unique index unless duplicate data already exists."""
	duplicate = _find_duplicate_value(conn, table=table, column=column)
	if duplicate is not None:
		_log.warning(
			"Skipping unique index %s because duplicate values already exist (%s=%s, count=%s)",
			label,
			column,
			duplicate["value"],
			duplicate["cnt"],
		)
		return
	conn.execute(ddl)


def _run_migrations(conn: sqlite3.Connection) -> None:
	"""Apply schema migrations for existing databases.

	These migrations handle columns/tables added after initial release.
	Safe to run multiple times (idempotent).

	Must be called within an IMMEDIATE transaction to prevent concurrent schema
	modifications and partial migration state.
	"""
	if not conn.in_transaction:
		raise RuntimeError("_run_migrations must run inside an active transaction")

	existing_columns = _get_columns(conn, "peers")
	if _add_column_if_missing(
		conn,
		table="peers",
		column="dns_logging_enabled",
		definition="INTEGER NOT NULL DEFAULT 1",
		existing_columns=existing_columns,
		log_message="Migrating peers table: adding dns_logging_enabled column",
	):
		existing_columns.add("dns_logging_enabled")

	if _add_column_if_missing(
		conn,
		table="peers",
		column="node_id",
		definition="TEXT REFERENCES nodes(id) ON DELETE SET NULL",
		existing_columns=existing_columns,
		log_message="Migrating peers table: adding node_id column for Master-Node architecture",
	):
		existing_columns.add("node_id")
	if "node_id" in existing_columns:
		conn.execute("CREATE INDEX IF NOT EXISTS idx_peers_node_id ON peers(node_id)")

	if _add_column_if_missing(
		conn,
		table="peers",
		column="allow_all_nodes",
		definition="INTEGER NOT NULL DEFAULT 0",
		existing_columns=existing_columns,
		log_message="Migrating peers table: adding allow_all_nodes for multi-node roaming",
	):
		existing_columns.add("allow_all_nodes")

	nodes_columns = _get_columns(conn, "nodes")
	if _add_column_if_missing(
		conn,
		table="nodes",
		column="tunnel_peer_id",
		definition="INTEGER REFERENCES peers(id) ON DELETE SET NULL",
		existing_columns=nodes_columns,
		log_message="Migrating nodes table: adding tunnel_peer_id for Node→Master DNS tunnel",
	):
		nodes_columns.add("tunnel_peer_id")
	if _add_column_if_missing(
		conn,
		table="nodes",
		column="last_metric_seq",
		definition="INTEGER",
		existing_columns=nodes_columns,
		log_message="Migrating nodes table: adding last_metric_seq for reliable metric delivery",
	):
		nodes_columns.add("last_metric_seq")
	if _add_column_if_missing(
		conn,
		table="nodes",
		column="sse_connected_at",
		definition="TIMESTAMP",
		existing_columns=nodes_columns,
		log_message="Migrating nodes table: adding sse_connected_at for multi-worker SSE tracking",
	):
		nodes_columns.add("sse_connected_at")
	if _add_column_if_missing(
		conn,
		table="nodes",
		column="pending_command",
		definition="TEXT",
		existing_columns=nodes_columns,
		log_message="Migrating nodes table: adding pending_command for multi-worker command delivery",
	):
		nodes_columns.add("pending_command")
	if _add_column_if_missing(
		conn,
		table="nodes",
		column="show_on_dashboard",
		definition="INTEGER NOT NULL DEFAULT 1",
		existing_columns=nodes_columns,
		log_message="Migrating nodes table: adding show_on_dashboard visibility flag",
	):
		nodes_columns.add("show_on_dashboard")

	conn.execute(
		"""
		CREATE TABLE IF NOT EXISTS node_commands (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_id TEXT NOT NULL,
			command_type TEXT NOT NULL,
			payload TEXT NOT NULL DEFAULT '{}',
			created_at timestamp NOT NULL,
			delivered_at timestamp,
			acked_at timestamp,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
		)
		"""
	)
	conn.execute("CREATE INDEX IF NOT EXISTS idx_node_commands_pending ON node_commands(node_id, acked_at, delivered_at, created_at)")
	conn.execute("CREATE INDEX IF NOT EXISTS idx_node_commands_acked_at ON node_commands(acked_at)")

	_create_unique_index_if_no_duplicates(
		conn,
		table="nodes",
		column="name",
		ddl="CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_name_unique ON nodes(name)",
		label="idx_nodes_name_unique",
	)
	_create_unique_index_if_no_duplicates(
		conn,
		table="nodes",
		column="fqdn",
		ddl="CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_fqdn_unique ON nodes(fqdn)",
		label="idx_nodes_fqdn_unique",
	)
	conn.execute("CREATE INDEX IF NOT EXISTS idx_nodes_api_secret_hash ON nodes(api_secret_hash)")


def ensure_default_admin(conn: sqlite3.Connection) -> None:
	"""Create a default admin user if no users exist.

	Uses ``transaction(immediate=True)`` to safely serialise against
	concurrent workers without standalone BEGIN/commit/rollback calls.
	"""
	try:
		with transaction(conn, immediate=True):
			(count,) = conn.execute("SELECT COUNT(*) FROM users").fetchone()
			if count == 0:
				conn.execute(
					"""
					INSERT INTO users (username, password_hash, is_admin, is_active, created_at)
					VALUES (?, ?, 1, 1, ?)
					""",
					("admin", hash_password("admin"), utcnow()),
				)
				_log.warning(
					"Created default admin user 'admin' with a well-known default password. Change it immediately."
				)
	except sqlite3.IntegrityError:
		_log.debug("Default admin insert skipped because a user already exists")
