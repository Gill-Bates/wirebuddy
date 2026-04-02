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
	"""Create the required database schema (factory default).

	This defines the complete schema for fresh installs.
	All historical migrations up to the current baseline are absorbed here.
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
				created_at timestamp NOT NULL,
				updated_at timestamp NOT NULL
			)
			"""
		)
		conn.execute("CREATE INDEX IF NOT EXISTS idx_peers_interface ON peers(interface)")
		conn.execute("CREATE INDEX IF NOT EXISTS idx_peers_peer_address ON peers(peer_address)")
		conn.execute("CREATE INDEX IF NOT EXISTS idx_peers_node_id ON peers(node_id)")
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

	# Run migrations for existing databases (must be inside transaction)
	with transaction(conn, immediate=True):
		_run_migrations(conn)


def _get_columns(conn: sqlite3.Connection, table: str) -> set[str]:
	"""Get set of column names for a table."""
	return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _run_migrations(conn: sqlite3.Connection) -> None:
	"""Apply schema migrations for existing databases.
	
	These migrations handle columns/tables added after initial release.
	Safe to run multiple times (idempotent).
	
	NOTE: Must be called within a transaction for atomicity.
	"""
	# Get existing columns in peers table
	existing_columns = _get_columns(conn, "peers")
	
	# Migration: Add dns_logging_enabled column (added in v1.4.0)
	if "dns_logging_enabled" not in existing_columns:
		_log.info("Migrating peers table: adding dns_logging_enabled column")
		conn.execute("ALTER TABLE peers ADD COLUMN dns_logging_enabled INTEGER NOT NULL DEFAULT 1")

	# Migration: Master-Node architecture — add node_id to peers
	# NOTE: nodes and node_interfaces tables are created by init_schema() with CREATE TABLE IF NOT EXISTS
	if "node_id" not in existing_columns:
		_log.info("Migrating peers table: adding node_id column for Master-Node architecture")
		conn.execute("ALTER TABLE peers ADD COLUMN node_id TEXT REFERENCES nodes(id) ON DELETE SET NULL")
		conn.execute("CREATE INDEX IF NOT EXISTS idx_peers_node_id ON peers(node_id)")

	# Migration: Add tunnel_peer_id to nodes (Node→Master tunnel for DNS)
	nodes_columns = _get_columns(conn, "nodes")
	if "tunnel_peer_id" not in nodes_columns:
		_log.info("Migrating nodes table: adding tunnel_peer_id for Node→Master DNS tunnel")
		conn.execute("ALTER TABLE nodes ADD COLUMN tunnel_peer_id INTEGER REFERENCES peers(id) ON DELETE SET NULL")

	# Migration: Add last_metric_seq to nodes (for reliable metric delivery idempotency)
	if "last_metric_seq" not in nodes_columns:
		_log.info("Migrating nodes table: adding last_metric_seq for reliable metric delivery")
		conn.execute("ALTER TABLE nodes ADD COLUMN last_metric_seq INTEGER")

	# Migration: Add sse_connected_at to nodes (for multi-worker SSE tracking)
	if "sse_connected_at" not in nodes_columns:
		_log.info("Migrating nodes table: adding sse_connected_at for multi-worker SSE tracking")
		conn.execute("ALTER TABLE nodes ADD COLUMN sse_connected_at TIMESTAMP")

	# Migration: Add pending_command to nodes (for multi-worker command delivery)
	if "pending_command" not in nodes_columns:
		_log.info("Migrating nodes table: adding pending_command for multi-worker command delivery")
		conn.execute("ALTER TABLE nodes ADD COLUMN pending_command TEXT")

	# Migration: Add name UNIQUE constraint to nodes (idempotent — fails silently if already exists)
	try:
		conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_name_unique ON nodes(name)")
	except sqlite3.OperationalError:
		pass  # Index may already exist if this is a fresh schema

	# Migration: Add FQDN UNIQUE constraint to nodes
	try:
		conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_fqdn_unique ON nodes(fqdn)")
	except sqlite3.OperationalError:
		pass  # Index may already exist if this is a fresh schema


def ensure_default_admin(conn: sqlite3.Connection) -> None:
	"""Create a default admin user if no users exist.

	Uses ``transaction(immediate=True)`` to safely serialise against
	concurrent workers without standalone BEGIN/commit/rollback calls.
	"""
	try:
		with transaction(conn, immediate=True):
			count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
			if count == 0:
				conn.execute(
					"""
					INSERT INTO users (username, password_hash, is_admin, is_active, created_at)
					VALUES (?, ?, 1, 1, ?)
					""",
					("admin", hash_password("admin"), utcnow()),
				)
				_log.warning("Created default admin user (username: admin, password: admin) - CHANGE THIS!")
	except sqlite3.IntegrityError:
		pass  # another worker beat us — row already exists
