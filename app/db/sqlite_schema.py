#!/usr/bin/env python3
#
# app/db/sqlite_schema.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
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
