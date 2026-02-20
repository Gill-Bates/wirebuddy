#!/usr/bin/env python3
#
# app/db/sqlite_leader.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Leader-election helpers for multi-worker safety."""

from __future__ import annotations

import logging
import os
import sqlite3
from datetime import timedelta

from ..utils.time import utcnow

_log = logging.getLogger(__name__)


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
