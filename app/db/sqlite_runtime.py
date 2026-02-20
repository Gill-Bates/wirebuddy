#!/usr/bin/env python3
#
# app/db/sqlite_runtime.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""SQLite runtime helpers: adapters, connections, and transactions."""

from __future__ import annotations

import logging
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

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
	"""Create a SQLite connection configured for this application.

	Multi-worker safe: retries WAL mode activation if database is temporarily locked.
	"""
	db_path.parent.mkdir(parents=True, exist_ok=True)
	conn = sqlite3.connect(
		str(db_path),
		detect_types=sqlite3.PARSE_DECLTYPES,
		check_same_thread=False,
		timeout=30.0,  # Busy timeout for multi-process access
	)
	conn.row_factory = sqlite3.Row

	# Enable WAL mode with retry logic for multi-worker safety
	max_retries = 5
	for attempt in range(max_retries):
		try:
			# Check current journal mode first (avoids unnecessary lock)
			cursor = conn.execute("PRAGMA journal_mode")
			current_mode = cursor.fetchone()[0].upper()
			cursor.close()

			if current_mode != "WAL":
				conn.execute("PRAGMA journal_mode=WAL")
				_log.debug("Enabled WAL mode for database")
			break
		except sqlite3.OperationalError as e:
			if "locked" in str(e).lower() and attempt < max_retries - 1:
				# Another worker is initializing - wait and retry
				import time

				wait = 0.1 * (2 ** attempt)  # Exponential backoff: 0.1s, 0.2s, 0.4s, 0.8s
				_log.debug(
					"Database locked during WAL activation (attempt %d/%d), retrying in %.1fs",
					attempt + 1,
					max_retries,
					wait,
				)
				time.sleep(wait)
			else:
				# Final attempt failed or non-lock error
				raise

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
