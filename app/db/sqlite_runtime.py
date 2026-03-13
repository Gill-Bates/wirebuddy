#!/usr/bin/env python3
#
# app/db/sqlite_runtime.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""SQLite runtime helpers: adapters, connections, and transactions."""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

_log = logging.getLogger(__name__)


class UnsetType(Enum):
	"""Singleton sentinel used to distinguish omitted update fields from ``None``."""

	UNSET = "UNSET"

	def __repr__(self) -> str:
		return "UNSET"

	def __bool__(self) -> bool:
		return False


# Sentinel value to distinguish "not provided" from "set to None" in update functions.
# Use ``is UNSET`` to check if a parameter was not provided.
UNSET = UnsetType.UNSET

_SQLITE_ADAPTERS_REGISTERED = False
_SQLITE_ADAPTERS_LOCK = threading.Lock()
_SAVEPOINT_COUNTER = 0
_SAVEPOINT_LOCK = threading.Lock()


def _adapt_datetime(value: datetime) -> str:
	if value.tzinfo is None:
		raise ValueError("Naive datetime not allowed in SQLite")
	return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _convert_datetime(value: bytes) -> datetime:
	try:
		s = value.decode("utf-8")
		if s.endswith("Z"):
			s = s[:-1] + "+00:00"
		dt = datetime.fromisoformat(s)
		if dt.tzinfo is None:
			dt = dt.replace(tzinfo=timezone.utc)
		return dt.astimezone(timezone.utc)
	except (UnicodeDecodeError, ValueError) as exc:
		decoded = value.decode("utf-8", errors="replace")
		_log.error("Corrupt timestamp in database: %r", decoded)
		raise sqlite3.InterfaceError(f"Cannot parse timestamp: {decoded!r}") from exc


def _ensure_sqlite_adapters() -> None:
	"""Register sqlite3 adapters/converters once per process."""
	global _SQLITE_ADAPTERS_REGISTERED
	if _SQLITE_ADAPTERS_REGISTERED:
		return
	with _SQLITE_ADAPTERS_LOCK:
		if _SQLITE_ADAPTERS_REGISTERED:
			return
		sqlite3.register_adapter(datetime, _adapt_datetime)
		sqlite3.register_converter("timestamp", _convert_datetime)
		_SQLITE_ADAPTERS_REGISTERED = True


def _next_savepoint_name() -> str:
	"""Generate a unique, SQLite-safe savepoint name."""
	global _SAVEPOINT_COUNTER
	with _SAVEPOINT_LOCK:
		_SAVEPOINT_COUNTER += 1
		return f"sp_{threading.get_ident()}_{_SAVEPOINT_COUNTER}"


# ---------------------------------------------------------------------------
# Connection Registry
# ---------------------------------------------------------------------------

# sqlite3.Connection is not weak-referenceable on this Python build, so the
# registry must hold strong references and callers must close their connections.
_OPEN_CONNECTIONS: set[sqlite3.Connection] = set()
_CONNECTIONS_LOCK = threading.Lock()


def connect(db_path: Path) -> sqlite3.Connection:
	"""Create a SQLite connection configured for this application.

	Concurrency contract:
	- Connections may cross thread boundaries within a single request/task
	  (hence ``check_same_thread=False``).
	- Callers must not use the same connection concurrently from multiple
	  threads; use one logical owner per connection.
	- Multi-worker safe: retries WAL mode activation if database is temporarily locked.
	"""
	_ensure_sqlite_adapters()
	db_path.parent.mkdir(parents=True, exist_ok=True)
	conn = sqlite3.connect(
		str(db_path),
		detect_types=sqlite3.PARSE_DECLTYPES,
		check_same_thread=False,  # Allows threadpool hops; not concurrent multi-thread use.
		timeout=30.0,  # Busy timeout for multi-process access
	)
	conn.row_factory = sqlite3.Row

	# Enable WAL mode with retry logic for multi-worker safety
	max_retries = 5
	for attempt in range(max_retries):
		try:
			# Check current journal mode first (avoids unnecessary lock)
			current_mode = conn.execute("PRAGMA journal_mode").fetchone()[0].upper()

			if current_mode != "WAL":
				result = conn.execute("PRAGMA journal_mode=WAL").fetchone()
				new_mode = str(result[0]).upper() if result and result[0] is not None else ""
				if new_mode != "WAL":
					raise sqlite3.OperationalError(
						f"Failed to enable WAL mode (got {result[0]!r})"
					)
				_log.debug("Enabled WAL mode for database")
			break
		except sqlite3.OperationalError as e:
			if "locked" in str(e).lower() and attempt < max_retries - 1:
				# Another worker is initializing - wait and retry
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
		conn = connect(db_path)
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
				close_connection(conn)
			except Exception:
				pass


@contextmanager
def transaction(conn: sqlite3.Connection, *, immediate: bool = False):
	"""Transaction context manager that commits or rolls back on error.

	If already inside a transaction, use a SAVEPOINT so nested callers can roll
	back their own unit of work without blowing away the outer transaction.
	"""
	if conn.in_transaction:
		savepoint = _next_savepoint_name()
		conn.execute(f"SAVEPOINT {savepoint}")
		try:
			yield
			conn.execute(f"RELEASE SAVEPOINT {savepoint}")
		except Exception:
			conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
			conn.execute(f"RELEASE SAVEPOINT {savepoint}")
			raise
		return

	conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
	try:
		yield
		conn.commit()
	except Exception:
		if conn.in_transaction:
			conn.rollback()
		raise
