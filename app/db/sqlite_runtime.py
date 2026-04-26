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
		raise TypeError(
			"UNSET cannot be used in boolean context; use 'is UNSET' for identity checks"
		)


# Sentinel value to distinguish "not provided" from "set to None" in update functions.
# Use ``is UNSET`` to check if a parameter was not provided.
UNSET = UnsetType.UNSET

_SQLITE_ADAPTERS_REGISTERED = False
_SQLITE_ADAPTERS_LOCK = threading.Lock()
_thread_local = threading.local()  # Thread-local storage for savepoint counter


def _adapt_datetime(value: datetime) -> str:
	if value.tzinfo is None:
		raise sqlite3.InterfaceError("Naive datetime not allowed in SQLite; use a UTC-aware datetime")
	return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _convert_datetime(value: bytes) -> datetime:
	"""Convert SQLite timestamp (ISO-8601 with UTC Z suffix and microseconds) to UTC datetime."""
	try:
		s = value.decode("utf-8")
		# Normalize Z suffix to +00:00 for fromisoformat compatibility
		if s.endswith("Z"):
			s = s[:-1] + "+00:00"
		dt = datetime.fromisoformat(s)  # Parses .%f (microseconds) automatically
		if dt.tzinfo is None:
			dt = dt.replace(tzinfo=timezone.utc)
		return dt.astimezone(timezone.utc)
	except (UnicodeDecodeError, ValueError) as exc:
		decoded = value.decode("utf-8", errors="replace")
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
	"""Generate a unique, SQLite-safe savepoint name (thread-local counter)."""
	count = getattr(_thread_local, "savepoint_counter", 0) + 1
	_thread_local.savepoint_counter = count
	return f"sp_{threading.get_ident()}_{count}"


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
	db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
	conn = sqlite3.connect(
		str(db_path),
		detect_types=sqlite3.PARSE_DECLTYPES,
		check_same_thread=False,  # Allows threadpool hops; not concurrent multi-thread use.
	)
	conn.row_factory = sqlite3.Row
	# Set busy timeout via PRAGMA for consistency with checkpoint_wal (30s = 30000ms)
	conn.execute("PRAGMA busy_timeout=30000")

	# Enable WAL mode with retry logic for multi-worker safety
	# (PRAGMA journal_mode=WAL is idempotent, no pre-check needed)
	max_retries = 5
	for attempt in range(max_retries):
		try:
			result = conn.execute("PRAGMA journal_mode=WAL").fetchone()
			new_mode = str(result[0]).upper() if result and result[0] is not None else ""
			if new_mode != "WAL":
				raise sqlite3.OperationalError(
					f"Failed to enable WAL mode (got {result[0]!r})"
				)
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


@contextmanager
def thread_connection(db_path: Path):
	"""Context manager for a thread-local SQLite connection.

	Intended for use inside ``asyncio.to_thread()`` callables where a new
	connection must be opened and closed within the same worker thread.

	Usage::

		def _load() -> list:
			with thread_connection(db_path) as conn:
				return get_all_items(conn)

		result = await asyncio.to_thread(_load)
	"""
	conn = connect(db_path)
	try:
		yield conn
	finally:
		close_connection(conn)


def close_all_connections() -> int:
	"""Close all tracked connections for graceful shutdown.
	
	Returns:
		Number of connections that were successfully closed.
	"""
	with _CONNECTIONS_LOCK:
		connections = list(_OPEN_CONNECTIONS)

	closed = 0
	for conn in connections:
		try:
			conn.close()
			closed += 1
		except Exception as e:
			_log.warning("Failed to close SQLite connection: %s", e)
		finally:
			with _CONNECTIONS_LOCK:
				_OPEN_CONNECTIONS.discard(conn)

	return closed


def _checkpoint_result(
	mode: str,
	busy: int = -1,
	log_frames: int = -1,
	checkpointed_frames: int = -1,
) -> dict[str, int | str]:
	"""Build the canonical checkpoint result dict."""
	return {
		"mode": mode,
		"busy": busy,
		"log_frames": log_frames,
		"checkpointed_frames": checkpointed_frames,
	}


# Valid WAL checkpoint modes for SQLite PRAGMA wal_checkpoint
_VALID_CHECKPOINT_MODES = frozenset({"PASSIVE", "FULL", "RESTART", "TRUNCATE"})


def checkpoint_wal(db_path: Path, mode: str = "TRUNCATE") -> dict[str, int | str]:
	"""Run a WAL checkpoint using a dedicated short-lived connection.

	Returns checkpoint counters in SQLite's ``wal_checkpoint`` format:
	``busy``, ``log_frames``, ``checkpointed_frames``.
	
	Raises:
		ValueError: If mode is not one of PASSIVE, FULL, RESTART, or TRUNCATE.
	"""
	mode_upper = mode.strip().upper()
	if mode_upper not in _VALID_CHECKPOINT_MODES:
		raise ValueError(
			f"Invalid WAL checkpoint mode {mode!r}; "
			f"must be one of {sorted(_VALID_CHECKPOINT_MODES)}"
		)

	conn: sqlite3.Connection | None = None
	try:
		conn = connect(db_path)
		# Note: f-string is safe here; mode_upper is constrained to _VALID_CHECKPOINT_MODES
		row = conn.execute(f"PRAGMA wal_checkpoint({mode_upper})").fetchone()
		if not row:
			return _checkpoint_result(mode_upper)
		return _checkpoint_result(
			mode_upper,
			busy=int(row[0]),
			log_frames=int(row[1]),
			checkpointed_frames=int(row[2]),
		)
	except Exception as e:
		_log.warning("WAL checkpoint failed (%s): %s", mode_upper, e)
		return _checkpoint_result(mode_upper)
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

	NOTE: ``conn.in_transaction`` reflects SQLite's autocommit state. In Python's
	``sqlite3`` module that can already be ``True`` after prior DML on the same
	connection, even without an explicit ``BEGIN`` from this helper. If a caller
	needs ``immediate=True`` lock escalation, it must enter this context before
	performing earlier writes on that connection.
	"""
	if conn.in_transaction:
		# Nested transaction: use SAVEPOINT
		if immediate:
			_log.warning(
				"transaction(immediate=True) called while already in transaction; "
				"lock escalation not possible, using SAVEPOINT instead"
			)
		savepoint = _next_savepoint_name()
		# Safe interpolation: savepoint names are generated internally from a
		# thread id plus monotonic counter and never include external input.
		conn.execute(f"SAVEPOINT {savepoint}")
		try:
			yield
			conn.execute(f"RELEASE SAVEPOINT {savepoint}")
		except Exception:
			rolled_back = False
			try:
				conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
				rolled_back = True
			except Exception as rollback_err:
				_log.error("Failed to rollback savepoint %s: %s", savepoint, rollback_err)
			if rolled_back:
				try:
					conn.execute(f"RELEASE SAVEPOINT {savepoint}")
				except Exception as release_err:
					_log.error("Failed to release savepoint %s: %s", savepoint, release_err)
			raise
	else:
		# Outer transaction: use BEGIN
		conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
		try:
			yield
			conn.commit()
		except Exception:
			if conn.in_transaction:
				conn.rollback()
			raise
