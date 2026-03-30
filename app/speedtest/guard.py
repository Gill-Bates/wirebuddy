#!/usr/bin/env python3
#
# app/speedtest/guard.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Cross-process run guard for speedtest execution.

Provides exclusive speedtest execution locking using both in-process
threading locks (fast rejection) and cross-process file locks (fcntl).
Also enforces cooldown periods between test runs.

IMPORTANT: Performs blocking file I/O. Assumes local filesystem for tsdb_dir.
On NFS or network filesystems, flock behavior may vary or block unexpectedly.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

try:
	import fcntl
	_HAS_FCNTL = True
except ImportError:
	_HAS_FCNTL = False

_log = logging.getLogger(__name__)

DEFAULT_SPEEDTEST_COOLDOWN_SECONDS = 30.0

_local_run_lock = threading.Lock()
_lock_owner: threading.Thread | None = None


class SpeedtestBusyError(RuntimeError):
	"""Raised when a speedtest is already running."""


class SpeedtestCooldownError(RuntimeError):
	"""Raised when a speedtest was triggered too recently."""

	def __init__(self, remaining_seconds: float):
		super().__init__(f"Please wait {remaining_seconds:.1f}s before running another test")
		self.remaining_seconds = remaining_seconds


def _lock_path(tsdb_dir: Path) -> Path:
	return tsdb_dir / ".speedtest.run.lock"


def _cooldown_path(tsdb_dir: Path) -> Path:
	return tsdb_dir / ".speedtest.last_run"


def _read_last_run(path: Path) -> float | None:
	"""Read last run timestamp from cooldown file with validation."""
	try:
		value = path.read_text(encoding="utf-8").strip()
		if not value:
			return None
		ts = float(value)
		# Reject timestamps that are clearly invalid (negative, zero, or future)
		# Allow 60s future skew for clock drift tolerance
		if not (0 < ts <= time.time() + 60):
			_log.warning("Ignoring suspicious last_run timestamp: %.2f", ts)
			return None
		return ts
	except FileNotFoundError:
		# Expected on fresh install - no previous speedtest run
		return None
	except (OSError, ValueError) as exc:
		_log.debug("Speedtest cooldown file unreadable: %s", exc)
		return None


def _write_last_run(path: Path, timestamp: float) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	path.write_text(f"{timestamp:.6f}\n", encoding="utf-8")


@dataclass(eq=False, repr=False)
class SpeedtestRunLease:
	"""Active speedtest run lease backed by local and file locks.
	
	Supports both sync and async context managers for automatic cleanup.
	Records cooldown timestamp on release, not acquisition, to accurately
	reflect test completion time.
	"""

	fd_obj: TextIO
	cooldown_path: Path | None = None
	released: bool = False

	def release(self) -> None:
		"""Release the lease and record cooldown timestamp."""
		if self.released:
			return
		self.released = True

		# Record cooldown timestamp *after* test completes
		if self.cooldown_path is not None:
			try:
				_write_last_run(self.cooldown_path, time.time())
			except OSError as exc:
				_log.warning("Failed to write cooldown timestamp: %s", exc)

		# Close file descriptor (implicitly releases flock on close)
		try:
			self.fd_obj.close()
		except OSError:
			pass

		# Release thread lock only if we own it (thread-safe cleanup)
		global _lock_owner
		if _lock_owner is threading.current_thread():
			_local_run_lock.release()
			_lock_owner = None
		else:
			_log.warning("SpeedtestRunLease released from non-owning thread")

	def __enter__(self) -> SpeedtestRunLease:
		"""Sync context manager entry."""
		return self

	def __exit__(self, *exc_info: object) -> None:
		"""Sync context manager exit."""
		self.release()

	async def __aenter__(self) -> SpeedtestRunLease:
		"""Async context manager entry."""
		return self

	async def __aexit__(self, *exc_info: object) -> None:
		"""Async context manager exit."""
		self.release()

	def __repr__(self) -> str:
		"""Custom repr that doesn't expose file handle details."""
		return f"SpeedtestRunLease(released={self.released})"


def acquire_speedtest_run_lease(
	tsdb_dir: Path,
	*,
	cooldown_seconds: float = DEFAULT_SPEEDTEST_COOLDOWN_SECONDS,
	update_cooldown: bool = True,
) -> SpeedtestRunLease:
	"""Acquire a non-blocking lease for a speedtest run.
	
	Uses layered locking:
	1. In-process threading.Lock for fast rejection
	2. Cross-process fcntl.flock for multi-worker safety
	
	Cooldown timestamp is recorded on lease.release(), not acquisition,
	to accurately reflect test completion time.
	
	Args:
		tsdb_dir: Base directory for lock and cooldown files
		cooldown_seconds: Minimum seconds between test completions
		update_cooldown: Whether to record cooldown timestamp on release
		
	Returns:
		SpeedtestRunLease context manager
		
	Raises:
		SpeedtestBusyError: Test already running in another process/thread
		SpeedtestCooldownError: Test completed too recently
	"""
	global _lock_owner

	if not _local_run_lock.acquire(blocking=False):
		raise SpeedtestBusyError("Speed test already in progress")

	_lock_owner = threading.current_thread()
	fd_obj: TextIO | None = None

	try:
		# Acquire file lock for cross-process coordination
		lock_path = _lock_path(tsdb_dir)
		lock_path.parent.mkdir(parents=True, exist_ok=True)
		fd_obj = lock_path.open("a+", encoding="utf-8")

		if _HAS_FCNTL:
			try:
				fcntl.flock(fd_obj.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
			except OSError as exc:
				fd_obj.close()
				raise SpeedtestBusyError("Speed test already in progress") from exc
		else:
			_log.warning("fcntl unavailable; cross-process locking disabled (Windows?)")

		# Check cooldown constraint
		last_run_path = _cooldown_path(tsdb_dir)
		now = time.time()
		last_run = _read_last_run(last_run_path)
		if last_run is not None:
			remaining = cooldown_seconds - (now - last_run)
			if remaining > 0:
				# Let exception handler clean up (no redundant explicit cleanup)
				raise SpeedtestCooldownError(remaining)

		# Return lease with cooldown_path so release() can record timestamp
		return SpeedtestRunLease(
			fd_obj=fd_obj,
			cooldown_path=last_run_path if update_cooldown else None,
		)

	except Exception:
		# Unified cleanup on any error (cooldown, busy, unexpected)
		if fd_obj is not None and not fd_obj.closed:
			try:
				fd_obj.close()
			except OSError:
				pass
		if _lock_owner is threading.current_thread():
			_local_run_lock.release()
			_lock_owner = None
		raise