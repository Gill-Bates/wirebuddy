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
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

try:
	import fcntl
	_HAS_FCNTL = True
except ImportError:
	_HAS_FCNTL = False

_log = logging.getLogger(__name__)

DEFAULT_SPEEDTEST_COOLDOWN_S = 30.0
DEFAULT_SPEEDTEST_COOLDOWN_SECONDS = DEFAULT_SPEEDTEST_COOLDOWN_S
_CLOCK_SKEW_TOLERANCE_S = 60.0

# In-process lock for fast rejection (no ownership tracking needed)
_local_run_lock = threading.Lock()


class SpeedtestBusyError(RuntimeError):
	"""Raised when a speedtest is already running."""


class SpeedtestCooldownError(RuntimeError):
	"""Raised when a speedtest was triggered too recently."""
	__slots__ = ("remaining_seconds",)

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
		# Allow limited future skew for clock drift tolerance.
		now = time.time()
		if not (0 < ts <= now + _CLOCK_SKEW_TOLERANCE_S):
			_log.warning(
				"Ignoring suspicious last_run timestamp: %.2f (now=%.2f, drift=%.1fs)",
				ts, now, ts - now
			)
			return None
		return ts
	except FileNotFoundError:
		# Expected on fresh install - no previous speedtest run
		return None
	except (OSError, ValueError) as exc:
		_log.debug("Speedtest cooldown file unreadable: %s", exc)
		return None


def _write_last_run(path: Path, timestamp: float) -> None:
	"""Write cooldown timestamp with fsync for durability."""
	path.parent.mkdir(parents=True, exist_ok=True)
	# Atomic write with fsync to ensure durability on crash
	tmp = path.with_suffix(".tmp")
	with open(tmp, "w", encoding="utf-8") as f:
		f.write(f"{timestamp:.6f}\n")
		f.flush()
		os.fsync(f.fileno())
	os.replace(tmp, path)


@dataclass(
	eq=False,  # Lease identity is object identity, not value equality.
	repr=False,  # Custom repr avoids exposing file handle internals.
)
class SpeedtestRunLease:
	"""Active speedtest run lease backed by local and file locks.
	
	Supports both sync and async context managers for automatic cleanup.
	Records cooldown timestamp on release, not acquisition, to accurately
	reflect test completion time.
	
	Note: Not frozen because we need to mutate released flag.
	"""

	fd_obj: IO[bytes]
	cooldown_path: Path | None = None
	released: bool = False
	_owner_thread_id: int = field(default_factory=threading.get_ident, init=False, repr=False)

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

		# Release thread lock (must be called from same thread that acquired it)
		if threading.get_ident() != self._owner_thread_id:
			_log.error(
				"Speedtest lock release skipped: called from wrong thread (owner=%s current=%s)",
				self._owner_thread_id,
				threading.get_ident(),
			)
			return
		try:
			_local_run_lock.release()
		except RuntimeError as exc:
			_log.error("Failed to release speedtest lock: %s", exc)

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
		"""Async context manager exit (synchronous release, no awaited I/O)."""
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
	if not _local_run_lock.acquire(blocking=False):
		raise SpeedtestBusyError("Speed test already in progress")

	fd_obj: IO[bytes] | None = None

	try:
		# Acquire file lock for cross-process coordination
		if not _HAS_FCNTL:
			# Fail hard instead of degrading silently - cross-process safety is critical
			raise RuntimeError(
				"Cross-process locking (fcntl) not available on this platform. "
				"Speedtest guard requires POSIX-compatible file locking. "
				f"Lock path: {_lock_path(tsdb_dir)}"
			)

		lock_path = _lock_path(tsdb_dir)
		lock_path.parent.mkdir(parents=True, exist_ok=True)
		# Use binary mode for lock file (encoding irrelevant, slight performance gain)
		fd_obj = lock_path.open("ab+")

		try:
			fcntl.flock(fd_obj.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
		except OSError as exc:
			fd_obj.close()
			raise SpeedtestBusyError("Speed test already in progress") from exc

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
		# Release thread lock (always safe here since we acquired it)
		_local_run_lock.release()
		raise
