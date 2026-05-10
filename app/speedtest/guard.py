#!/usr/bin/env python3
#
# app/speedtest/guard.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Cross-process run guard for speedtest execution.

Provides exclusive speedtest execution locking using:
1. `asyncio.Lock` for async task-level isolation.
2. `threading.Lock` for fast thread-level rejection.
3. `fcntl.flock` for cross-process coordination.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False

_log = logging.getLogger(__name__)

DEFAULT_SPEEDTEST_COOLDOWN_SECONDS = 30.0
_CLOCK_SKEW_TOLERANCE_S = 60.0

# Synchronization primitives
_local_thread_lock = threading.Lock()
_local_async_lock = asyncio.Lock()


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
    except FileNotFoundError:
        return None
    except OSError as exc:
        _log.warning("Unexpected error reading cooldown file %s: %s", path, exc)
        return None

    if not value:
        return None

    try:
        ts = float(value)
    except ValueError:
        return None

    now = time.time()
    # Reject invalid timestamps
    if not (0 < ts <= now + _CLOCK_SKEW_TOLERANCE_S):
        return None
    return ts


def _write_last_run(path: Path, timestamp: float) -> None:
    """Write cooldown timestamp with fsync for durability."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(f"{timestamp:.6f}\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


@dataclass(eq=False, repr=False, slots=True)
class SpeedtestRunLease:
    """Active speedtest run lease backed by cross-layer locks."""

    fd_obj: IO[bytes]
    cooldown_path: Path | None = None
    released: bool = False
    _async_acquired: bool = False
    _owns_thread_lock: bool = False

    def _persist_cooldown(self) -> None:
        if not self.cooldown_path:
            return
        try:
            _write_last_run(self.cooldown_path, time.time())
        except OSError as exc:
            _log.warning("Failed to write cooldown timestamp: %s", exc)

    def _close_fd(self) -> None:
        try:
            self.fd_obj.close()
        except OSError:
            pass

    def _release_thread_lock(self) -> None:
        if not self._owns_thread_lock:
            return
        try:
            _local_thread_lock.release()
        except RuntimeError as exc:
            _log.warning("Failed to release speedtest thread lock: %s", exc)

    def release(self) -> None:
        """Release the lease (sync version)."""
        if self.released:
            return
        self.released = True

        # 1. Record cooldown
        self._persist_cooldown()

        # 2. Release fcntl lock
        self._close_fd()

        # 3. Release thread lock
        self._release_thread_lock()
            
        # Note: asyncio.Lock must be released via 'async with' or manual release()
        # if acquired. This class handles it in __aexit__.

    async def __aenter__(self) -> SpeedtestRunLease:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if not self.released:
            await asyncio.to_thread(self.release)
        if self._async_acquired:
            _local_async_lock.release()

    def __enter__(self) -> SpeedtestRunLease:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()
        if self._async_acquired:
            # We are in a sync context but acquired an async lock? 
            # This shouldn't happen with the current API design, but for safety:
            try:
                loop = asyncio.get_running_loop()
                loop.call_soon_threadsafe(_local_async_lock.release)
            except RuntimeError as exc:
                _log.error("Cannot release async speedtest lock from sync context: %s", exc)


def acquire_speedtest_run_lease(
    tsdb_dir: Path,
    *,
    cooldown_seconds: float = DEFAULT_SPEEDTEST_COOLDOWN_SECONDS,
    update_cooldown: bool = True,
) -> SpeedtestRunLease:
    """Synchronously acquire a speedtest lease (use in background threads)."""
    if not _local_thread_lock.acquire(blocking=False):
        raise SpeedtestBusyError("Speed test already in progress (thread lock)")

    fd_obj: IO[bytes] | None = None
    try:
        if not _HAS_FCNTL:
            raise RuntimeError("fcntl locking required but not available")

        lock_path = _lock_path(tsdb_dir)
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd_obj = lock_path.open("ab+")

        try:
            fcntl.flock(fd_obj.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fd_obj.close()
            raise SpeedtestBusyError("Speed test already in progress (process lock)")

        # Cooldown
        last_run = _read_last_run(_cooldown_path(tsdb_dir))
        if last_run is not None:
            remaining = cooldown_seconds - (time.time() - last_run)
            if remaining > 0:
                raise SpeedtestCooldownError(remaining)

        return SpeedtestRunLease(
            fd_obj=fd_obj,
            cooldown_path=_cooldown_path(tsdb_dir) if update_cooldown else None,
            _owns_thread_lock=True,
        )
    except Exception:
        if fd_obj and not fd_obj.closed:
            fd_obj.close()
        _local_thread_lock.release()
        raise


async def acquire_speedtest_run_lease_async(
    tsdb_dir: Path,
    *,
    cooldown_seconds: float = DEFAULT_SPEEDTEST_COOLDOWN_SECONDS,
    update_cooldown: bool = True,
) -> SpeedtestRunLease:
    """Asynchronously acquire a speedtest lease (event-loop safe)."""
    # 1. Async task-level lock
    if _local_async_lock.locked():
        raise SpeedtestBusyError("Speed test already in progress (async lock)")
    await _local_async_lock.acquire()
    
    try:
        # 2. delegate to sync version for thread/process locks
        # We run this in a thread to avoid blocking the event loop on I/O (flock/file read)
        lease = await asyncio.to_thread(
            acquire_speedtest_run_lease,
            tsdb_dir,
            cooldown_seconds=cooldown_seconds,
            update_cooldown=update_cooldown
        )
        lease._async_acquired = True
        return lease
    except Exception:
        _local_async_lock.release()
        raise
