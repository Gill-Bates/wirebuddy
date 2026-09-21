#!/usr/bin/env python3
#
# tests/test_speedtest_guard.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Speedtest run guard regressions: cooldown symlink safety and lease misuse.

The cooldown file must be opened the same way the lock file already is -
descriptor-first with O_NOFOLLOW, verified via fstat() - instead of a
separate is_symlink() check followed by Path.read_text(), which leaves a
TOCTOU window. A sync `with` block used on an async-acquired lease is caller
misuse, but must not leak the module-level asyncio.Lock permanently.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from app.speedtest import guard


@pytest.fixture(autouse=True)
def _reset_async_lock():
	"""Ensure the module-level async lock starts and ends unlocked per test."""
	assert not guard._local_async_lock.locked()
	yield
	if guard._local_async_lock.locked():
		guard._local_async_lock.release()


def test_read_last_run_ignores_symlinked_cooldown_file(tmp_path: Path):
	real_target = tmp_path / "real_timestamp"
	real_target.write_text("123456.0", encoding="utf-8")

	cooldown_link = tmp_path / ".speedtest.last_run"
	cooldown_link.symlink_to(real_target)

	assert guard._read_last_run(cooldown_link) is None


def test_read_last_run_reads_regular_file(tmp_path: Path):
	cooldown_path = tmp_path / ".speedtest.last_run"
	now = 1_700_000_000.0
	cooldown_path.write_text(f"{now:.6f}\n", encoding="utf-8")

	assert guard._read_last_run(cooldown_path) == pytest.approx(now)


def test_read_last_run_missing_file_returns_none(tmp_path: Path):
	assert guard._read_last_run(tmp_path / "does-not-exist") is None


def test_read_last_run_rejects_oversized_file(tmp_path: Path):
	cooldown_path = tmp_path / ".speedtest.last_run"
	cooldown_path.write_text("1" * (guard._MAX_COOLDOWN_FILE_SIZE + 1), encoding="utf-8")

	assert guard._read_last_run(cooldown_path) is None


def test_read_last_run_rejects_non_regular_file(tmp_path: Path):
	"""A non-regular file (e.g. a FIFO) must be rejected via fstat(), not read.

	_read_last_run() opens with a plain (blocking) O_RDONLY, which blocks
	until a writer is present. A writer is kept open here purely so that
	open() returns immediately; the function under test never sees or uses
	that writer end.
	"""
	fifo_path = tmp_path / ".speedtest.last_run"
	os.mkfifo(fifo_path)
	writer_fd = os.open(fifo_path, os.O_RDWR)
	try:
		assert guard._read_last_run(fifo_path) is None
	finally:
		os.close(writer_fd)


def test_sync_exit_on_async_acquired_lease_releases_async_lock():
	"""Caller misuse (sync `with` on an async-acquired lease) must raise but must not leave the process-wide async lock permanently held."""

	async def _acquire() -> None:
		await guard._local_async_lock.acquire()

	asyncio.run(_acquire())
	assert guard._local_async_lock.locked()

	fd_obj = os.fdopen(os.open(os.devnull, os.O_RDONLY), "rb")
	lease = guard.SpeedtestRunLease(fd_obj=fd_obj, _async_acquired=True)

	with pytest.raises(RuntimeError, match="sync context"):
		with lease:
			pass

	assert not guard._local_async_lock.locked()
	assert lease.released is True
