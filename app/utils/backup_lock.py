#!/usr/bin/env python3
#
# app/utils/backup_lock.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Cross-process backup and restore coordination helpers.

POSIX advisory file-lock coordination.
Not guaranteed safe on all network filesystems or non-POSIX platforms.

Lock ordering:
1. acquire_backup_operation_lock()
2. acquire_restore_guard()
"""

from __future__ import annotations

import fcntl
import logging
import os
import socket
import stat
import time
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator

_log = logging.getLogger(__name__)

BACKUP_LOCK_DIR_NAME = "backup"
BACKUP_OPERATION_LOCK_NAME = ".backup-operation.lock"
BACKUP_RESTORE_LOCK_NAME = ".backup-restore.lock"


class BackupLockBusyError(RuntimeError):
	"""Raised when another worker already holds a backup-related lock."""


def _ensure_private_lock_dir(path: Path) -> None:
	"""Ensure the backup lock directory exists and is a real private directory."""
	try:
		st = path.lstat()
	except FileNotFoundError:
		path.mkdir(mode=0o700, parents=True)
		st = path.lstat()

	if path.is_symlink() or not stat.S_ISDIR(st.st_mode):
		raise RuntimeError(f"Backup lock path is not a safe directory: {path}")

	path.chmod(0o700)


def _lock_path(data_dir: Path, lock_name: str) -> Path:
	data_dir = data_dir.resolve(strict=False)
	lock_dir = data_dir / BACKUP_LOCK_DIR_NAME
	_ensure_private_lock_dir(lock_dir)
	return lock_dir / lock_name


@contextmanager
def _acquire_lock_file(
	lock_path: Path,
	*,
	blocking: bool = False,
	timeout: float | None = None,
	shared: bool = False,
	update_metadata: bool = True,
) -> Iterator[BinaryIO]:
	flags = os.O_RDWR | os.O_CREAT
	flags |= getattr(os, "O_NOFOLLOW", 0)
	flags |= getattr(os, "O_CLOEXEC", 0)
	fd = os.open(lock_path, flags, 0o600)
	lock_file = os.fdopen(fd, "a+b", buffering=0)
	try:
		st = os.fstat(lock_file.fileno())
		if not stat.S_ISREG(st.st_mode):
			raise RuntimeError("Backup lock path is not a regular file")
		os.fchmod(lock_file.fileno(), 0o600)

		deadline = None if timeout is None else time.monotonic() + timeout
		while True:
			try:
				base_lock = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
				lock_mode = base_lock if blocking else (base_lock | fcntl.LOCK_NB)
				fcntl.flock(lock_file.fileno(), lock_mode)
				break
			except BlockingIOError as exc:
				_log.debug("Backup lock busy: %s", lock_path)
				if not blocking:
					raise BackupLockBusyError(lock_path.name) from exc
				if deadline is not None and time.monotonic() >= deadline:
					raise BackupLockBusyError(lock_path.name) from exc
				time.sleep(0.1)

		if update_metadata:
			lock_file.seek(0)
			lock_file.truncate()
			lock_file.write(
				f"pid={os.getpid()} host={socket.gethostname()} acquired_at={time.time():.6f}\n".encode("utf-8")
			)
			lock_file.flush()
			os.fsync(lock_file.fileno())
		yield lock_file
	finally:
		try:
			fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
		except OSError:
			_log.exception("Failed to release backup lock: %s", lock_path)
		finally:
			lock_file.close()


@contextmanager
def acquire_backup_operation_lock(data_dir: Path) -> Iterator[BinaryIO]:
	"""Serialize all backup/archive/restore operations across workers."""
	with _acquire_lock_file(_lock_path(data_dir, BACKUP_OPERATION_LOCK_NAME)) as lock_file:
		yield lock_file


@contextmanager
def acquire_restore_guard(data_dir: Path) -> Iterator[BinaryIO]:
	"""Hold the cross-process restore guard while replacing on-disk state."""
	with _acquire_lock_file(_lock_path(data_dir, BACKUP_RESTORE_LOCK_NAME)) as lock_file:
		yield lock_file


def is_restore_in_progress(data_dir: Path, *, create: bool = True) -> bool:
	"""Advisory restore-state probe.

	Result may become stale immediately after return.
	"""
	if create:
		lock_path = _lock_path(data_dir, BACKUP_RESTORE_LOCK_NAME)
	else:
		data_dir = data_dir.resolve(strict=False)
		lock_dir = data_dir / BACKUP_LOCK_DIR_NAME
		try:
			st = lock_dir.lstat()
		except FileNotFoundError:
			return False
		if lock_dir.is_symlink() or not stat.S_ISDIR(st.st_mode):
			raise RuntimeError(f"Backup lock path is not a safe directory: {lock_dir}")
		lock_path = lock_dir / BACKUP_RESTORE_LOCK_NAME
	try:
		with _acquire_lock_file(lock_path, shared=True, update_metadata=False):
			return False
	except BackupLockBusyError:
		return True