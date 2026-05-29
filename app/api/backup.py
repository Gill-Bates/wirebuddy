#!/usr/bin/env python3
#
# app/api/backup.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Backup and restore API routes (admin-only).

Provides functionality to:
- Download full configuration backup as .tar.gz
- Restore configuration from uploaded backup
- Schedule nightly automatic backups with 30-day retention
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import re
import shutil
import signal
import sqlite3
import tarfile
import tempfile
import time
from contextlib import suppress
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Callable, Iterator, Literal, TypeVar

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ..db.sqlite_runtime import close_all_connections, connect, close_connection, thread_connection
from ..db.sqlite_settings import get_setting, set_setting, validate_secret_key
from ..utils.backup_lock import (
	BackupLockBusyError,
	acquire_backup_operation_lock,
	acquire_restore_guard,
)
from ..utils.crypto import verify_password
from ..db.sqlite_users import get_user_by_id
from ..utils.rate_limit import RATE_LIMIT_CRITICAL, limiter
from ..utils.time import utcnow
from .auth import require_admin
from .response import OkResponse

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/backup", tags=["backup"])

# Directories to include in backup (relative to data_dir)
# These contain all persistent state that should survive a restore
BACKUP_DIRECTORIES = ("tsdb", "dns", "certs")
BACKUP_DATABASE_NAME = "wirebuddy.db"
BACKUP_SUBDIR = "backup"  # Scheduled backups stored here
BACKUP_RETENTION_DAYS = 30  # Default retention
BACKUP_RETENTION_OPTIONS = (1, 7, 14, 21, 30)  # Valid retention values (tuple for deterministic ordering)
MAX_BACKUP_UPLOAD_BYTES = 5 * 1024 * 1024 * 1024  # 5 GB

# Compiled regex for backup filename validation (shared by validate + restore + delete)
_BACKUP_FILENAME_RE = re.compile(
	r"wirebuddy_backup_\d{8}_\d{6}_([a-f0-9]{32})\.tar\.gz",
	re.ASCII,
)

# Settings keys for backup configuration
SETTING_BACKUP_ENABLED = "backup_scheduled_enabled"
SETTING_BACKUP_LAST_AT = "backup_last_at"
SETTING_BACKUP_HMAC_SECRET = "backup_hmac_secret"
SETTING_BACKUP_RETENTION = "backup_retention_days"

_T = TypeVar("_T")

_DB_CONNECT_TIMEOUT_SECONDS = 10.0
_VERIFY_PASSWORD_TIMEOUT_SECONDS = 15.0
_BACKUP_HMAC_TIMEOUT_SECONDS = 60.0
_BACKUP_CREATE_TIMEOUT_SECONDS = 300.0
_TAR_EXTRACT_TIMEOUT_SECONDS = 120.0
_DB_INTEGRITY_CHECK_TIMEOUT_SECONDS = 30.0
_BACKUP_SECRET_KEY_COMPAT_TIMEOUT_SECONDS = 90.0
_BACKUP_HMAC_CONTEXT = b"wirebuddy-backup-hmac\0"
_BACKUP_ARCHIVE_DB_MEMBER = f"data/{BACKUP_DATABASE_NAME}"
MAX_BACKUP_EXTRACTED_BYTES = 10 * 1024 * 1024 * 1024  # 10 GB
_ALLOWED_BACKUP_ROOTS = frozenset({
	f"data/{BACKUP_DATABASE_NAME}",
	*(f"data/{name}" for name in BACKUP_DIRECTORIES),
})


def _with_db(db_path: Path, fn: Callable[[sqlite3.Connection], _T]) -> _T:
    """Open a short-lived SQLite connection, call fn(conn), close it."""
    with thread_connection(db_path) as conn:
        return fn(conn)


async def _run_blocking(
	fn: Callable[..., _T],
	*args: object,
	timeout: float | None,
	operation: str,
	**kwargs: object,
) -> _T:
	"""Run blocking work in a thread, optionally with a timeout."""
	call = partial(fn, *args, **kwargs)
	worker = asyncio.create_task(asyncio.to_thread(call))
	if timeout is None:
		return await worker
	try:
		return await asyncio.wait_for(asyncio.shield(worker), timeout=timeout)
	except TimeoutError as exc:
		def _log_late_completion(task: asyncio.Task[_T]) -> None:
			with suppress(asyncio.CancelledError):
				err = task.exception()
				if err is None:
					_log.warning("BACKUP_OPERATION_COMPLETED_AFTER_TIMEOUT operation=%s", operation)
				else:
					_log.warning("BACKUP_OPERATION_FAILED_AFTER_TIMEOUT operation=%s error=%s", operation, err)

		worker.add_done_callback(_log_late_completion)
		_log.error("BACKUP_OPERATION_TIMEOUT operation=%s timeout=%ss", operation, timeout)
		raise HTTPException(status_code=504, detail=f"Operation still running: {operation}") from exc


async def _open_db_connection(db_path: Path) -> sqlite3.Connection:
	"""Open a SQLite connection for async routes via thread offload."""
	return await _run_blocking(
		connect,
		db_path,
		timeout=_DB_CONNECT_TIMEOUT_SECONDS,
		operation="open backup database connection",
	)


async def _close_db_connection(conn: sqlite3.Connection | None) -> None:
	"""Close a SQLite connection opened by an async route."""
	if conn is None:
		return
	await _run_blocking(
		close_connection,
		conn,
		timeout=_DB_CONNECT_TIMEOUT_SECONDS,
		operation="close backup database connection",
	)


def _get_retention_days(conn: sqlite3.Connection) -> int:
    """Read and validate backup retention days from DB, with safe fallback."""
    raw = get_setting(conn, SETTING_BACKUP_RETENTION, str(BACKUP_RETENTION_DAYS))
    try:
        val = int(raw)
        return val if val in BACKUP_RETENTION_OPTIONS else BACKUP_RETENTION_DAYS
    except (ValueError, TypeError):
        _log.warning("Invalid retention_days in DB: %r, using default", raw)
        return BACKUP_RETENTION_DAYS


def _iter_backup_files(backup_dir: Path) -> Iterator[Path]:
    """Yield all backup archive paths in the backup directory."""
    yield from backup_dir.glob("wirebuddy_backup_*.tar.gz")


def _get_legacy_backup_hmac_secret(conn: sqlite3.Connection) -> str | None:
	"""Return the pre-v1.5 per-database backup HMAC secret, if present."""
	return get_setting(conn, SETTING_BACKUP_HMAC_SECRET)


def _derive_backup_hmac_secret(secret_key: str) -> bytes:
	"""Derive a stable backup HMAC key from WIREBUDDY_SECRET_KEY.

	This keeps backups restorable on replacement instances configured with the
	same application secret key while separating the backup HMAC domain from
	other secret-key uses.
	"""
	secret = str(secret_key or "")
	if not secret:
		raise RuntimeError("WIREBUDDY_SECRET_KEY is required for backup integrity checks")
	return hashlib.sha256(_BACKUP_HMAC_CONTEXT + secret.encode("utf-8")).digest()


def _get_backup_hmac_secrets(conn: sqlite3.Connection, secret_key: str) -> tuple[bytes, ...]:
	"""Return active backup HMAC keys, newest first.

	The first key is the stable key derived from WIREBUDDY_SECRET_KEY. A legacy
	database-scoped secret is included when present so old backups remain valid
	on the original installation.
	"""
	derived_secret = _derive_backup_hmac_secret(secret_key)
	legacy_secret = _get_legacy_backup_hmac_secret(conn)
	if not legacy_secret:
		return (derived_secret,)

	legacy_bytes = legacy_secret.encode("utf-8")
	if hmac.compare_digest(legacy_bytes, derived_secret):
		return (derived_secret,)
	return (derived_secret, legacy_bytes)


def _compute_backup_hmac(filepath: Path, secret: bytes | str) -> str:
	"""Compute the truncated HMAC signature for a backup archive."""
	key = secret if isinstance(secret, bytes) else secret.encode("utf-8")
	h = hmac.new(key, digestmod=hashlib.sha256)
	with open(filepath, "rb") as f:
		for chunk in iter(lambda: f.read(1024 * 1024), b""):
			h.update(chunk)
	return h.hexdigest()[:32]


def _compute_backup_hmac_candidates(filepath: Path, secrets: tuple[bytes, ...]) -> tuple[str, ...]:
	"""Compute candidate backup HMACs for the provided secrets in one file pass."""
	hmacs = [hmac.new(secret, digestmod=hashlib.sha256) for secret in secrets]
	with open(filepath, "rb") as f:
		for chunk in iter(lambda: f.read(1024 * 1024), b""):
			for digest in hmacs:
				digest.update(chunk)
	return tuple(digest.hexdigest()[:32] for digest in hmacs)


def _backup_matches_current_secret_key(filepath: Path, secret_key: str) -> bool:
	"""Check whether the uploaded backup DB matches the current app secret key.

	This provides a compatibility path for legacy backups that were signed with a
	random DB-scoped HMAC secret instead of the stable application secret.
	"""
	if not secret_key:
		return False

	try:
		with tempfile.TemporaryDirectory() as tmpdir:
			extracted_db = Path(tmpdir) / BACKUP_DATABASE_NAME
			with tarfile.open(filepath, mode="r:gz") as tar:
				_validate_tar_members(tar)
				try:
					member = tar.getmember(_BACKUP_ARCHIVE_DB_MEMBER)
				except KeyError:
					return False
				if not member.isfile():
					return False

				extracted_stream = tar.extractfile(member)
				if extracted_stream is None:
					return False

				with extracted_stream, open(extracted_db, "wb") as out:
					shutil.copyfileobj(extracted_stream, out)

			_validate_restored_database(extracted_db)
			with thread_connection(extracted_db) as test_conn:
				if get_setting(test_conn, "_key_validation_token") is None:
					return False
				return validate_secret_key(test_conn, secret_key)
	except (HTTPException, OSError, sqlite3.Error, tarfile.TarError, ValueError):
		return False


def _is_allowed_backup_member(member_name: str) -> bool:
	"""Return True when the tar member is inside the expected backup layout."""
	normalized = member_name.rstrip("/")
	if normalized == "data":
		return True
	return any(normalized == root or normalized.startswith(f"{root}/") for root in _ALLOWED_BACKUP_ROOTS)


def _validate_tar_members(tar: tarfile.TarFile) -> None:
	"""Reject unexpected or over-large tar members before extraction."""
	total_size = 0
	for member in tar.getmembers():
		name = member.name.rstrip("/")
		if not name or not _is_allowed_backup_member(name):
			raise HTTPException(status_code=400, detail=f"Unexpected backup member: {member.name}")
		if not (member.isfile() or member.isdir()):
			raise HTTPException(status_code=400, detail=f"Unsupported backup member type: {member.name}")
		if member.isfile():
			total_size += max(member.size, 0)
			if total_size > MAX_BACKUP_EXTRACTED_BYTES:
				raise HTTPException(status_code=413, detail="Backup expands beyond allowed size")


def _safe_tar_extract(tar: tarfile.TarFile, dest: Path) -> None:
	"""Safely extract tar archive, preventing path traversal attacks.
	
	Python 3.13+ always supports filter='data', which rejects unsafe members.
	"""
	_validate_tar_members(tar)
	tar.extractall(dest, filter="data")


def _validate_extracted_backup_structure(extracted_data: Path) -> None:
	"""Ensure extracted backup entries have the expected file/directory types."""
	extracted_db = extracted_data / BACKUP_DATABASE_NAME
	if extracted_db.exists() and not extracted_db.is_file():
		raise HTTPException(status_code=400, detail="Backup database entry is not a file")

	for subdir in BACKUP_DIRECTORIES:
		extracted_subdir = extracted_data / subdir
		if extracted_subdir.exists() and not extracted_subdir.is_dir():
			raise HTTPException(
				status_code=400,
				detail=f"Backup entry data/{subdir} is not a directory",
			)


def _verify_admin_password(conn: sqlite3.Connection, admin: dict, password: str) -> None:
	"""Verify admin user's password for destructive operations.
	
	Raises HTTPException(401) if password is invalid.
	"""
	user = get_user_by_id(conn, admin["id"])
	if not user or not verify_password(password, user["password_hash"]):
		raise HTTPException(status_code=401, detail="Invalid password")


def _get_backup_dir(data_dir: Path) -> Path:
	"""Get the backup directory, creating it if necessary."""
	backup_dir = data_dir / BACKUP_SUBDIR
	backup_dir.mkdir(parents=True, exist_ok=True)
	return backup_dir


async def _receive_and_verify_upload(
	file: UploadFile,
	conn: sqlite3.Connection,
	secret_key: str,
	*,
	max_bytes: int = MAX_BACKUP_UPLOAD_BYTES,
) -> tuple[Path, str]:
	"""Stream an uploaded backup to a temp file, validate gzip magic + HMAC.

	Returns ``(tmp_path, filename)``.  The caller owns cleanup of *tmp_path*.
	Raises :class:`HTTPException` on any validation failure.
	"""
	filename = file.filename or ""

	match = _BACKUP_FILENAME_RE.fullmatch(filename)
	if not match:
		raise HTTPException(
			status_code=400,
			detail="Invalid backup file. Expected format: wirebuddy_backup_YYYYMMDD_HHMMSS_<hmac>.tar.gz",
		)

	expected_hmac = match.group(1)

	fd, tmp_str = tempfile.mkstemp(suffix=".tar.gz")
	os.close(fd)
	tmp_path = Path(tmp_str)

	try:
		total = 0
		first_chunk = True

		with open(tmp_path, "wb") as out:
			while True:
				chunk = await file.read(1024 * 1024)
				if not chunk:
					break
				total += len(chunk)
				if total > max_bytes:
					raise HTTPException(status_code=413, detail="Backup file too large")
				if first_chunk:
					if len(chunk) < 2 or chunk[:2] != b"\x1f\x8b":
						raise HTTPException(
							status_code=400,
							detail="Invalid backup file (not a gzip archive)",
						)
					first_chunk = False
				await asyncio.to_thread(out.write, chunk)

		if total == 0:
			raise HTTPException(status_code=400, detail="Backup file is empty")

		candidate_hmacs = await _run_blocking(
			_compute_backup_hmac_candidates,
			tmp_path,
			_get_backup_hmac_secrets(conn, secret_key),
			timeout=_BACKUP_HMAC_TIMEOUT_SECONDS,
			operation="compute backup upload HMAC",
		)
		if not any(hmac.compare_digest(candidate, expected_hmac) for candidate in candidate_hmacs):
			matches_current_secret_key = await _run_blocking(
				_backup_matches_current_secret_key,
				tmp_path,
				secret_key,
				timeout=_BACKUP_SECRET_KEY_COMPAT_TIMEOUT_SECONDS,
				operation="validate backup secret-key compatibility",
			)
			if not matches_current_secret_key:
				_log.error("Backup HMAC mismatch for file: %s", filename)
				raise HTTPException(
					status_code=400,
					detail="Backup integrity check failed (HMAC mismatch - wrong instance or corrupted file)",
				)
			_log.warning(
				"Backup HMAC mismatch for %s accepted via WIREBUDDY_SECRET_KEY compatibility fallback",
				filename,
			)
	except Exception:
		tmp_path.unlink(missing_ok=True)
		raise

	return tmp_path, filename


def _validate_restored_database(extracted_db: Path) -> None:
	"""Validate integrity of a restored SQLite database snapshot."""
	try:
		test_conn = sqlite3.connect(str(extracted_db))
		try:
			result = test_conn.execute("PRAGMA integrity_check").fetchone()
		finally:
			test_conn.close()
		if result is None or result[0] != "ok":
			raise HTTPException(
				status_code=400,
				detail="Backup contains corrupt database",
			)
	except sqlite3.Error as exc:
		raise HTTPException(
			status_code=400,
			detail=f"Backup database is invalid: {exc}",
		) from exc


def _apply_restored_backup(data_dir: Path, db_path: Path, extracted_data: Path) -> list[str]:
	"""Apply extracted backup contents with rollback protection.

	Runs in a worker thread because it performs blocking filesystem operations.
	This commit phase intentionally has no timeout: thread cancellation would be
	unsafe once destructive moves have started.
	"""
	restored_items: list[str] = []
	closed_count = close_all_connections()
	_log.info("Closed %d SQLite connections before restore", closed_count)

	rollback_dir = data_dir / f".rollback_{utcnow().strftime('%Y%m%d_%H%M%S')}"
	rollback_dir.mkdir(exist_ok=True)
	restore_succeeded = False
	extracted_db = extracted_data / BACKUP_DATABASE_NAME

	try:
		if extracted_db.exists():
			if db_path.exists():
				shutil.move(str(db_path), str(rollback_dir / BACKUP_DATABASE_NAME))
			shutil.move(str(extracted_db), str(db_path))
			restored_items.append(BACKUP_DATABASE_NAME)
			_log.info("Restored database")

		for subdir in BACKUP_DIRECTORIES:
			extracted_subdir = extracted_data / subdir
			target_subdir = data_dir / subdir

			if extracted_subdir.exists():
				if target_subdir.exists():
					shutil.move(str(target_subdir), str(rollback_dir / subdir))
				shutil.move(str(extracted_subdir), str(target_subdir))
				restored_items.append(subdir)
				_log.info("Restored directory: %s", subdir)

		restore_succeeded = True
		_log.info("Restored %d items: %s", len(restored_items), ", ".join(restored_items))
		return restored_items

	except Exception as exc:
		_log.error("Restore failed: %s. Attempting rollback...", exc)
		try:
			rollback_db = rollback_dir / BACKUP_DATABASE_NAME
			if rollback_db.exists():
				if db_path.exists():
					db_path.unlink()
				shutil.move(str(rollback_db), str(db_path))

			for subdir in BACKUP_DIRECTORIES:
				target_subdir = data_dir / subdir
				rollback_subdir = rollback_dir / subdir

				if rollback_subdir.exists() and target_subdir.exists():
					shutil.rmtree(target_subdir)
				if rollback_subdir.exists():
					shutil.move(str(rollback_subdir), str(target_subdir))

			_log.info("Rollback successful")
		except Exception as rollback_error:
			_log.critical("ROLLBACK FAILED: %s. Manual intervention required!", rollback_error)
			raise HTTPException(
				status_code=500,
				detail=f"Restore AND rollback failed! Backup at: {rollback_dir}",
			) from rollback_error

		raise HTTPException(
			status_code=500,
			detail="Restore failed, rollback successful. Original data restored.",
		) from exc

	finally:
		if restore_succeeded and rollback_dir.exists():
			try:
				shutil.rmtree(rollback_dir)
			except Exception as cleanup_error:
				_log.warning("Failed to clean up rollback: %s", cleanup_error)


def _create_backup_archive(data_dir: Path, db_path: Path, secret_key: str) -> tuple[Path, str, int]:
	"""Create a backup archive of the data directory.
	
	Uses SQLite's online backup API for an atomic, consistent database snapshot.
	
	Returns:
		Tuple of (archive_path, filename, file_size)
	"""
	# Create tarball in a temp file
	tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz")
	tmp_path = Path(tmp_file.name)
	tmp_file.close()
	
	try:
		with tarfile.open(tmp_path, mode="w:gz") as tar:
			# Add the SQLite database using the online backup API for consistency
			if db_path.exists():
				with tempfile.TemporaryDirectory(dir=data_dir) as backup_tmpdir:
					backup_db_path = Path(backup_tmpdir) / BACKUP_DATABASE_NAME
					src = sqlite3.connect(str(db_path))
					try:
						dst = sqlite3.connect(str(backup_db_path))
						try:
							src.backup(dst)
						finally:
							dst.close()
					finally:
						src.close()
					tar.add(backup_db_path, arcname=f"data/{BACKUP_DATABASE_NAME}")
					_log.debug("Added database to backup (via online backup API)")
			
			# Add configured subdirectories
			for subdir in BACKUP_DIRECTORIES:
				subdir_path = data_dir / subdir
				if subdir_path.exists():
					tar.add(subdir_path, arcname=f"data/{subdir}")
					_log.debug("Added %s to backup", subdir)
		
		# Calculate HMAC signature
		hmac_signature = _compute_backup_hmac(tmp_path, _derive_backup_hmac_secret(secret_key))
		file_size = tmp_path.stat().st_size
		
		# Generate filename with timestamp and HMAC
		now = utcnow()
		timestamp = now.strftime("%Y%m%d_%H%M%S")
		filename = f"wirebuddy_backup_{timestamp}_{hmac_signature}.tar.gz"
		
		return tmp_path, filename, file_size
		
	except Exception:
		tmp_path.unlink(missing_ok=True)
		raise


# ─── API ENDPOINTS ───────────────────────────────────────────────────────────


class BackupSettingsResponse(BaseModel):
	"""Backup settings response."""
	scheduled_enabled: bool
	last_backup_at: str | None
	backup_count: int
	retention_days: int
	backup_size_bytes: int
	disk_free_bytes: int
	disk_warning: bool  # True if disk space is low


class BackupSettingsUpdate(BaseModel):
	"""Backup settings update payload."""
	scheduled_enabled: bool | None = None
	retention_days: Literal[1, 7, 14, 21, 30] | None = None


class BackupSettingsUpdateResult(BaseModel):
	deleted_backups: int


class BackupListItem(BaseModel):
	filename: str
	size_bytes: int
	created_at: str


class RestoreResult(BaseModel):
	restored: list[str]


@router.get("/settings", response_model=BackupSettingsResponse)
def get_backup_settings(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
):
	"""Get current backup settings and status.

	NOTE: sync – FastAPI threadpools this handler. Performs glob() + stat() ×
	backup-file-count + shutil.disk_usage() – all blocking file-system calls.
	"""
	def _read(conn: sqlite3.Connection) -> BackupSettingsResponse:
		enabled = get_setting(conn, SETTING_BACKUP_ENABLED, "0") == "1"
		last_backup = get_setting(conn, SETTING_BACKUP_LAST_AT)
		retention = _get_retention_days(conn)

		# Count existing backups and calculate total size
		backup_dir = _get_backup_dir(request.app.state.cfg.data_dir)
		backup_count = 0
		backup_size = 0
		for f in _iter_backup_files(backup_dir):
			backup_count += 1
			backup_size += f.stat().st_size

		# Get disk space info
		disk_free = shutil.disk_usage(backup_dir).free
		# Warn if less than 500MB free or if free space < 2x current backup size
		disk_warning = disk_free < 500 * 1024 * 1024 or (backup_size > 0 and disk_free < backup_size * 2)

		# Verify last_backup timestamp points to an existing file
		if last_backup and backup_count == 0:
			# Timestamp exists but no backups found - clear stale timestamp
			last_backup = None

		return BackupSettingsResponse(
			scheduled_enabled=enabled,
			last_backup_at=last_backup,
			backup_count=backup_count,
			retention_days=retention,
			backup_size_bytes=backup_size,
			disk_free_bytes=disk_free,
			disk_warning=disk_warning,
		)

	return _with_db(request.app.state.cfg.db_path, _read)


@router.patch("/settings", response_model=OkResponse[BackupSettingsUpdateResult])
def update_backup_settings(
	request: Request,
	payload: BackupSettingsUpdate,
	admin: sqlite3.Row = Depends(require_admin),
):
	"""Update backup settings (enable/disable scheduled backups)."""
	def _update(conn: sqlite3.Connection):
		if payload.scheduled_enabled is not None:
			set_setting(conn, SETTING_BACKUP_ENABLED, "1" if payload.scheduled_enabled else "0")
			_log.info(
				"Scheduled backup %s by %s",
				"enabled" if payload.scheduled_enabled else "disabled",
				admin["username"],
			)

		if payload.retention_days is not None:
			set_setting(conn, SETTING_BACKUP_RETENTION, str(payload.retention_days))
			_log.info(
				"Backup retention set to %d days by %s",
				payload.retention_days,
				admin["username"],
			)

			# Immediately cleanup backups that exceed new retention period
			backup_dir = _get_backup_dir(request.app.state.cfg.data_dir)
			deleted_count = _cleanup_old_backups(backup_dir, payload.retention_days)
			if deleted_count > 0:
				_log.info("Cleaned up %d old backup(s) after retention change", deleted_count)
				return deleted_count
		return 0

	deleted = _with_db(request.app.state.cfg.db_path, _update)
	return OkResponse[BackupSettingsUpdateResult](
		message="Backup settings updated",
		data=BackupSettingsUpdateResult(deleted_backups=deleted),
	)


@router.post("/download")
async def create_backup(
	request: Request,
	background_tasks: BackgroundTasks,
	admin: sqlite3.Row = Depends(require_admin),
):
	"""Create and download a backup of the configuration.

	Returns a gzip-compressed tarball with HMAC signature in filename.
	Uses POST because this operation has side effects (updates last-backup timestamp).
	"""
	data_dir = request.app.state.cfg.data_dir
	db_path = request.app.state.cfg.db_path
	conn: sqlite3.Connection | None = None
	tmp_path: Path | None = None
	filename = ""
	file_size = 0
	try:
		try:
			with acquire_backup_operation_lock(data_dir):
				if not data_dir.exists():
					raise HTTPException(status_code=404, detail="Data directory not found")

				conn = await _open_db_connection(db_path)
				try:
					tmp_path, filename, file_size = await _run_blocking(
						_create_backup_archive,
						data_dir,
						db_path,
						request.app.state.cfg.secret_key,
						timeout=_BACKUP_CREATE_TIMEOUT_SECONDS,
						operation="create backup archive",
					)

					await _run_blocking(
						set_setting,
						conn,
						SETTING_BACKUP_LAST_AT,
						utcnow().isoformat(),
						timeout=_DB_CONNECT_TIMEOUT_SECONDS,
						operation="update backup timestamp",
					)

					_log.info(
						"Backup created: %s (%d bytes) by %s",
						filename, file_size, admin["username"],
					)
				finally:
					await _close_db_connection(conn)
					conn = None
		except BackupLockBusyError as exc:
			raise HTTPException(status_code=409, detail="A backup or restore operation is already in progress") from exc
	
		if tmp_path is None:
			raise HTTPException(status_code=500, detail="Backup archive was not created")

		archive_path = tmp_path

		# Stream the file (conn is already closed)
		def iter_file(path: Path):
			with open(path, "rb") as f:
				yield from iter(lambda: f.read(1024 * 1024), b"")

		# Guaranteed cleanup even on client disconnect
		background_tasks.add_task(archive_path.unlink, missing_ok=True)
		response = StreamingResponse(
			iter_file(archive_path),
			media_type="application/gzip",
			headers={
				"Content-Disposition": f'attachment; filename="{filename}"',
				"Cache-Control": "no-store",
				"Pragma": "no-cache",
				"X-Content-Type-Options": "nosniff",
			},
		)
		tmp_path = None
		return response
	finally:
		await _close_db_connection(conn)
		if tmp_path is not None:
			await _run_blocking(
				tmp_path.unlink,
				missing_ok=True,
				timeout=_DB_CONNECT_TIMEOUT_SECONDS,
				operation="delete failed backup archive",
			)


@router.post("/validate", response_model=OkResponse[None])
async def validate_backup(
	request: Request,
	file: UploadFile = File(...),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Validate a backup file's HMAC signature without restoring.
	
	Use this to check backup integrity before prompting for password confirmation.
	Returns 200 if valid, 400 with error detail if invalid.
	"""
	conn = await _open_db_connection(request.app.state.cfg.db_path)
	tmp_path: Path | None = None
	try:
		tmp_path, _filename = await _receive_and_verify_upload(
			file,
			conn,
			request.app.state.cfg.secret_key,
		)
		return OkResponse[None](message="Backup file is valid")
	finally:
		await file.close()
		await _close_db_connection(conn)
		if tmp_path is not None:
			await _run_blocking(
				tmp_path.unlink,
				missing_ok=True,
				timeout=_DB_CONNECT_TIMEOUT_SECONDS,
				operation="delete validated backup upload",
			)


@router.post("/restore", response_model=OkResponse[RestoreResult])
@limiter.limit(RATE_LIMIT_CRITICAL)
async def restore_backup(  # async: uses await for file I/O
	request: Request,
	background_tasks: BackgroundTasks,
	password: str = Form(...),
	file: UploadFile = File(...),
	admin: sqlite3.Row = Depends(require_admin),
):
	"""Restore configuration from an uploaded backup.
	
	CRITICAL: Requires password confirmation (destructive operation).
	Validates HMAC signature before restoring.
	Triggers application restart after successful restore.

	Only one restore may run at a time (concurrency guard).
	"""
	data_dir = request.app.state.cfg.data_dir
	db_path = request.app.state.cfg.db_path
	restored_items: list[str] = []
	conn: sqlite3.Connection | None = None
	tmp_upload_path: Path | None = None

	try:
		with acquire_backup_operation_lock(data_dir):
			conn = await _open_db_connection(db_path)
			# Verify admin password (PBKDF2-SHA256 – moved off event loop)
			await _run_blocking(
				_verify_admin_password,
				conn,
				admin,
				password,
				timeout=_VERIFY_PASSWORD_TIMEOUT_SECONDS,
				operation="verify restore admin password",
			)
			tmp_upload_path, filename = await _receive_and_verify_upload(
				file,
				conn,
				request.app.state.cfg.secret_key,
			)

			try:
				_log.warning(
					"Backup restore initiated: file=%s by=%s",
					filename,
					admin["username"],
				)

				# Extract to temporary directory
				with tempfile.TemporaryDirectory() as tmpdir:
					tmp_path = Path(tmpdir)

					# Tar extraction is blocking file I/O – moved off event loop
					def _extract_tar() -> None:
						with tarfile.open(tmp_upload_path, mode="r:gz") as tar:
							_safe_tar_extract(tar, tmp_path)
					try:
						await _run_blocking(
							_extract_tar,
							timeout=_TAR_EXTRACT_TIMEOUT_SECONDS,
							operation="extract backup archive",
						)
					except ValueError as e:
						_log.error("Unsafe tar archive: %s", e)
						raise HTTPException(
							status_code=400,
							detail=f"Backup security violation: {e}",
						)
					except Exception as e:
						_log.error("Failed to extract backup: %s", e)
						raise HTTPException(
							status_code=400,
							detail="Failed to extract backup archive",
						)

					extracted_data = tmp_path / "data"
					if not extracted_data.exists():
						raise HTTPException(
							status_code=400,
							detail="Invalid backup structure (no data directory)",
						)

					await _run_blocking(
						_validate_extracted_backup_structure,
						extracted_data,
						timeout=_DB_INTEGRITY_CHECK_TIMEOUT_SECONDS,
						operation="validate extracted backup structure",
					)

					# Validate restored database integrity before proceeding
					extracted_db = extracted_data / BACKUP_DATABASE_NAME
					if extracted_db.exists():
						await _run_blocking(
							_validate_restored_database,
							extracted_db,
							timeout=_DB_INTEGRITY_CHECK_TIMEOUT_SECONDS,
							operation="validate restored backup database",
						)

					with acquire_restore_guard(data_dir):
						# Close our own connection before closing all connections
						await _close_db_connection(conn)
						conn = None  # prevent double-close in outer finally

						# Block concurrent requests in this worker; other workers observe the restore guard.
						request.app.state.maintenance = True

						try:
							restored_items = await _run_blocking(
								_apply_restored_backup,
								data_dir,
								db_path,
								extracted_data,
								timeout=None,
								operation="apply restored backup",
							)
							if not restored_items:
								raise HTTPException(
									status_code=400,
									detail="Backup did not contain any restorable items",
								)

						finally:
							if not restored_items:
								request.app.state.maintenance = False
			finally:
				await file.close()
				if tmp_upload_path is not None:
					await _run_blocking(
						tmp_upload_path.unlink,
						missing_ok=True,
						timeout=_DB_CONNECT_TIMEOUT_SECONDS,
						operation="delete uploaded restore archive",
					)
	except BackupLockBusyError as exc:
		raise HTTPException(
			status_code=409,
			detail="A backup or restore operation is already in progress",
		) from exc
	finally:
		await _close_db_connection(conn)

	_log.warning("Backup restored successfully, initiating restart")

	# Schedule application restart
	async def restart_app():
		await asyncio.sleep(1)
		_log.critical("Intentional process termination for restart after backup restore")
		os.kill(os.getpid(), signal.SIGTERM)

	background_tasks.add_task(restart_app)

	return OkResponse[RestoreResult](
		message="Backup restored successfully. Application is restarting...",
		data=RestoreResult(restored=restored_items),
	)


@router.get("/list", response_model=OkResponse[list[BackupListItem]])
def list_backups(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
):
	"""List scheduled backups stored on the server."""
	backup_dir = _get_backup_dir(request.app.state.cfg.data_dir)
	
	backups = []
	for backup_file in sorted(_iter_backup_files(backup_dir), reverse=True):
		file_stat = backup_file.stat()
		backups.append(BackupListItem(
			filename=backup_file.name,
			size_bytes=file_stat.st_size,
			created_at=datetime.fromtimestamp(file_stat.st_mtime, tz=UTC).isoformat(),
		))
	
	return OkResponse[list[BackupListItem]](data=backups)


@router.delete("/scheduled/{filename}", response_model=OkResponse[None])
def delete_scheduled_backup(
	request: Request,
	filename: str,
	admin: sqlite3.Row = Depends(require_admin),
):
	"""Delete a specific scheduled backup.

	Admin authentication is sufficient here; no separate password confirmation is
	required for deleting an individual stored backup file.
	"""
	# Validate filename format to prevent path traversal
	if not _BACKUP_FILENAME_RE.fullmatch(filename):
		raise HTTPException(status_code=400, detail="Invalid backup filename")
	
	backup_dir = _get_backup_dir(request.app.state.cfg.data_dir)
	backup_path = backup_dir / filename
	
	if not backup_path.exists():
		raise HTTPException(status_code=404, detail="Backup not found")
	
	backup_path.unlink()
	_log.info("Deleted scheduled backup: %s by %s", filename, admin["username"])
	
	return OkResponse[None](message="Backup deleted")


# ─── SCHEDULED BACKUP FUNCTIONS (called by scheduler) ────────────────────────


def is_scheduled_backup_enabled(db_path: Path) -> bool:
	"""Check if scheduled backups are enabled."""
	return _with_db(db_path, lambda conn: get_setting(conn, SETTING_BACKUP_ENABLED, "0") == "1")


def run_scheduled_backup(data_dir: Path, db_path: Path, secret_key: str) -> dict:
	"""Execute a scheduled backup and manage retention.
	
	Called by the scheduler task. Creates a new backup and removes
	backups older than the configured retention period.
	
	Returns:
		Dict with backup status and cleanup stats
	
	Raises:
		OSError: If insufficient disk space
	"""
	tmp_path: Path | None = None
	try:
		with acquire_backup_operation_lock(data_dir):
			with thread_connection(db_path) as conn:
				# Get retention setting
				retention_days = _get_retention_days(conn)

				# Check disk space before creating backup
				backup_dir = _get_backup_dir(data_dir)
				disk_free = shutil.disk_usage(backup_dir).free
				min_required = 100 * 1024 * 1024  # Require at least 100MB free
				
				if disk_free < min_required:
					_log.error("Insufficient disk space for backup: %d bytes free, need %d", disk_free, min_required)
					raise OSError(f"Insufficient disk space: {disk_free // (1024*1024)}MB free, need at least 100MB")
				
				# Create backup archive
				tmp_path, filename, file_size = _create_backup_archive(data_dir, db_path, secret_key)
				
				# Move to backup directory
				final_path = backup_dir / filename
				shutil.move(str(tmp_path), str(final_path))
				tmp_path = None
				
				# Verify file was created successfully before updating timestamp
				if not final_path.exists():
					_log.error("Backup file not found after move: %s", final_path)
					raise OSError(f"Backup file not created: {filename}")
				
				actual_size = final_path.stat().st_size
				if actual_size != file_size:
					_log.warning("Backup size mismatch: expected %d, got %d", file_size, actual_size)
				
				# Update last backup timestamp only after successful file creation
				set_setting(conn, SETTING_BACKUP_LAST_AT, utcnow().isoformat())
				
				_log.info("Scheduled backup created: %s (%d bytes)", filename, actual_size)
				
				# Cleanup old backups
				deleted_count = _cleanup_old_backups(backup_dir, retention_days)
				
				return {
					"filename": filename,
					"size_bytes": actual_size,
					"deleted_old_backups": deleted_count,
				}
	except BackupLockBusyError:
		_log.warning("Backup or restore already running, skipping scheduled backup")
		return {"skipped": True}
	finally:
		if tmp_path is not None:
			with suppress(FileNotFoundError):
				tmp_path.unlink()


def _cleanup_old_backups(backup_dir: Path, retention_days: int = BACKUP_RETENTION_DAYS) -> int:
	"""Remove backups older than retention period."""
	cutoff_time = time.time() - (retention_days * 86400)
	deleted = 0
	
	for backup_file in _iter_backup_files(backup_dir):
		try:
			if backup_file.stat().st_mtime < cutoff_time:
				backup_file.unlink()
				_log.info("Deleted old backup: %s", backup_file.name)
				deleted += 1
		except Exception as e:
			_log.warning("Failed to process backup %s: %s", backup_file.name, e)
	
	return deleted
