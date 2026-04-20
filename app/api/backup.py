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
import secrets
import shutil
import signal
import sqlite3
import sys
import tarfile
import tempfile
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ..db.sqlite_runtime import close_all_connections, connect, close_connection, transaction
from ..db.sqlite_settings import get_setting, set_setting
from ..utils.crypto import verify_password
from ..db.sqlite_users import get_user_by_id
from ..utils.time import utcnow
from .auth import require_admin
from .response import ok_response

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
	r"wirebuddy_backup_\d{8}_\d{6}_([a-f0-9]{32})\.tar\.gz$"
)

# Concurrency guard — only one restore may run at a time
_restore_lock = asyncio.Lock()

# Concurrency guard — only one scheduled backup may run at a time
_scheduled_backup_lock = threading.Lock()

# Settings keys for backup configuration
SETTING_BACKUP_ENABLED = "backup_scheduled_enabled"
SETTING_BACKUP_LAST_AT = "backup_last_at"
SETTING_BACKUP_HMAC_SECRET = "backup_hmac_secret"
SETTING_BACKUP_RETENTION = "backup_retention_days"


def _get_backup_hmac_secret(conn: sqlite3.Connection) -> str:
	"""Return backup HMAC secret for integrity verification.
	
	Creates a new secret on first use and stores it atomically in the database.
	This secret is unique per installation, preventing backup forgery.
	"""
	secret = get_setting(conn, SETTING_BACKUP_HMAC_SECRET)
	if secret:
		return secret

	candidate_secret = secrets.token_hex(32)  # 256-bit key
	with transaction(conn):
		conn.execute(
			"INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
			(SETTING_BACKUP_HMAC_SECRET, candidate_secret, utcnow()),
		)

	secret = get_setting(conn, SETTING_BACKUP_HMAC_SECRET)
	if not secret:
		raise RuntimeError("Failed to initialize backup HMAC secret")
	return secret


def _compute_backup_hmac(filepath: Path, conn: sqlite3.Connection) -> str:
	"""Compute HMAC of backup file using instance-specific secret.
	
	Uses streaming to avoid loading large backups into memory.
	Returns: 32-character hex HMAC signature (128 bits, truncated from SHA-256
	to keep filename length manageable; 128 bits is sufficient for integrity).
	"""
	secret = _get_backup_hmac_secret(conn)
	h = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
	with open(filepath, "rb") as f:
		for chunk in iter(lambda: f.read(1024 * 1024), b""):
			h.update(chunk)
	return h.hexdigest()[:32]


def _safe_tar_extract(tar: tarfile.TarFile, dest: Path) -> None:
	"""Safely extract tar archive, preventing path traversal attacks.
	
	Uses Python 3.12+ filter='data' when available, falls back to manual checks.
	Raises ValueError if any member attempts to escape the destination directory
	or contains non-regular file types (symlinks, device files, FIFOs, etc.).
	"""
	if sys.version_info >= (3, 12):
		tar.extractall(dest, filter="data")
	else:
		dest = dest.resolve()
		members = tar.getmembers()
		for member in members:
			# Only allow regular files and directories (block symlinks, hardlinks,
			# device files, FIFOs, etc. to match Python 3.12's filter="data")
			if not member.isfile() and not member.isdir():
				raise ValueError(f"Unsupported file type in backup: {member.name}")
			member_path = (dest / member.name).resolve()
			if dest not in member_path.parents and member_path != dest:
				raise ValueError(f"Path traversal attempt detected: {member.name}")
		tar.extractall(dest, members=members)


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
	*,
	max_bytes: int = MAX_BACKUP_UPLOAD_BYTES,
) -> tuple[Path, str]:
	"""Stream an uploaded backup to a temp file, validate gzip magic + HMAC.

	Returns ``(tmp_path, filename)``.  The caller owns cleanup of *tmp_path*.
	Raises :class:`HTTPException` on any validation failure.
	"""
	filename = file.filename or ""

	match = _BACKUP_FILENAME_RE.match(filename)
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
				out.write(chunk)

		if total == 0:
			raise HTTPException(status_code=400, detail="Backup file is empty")

		actual_hmac = _compute_backup_hmac(tmp_path, conn)
		if not hmac.compare_digest(actual_hmac, expected_hmac):
			_log.warning("Backup HMAC mismatch for file: %s", filename)
			raise HTTPException(
				status_code=400,
				detail="Backup integrity check failed (HMAC mismatch - wrong instance or corrupted file)",
			)
	except Exception:
		tmp_path.unlink(missing_ok=True)
		raise

	return tmp_path, filename


def _create_backup_archive(data_dir: Path, db_path: Path, conn: sqlite3.Connection) -> tuple[Path, str, int]:
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
				with tempfile.TemporaryDirectory() as backup_tmpdir:
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
		hmac_signature = _compute_backup_hmac(tmp_path, conn)
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


@router.get("/settings", response_model=BackupSettingsResponse)
def get_backup_settings(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
):
	"""Get current backup settings and status.

	NOTE: sync – FastAPI threadpools this handler. Performs glob() + stat() ×
	backup-file-count + shutil.disk_usage() – all blocking file-system calls.
	"""
	conn = connect(request.app.state.cfg.db_path)
	try:
		enabled = get_setting(conn, SETTING_BACKUP_ENABLED, "0") == "1"
		last_backup = get_setting(conn, SETTING_BACKUP_LAST_AT)
		raw_retention = get_setting(conn, SETTING_BACKUP_RETENTION, str(BACKUP_RETENTION_DAYS))
		try:
			retention = int(raw_retention)
			if retention not in BACKUP_RETENTION_OPTIONS:
				_log.warning("Invalid retention_days in DB: %r, using default", raw_retention)
				retention = BACKUP_RETENTION_DAYS
		except (ValueError, TypeError):
			_log.warning("Non-integer retention_days in DB: %r, using default", raw_retention)
			retention = BACKUP_RETENTION_DAYS
		
		# Count existing backups and calculate total size
		backup_dir = _get_backup_dir(request.app.state.cfg.data_dir)
		backup_count = 0
		backup_size = 0
		for f in backup_dir.glob("wirebuddy_backup_*.tar.gz"):
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
	finally:
		close_connection(conn)


@router.patch("/settings")
def update_backup_settings(
	request: Request,
	payload: BackupSettingsUpdate,
	admin: sqlite3.Row = Depends(require_admin),
):
	"""Update backup settings (enable/disable scheduled backups)."""
	conn = connect(request.app.state.cfg.db_path)
	try:
		if payload.scheduled_enabled is not None:
			set_setting(conn, SETTING_BACKUP_ENABLED, "1" if payload.scheduled_enabled else "0")
			_log.info(
				"Scheduled backup %s by %s",
				"enabled" if payload.scheduled_enabled else "disabled",
				admin["username"],
			)
		
		if payload.retention_days is not None:
			# Literal[1,7,14,21,30] validator in BackupSettingsUpdate catches invalid values
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
				return ok_response(
					message="Backup settings updated",
					data={"deleted_backups": deleted_count},
				)
		
		return ok_response(message="Backup settings updated")
	finally:
		close_connection(conn)


@router.post("/download")
def create_backup(
	request: Request,
	background_tasks: BackgroundTasks,
	admin: sqlite3.Row = Depends(require_admin),
):
	"""Create and download a backup of the configuration.

	NOTE: sync – FastAPI threadpools this handler. _create_backup_archive()
	performs full tar + gzip archiving of the data directory (blocking file I/O,
	can take seconds for large datasets). Intentionally kept sync to allow the
	StreamingResponse to be returned directly after archiving completes.

	Returns a gzip-compressed tarball with HMAC signature in filename.
	Uses POST because this operation has side effects (updates last-backup timestamp).
	"""
	data_dir = request.app.state.cfg.data_dir
	db_path = request.app.state.cfg.db_path
	
	if not data_dir.exists():
		raise HTTPException(status_code=404, detail="Data directory not found")
	
	conn = connect(db_path)
	try:
		tmp_path, filename, file_size = _create_backup_archive(data_dir, db_path, conn)
		
		# Update last backup timestamp
		set_setting(conn, SETTING_BACKUP_LAST_AT, utcnow().isoformat())
		
		_log.info(
			"Backup created: %s (%d bytes) by %s",
			filename, file_size, admin["username"],
		)
	finally:
		close_connection(conn)
	
	# Stream the file (conn is already closed)
	def iter_file():
		with open(tmp_path, "rb") as f:
			yield from iter(lambda: f.read(1024 * 1024), b"")
	
	# Guaranteed cleanup even on client disconnect
	background_tasks.add_task(tmp_path.unlink, missing_ok=True)
	
	return StreamingResponse(
		iter_file(),
		media_type="application/gzip",
		headers={
			"Content-Disposition": f'attachment; filename="{filename}"',
			"Content-Length": str(file_size),
		},
	)


@router.post("/validate")
async def validate_backup(
	request: Request,
	file: UploadFile = File(...),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Validate a backup file's HMAC signature without restoring.
	
	Use this to check backup integrity before prompting for password confirmation.
	Returns 200 if valid, 400 with error detail if invalid.
	"""
	conn = connect(request.app.state.cfg.db_path)
	try:
		tmp_path, _filename = await _receive_and_verify_upload(file, conn)
		tmp_path.unlink(missing_ok=True)
		return ok_response(message="Backup file is valid")
	finally:
		close_connection(conn)


class RestoreRequest(BaseModel):
	"""Password confirmation for restore operation.

	NOTE: Not used directly — multipart endpoints cannot mix Pydantic
	models with File()/Form() parameters in FastAPI. The password field
	is received via Form(...) instead. Kept here for documentation only.
	"""
	password: str


@router.post("/restore")
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
	if _restore_lock.locked():
		raise HTTPException(
			status_code=409,
			detail="A restore operation is already in progress",
		)

	async with _restore_lock:
		data_dir = request.app.state.cfg.data_dir
		db_path = request.app.state.cfg.db_path
		restored_items: list[str] = []

		conn = connect(db_path)
		tmp_upload_path: Path | None = None
		try:
			# Verify admin password (PBKDF2-SHA256 – moved off event loop)
			await asyncio.to_thread(_verify_admin_password, conn, admin, password)
			tmp_upload_path, filename = await _receive_and_verify_upload(file, conn)

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
						await asyncio.to_thread(_extract_tar)
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

					# Validate restored database integrity before proceeding
					extracted_db = extracted_data / BACKUP_DATABASE_NAME
					if extracted_db.exists():
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
						except sqlite3.Error as e:
							raise HTTPException(
								status_code=400,
								detail=f"Backup database is invalid: {e}",
							)

					# Close our own connection before closing all connections
					close_connection(conn)
					conn = None  # prevent double-close in outer finally

					# Block concurrent requests from opening fresh DB connections
					request.app.state.maintenance = True

					# Close all remaining SQLite connections before restore
					closed_count = close_all_connections()
					_log.info("Closed %d SQLite connections before restore", closed_count)

					# Create rollback directory
					rollback_dir = data_dir / f".rollback_{utcnow().strftime('%Y%m%d_%H%M%S')}"
					rollback_dir.mkdir(exist_ok=True)
					restore_succeeded = False

					# Restore database (extracted_db defined above)
					try:
						if extracted_db.exists():
							if db_path.exists():
								shutil.move(str(db_path), str(rollback_dir / BACKUP_DATABASE_NAME))
							shutil.move(str(extracted_db), str(db_path))
							restored_items.append(BACKUP_DATABASE_NAME)
							_log.info("Restored database")

						# Restore directories
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

					except Exception as e:
						_log.error("Restore failed: %s. Attempting rollback...", e)

						# Attempt rollback
						try:
							# Rollback database
							if BACKUP_DATABASE_NAME in restored_items:
								if db_path.exists():
									db_path.unlink()
								rollback_db = rollback_dir / BACKUP_DATABASE_NAME
								if rollback_db.exists():
									shutil.move(str(rollback_db), str(db_path))

							# Rollback directories
							for subdir in BACKUP_DIRECTORIES:
								target_subdir = data_dir / subdir
								rollback_subdir = rollback_dir / subdir

								if subdir in restored_items and target_subdir.exists():
									shutil.rmtree(target_subdir)
								if rollback_subdir.exists():
									shutil.move(str(rollback_subdir), str(target_subdir))

							_log.info("Rollback successful")
						except Exception as rollback_error:
							_log.critical("ROLLBACK FAILED: %s. Manual intervention required!", rollback_error)
							raise HTTPException(
								status_code=500,
								detail=f"Restore AND rollback failed! Backup at: {rollback_dir}",
							)

						raise HTTPException(
							status_code=500,
							detail="Restore failed, rollback successful. Original data restored.",
						)

					finally:
						if restore_succeeded:
							# Rollback dir is no longer needed after successful restore
							if rollback_dir.exists():
								try:
									shutil.rmtree(rollback_dir)
								except Exception as cleanup_error:
									_log.warning("Failed to clean up rollback: %s", cleanup_error)
							# Maintenance mode intentionally stays True on success:
							# the app will restart momentarily and reset it on boot.
						else:
							# Restore failed (rollback may have succeeded) — re-open for traffic.
							# rollback_dir is intentionally kept as a last-resort recovery artifact.
							request.app.state.maintenance = False

			finally:
				await file.close()
				if tmp_upload_path is not None:
					tmp_upload_path.unlink(missing_ok=True)

		finally:
			if conn is not None:
				close_connection(conn)

	_log.warning("Backup restored successfully, initiating restart")

	# Schedule application restart
	async def restart_app():
		await asyncio.sleep(1)
		_log.critical("Intentional process termination for restart after backup restore")
		os.kill(os.getpid(), signal.SIGTERM)

	background_tasks.add_task(restart_app)

	return ok_response(
		message="Backup restored successfully. Application is restarting...",
		restored=restored_items,
	)


@router.get("/list")
def list_backups(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
):
	"""List scheduled backups stored on the server."""
	backup_dir = _get_backup_dir(request.app.state.cfg.data_dir)
	
	backups = []
	for backup_file in sorted(backup_dir.glob("wirebuddy_backup_*.tar.gz"), reverse=True):
		file_stat = backup_file.stat()
		backups.append({
			"filename": backup_file.name,
			"size_bytes": file_stat.st_size,
			"created_at": datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc).isoformat(),
		})
	
	return ok_response(data=backups)


@router.delete("/scheduled/{filename}")
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
	if not _BACKUP_FILENAME_RE.match(filename):
		raise HTTPException(status_code=400, detail="Invalid backup filename")
	
	backup_dir = _get_backup_dir(request.app.state.cfg.data_dir)
	backup_path = backup_dir / filename
	
	if not backup_path.exists():
		raise HTTPException(status_code=404, detail="Backup not found")
	
	backup_path.unlink()
	_log.info("Deleted scheduled backup: %s by %s", filename, admin["username"])
	
	return ok_response(message="Backup deleted")


# ─── SCHEDULED BACKUP FUNCTIONS (called by scheduler) ────────────────────────


def is_scheduled_backup_enabled(db_path: Path) -> bool:
	"""Check if scheduled backups are enabled."""
	conn = connect(db_path)
	try:
		return get_setting(conn, SETTING_BACKUP_ENABLED, "0") == "1"
	finally:
		close_connection(conn)


def run_scheduled_backup(data_dir: Path, db_path: Path) -> dict:
	"""Execute a scheduled backup and manage retention.
	
	Called by the scheduler task. Creates a new backup and removes
	backups older than the configured retention period.
	
	Returns:
		Dict with backup status and cleanup stats
	
	Raises:
		OSError: If insufficient disk space
	"""
	if not _scheduled_backup_lock.acquire(blocking=False):
		_log.warning("Scheduled backup already running, skipping")
		return {"skipped": True}
	try:
		conn = connect(db_path)
		try:
			# Get retention setting
			raw_retention = get_setting(conn, SETTING_BACKUP_RETENTION, str(BACKUP_RETENTION_DAYS))
			try:
				retention_days = int(raw_retention)
				if retention_days not in BACKUP_RETENTION_OPTIONS:
					_log.warning("Invalid retention_days in DB: %r, using default", raw_retention)
					retention_days = BACKUP_RETENTION_DAYS
			except (ValueError, TypeError):
				_log.warning("Non-integer retention_days in DB: %r, using default", raw_retention)
				retention_days = BACKUP_RETENTION_DAYS
			
			# Check disk space before creating backup
			backup_dir = _get_backup_dir(data_dir)
			disk_free = shutil.disk_usage(backup_dir).free
			min_required = 100 * 1024 * 1024  # Require at least 100MB free
			
			if disk_free < min_required:
				_log.error("Insufficient disk space for backup: %d bytes free, need %d", disk_free, min_required)
				raise OSError(f"Insufficient disk space: {disk_free // (1024*1024)}MB free, need at least 100MB")
			
			# Create backup archive
			tmp_path, filename, file_size = _create_backup_archive(data_dir, db_path, conn)
			
			# Move to backup directory
			final_path = backup_dir / filename
			shutil.move(str(tmp_path), str(final_path))
			
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
		finally:
			close_connection(conn)
	finally:
		_scheduled_backup_lock.release()


def _cleanup_old_backups(backup_dir: Path, retention_days: int = BACKUP_RETENTION_DAYS) -> int:
	"""Remove backups older than retention period.
	
	Args:
		backup_dir: Directory containing backup files
		retention_days: Number of days to retain backups
	
	Returns: Number of deleted backups
	"""
	cutoff_time = time.time() - (retention_days * 86400)
	deleted = 0
	
	for backup_file in backup_dir.glob("wirebuddy_backup_*.tar.gz"):
		try:
			if backup_file.stat().st_mtime < cutoff_time:
				backup_file.unlink()
				_log.info("Deleted old backup: %s", backup_file.name)
				deleted += 1
		except Exception as e:
			_log.warning("Failed to process backup %s: %s", backup_file.name, e)
	
	return deleted
