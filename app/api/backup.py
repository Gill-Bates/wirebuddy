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
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ..db.sqlite_runtime import close_all_connections, connect, close_connection
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
BACKUP_RETENTION_DAYS = 30
MAX_BACKUP_UPLOAD_BYTES = 5 * 1024 * 1024 * 1024  # 5 GB

# Settings keys for backup configuration
SETTING_BACKUP_ENABLED = "backup_scheduled_enabled"
SETTING_BACKUP_LAST_AT = "backup_last_at"
SETTING_BACKUP_HMAC_SECRET = "backup_hmac_secret"


def _get_backup_hmac_secret(conn) -> str:
	"""Return backup HMAC secret for integrity verification.
	
	Creates a new secret on first use and stores it in the database.
	This secret is unique per installation, preventing backup forgery.
	"""
	secret = get_setting(conn, SETTING_BACKUP_HMAC_SECRET)
	if not secret:
		secret = secrets.token_hex(32)  # 256-bit key
		set_setting(conn, SETTING_BACKUP_HMAC_SECRET, secret)
	return secret


def _compute_backup_hmac(filepath: Path, conn) -> str:
	"""Compute HMAC of backup file using instance-specific secret.
	
	Uses streaming to avoid loading large backups into memory.
	Returns: 32-character hex HMAC signature (128 bits)
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
	or if any symlinks are present (known TAR exploit vector).
	"""
	import sys

	if sys.version_info >= (3, 12):
		tar.extractall(dest, filter="data")
	else:
		dest = dest.resolve()
		members = tar.getmembers()
		for member in members:
			if member.issym() or member.islnk():
				raise ValueError(f"Symlinks are not allowed in backups: {member.name}")
			member_path = (dest / member.name).resolve()
			if dest not in member_path.parents and member_path != dest:
				raise ValueError(f"Path traversal attempt detected: {member.name}")
		tar.extractall(dest, members=members)


def _verify_admin_password(conn, admin: dict, password: str) -> None:
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


def _create_backup_archive(data_dir: Path, db_path: Path, conn) -> tuple[Path, str, int]:
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


class BackupSettingsUpdate(BaseModel):
	"""Backup settings update payload."""
	scheduled_enabled: bool


@router.get("/settings", response_model=BackupSettingsResponse)
def get_backup_settings(
	request: Request,
	admin: dict = Depends(require_admin),
):
	"""Get current backup settings and status."""
	conn = connect(request.app.state.cfg.db_path)
	try:
		enabled = get_setting(conn, SETTING_BACKUP_ENABLED, "0") == "1"
		last_backup = get_setting(conn, SETTING_BACKUP_LAST_AT)
		
		# Count existing backups
		backup_dir = _get_backup_dir(request.app.state.cfg.data_dir)
		backup_count = len(list(backup_dir.glob("wirebuddy_backup_*.tar.gz")))
		
		return BackupSettingsResponse(
			scheduled_enabled=enabled,
			last_backup_at=last_backup,
			backup_count=backup_count,
		)
	finally:
		close_connection(conn)


@router.patch("/settings")
def update_backup_settings(
	request: Request,
	payload: BackupSettingsUpdate,
	admin: dict = Depends(require_admin),
):
	"""Update backup settings (enable/disable scheduled backups)."""
	conn = connect(request.app.state.cfg.db_path)
	try:
		set_setting(conn, SETTING_BACKUP_ENABLED, "1" if payload.scheduled_enabled else "0")
		_log.info(
			"Scheduled backup %s by %s",
			"enabled" if payload.scheduled_enabled else "disabled",
			admin["username"],
		)
		return ok_response(message="Backup settings updated")
	finally:
		close_connection(conn)


@router.post("/download")
def create_backup(
	request: Request,
	admin: dict = Depends(require_admin),
):
	"""Create and download a backup of the configuration.
	
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
		try:
			with open(tmp_path, "rb") as f:
				yield from iter(lambda: f.read(1024 * 1024), b"")
		finally:
			tmp_path.unlink(missing_ok=True)
	
	return StreamingResponse(
		iter_file(),
		media_type="application/gzip",
		headers={"Content-Disposition": f'attachment; filename="{filename}"'}
	)


@router.post("/validate")
async def validate_backup(
	request: Request,
	file: UploadFile = File(...),
	admin: dict = Depends(require_admin),
):
	"""Validate a backup file's HMAC signature without restoring.
	
	Use this to check backup integrity before prompting for password confirmation.
	Returns 200 if valid, 400 with error detail if invalid.
	"""
	db_path = request.app.state.cfg.db_path
	filename = file.filename or ""
	
	# Validate filename format and extract HMAC
	match = re.match(r"wirebuddy_backup_\d{8}_\d{6}_([a-f0-9]{32})\.tar\.gz$", filename)
	if not match:
		raise HTTPException(
			status_code=400,
			detail="Invalid backup file. Expected format: wirebuddy_backup_YYYYMMDD_HHMMSS_<hmac>.tar.gz"
		)
	
	expected_hmac = match.group(1)
	
	# Stream upload to temp file
	fd, tmp_upload_str = tempfile.mkstemp(suffix=".tar.gz")
	os.close(fd)
	tmp_upload_path = Path(tmp_upload_str)
	
	conn = connect(db_path)
	try:
		chunk_size = 1024 * 1024
		first_chunk = True
		total_written = 0
		
		with open(tmp_upload_path, "wb") as tmp_upload:
			while True:
				chunk = await file.read(chunk_size)
				if not chunk:
					break
				total_written += len(chunk)
				if total_written > MAX_BACKUP_UPLOAD_BYTES:
					tmp_upload_path.unlink(missing_ok=True)
					raise HTTPException(status_code=413, detail="Backup file too large")
				
				# Validate gzip magic bytes on first chunk
				if first_chunk:
					if len(chunk) < 2 or chunk[:2] != b"\x1f\x8b":
						tmp_upload_path.unlink(missing_ok=True)
						raise HTTPException(
							status_code=400,
							detail="Invalid backup file (not a gzip archive)"
						)
					first_chunk = False
				
				tmp_upload.write(chunk)
		
		# Verify HMAC (constant-time comparison to prevent timing attacks)
		actual_hmac = _compute_backup_hmac(tmp_upload_path, conn)
		if not hmac.compare_digest(actual_hmac, expected_hmac):
			tmp_upload_path.unlink(missing_ok=True)
			_log.warning("Backup validation failed: HMAC mismatch")
			raise HTTPException(
				status_code=400,
				detail="Backup integrity check failed (HMAC mismatch - wrong instance or corrupted file)"
			)
		
		return ok_response(message="Backup file is valid")
	finally:
		tmp_upload_path.unlink(missing_ok=True)
		close_connection(conn)


class RestoreRequest(BaseModel):
	"""Password confirmation for restore operation."""
	password: str


@router.post("/restore")
async def restore_backup(  # async: uses await for file I/O
	request: Request,
	background_tasks: BackgroundTasks,
	password: str = Form(...),
	file: UploadFile = File(...),
	admin: dict = Depends(require_admin),
):
	"""Restore configuration from an uploaded backup.
	
	CRITICAL: Requires password confirmation (destructive operation).
	Validates HMAC signature before restoring.
	Triggers application restart after successful restore.
	"""
	data_dir = request.app.state.cfg.data_dir
	db_path = request.app.state.cfg.db_path
	restored_items: list[str] = []
	
	conn = connect(db_path)
	try:
		# Verify admin password
		_verify_admin_password(conn, admin, password)
		
		filename = file.filename or ""
		
		# Validate filename format and extract HMAC
		match = re.match(r"wirebuddy_backup_\d{8}_\d{6}_([a-f0-9]{32})\.tar\.gz$", filename)
		if not match:
			raise HTTPException(
				status_code=400,
				detail="Invalid backup file. Expected format: wirebuddy_backup_YYYYMMDD_HHMMSS_<hmac>.tar.gz"
			)
		
		expected_hmac = match.group(1)
		
		# Stream upload to temp file
		fd, tmp_upload_str = tempfile.mkstemp(suffix=".tar.gz")
		os.close(fd)
		tmp_upload_path = Path(tmp_upload_str)
		
		try:
			chunk_size = 1024 * 1024
			first_chunk = True
			total_written = 0
			
			with open(tmp_upload_path, "wb") as tmp_upload:
				while True:
					chunk = await file.read(chunk_size)
					if not chunk:
						break
					total_written += len(chunk)
					if total_written > MAX_BACKUP_UPLOAD_BYTES:
						tmp_upload_path.unlink(missing_ok=True)
						raise HTTPException(status_code=413, detail="Backup file too large")
					
					# Validate gzip magic bytes on first chunk
					if first_chunk:
						if len(chunk) < 2 or chunk[:2] != b"\x1f\x8b":
							tmp_upload_path.unlink(missing_ok=True)
							raise HTTPException(
								status_code=400,
								detail="Invalid backup file (not a gzip archive)"
							)
						first_chunk = False
					
					tmp_upload.write(chunk)
			
			# Verify HMAC (constant-time comparison to prevent timing attacks)
			actual_hmac = _compute_backup_hmac(tmp_upload_path, conn)
			if not hmac.compare_digest(actual_hmac, expected_hmac):
				tmp_upload_path.unlink(missing_ok=True)
				_log.warning("Backup HMAC mismatch: expected %s, got %s", expected_hmac, actual_hmac)
				raise HTTPException(
					status_code=400,
					detail="Backup integrity check failed (HMAC mismatch - wrong instance or corrupted file)"
				)
			
			_log.warning(
				"Backup restore initiated by %s",
				admin["username"],
			)
			
			# Extract to temporary directory
			with tempfile.TemporaryDirectory() as tmpdir:
				tmp_path = Path(tmpdir)
				
				try:
					with tarfile.open(tmp_upload_path, mode="r:gz") as tar:
						_safe_tar_extract(tar, tmp_path)
				except ValueError as e:
					_log.error("Unsafe tar archive: %s", e)
					raise HTTPException(
						status_code=400,
						detail=f"Backup security violation: {e}"
					)
				except Exception as e:
					_log.error("Failed to extract backup: %s", e)
					raise HTTPException(
						status_code=400,
						detail="Failed to extract backup archive"
					)
				
				extracted_data = tmp_path / "data"
				if not extracted_data.exists():
					raise HTTPException(
						status_code=400,
						detail="Invalid backup structure (no data directory)"
					)
				
				# Validate restored database integrity before proceeding
				extracted_db = extracted_data / BACKUP_DATABASE_NAME
				if extracted_db.exists():
					try:
						test_conn = sqlite3.connect(str(extracted_db))
						result = test_conn.execute("PRAGMA integrity_check").fetchone()
						test_conn.close()
						if result[0] != "ok":
							raise HTTPException(
								status_code=400,
								detail="Backup contains corrupt database"
							)
					except sqlite3.Error as e:
						raise HTTPException(
							status_code=400,
							detail=f"Backup database is invalid: {e}"
						)
				
				# Close our own connection before closing all connections
				close_connection(conn)
				conn = None  # prevent double-close in outer finally
				
				# Close all remaining SQLite connections before restore
				closed_count = close_all_connections()
				_log.info("Closed %d SQLite connections before restore", closed_count)
				
				# Create rollback directory
				rollback_dir = data_dir / f".rollback_{utcnow().strftime('%Y%m%d_%H%M%S')}"
				rollback_dir.mkdir(exist_ok=True)
				restore_succeeded = False
				
				try:
					# Restore database (extracted_db defined above)
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
							detail=f"Restore AND rollback failed! Backup at: {rollback_dir}"
						)
					
					raise HTTPException(
						status_code=500,
						detail="Restore failed, rollback successful. Original data restored."
					)
				
				finally:
					if restore_succeeded and rollback_dir.exists():
						try:
							shutil.rmtree(rollback_dir)
						except Exception as cleanup_error:
							_log.warning("Failed to clean up rollback: %s", cleanup_error)
		
		finally:
			await file.close()
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
	admin: dict = Depends(require_admin),
):
	"""List scheduled backups stored on the server."""
	backup_dir = _get_backup_dir(request.app.state.cfg.data_dir)
	
	backups = []
	for backup_file in sorted(backup_dir.glob("wirebuddy_backup_*.tar.gz"), reverse=True):
		stat = backup_file.stat()
		backups.append({
			"filename": backup_file.name,
			"size_bytes": stat.st_size,
			"created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
		})
	
	return ok_response(data=backups)


@router.delete("/scheduled/{filename}")
def delete_scheduled_backup(
	request: Request,
	filename: str,
	admin: dict = Depends(require_admin),
):
	"""Delete a specific scheduled backup."""
	# Validate filename format to prevent path traversal
	if not re.match(r"wirebuddy_backup_\d{8}_\d{6}_[a-f0-9]{32}\.tar\.gz$", filename):
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
	backups older than BACKUP_RETENTION_DAYS.
	
	Returns:
		Dict with backup status and cleanup stats
	"""
	conn = connect(db_path)
	try:
		# Create backup archive
		tmp_path, filename, file_size = _create_backup_archive(data_dir, db_path, conn)
		
		# Move to backup directory
		backup_dir = _get_backup_dir(data_dir)
		final_path = backup_dir / filename
		shutil.move(str(tmp_path), str(final_path))
		
		# Update last backup timestamp
		set_setting(conn, SETTING_BACKUP_LAST_AT, utcnow().isoformat())
		
		_log.info("Scheduled backup created: %s (%d bytes)", filename, file_size)
		
		# Cleanup old backups
		deleted_count = _cleanup_old_backups(backup_dir)
		
		return {
			"filename": filename,
			"size_bytes": file_size,
			"deleted_old_backups": deleted_count,
		}
	finally:
		close_connection(conn)


def _cleanup_old_backups(backup_dir: Path) -> int:
	"""Remove backups older than retention period.
	
	Returns: Number of deleted backups
	"""
	cutoff_time = time.time() - (BACKUP_RETENTION_DAYS * 86400)
	deleted = 0
	
	for backup_file in backup_dir.glob("wirebuddy_backup_*.tar.gz"):
		if backup_file.stat().st_mtime < cutoff_time:
			try:
				backup_file.unlink()
				_log.info("Deleted old backup: %s", backup_file.name)
				deleted += 1
			except Exception as e:
				_log.warning("Failed to delete old backup %s: %s", backup_file.name, e)
	
	return deleted
