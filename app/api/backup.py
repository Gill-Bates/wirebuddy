#!/usr/bin/env python3
#
# app/api/backup.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Backup and restore API routes (admin-only).

Provides functionality to:
- Download a configuration backup as .tar.gz (format v2)
- Restore the SQLite schema and configuration data from an uploaded backup
- Schedule nightly automatic backups with configurable retention
- Optionally include time-range-limited TSDB metrics in the archive

Backup archive layout (format v2):
    backup.json            # manifest
    data/schema.sql        # SQLite DDL (CREATE TABLE/INDEX/VIEW/TRIGGER)
    data/data.sql          # SQLite INSERT statements for configuration tables
    data/tsdb/...          # optional, only when include_tsdb_metrics is set

Configuration tables included in data.sql:
    schema_version, users, passkeys, settings, interfaces, peers, nodes,
    node_interfaces

Excluded (ephemeral): auth_tokens, passkey_challenges, login_attempts,
    node_commands
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import hmac
import io
import json
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
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Callable, Iterator, Literal, TypeVar, cast

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ..db.sqlite_runtime import close_all_connections, connect, close_connection, thread_connection
from ..db.sqlite_settings import get_setting, set_setting
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

BACKUP_DATABASE_NAME = "wirebuddy.db"
BACKUP_SUBDIR = "backup"  # Scheduled backups stored here
BACKUP_RETENTION_DAYS = 30  # Default retention
BACKUP_RETENTION_OPTIONS = (1, 7, 14, 21, 30)  # Valid retention values (tuple for deterministic ordering)
# Schema-only backups are small; the optional TSDB export is time-range bounded.
# 1 GB is a generous upper bound for a long (1y) metrics export.
MAX_BACKUP_UPLOAD_BYTES = 1 * 1024 * 1024 * 1024  # 1 GB

# Backup archive format (v2: schema-only DB + optional range-bounded TSDB)
_BACKUP_FORMAT_VERSION = 2
_BACKUP_MANIFEST_MEMBER = "backup.json"
_BACKUP_SCHEMA_MEMBER = "data/schema.sql"
_BACKUP_DATA_MEMBER = "data/data.sql"
_BACKUP_TSDB_DIRNAME = "tsdb"

# Optional TSDB metrics export ranges (label -> day count)
BACKUP_TSDB_RANGE_DAYS: dict[str, int] = {
	"7d": 7,
	"30d": 30,
	"90d": 90,
	"180d": 180,
	"1y": 365,
}
BACKUP_TSDB_RANGE_OPTIONS: tuple[str, ...] = tuple(BACKUP_TSDB_RANGE_DAYS)
BACKUP_TSDB_RANGE_DEFAULT = "30d"

# Backed-up DDL is small; reject anything implausibly large early during restore.
MAX_BACKUP_SCHEMA_BYTES = 5 * 1024 * 1024  # 5 MB
# data.sql holds INSERT statements for all config tables; 50 MB is a generous
# bound for realistic deployments (many peers, settings, nodes).
MAX_BACKUP_DATA_BYTES = 50 * 1024 * 1024  # 50 MB

# Only schema-creating DDL is permitted in schema.sql.
_ALLOWED_SCHEMA_STATEMENT_PREFIXES = (
	"CREATE TABLE ",
	"CREATE INDEX ",
	"CREATE UNIQUE INDEX ",
	"CREATE TRIGGER ",
	"CREATE VIEW ",
)

# Only INSERT statements are permitted in data.sql.
_ALLOWED_DATA_STATEMENT_PREFIXES = ("INSERT INTO ",)

# Configuration tables exported with row data.  Order is dependency-safe for
# FK relationships that can be resolved linearly; the circular reference between
# nodes.tunnel_peer_id and peers.node_id is harmless because foreign-key
# enforcement is off by default in SQLite.
_BACKUP_DATA_TABLES: tuple[str, ...] = (
	"schema_version",
	"users",
	"settings",
	"interfaces",
	"nodes",
	"peers",
	"passkeys",
	"node_interfaces",
)

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
SETTING_BACKUP_INCLUDE_TSDB = "backup_include_tsdb_metrics"
SETTING_BACKUP_TSDB_RANGE = "backup_tsdb_range"

_T = TypeVar("_T")

_DB_CONNECT_TIMEOUT_SECONDS = 10.0
_VERIFY_PASSWORD_TIMEOUT_SECONDS = 15.0
_BACKUP_HMAC_TIMEOUT_SECONDS = 60.0
_BACKUP_CREATE_TIMEOUT_SECONDS = 300.0
_TAR_EXTRACT_TIMEOUT_SECONDS = 120.0
_DB_INTEGRITY_CHECK_TIMEOUT_SECONDS = 30.0
_BACKUP_HMAC_CONTEXT = b"wirebuddy-backup-hmac\0"
MAX_BACKUP_EXTRACTED_BYTES = 10 * 1024 * 1024 * 1024  # 10 GB
# Allowed top-level archive members for format v2. TSDB is matched by prefix.
_ALLOWED_BACKUP_FILES_V2 = frozenset({
	_BACKUP_MANIFEST_MEMBER,
	_BACKUP_SCHEMA_MEMBER,
	_BACKUP_DATA_MEMBER,
	"data",
	f"data/{_BACKUP_TSDB_DIRNAME}",
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


def _get_backup_tsdb_range(conn: sqlite3.Connection) -> BackupMetricsRange:
    """Read and validate the configured TSDB export range, with safe fallback."""
    raw = get_setting(conn, SETTING_BACKUP_TSDB_RANGE, BACKUP_TSDB_RANGE_DEFAULT)
    if raw not in BACKUP_TSDB_RANGE_OPTIONS:
        _log.warning("Invalid backup TSDB range in DB: %r, using default", raw)
        return cast(BackupMetricsRange, BACKUP_TSDB_RANGE_DEFAULT)
    return cast(BackupMetricsRange, raw)


def _get_backup_create_options(conn: sqlite3.Connection) -> BackupCreateOptions:
    """Read backup content options (TSDB inclusion + range) from settings."""
    include_tsdb = get_setting(conn, SETTING_BACKUP_INCLUDE_TSDB, "0") == "1"
    return BackupCreateOptions(
        include_tsdb_metrics=include_tsdb,
        tsdb_range=_get_backup_tsdb_range(conn),
    )


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


def _is_allowed_backup_member(member_name: str) -> bool:
	"""Return True when the tar member is inside the expected v2 backup layout.

	Permitted: ``backup.json``, ``data/schema.sql`` and anything under
	``data/tsdb/``. Legacy full-data members (``data/wirebuddy.db``,
	``data/dns``, ``data/certs``) are rejected.
	"""
	normalized = member_name.rstrip("/")
	if normalized in _ALLOWED_BACKUP_FILES_V2:
		return True
	return normalized.startswith(f"data/{_BACKUP_TSDB_DIRNAME}/")


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


def _validate_extracted_backup_structure(extracted_data: Path, manifest: BackupManifest) -> None:
	"""Ensure extracted entries match the expected types *and* the manifest.

	Restore semantics are driven by the manifest, not by whatever happens to be
	present in the archive: TSDB data is only accepted when the manifest declares
	``include_tsdb_metrics`` (and a range for it).
	"""
	schema_file = extracted_data / "schema.sql"
	if not schema_file.is_file():
		raise HTTPException(status_code=400, detail="Backup is missing data/schema.sql")

	data_file = extracted_data / "data.sql"
	if not data_file.is_file():
		raise HTTPException(status_code=400, detail="Backup is missing data/data.sql")

	tsdb_dir = extracted_data / _BACKUP_TSDB_DIRNAME
	if tsdb_dir.exists():
		if not tsdb_dir.is_dir():
			raise HTTPException(
				status_code=400,
				detail=f"Backup entry data/{_BACKUP_TSDB_DIRNAME} is not a directory",
			)
		if not manifest.include_tsdb_metrics:
			raise HTTPException(
				status_code=400,
				detail="Backup contains TSDB metrics but its manifest disables them",
			)

	if manifest.include_tsdb_metrics and manifest.tsdb_range is None:
		raise HTTPException(status_code=400, detail="Backup manifest is missing the TSDB range")


def _read_backup_manifest(extract_root: Path) -> BackupManifest:
	"""Read and validate the archive manifest, rejecting unsupported formats.

	Legacy full-data backups (no manifest) and any future format are rejected so
	the schema-only restore path never operates on an unexpected layout.
	"""
	manifest_path = extract_root / _BACKUP_MANIFEST_MEMBER
	if not manifest_path.is_file():
		raise HTTPException(
			status_code=400,
			detail="Unsupported backup: missing manifest (legacy full-data backups are not supported)",
		)
	try:
		return BackupManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
	except (OSError, ValueError) as exc:
		raise HTTPException(status_code=400, detail="Backup manifest is invalid or unsupported") from exc


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
			_log.error("Backup HMAC mismatch for file: %s", filename)
			raise HTTPException(
				status_code=400,
				detail="Backup integrity check failed (HMAC mismatch - wrong instance or corrupted file)",
			)
	except Exception:
		tmp_path.unlink(missing_ok=True)
		raise

	return tmp_path, filename


def _iter_sql_statements(sql: str) -> Iterator[str]:
	"""Yield complete SQL statements from *sql* (trigger bodies stay intact)."""
	buffer: list[str] = []
	for line in sql.splitlines():
		if not line.strip() and not buffer:
			continue
		buffer.append(line)
		statement = "\n".join(buffer).strip()
		if statement and sqlite3.complete_statement(statement):
			yield statement
			buffer.clear()
	if any(part.strip() for part in buffer):
		raise HTTPException(status_code=400, detail="Backup schema contains an incomplete SQL statement")


def _validate_schema_statement_types(schema_sql: str) -> None:
	"""Reject any statement that is not schema-creating DDL."""
	for statement in _iter_sql_statements(schema_sql):
		normalized = " ".join(statement.upper().split())
		if not normalized.startswith(_ALLOWED_SCHEMA_STATEMENT_PREFIXES):
			raise HTTPException(status_code=400, detail="Backup schema contains non-DDL SQL")


def _validate_schema_sql(schema_sql: str) -> None:
	"""Validate the backed-up DDL before any destructive change.

	First enforces that every statement is schema-creating DDL (no row data or
	side effects), then applies it to a throwaway database and runs an integrity
	check.
	"""
	if not schema_sql.strip():
		raise HTTPException(status_code=400, detail="Backup schema is empty")

	_validate_schema_statement_types(schema_sql)

	try:
		with tempfile.TemporaryDirectory() as tmpdir:
			test_db = Path(tmpdir) / "schema_test.db"
			test_conn = sqlite3.connect(str(test_db))
			try:
				test_conn.executescript(schema_sql)
				result = test_conn.execute("PRAGMA integrity_check").fetchone()
			finally:
				test_conn.close()
			if result is None or result[0] != "ok":
				raise HTTPException(status_code=400, detail="Backup schema failed integrity check")
	except sqlite3.Error as exc:
		raise HTTPException(status_code=400, detail=f"Backup schema is invalid: {exc}") from exc


def _read_schema_sql(extracted_data: Path) -> str:
	"""Read ``data/schema.sql`` with an early size guard (off the event loop)."""
	schema_path = extracted_data / "schema.sql"
	size = schema_path.stat().st_size
	if size > MAX_BACKUP_SCHEMA_BYTES:
		raise HTTPException(status_code=413, detail="Backup schema is too large")
	return schema_path.read_text(encoding="utf-8")


def _validate_data_statement_types(data_sql: str) -> None:
	"""Reject any statement in data.sql that is not an INSERT INTO."""
	for statement in _iter_sql_statements(data_sql):
		normalized = " ".join(statement.upper().split())
		if not normalized.startswith(_ALLOWED_DATA_STATEMENT_PREFIXES):
			raise HTTPException(status_code=400, detail="Backup data contains non-INSERT SQL")


def _validate_data_sql(schema_sql: str, data_sql: str) -> None:
	"""Validate the backed-up data SQL against the accompanying schema.

	Enforces that every statement is an INSERT INTO, then applies schema+data
	to a throwaway in-memory database and runs an integrity check.  Empty data
	is valid (fresh install with no rows).
	"""
	if not data_sql.strip():
		return

	_validate_data_statement_types(data_sql)

	try:
		with tempfile.TemporaryDirectory() as tmpdir:
			test_db = Path(tmpdir) / "data_test.db"
			test_conn = sqlite3.connect(str(test_db))
			try:
				test_conn.executescript(schema_sql)
				test_conn.executescript(data_sql)
				result = test_conn.execute("PRAGMA integrity_check").fetchone()
			finally:
				test_conn.close()
			if result is None or result[0] != "ok":
				raise HTTPException(status_code=400, detail="Backup data failed integrity check")
	except sqlite3.Error as exc:
		raise HTTPException(status_code=400, detail=f"Backup data is invalid: {exc}") from exc


def _read_data_sql(extracted_data: Path) -> str:
	"""Read ``data/data.sql`` with an early size guard (off the event loop)."""
	data_path = extracted_data / "data.sql"
	if not data_path.exists():
		raise HTTPException(status_code=400, detail="Backup is missing data/data.sql")
	size = data_path.stat().st_size
	if size > MAX_BACKUP_DATA_BYTES:
		raise HTTPException(status_code=413, detail="Backup data is too large")
	return data_path.read_text(encoding="utf-8")


def _sqlite_files(db_path: Path) -> tuple[Path, ...]:
	"""Return the database file and its WAL/SHM sidecar paths as a unit."""
	return (
		db_path,
		db_path.with_name(f"{db_path.name}-wal"),
		db_path.with_name(f"{db_path.name}-shm"),
	)


def _move_sqlite_files_to_rollback(db_path: Path, rollback_dir: Path) -> None:
	"""Move the database and any WAL/SHM sidecars into the rollback directory."""
	for path in _sqlite_files(db_path):
		if path.exists():
			shutil.move(str(path), str(rollback_dir / path.name))


def _restore_sqlite_files_from_rollback(db_path: Path, rollback_dir: Path) -> None:
	"""Restore the database and sidecars from rollback, discarding the new DB."""
	for path in _sqlite_files(db_path):
		path.unlink(missing_ok=True)
	for original in _sqlite_files(db_path):
		saved = rollback_dir / original.name
		if saved.exists():
			shutil.move(str(saved), str(original))


def _apply_restored_backup(
	data_dir: Path,
	db_path: Path,
	extracted_data: Path,
	schema_sql: str,
	data_sql: str,
) -> list[str]:
	"""Apply a configuration restore with rollback protection.

	Replaces the live database with a fresh database created from the backed-up
	DDL and INSERT statements.  The database and its WAL/SHM sidecars are moved
	aside as a unit so a restore never starts against stale WAL frames.  When
	the archive contains TSDB metrics, the ``tsdb`` directory is replaced as
	well.  The previous database/sidecars/directory are kept in a rollback
	directory until the restore succeeds.

	Runs in a worker thread because it performs blocking filesystem operations.
	This commit phase intentionally has no timeout: thread cancellation would be
	unsafe once destructive moves have started.
	"""
	restored_items: list[str] = []
	closed_count = close_all_connections()
	_log.info("Closed %d SQLite connections before restore", closed_count)

	extracted_tsdb = extracted_data / _BACKUP_TSDB_DIRNAME

	rollback_dir = data_dir / f".rollback_{utcnow().strftime('%Y%m%d_%H%M%S')}"
	rollback_dir.mkdir(exist_ok=True)
	restore_succeeded = False

	try:
		# Move the existing database + WAL/SHM aside, then build a fresh DB.
		_move_sqlite_files_to_rollback(db_path, rollback_dir)
		new_conn = sqlite3.connect(str(db_path))
		try:
			new_conn.executescript(schema_sql)
			if data_sql.strip():
				new_conn.executescript(data_sql)
			new_conn.commit()
		finally:
			new_conn.close()
		restored_items.append(BACKUP_DATABASE_NAME)
		_log.info("Restored database schema and configuration data")

		if extracted_tsdb.exists():
			target_tsdb = data_dir / _BACKUP_TSDB_DIRNAME
			if target_tsdb.exists():
				shutil.move(str(target_tsdb), str(rollback_dir / _BACKUP_TSDB_DIRNAME))
			shutil.move(str(extracted_tsdb), str(target_tsdb))
			restored_items.append(_BACKUP_TSDB_DIRNAME)
			_log.info("Restored directory: %s", _BACKUP_TSDB_DIRNAME)

		restore_succeeded = True
		_log.info("Restored %d items: %s", len(restored_items), ", ".join(restored_items))
		return restored_items

	except Exception as exc:
		_log.error("Restore failed: %s. Attempting rollback...", exc)
		try:
			# Discard the freshly created DB (incl. its own new WAL/SHM) and
			# restore the original database files as a unit.
			_restore_sqlite_files_from_rollback(db_path, rollback_dir)

			target_tsdb = data_dir / _BACKUP_TSDB_DIRNAME
			rollback_tsdb = rollback_dir / _BACKUP_TSDB_DIRNAME
			if rollback_tsdb.exists() and target_tsdb.exists():
				shutil.rmtree(target_tsdb)
			if rollback_tsdb.exists():
				shutil.move(str(rollback_tsdb), str(target_tsdb))

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


def _export_sqlite_schema(db_path: Path) -> str:
	"""Export the SQLite schema (DDL only, no row data).

	Returns a string of ``CREATE`` statements for tables, indexes, triggers and
	views in dependency-safe order (tables first, then indexes/triggers/views).
	Internal ``sqlite_*`` objects are excluded. No ``INSERT`` statements are
	emitted, so the resulting backup contains no user, settings or runtime data.
	"""
	conn = sqlite3.connect(str(db_path))
	try:
		rows = conn.execute(
			"""
			SELECT sql
			FROM sqlite_master
			WHERE sql IS NOT NULL
			  AND type IN ('table', 'index', 'trigger', 'view')
			  AND name NOT LIKE 'sqlite_%'
			ORDER BY
			  CASE type
			    WHEN 'table' THEN 1
			    WHEN 'index' THEN 2
			    WHEN 'trigger' THEN 3
			    WHEN 'view' THEN 4
			  END,
			  name
			"""
		).fetchall()
	finally:
		conn.close()

	statements = [str(row[0]).rstrip().rstrip(";") + ";" for row in rows]
	return "\n\n".join(statements) + "\n"


def _sqlite_value_to_sql(value: object) -> str:
	"""Convert a Python SQLite value to a SQL literal for INSERT generation."""
	if value is None:
		return "NULL"
	if isinstance(value, bool):
		return "1" if value else "0"
	if isinstance(value, int):
		return str(value)
	if isinstance(value, float):
		return repr(value)
	if isinstance(value, bytes):
		return "X'" + value.hex() + "'"
	return "'" + str(value).replace("'", "''") + "'"


def _export_sqlite_data(db_path: Path) -> str:
	"""Export INSERT statements for configuration tables (no ephemeral data).

	Tables exported: schema_version, users, settings, interfaces, nodes, peers,
	passkeys, node_interfaces.  Ephemeral tables (auth_tokens,
	passkey_challenges, login_attempts, node_commands) are intentionally
	excluded.

	Foreign-key enforcement is left off (SQLite default) so the circular
	reference between nodes.tunnel_peer_id and peers.node_id does not cause
	ordering problems.  Tables absent in the source DB (e.g. during unit tests
	with a minimal schema) are silently skipped.
	"""
	conn = sqlite3.connect(str(db_path))
	try:
		lines: list[str] = []
		for table in _BACKUP_DATA_TABLES:
			exists = conn.execute(
				"SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
			).fetchone()
			if exists is None:
				continue
			cursor = conn.execute(f'SELECT * FROM "{table}" LIMIT 0')
			col_names = [d[0] for d in cursor.description]
			col_list = ", ".join(f'"{c}"' for c in col_names)
			for row in conn.execute(f'SELECT * FROM "{table}"'):
				values = ", ".join(_sqlite_value_to_sql(v) for v in row)
				lines.append(f'INSERT INTO "{table}" ({col_list}) VALUES ({values});')
		return "\n".join(lines) + "\n" if lines else ""
	finally:
		conn.close()


def _add_bytes_to_tar(tar: tarfile.TarFile, arcname: str, data: bytes, mtime: int) -> None:
	"""Add an in-memory byte payload to the tar archive under *arcname*."""
	info = tarfile.TarInfo(arcname)
	info.size = len(data)
	info.mtime = mtime
	info.mode = 0o600
	tar.addfile(info, io.BytesIO(data))


def _line_is_in_range(line: bytes, cutoff: datetime) -> bool:
	"""Return True when a JSONL line's ``ts`` is >= *cutoff* (UTC-aware).

	Unparseable lines are treated as out of range (the TSDB reader skips them).
	"""
	try:
		ts = datetime.fromisoformat(json.loads(line)["ts"])
	except (ValueError, KeyError, TypeError):
		return False
	if ts.tzinfo is None:
		ts = ts.replace(tzinfo=UTC)
	return ts >= cutoff


def _write_filtered_tsdb_file(src: Path, dst: Path, cutoff: datetime) -> bool:
	"""Stream-filter one TSDB series file by timestamp into *dst*.

	Reads line-by-line (so memory stays bounded regardless of file size),
	preserving the source's plain/gzip encoding. Returns True if any in-range
	line was written.
	"""
	is_gzip = src.suffix == ".gz"
	opener = gzip.open if is_gzip else open
	wrote = False
	with opener(src, "rb") as inp, opener(dst, "wb") as out:
		for line in inp:
			stripped = line.strip()
			if not stripped:
				continue
			if _line_is_in_range(stripped, cutoff):
				out.write(stripped + b"\n")
				wrote = True
	return wrote


def _export_tsdb_range_to_tar(
	tar: tarfile.TarFile,
	tsdb_dir: Path,
	range_days: int,
	now: datetime,
) -> int:
	"""Add TSDB series data within the last *range_days* to the archive.

	Each series file (current ``.jsonl`` plus rotated ``.gz``/uncompressed
	archives) is stream-filtered line-by-line by timestamp into a temp file and
	only then added to the tar; memory use stays bounded even for 1y exports of
	large rotated files. Files with no in-range points and internal marker files
	(``.lock``/``.prune``/``.tmp``) are skipped. Returns the number of files
	written.
	"""
	if not tsdb_dir.is_dir():
		return 0

	cutoff = now - timedelta(days=range_days)
	written = 0

	with tempfile.TemporaryDirectory() as tmpdir:
		tmp_root = Path(tmpdir)
		for path in sorted(tsdb_dir.rglob("*")):
			if not path.is_file():
				continue
			if path.suffix in (".lock", ".prune", ".tmp"):
				continue

			tmp_file = tmp_root / path.name
			try:
				if not _write_filtered_tsdb_file(path, tmp_file, cutoff):
					continue
			except (OSError, EOFError) as exc:
				_log.warning("Skipping unreadable/corrupt TSDB file %s: %s", path, exc)
				continue

			arcname = f"data/{_BACKUP_TSDB_DIRNAME}/{path.relative_to(tsdb_dir).as_posix()}"
			tar.add(tmp_file, arcname=arcname)
			written += 1

	_log.debug("Added %d TSDB series file(s) within %dd to backup", written, range_days)
	return written


def _create_backup_archive(
	data_dir: Path,
	db_path: Path,
	secret_key: str,
	options: BackupCreateOptions,
) -> tuple[Path, str, int]:
	"""Create a schema-only backup archive (format v2).

	The archive contains a manifest, the SQLite DDL (no row data) and, when
	requested, range-bounded TSDB metrics. No full database copy is included.

	Returns:
		Tuple of (archive_path, filename, file_size)
	"""
	# Create tarball in a temp file
	tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz")
	tmp_path = Path(tmp_file.name)
	tmp_file.close()

	now = utcnow()
	mtime = int(now.timestamp())

	try:
		manifest = BackupManifest(
			format_version=_BACKUP_FORMAT_VERSION,
			created_at=now.isoformat(),
			database="schema_and_data",
			include_tsdb_metrics=options.include_tsdb_metrics,
			tsdb_range=options.tsdb_range if options.include_tsdb_metrics else None,
		)

		with tarfile.open(tmp_path, mode="w:gz") as tar:
			manifest_bytes = manifest.model_dump_json().encode("utf-8")
			_add_bytes_to_tar(tar, _BACKUP_MANIFEST_MEMBER, manifest_bytes, mtime)

			if not db_path.exists():
				raise HTTPException(status_code=404, detail="Database not found")
			schema_bytes = _export_sqlite_schema(db_path).encode("utf-8")
			_add_bytes_to_tar(tar, _BACKUP_SCHEMA_MEMBER, schema_bytes, mtime)
			_log.debug("Added SQLite schema (%d bytes) to backup", len(schema_bytes))

			data_bytes = _export_sqlite_data(db_path).encode("utf-8")
			_add_bytes_to_tar(tar, _BACKUP_DATA_MEMBER, data_bytes, mtime)
			_log.debug("Added SQLite data (%d bytes) to backup", len(data_bytes))

			if options.include_tsdb_metrics:
				_export_tsdb_range_to_tar(
					tar,
					data_dir / _BACKUP_TSDB_DIRNAME,
					BACKUP_TSDB_RANGE_DAYS[options.tsdb_range],
					now,
				)

		# Calculate HMAC signature
		hmac_signature = _compute_backup_hmac(tmp_path, _derive_backup_hmac_secret(secret_key))
		file_size = tmp_path.stat().st_size

		# Generate filename with timestamp and HMAC
		timestamp = now.strftime("%Y%m%d_%H%M%S")
		filename = f"wirebuddy_backup_{timestamp}_{hmac_signature}.tar.gz"

		return tmp_path, filename, file_size

	except Exception:
		tmp_path.unlink(missing_ok=True)
		raise


# ─── API ENDPOINTS ───────────────────────────────────────────────────────────


BackupMetricsRange = Literal["7d", "30d", "90d", "180d", "1y"]


@dataclass(frozen=True, slots=True)
class BackupCreateOptions:
	"""Options controlling what a backup archive contains."""
	include_tsdb_metrics: bool
	tsdb_range: BackupMetricsRange


class BackupManifest(BaseModel):
	"""Backup archive manifest (member ``backup.json``)."""
	format_version: Literal[2]
	created_at: str
	database: Literal["schema_and_data"]
	include_tsdb_metrics: bool
	tsdb_range: BackupMetricsRange | None = None


class BackupSettingsResponse(BaseModel):
	"""Backup settings response."""
	scheduled_enabled: bool
	last_backup_at: str | None
	backup_count: int
	retention_days: int
	backup_size_bytes: int
	disk_free_bytes: int
	disk_warning: bool  # True if disk space is low
	include_tsdb_metrics: bool
	tsdb_range: BackupMetricsRange


class BackupSettingsUpdate(BaseModel):
	"""Backup settings update payload."""
	scheduled_enabled: bool | None = None
	retention_days: Literal[1, 7, 14, 21, 30] | None = None
	include_tsdb_metrics: bool | None = None
	tsdb_range: BackupMetricsRange | None = None


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

		options = _get_backup_create_options(conn)

		return BackupSettingsResponse(
			scheduled_enabled=enabled,
			last_backup_at=last_backup,
			backup_count=backup_count,
			retention_days=retention,
			backup_size_bytes=backup_size,
			disk_free_bytes=disk_free,
			disk_warning=disk_warning,
			include_tsdb_metrics=options.include_tsdb_metrics,
			tsdb_range=options.tsdb_range,
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

		if payload.include_tsdb_metrics is not None:
			set_setting(conn, SETTING_BACKUP_INCLUDE_TSDB, "1" if payload.include_tsdb_metrics else "0")
			_log.info(
				"Backup TSDB metrics %s by %s",
				"enabled" if payload.include_tsdb_metrics else "disabled",
				admin["username"],
			)

		if payload.tsdb_range is not None:
			# Persisted even while TSDB inclusion is off, so the choice survives re-enabling.
			set_setting(conn, SETTING_BACKUP_TSDB_RANGE, payload.tsdb_range)
			_log.info("Backup TSDB range set to %s by %s", payload.tsdb_range, admin["username"])

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
					options = await _run_blocking(
						_get_backup_create_options,
						conn,
						timeout=_DB_CONNECT_TIMEOUT_SECONDS,
						operation="read backup options",
					)
					tmp_path, filename, file_size = await _run_blocking(
						_create_backup_archive,
						data_dir,
						db_path,
						request.app.state.cfg.secret_key,
						options,
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

					# Reject anything that is not a supported schema-only (v2) backup
					manifest = await _run_blocking(
						_read_backup_manifest,
						tmp_path,
						timeout=_DB_INTEGRITY_CHECK_TIMEOUT_SECONDS,
						operation="read backup manifest",
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
						manifest,
						timeout=_DB_INTEGRITY_CHECK_TIMEOUT_SECONDS,
						operation="validate extracted backup structure",
					)

					# Read (size-limited, off-loop) and validate both DDL and data
					# before touching the live database.
					schema_sql = await _run_blocking(
						_read_schema_sql,
						extracted_data,
						timeout=_DB_INTEGRITY_CHECK_TIMEOUT_SECONDS,
						operation="read restored backup schema",
					)
					await _run_blocking(
						_validate_schema_sql,
						schema_sql,
						timeout=_DB_INTEGRITY_CHECK_TIMEOUT_SECONDS,
						operation="validate restored backup schema",
					)
					data_sql = await _run_blocking(
						_read_data_sql,
						extracted_data,
						timeout=_DB_INTEGRITY_CHECK_TIMEOUT_SECONDS,
						operation="read restored backup data",
					)
					await _run_blocking(
						_validate_data_sql,
						schema_sql,
						data_sql,
						timeout=_DB_INTEGRITY_CHECK_TIMEOUT_SECONDS,
						operation="validate restored backup data",
					)
					_log.info("Restoring configuration backup (format v%d)", manifest.format_version)

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
								schema_sql,
								data_sql,
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
				# Get retention setting and content options
				retention_days = _get_retention_days(conn)
				options = _get_backup_create_options(conn)

				# Check disk space before creating backup
				backup_dir = _get_backup_dir(data_dir)
				disk_free = shutil.disk_usage(backup_dir).free
				min_required = 100 * 1024 * 1024  # Require at least 100MB free

				if disk_free < min_required:
					_log.error("Insufficient disk space for backup: %d bytes free, need %d", disk_free, min_required)
					raise OSError(f"Insufficient disk space: {disk_free // (1024*1024)}MB free, need at least 100MB")

				# Create backup archive
				tmp_path, filename, file_size = _create_backup_archive(data_dir, db_path, secret_key, options)
				
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
