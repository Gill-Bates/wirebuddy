#!/usr/bin/env python3
#
# app/tasks/maintenance.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Periodic maintenance tasks for database health and cleanup."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import aiosqlite

from app.utils.config import get_config

_log = logging.getLogger(__name__)

__all__ = [
	"sqlite_maintenance",
	"sqlite_integrity_check",
	"tsdb_retention_cleanup",
	"cleanup_stale_sessions",
]


async def sqlite_maintenance() -> None:
	"""Periodic SQLite maintenance: WAL checkpoint, analyze, optimize.
	
	This task should run every 6-12 hours to:
	- Checkpoint WAL file to prevent unbounded growth
	- Update query planner statistics (ANALYZE)
	- Optimize query performance (PRAGMA optimize)
	
	Note: VACUUM is intentionally omitted (heavy I/O, run manually if needed).
	"""
	cfg = get_config()
	db_path = cfg.db_path
	
	if not Path(db_path).exists():
		_log.warning("MAINTENANCE SQLite database not found at %s", db_path)
		return
	
	try:
		async with aiosqlite.connect(db_path) as db:
			# Force WAL checkpoint to prevent unbounded WAL growth
			# TRUNCATE mode: checkpoints and truncates WAL file to 0 bytes
			await db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
			
			# Update query planner statistics for optimal query plans
			await db.execute("ANALYZE")
			
			# Optimize internal schema (query planner hints)
			await db.execute("PRAGMA optimize")
			
			_log.info("MAINTENANCE SQLite maintenance completed")
	except Exception:
		_log.exception("MAINTENANCE SQLite maintenance failed")
		raise


async def sqlite_integrity_check() -> None:
	"""Weekly integrity check (expensive, run infrequently).
	
	This task should run weekly to detect database corruption early.
	On failure, logs a CRITICAL alert for operator intervention.
	"""
	cfg = get_config()
	db_path = cfg.db_path
	
	if not Path(db_path).exists():
		_log.warning("MAINTENANCE SQLite database not found at %s", db_path)
		return
	
	try:
		async with aiosqlite.connect(db_path) as db:
			cursor = await db.execute("PRAGMA integrity_check")
			result = await cursor.fetchone()
			
			if result and result[0] == "ok":
				_log.info("MAINTENANCE SQLite integrity check passed")
			else:
				failure_msg = result[0] if result else "unknown error"
				_log.critical("MAINTENANCE SQLite integrity check FAILED: %s", failure_msg)
	except Exception:
		_log.exception("MAINTENANCE SQLite integrity check error")
		raise


def _tsdb_cleanup_sync(tsdb_dir: Path, retention_days: int) -> tuple[int, int]:
	"""Synchronous TSDB cleanup (runs in thread pool).
	
	Args:
		tsdb_dir: Path to TSDB directory
		retention_days: Number of days to retain data
	
	Returns:
		Tuple of (deleted_files_count, deleted_bytes)
	"""
	cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
	deleted_files = 0
	deleted_bytes = 0
	
	for arrow_file in tsdb_dir.glob("**/*.arrow"):
		try:
			st = arrow_file.stat()
			mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
			
			if mtime < cutoff:
				arrow_file.unlink()
				deleted_files += 1
				deleted_bytes += st.st_size
				_log.debug(
					"MAINTENANCE TSDB deleted expired file: %s (age: %d days)",
					arrow_file.name,
					(datetime.now(timezone.utc) - mtime).days,
				)
		except FileNotFoundError:
			continue  # Concurrent deletion, harmless
		except Exception as e:
			_log.warning(
				"MAINTENANCE TSDB failed to process %s: %s",
				arrow_file.name, e,
			)
	
	# Clean up empty directories (bottom-up)
	for dirpath in sorted(tsdb_dir.rglob("*"), reverse=True):
		if dirpath.is_dir():
			try:
				dirpath.rmdir()
			except OSError:
				pass
	
	return deleted_files, deleted_bytes


async def tsdb_retention_cleanup() -> None:
	"""Purge expired time-series data beyond retention window.
	
	WireBuddy uses a custom TSDB implementation (Arrow IPC files).
	This task removes old .arrow files based on retention policy.
	
	Note: File I/O runs in thread pool to avoid blocking the event loop.
	"""
	cfg = get_config()
	tsdb_dir = Path(cfg.tsdb_dir)
	
	if not await asyncio.to_thread(tsdb_dir.exists):
		_log.debug("MAINTENANCE TSDB directory does not exist: %s", tsdb_dir)
		return
	
	try:
		retention_days = getattr(cfg, "TSDB_RETENTION_DAYS", 90)
		
		deleted_files, deleted_bytes = await asyncio.to_thread(
			_tsdb_cleanup_sync, tsdb_dir, retention_days,
		)
		
		if deleted_files > 0:
			_log.info(
				"MAINTENANCE TSDB retention cleanup: deleted %d files (%.2f MB)",
				deleted_files,
				deleted_bytes / (1024 * 1024),
			)
		else:
			_log.debug("MAINTENANCE TSDB retention cleanup: no expired files")
	except Exception:
		_log.exception("MAINTENANCE TSDB retention cleanup failed")
		raise


async def cleanup_stale_sessions() -> None:
	"""Remove expired auth tokens from SQLite.
	
	Runs hourly to prevent auth_tokens table bloat.
	"""
	cfg = get_config()
	db_path = cfg.db_path
	
	if not Path(db_path).exists():
		_log.warning("MAINTENANCE SQLite database not found at %s", db_path)
		return
	
	try:
		async with aiosqlite.connect(db_path) as db:
			# Delete expired auth tokens
			cursor = await db.execute(
				"DELETE FROM auth_tokens WHERE expires_at < ?",
				(datetime.now(timezone.utc).isoformat(),),
			)
			await db.commit()
			
			deleted_count = cursor.rowcount
			if deleted_count > 0:
				_log.info("MAINTENANCE cleaned up %d expired auth tokens", deleted_count)
			else:
				_log.debug("MAINTENANCE no expired auth tokens to clean up")
	except Exception:
		_log.exception("MAINTENANCE auth token cleanup failed")
		raise
