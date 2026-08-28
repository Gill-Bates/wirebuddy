#!/usr/bin/env python3
#
# app/tasks/maintenance.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Periodic maintenance tasks for database health and cleanup."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiosqlite

from ..utils.config import get_config

_log = logging.getLogger(__name__)

__all__ = [
    "sqlite_maintenance",
    "sqlite_integrity_check",
    "tsdb_retention_cleanup",
    "cleanup_stale_sessions",
    "cleanup_login_attempts",
    "cleanup_acked_node_commands",
]

# SQLite busy timeout in seconds
_SQLITE_BUSY_TIMEOUT_SECONDS = 10.0

def _ensure_db_exists(label: str) -> str | None:
    """Return the db_path if the database exists, else log a warning."""
    cfg = get_config()
    db_path = str(cfg.db_path)
    if not Path(db_path).exists():
        _log.warning("MAINTENANCE %s: SQLite database not found at %s", label, db_path)
        return None
    return db_path

async def sqlite_maintenance() -> None:
    """Periodic SQLite maintenance: WAL checkpoint, analyze, optimize."""
    db_path = _ensure_db_exists("maintenance")
    if db_path is None:
        return
    
    try:
        async with aiosqlite.connect(db_path, timeout=_SQLITE_BUSY_TIMEOUT_SECONDS) as db:
            # WAL checkpoint: RESTART mode is less aggressive than TRUNCATE.
            # It allows concurrent readers to continue from the old WAL file.
            checkpoint_cursor = await db.execute("PRAGMA wal_checkpoint(RESTART)")
            try:
                checkpoint = await checkpoint_cursor.fetchone()
            finally:
                await checkpoint_cursor.close()

            if checkpoint is not None:
                busy, log_frames, checkpointed_frames = checkpoint
                if busy:
                    _log.warning(
                        "MAINTENANCE SQLite checkpoint incomplete busy=%s log_frames=%s checkpointed_frames=%s",
                        busy,
                        log_frames,
                        checkpointed_frames,
                    )

            await db.execute("ANALYZE")
            await db.execute("PRAGMA optimize")
            await db.commit()
            
            _log.info("MAINTENANCE SQLite maintenance completed (RESTART checkpoint)")
    except Exception:
        _log.exception("MAINTENANCE SQLite maintenance failed")
        raise

async def sqlite_integrity_check() -> None:
    """Weekly integrity check."""
    db_path = _ensure_db_exists("integrity_check")
    if db_path is None:
        return
    
    try:
        async with aiosqlite.connect(db_path, timeout=_SQLITE_BUSY_TIMEOUT_SECONDS) as db:
            cursor = await db.execute("PRAGMA integrity_check")
            try:
                result = await cursor.fetchone()
            finally:
                await cursor.close()
            
            if result and result[0] == "ok":
                _log.info("MAINTENANCE SQLite integrity check passed")
            else:
                failure_msg = result[0] if result else "unknown error"
                _log.critical("MAINTENANCE SQLite integrity check FAILED: %s", failure_msg)
                raise RuntimeError(f"SQLite integrity check failed: {failure_msg}")
    except Exception:
        _log.exception("MAINTENANCE SQLite integrity check error")
        raise

async def tsdb_retention_cleanup() -> None:
    """Purge expired time-series data using unified TSDB maintenance logic.
    
    Consolidates cleanup by delegating to tsdb.run_maintenance, which handles
    both file rotation and retention pruning correctly with locks.
    """
    from ..db import tsdb
    from ..db.sqlite_settings import get_tsdb_retention_days, DEFAULT_TSDB_RETENTION_DAYS
    from ..db.sqlite_runtime import connect, close_connection
    
    cfg = get_config()
    tsdb_dir = Path(cfg.tsdb_dir)
    
    if not await asyncio.to_thread(tsdb_dir.exists):
        return
    
    try:
        def _read_retention() -> int:
            conn = connect(cfg.db_path)
            try:
                return get_tsdb_retention_days(conn)
            except Exception:
                return DEFAULT_TSDB_RETENTION_DAYS
            finally:
                close_connection(conn)

        retention_days = await asyncio.to_thread(_read_retention)
        
        # Delegate to unified maintenance logic
        stats = await asyncio.to_thread(tsdb.run_maintenance, tsdb_dir, retention_days)
        
        if stats.get("pruned", 0) > 0:
            _log.info(
                "MAINTENANCE TSDB retention cleanup: pruned %d series (total series: %d)",
                stats["pruned"], stats["series"]
            )
        else:
            _log.debug("MAINTENANCE TSDB retention cleanup: no expired data")
    except Exception:
        _log.exception("MAINTENANCE TSDB retention cleanup failed")
        raise

async def cleanup_stale_sessions() -> None:
    """Remove expired auth tokens from SQLite."""
    db_path = _ensure_db_exists("session_cleanup")
    if db_path is None:
        return
    
    try:
        async with aiosqlite.connect(db_path, timeout=_SQLITE_BUSY_TIMEOUT_SECONDS) as db:
            now_iso = datetime.now(UTC).isoformat()
            cursor = await db.execute("DELETE FROM auth_tokens WHERE expires_at < ?", (now_iso,))
            try:
                deleted = cursor.rowcount
            finally:
                await cursor.close()
            await db.commit()

            if deleted > 0:
                _log.info("MAINTENANCE cleaned up %d expired auth tokens", deleted)
    except Exception:
        _log.exception("MAINTENANCE auth token cleanup failed")
        raise

async def cleanup_login_attempts() -> None:
    """Remove stale login-attempt lockout rows from SQLite.

    Distributed or rotating-IP login attempts each get their own row (see
    sqlite_auth._build_attempt_keys); a row is only cleared on a successful
    login for that exact key, so failed attempts against IPs/usernames that
    never succeed would otherwise accumulate forever. Batched deletes avoid
    holding a long write lock on a large backlog. Two days safely exceeds
    every lockout policy's max window (longest is 24h).
    """
    db_path = _ensure_db_exists("login_attempts_cleanup")
    if db_path is None:
        return

    cutoff_iso = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    try:
        async with aiosqlite.connect(db_path, timeout=_SQLITE_BUSY_TIMEOUT_SECONDS) as db:
            total_deleted = 0
            while True:
                cursor = await db.execute(
                    """
                    DELETE FROM login_attempts
                    WHERE id IN (
                        SELECT id FROM login_attempts
                        WHERE last_attempt_at < ?
                        LIMIT 1000
                    )
                    """,
                    (cutoff_iso,),
                )
                try:
                    deleted = cursor.rowcount
                finally:
                    await cursor.close()
                await db.commit()
                total_deleted += deleted
                if deleted < 1000:
                    break

            if total_deleted > 0:
                _log.info("MAINTENANCE cleaned up %d stale login-attempt rows", total_deleted)
    except Exception:
        _log.exception("MAINTENANCE login attempt cleanup failed")
        raise

async def cleanup_acked_node_commands() -> None:
    """Remove old acknowledged rows from the durable node_commands queue.

    Every config/restart/speedtest/removed command sent to any node is kept
    until explicitly pruned; nothing else ever deletes acked rows.
    """
    db_path = _ensure_db_exists("node_commands_cleanup")
    if db_path is None:
        return

    cutoff_iso = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    try:
        async with aiosqlite.connect(db_path, timeout=_SQLITE_BUSY_TIMEOUT_SECONDS) as db:
            total_deleted = 0
            while True:
                cursor = await db.execute(
                    """
                    DELETE FROM node_commands
                    WHERE id IN (
                        SELECT id FROM node_commands
                        WHERE acked_at IS NOT NULL AND acked_at < ?
                        LIMIT 1000
                    )
                    """,
                    (cutoff_iso,),
                )
                try:
                    deleted = cursor.rowcount
                finally:
                    await cursor.close()
                await db.commit()
                total_deleted += deleted
                if deleted < 1000:
                    break

            if total_deleted > 0:
                _log.info("MAINTENANCE cleaned up %d acknowledged node commands", total_deleted)
    except Exception:
        _log.exception("MAINTENANCE node command cleanup failed")
        raise
