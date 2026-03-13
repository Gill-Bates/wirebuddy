#!/usr/bin/env python3
#
# app/api/speedtest.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Speedtest settings and trigger endpoints."""

from __future__ import annotations

import asyncio
import gzip
import logging
import os
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from starlette.concurrency import run_in_threadpool

from ..db.sqlite_runtime import transaction
from ..db.sqlite_settings import (
	SPEEDTEST_SERVER_LIST,
	SPEEDTEST_SERVER_MAP,
	SPEEDTEST_RETENTION_OPTIONS,
	get_speedtest_downstream_mbit,
	get_speedtest_enabled,
	get_speedtest_target,
	get_speedtest_upstream_mbit,
	get_speedtest_retention_days,
	set_speedtest_downstream_mbit,
	set_speedtest_enabled,
	set_speedtest_target,
	set_speedtest_upstream_mbit,
	set_speedtest_retention_days,
)
from ..utils.deps import get_conn, get_config
from .auth import get_current_user, require_admin
from .response import ok_response

_log = logging.getLogger(__name__)

router = APIRouter(tags=["speedtest"])

# TSDB synthetic key for speedtest results
SPEEDTEST_TSDB_KEY = "__speedtest__"
SPEEDTEST_TSDB_METRIC = "speedtest_result"

# Time range mapping for history queries
SPEEDTEST_RANGE_TO_HOURS = {
	"6h": 6,
	"24h": 24,
	"7d": 7 * 24,
	"30d": 30 * 24,
	"90d": 90 * 24,
	"180d": 180 * 24,
	"y1": 365 * 24,
}

# Concurrency guard to prevent multiple simultaneous speedtests
_speedtest_lock = asyncio.Lock()


class SpeedtestSettingsPayload(BaseModel):
	"""Payload for updating speedtest settings."""
	enabled: Optional[bool] = None
	target: Optional[str] = Field(None, max_length=64)
	upstream_mbit: Optional[float] = Field(None, ge=0, le=100_000)
	downstream_mbit: Optional[float] = Field(None, ge=0, le=100_000)

	@field_validator("target")
	@classmethod
	def validate_target(cls, v: Optional[str]) -> Optional[str]:
		if v is None:
			return v
		v = v.strip().lower()
		if v != "auto" and v not in SPEEDTEST_SERVER_MAP:
			raise ValueError(f"Unknown target: {v}. Must be 'auto' or one of: {', '.join(SPEEDTEST_SERVER_MAP)}")
		return v


@router.get("/speedtest/settings")
async def get_speedtest_settings(
	_: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get speedtest configuration."""
	return ok_response(data={
		"enabled": get_speedtest_enabled(conn),
		"target": get_speedtest_target(conn),
		"upstream_mbit": get_speedtest_upstream_mbit(conn),
		"downstream_mbit": get_speedtest_downstream_mbit(conn),
		"servers": SPEEDTEST_SERVER_LIST,
	})


@router.patch("/speedtest/settings")
async def update_speedtest_settings(
	payload: SpeedtestSettingsPayload,
	_: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Update speedtest settings (admin only)."""
	try:
		with transaction(conn, immediate=True):
			if payload.enabled is not None:
				set_speedtest_enabled(conn, payload.enabled)
			if payload.target is not None:
				set_speedtest_target(conn, payload.target)
			if payload.upstream_mbit is not None:
				set_speedtest_upstream_mbit(conn, payload.upstream_mbit)
			if payload.downstream_mbit is not None:
				set_speedtest_downstream_mbit(conn, payload.downstream_mbit)
			# Read response data inside transaction to avoid TOCTOU
			result = {
				"enabled": get_speedtest_enabled(conn),
				"target": get_speedtest_target(conn),
				"upstream_mbit": get_speedtest_upstream_mbit(conn),
				"downstream_mbit": get_speedtest_downstream_mbit(conn),
			}
	except ValueError as exc:
		raise HTTPException(status_code=422, detail=str(exc))
	except Exception:
		_log.exception("SPEEDTEST_SETTINGS_UPDATE_FAILED")
		raise HTTPException(status_code=500, detail="Failed to persist speedtest settings")

	return ok_response(data=result)


@router.post("/speedtest/run")
async def trigger_speedtest(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Trigger an immediate speed test (admin only)."""
	# Lazy import to avoid circular dependency with speedtest.tester
	from ..speedtest.tester import BandwidthTester
	from ..db import tsdb

	# Concurrency guard: prevent multiple simultaneous tests (network saturation risk)
	if _speedtest_lock.locked():
		raise HTTPException(status_code=409, detail="Speed test already in progress")

	async with _speedtest_lock:
		cfg = get_config(request)

		# Note: We don't check get_speedtest_enabled() here because that setting
		# controls the *scheduler* only. Manual admin-triggered tests should always work.

		# Build server list based on target setting
		target = get_speedtest_target(conn)
		if target == "auto":
			servers = None  # Use defaults (RTT-based selection)
		else:
			server_info = SPEEDTEST_SERVER_MAP.get(target)
			if not server_info:
				raise HTTPException(status_code=422, detail=f"Unknown target: {target}")
			servers = [server_info["url"]]

		tester = BandwidthTester(servers=servers)

		try:
			# Timeout guard: prevent hanging on unresponsive servers
			result = await asyncio.wait_for(tester.run(), timeout=120)
		except asyncio.TimeoutError:
			_log.error("SPEEDTEST_TIMEOUT: test exceeded 120s")
			raise HTTPException(status_code=504, detail="Speed test timed out")
		except Exception as exc:
			_log.error("SPEEDTEST_RUN_FAILED: %s", exc)
			raise HTTPException(status_code=500, detail="Speed test failed")

		# Store result in TSDB (offload blocking I/O to threadpool)
		stored = True
		try:
			await run_in_threadpool(
				tsdb.append_point,
				cfg.tsdb_dir,
				peer_key=SPEEDTEST_TSDB_KEY,
				metric=SPEEDTEST_TSDB_METRIC,
				value=result,
			)
		except Exception as exc:
			_log.warning("SPEEDTEST_TSDB_WRITE_FAILED: %s", exc)
			stored = False

		# Flag TSDB write failures in response (robust: handle non-dict results)
		if isinstance(result, dict):
			result["stored"] = stored
		else:
			result = {"result": result, "stored": stored}
		return ok_response(data=result)


@router.get("/speedtest/history")
async def get_speedtest_history(
	request: Request,
	range_key: str | None = Query(None, pattern="^(6h|24h|7d|30d|90d|180d|y1)$"),
	_: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get recent speed test results from TSDB.
	
	Args:
		range_key: Optional time range filter (6h, 24h, 7d, 30d, 90d, 180d, y1).
		          If not provided, uses configured retention_days.
	"""
	# Lazy import to avoid circular dependency
	from ..db import tsdb

	cfg = get_config(request)

	# Use range_key if provided, otherwise fall back to retention_days
	if range_key:
		hours = SPEEDTEST_RANGE_TO_HOURS[range_key]
		since = datetime.now(timezone.utc) - timedelta(hours=hours)
	else:
		retention_days = get_speedtest_retention_days(conn)
		since = datetime.now(timezone.utc) - timedelta(days=retention_days)

	# Offload blocking I/O (file reads, parsing) to threadpool
	points = await run_in_threadpool(
		tsdb.query,
		cfg.tsdb_dir,
		peer_key=SPEEDTEST_TSDB_KEY,
		metric=SPEEDTEST_TSDB_METRIC,
		since=since,
		limit=500,
	)

	history = []
	for pt in points:
		# Shallow copy to avoid mutating original MetricPoint.value
		entry = dict(pt.value) if isinstance(pt.value, dict) else {}
		entry["ts"] = pt.ts.isoformat()
		history.append(entry)

	# Also return the configured min/max (provider values)
	return ok_response(data={
		"history": history,
		"upstream_mbit": get_speedtest_upstream_mbit(conn),
		"downstream_mbit": get_speedtest_downstream_mbit(conn),
	})


class SpeedtestRetentionPayload(BaseModel):
	"""Payload for updating speedtest retention settings."""
	retention_days: int

	@field_validator("retention_days")
	@classmethod
	def validate_retention_days(cls, v: int) -> int:
		if v not in SPEEDTEST_RETENTION_OPTIONS:
			raise ValueError(f"Invalid retention_days. Allowed: {list(SPEEDTEST_RETENTION_OPTIONS)}")
		return v


@router.get("/speedtest/storage")
async def get_speedtest_storage_stats(
	request: Request,
	_: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get speedtest storage statistics."""
	cfg = get_config(request)
	tsdb_dir = Path(cfg.tsdb_dir)
	# TSDB stores synthetic keys as tsdb_dir / "speedtest" / "*.jsonl"
	speedtest_dir = tsdb_dir / "speedtest"

	# Offload blocking I/O (stat, glob, file reads) to threadpool
	def _compute_stats():
		size_bytes = 0
		file_count = 0
		record_count = 0

		if speedtest_dir.exists():
			# Count active JSONL files
			for f in speedtest_dir.glob("*.jsonl"):
				try:
					st = f.stat()
					size_bytes += st.st_size
					file_count += 1
					# Count lines (records) in JSONL file
					with open(f, "rb") as fp:
						record_count += sum(1 for _ in fp)
				except OSError:
					pass

			# Count compressed archives (include records)
			for f in speedtest_dir.glob("*.jsonl.*.gz"):
				try:
					st = f.stat()
					size_bytes += st.st_size
					file_count += 1
					# Count lines in compressed file
					with gzip.open(f, "rb") as fp:
						record_count += sum(1 for _ in fp)
				except OSError:
					pass

		return size_bytes, file_count, record_count

	size_bytes, file_count, record_count = await run_in_threadpool(_compute_stats)

	return ok_response(data={
		"path": str(speedtest_dir),
		"size_bytes": size_bytes,
		"file_count": file_count,
		"record_count": record_count,
		"retention_days": get_speedtest_retention_days(conn),
		"retention_options": list(SPEEDTEST_RETENTION_OPTIONS),
	})


@router.patch("/speedtest/storage/retention")
async def update_speedtest_retention(
	payload: SpeedtestRetentionPayload,
	_: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Update speedtest data retention period (admin only)."""
	days = payload.retention_days
	# Wrap in transaction for consistency
	with transaction(conn, immediate=True):
		set_speedtest_retention_days(conn, days)
		result_days = get_speedtest_retention_days(conn)
	return ok_response(data={
		"retention_days": result_days,
	})


@router.delete("/speedtest/storage")
async def purge_speedtest_data(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
):
	"""Delete all speedtest data (admin only)."""
	cfg = get_config(request)
	tsdb_dir = Path(cfg.tsdb_dir)
	# TSDB stores synthetic keys as tsdb_dir / "speedtest" / "*.jsonl"
	speedtest_dir = tsdb_dir / "speedtest"

	# Offload blocking I/O (stat, rmtree) to threadpool
	def _purge():
		deleted_bytes = 0
		if speedtest_dir.exists():
			# Calculate size before deletion
			for f in speedtest_dir.iterdir():
				try:
					deleted_bytes += f.stat().st_size
				except OSError:
					pass
			# Delete entire directory
			shutil.rmtree(speedtest_dir)  # Let OSError propagate
		return deleted_bytes

	try:
		deleted_bytes = await run_in_threadpool(_purge)
	except OSError as e:
		_log.warning("Failed to delete speedtest data: %s", e)
		raise HTTPException(status_code=500, detail="Failed to delete speedtest data")

	return ok_response(message=f"Speedtest data deleted ({deleted_bytes} bytes)")
