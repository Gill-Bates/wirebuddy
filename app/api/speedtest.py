#!/usr/bin/env python3
#
# app/api/speedtest.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Speedtest settings and trigger endpoints."""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from starlette.concurrency import run_in_threadpool

from ..db.sqlite_runtime import transaction
from ..db.sqlite_settings import (
	SPEEDTEST_SERVER_LIST,
	SPEEDTEST_SERVER_MAP,
	SPEEDTEST_RETENTION_OPTIONS,
	get_speedtest_enabled,
	get_speedtest_target,
	get_speedtest_retention_days,
	set_speedtest_enabled,
	set_speedtest_target,
	set_speedtest_retention_days,
)
from ..speedtest import (
	DEFAULT_SPEEDTEST_COOLDOWN_SECONDS,
	SpeedtestBusyError,
	SpeedtestCooldownError,
	acquire_speedtest_run_lease,
)
from ..utils.deps import get_conn, get_config
from .auth import get_current_user, require_admin
from .response import ok_response

_log = logging.getLogger(__name__)

router = APIRouter(tags=["speedtest"])

# TSDB synthetic key for speedtest results
SPEEDTEST_TSDB_KEY = "__speedtest__"
SPEEDTEST_TSDB_METRIC = "speedtest_result"
SPEEDTEST_RUN_TIMEOUT_SECONDS = 120
SPEEDTEST_HISTORY_DEFAULT_LIMIT = 500
SPEEDTEST_HISTORY_MAX_LIMIT = 5000

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

class SpeedtestSettingsPayload(BaseModel):
	"""Payload for updating speedtest settings."""
	enabled: Optional[bool] = None
	target: Optional[str] = Field(None, max_length=64)

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
			# Read response data inside transaction to avoid TOCTOU
			result = {
				"enabled": get_speedtest_enabled(conn),
				"target": get_speedtest_target(conn),
			}
	except ValueError as exc:
		raise HTTPException(status_code=422, detail=str(exc)) from None
	except (sqlite3.OperationalError, sqlite3.IntegrityError):
		_log.exception("SPEEDTEST_SETTINGS_UPDATE_FAILED")
		raise HTTPException(status_code=500, detail="Failed to persist speedtest settings") from None

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

	cfg = get_config(request)
	try:
		lease = acquire_speedtest_run_lease(
			cfg.tsdb_dir,
			cooldown_seconds=DEFAULT_SPEEDTEST_COOLDOWN_SECONDS,
		)
	except SpeedtestBusyError:
		raise HTTPException(status_code=409, detail="Speed test already in progress") from None
	except SpeedtestCooldownError as exc:
		raise HTTPException(status_code=429, detail=str(exc)) from None

	async with lease:
		# Note: We don't check get_speedtest_enabled() here because that setting
		# controls the *scheduler* only. Manual admin-triggered tests should always work.

		target = get_speedtest_target(conn)
		if target == "auto":
			servers = None  # Use defaults (RTT-based selection)
		else:
			server_info = SPEEDTEST_SERVER_MAP.get(target)
			if not server_info:
				raise HTTPException(status_code=422, detail=f"Unknown target: {target}") from None
			servers = [server_info["url"]]

		tester = BandwidthTester(servers=servers)

		try:
			result = await asyncio.wait_for(tester.run(), timeout=SPEEDTEST_RUN_TIMEOUT_SECONDS)
		except asyncio.TimeoutError:
			_log.error("SPEEDTEST_TIMEOUT: test exceeded %ss", SPEEDTEST_RUN_TIMEOUT_SECONDS)
			raise HTTPException(status_code=504, detail="Speed test timed out") from None
		except Exception:
			_log.exception("SPEEDTEST_RUN_FAILED")
			raise HTTPException(status_code=500, detail="Speed test failed") from None

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

		if isinstance(result, dict):
			result["stored"] = stored
		else:
			result = {"result": result, "stored": stored}
		return ok_response(data=result)


@router.get("/speedtest/run/stream")
async def trigger_speedtest_stream(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Trigger a speed test with real-time progress via Server-Sent Events.
	
	Returns a stream of SSE events with progress updates:
	- event: progress (phase updates)
	- event: result (final result)
	- event: error (on failure)
	
	Each progress event contains: phase, progress (0-1), message, detail (optional)
	"""
	from ..speedtest.tester import BandwidthTester, ProgressEvent
	from ..db import tsdb

	cfg = get_config(request)
	try:
		lease = acquire_speedtest_run_lease(
			cfg.tsdb_dir,
			cooldown_seconds=DEFAULT_SPEEDTEST_COOLDOWN_SECONDS,
		)
	except SpeedtestBusyError:
		raise HTTPException(status_code=409, detail="Speed test already in progress") from None
	except SpeedtestCooldownError as exc:
		raise HTTPException(status_code=429, detail=str(exc)) from None

	# Build server list
	target = get_speedtest_target(conn)
	if target == "auto":
		servers = None
	else:
		server_info = SPEEDTEST_SERVER_MAP.get(target)
		if not server_info:
			raise HTTPException(status_code=422, detail=f"Unknown target: {target}")
		servers = [server_info["url"]]

	async def event_generator():
		"""Generate SSE events for speedtest progress."""
		async with lease:
			progress_queue: asyncio.Queue[ProgressEvent | None] = asyncio.Queue()

			def progress_callback(event: ProgressEvent) -> None:
				"""Thread-safe callback to enqueue progress events."""
				try:
					progress_queue.put_nowait(event)
				except asyncio.QueueFull:
					pass  # Drop event if queue is full (shouldn't happen)

			tester = BandwidthTester(servers=servers, progress_callback=progress_callback)

			async def run_test():
				try:
					return await asyncio.wait_for(tester.run(), timeout=SPEEDTEST_RUN_TIMEOUT_SECONDS)
				except asyncio.TimeoutError:
					return {"status": "error", "reason": f"Timeout after {SPEEDTEST_RUN_TIMEOUT_SECONDS}s"}
				except Exception as exc:
					_log.error("SPEEDTEST_STREAM_FAILED: %s", exc)
					return {"status": "error", "reason": str(exc)}

			test_task = asyncio.create_task(run_test())
			try:
				while not test_task.done():
					try:
						event = await asyncio.wait_for(progress_queue.get(), timeout=0.5)
						if event is not None:
							yield f"event: progress\ndata: {json.dumps(event)}\n\n"
					except asyncio.TimeoutError:
						yield ": keepalive\n\n"

				while not progress_queue.empty():
					try:
						event = progress_queue.get_nowait()
						if event is not None:
							yield f"event: progress\ndata: {json.dumps(event)}\n\n"
					except asyncio.QueueEmpty:
						break

				result = await test_task

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

				if isinstance(result, dict):
					result["stored"] = stored

				if result.get("status") == "error":
					yield f"event: error\ndata: {json.dumps(result)}\n\n"
				else:
					yield f"event: result\ndata: {json.dumps(result)}\n\n"
			finally:
				if not test_task.done():
					test_task.cancel()
					try:
						await test_task
					except asyncio.CancelledError:
						pass

	return StreamingResponse(
		event_generator(),
		media_type="text/event-stream",
		headers={
			"Cache-Control": "no-cache",
			"Connection": "keep-alive",
			"X-Accel-Buffering": "no",  # Disable nginx buffering
		},
	)


@router.get("/speedtest/history")
async def get_speedtest_history(
	request: Request,
	range_key: Optional[str] = Query(None, pattern="^(6h|24h|7d|30d|90d|180d|y1)$"),
	limit: int = Query(SPEEDTEST_HISTORY_DEFAULT_LIMIT, ge=1, le=SPEEDTEST_HISTORY_MAX_LIMIT),
	_: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get speedtest history data for charting.
	
	Args:
		range_key: Time range preset (6h, 24h, 7d, 30d, 90d, 180d, y1)
		limit: Maximum number of points to return
	
	Returns:
		List of speedtest results with timestamps
	"""
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
		limit=limit,
	)

	history = []
	for pt in points:
		# Shallow copy to avoid mutating original MetricPoint.value
		entry = dict(pt.value) if isinstance(pt.value, dict) else {}
		entry["ts"] = pt.ts.isoformat()
		history.append(entry)

	return ok_response(data={
		"history": history,
		"limit": limit,
		"truncated": len(points) == limit,
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
	from ..db import tsdb

	cfg = get_config(request)
	stats = await run_in_threadpool(tsdb.get_synthetic_storage_stats, cfg.tsdb_dir, SPEEDTEST_TSDB_KEY)

	return ok_response(data={
		**stats,
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
	from ..db import tsdb

	cfg = get_config(request)
	try:
		lease = acquire_speedtest_run_lease(
			cfg.tsdb_dir,
			cooldown_seconds=0.0,
			update_cooldown=False,
		)
	except SpeedtestBusyError:
		raise HTTPException(status_code=409, detail="Speed test already in progress") from None

	try:
		deleted_bytes = await run_in_threadpool(tsdb.purge_synthetic_data, cfg.tsdb_dir, SPEEDTEST_TSDB_KEY)
	except OSError as exc:
		_log.warning("Failed to delete speedtest data: %s", exc)
		raise HTTPException(status_code=500, detail="Failed to delete speedtest data") from None
	finally:
		lease.release()

	return ok_response(message=f"Speedtest data deleted ({deleted_bytes} bytes)")
