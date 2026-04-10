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
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator
from starlette.concurrency import run_in_threadpool

from ..db.sqlite_runtime import close_connection, connect, transaction
from ..db.sqlite_settings import (
	SPEEDTEST_RETENTION_OPTIONS,
	get_speedtest_enabled,
	get_speedtest_retention_days,
	set_speedtest_enabled,
	set_speedtest_last_run_at,
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
SPEEDTEST_PROGRESS_QUEUE_SIZE = 32  # SSE progress event queue capacity

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


@router.get("/speedtest/settings")
async def get_speedtest_settings(
	_: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get speedtest configuration."""
	return ok_response(data={
		"enabled": get_speedtest_enabled(conn),
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
			# Read response data inside transaction to avoid TOCTOU
			result = {
				"enabled": get_speedtest_enabled(conn),
			}
	except ValueError as exc:
		raise HTTPException(status_code=422, detail=str(exc)) from None
	except (sqlite3.OperationalError, sqlite3.IntegrityError):
		_log.exception("SPEEDTEST_SETTINGS_UPDATE_FAILED")
		raise HTTPException(status_code=500, detail="Failed to persist speedtest settings") from None

	return ok_response(data=result)


def _wrap_result(result: dict | Any, stored: bool) -> dict:
	"""Wrap speedtest result with storage status.
	
	Args:
		result: Test result (dict or other type)
		stored: Whether result was persisted to TSDB
	
	Returns:
		Dict with result and stored flag
	"""
	if isinstance(result, dict):
		return {**result, "stored": stored}
	return {"result": result, "stored": stored}


async def _persist_last_run_to_db(db_path) -> None:
	"""Persist the latest completed local speedtest run in SQLite."""
	def _write() -> None:
		conn = connect(db_path)
		try:
			set_speedtest_last_run_at(conn)
		finally:
			close_connection(conn)

	await run_in_threadpool(_write)


@router.post("/speedtest/run")
async def trigger_speedtest(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
):
	"""Trigger an immediate speed test (admin only)."""
	from ..speedtest.tester import run_speedtest
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
		started_run = False
		try:
			try:
				started_run = True
				result = await asyncio.wait_for(run_speedtest(), timeout=SPEEDTEST_RUN_TIMEOUT_SECONDS)
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

			return ok_response(data=_wrap_result(result, stored))
		finally:
			if started_run:
				try:
					await _persist_last_run_to_db(cfg.db_path)
				except Exception as exc:
					_log.warning("SPEEDTEST_LAST_RUN_DB_WRITE_FAILED: %s", exc)


@router.get("/speedtest/run/stream")
async def trigger_speedtest_stream(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
):
	"""Trigger a speed test with real-time progress via Server-Sent Events.
	
	Returns a stream of SSE events with progress updates:
	- event: progress (phase updates)
	- event: result (final result)
	- event: error (on failure)
	
	Each progress event contains: phase, progress (0-1), message, detail (optional)
	"""
	from ..speedtest.tester import run_speedtest, ProgressEvent
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

	async def event_generator():
		"""Generate SSE events for speedtest progress."""
		async with lease:
			started_run = False
			# Bounded queue to prevent memory growth if callback produces events faster than consumption
			progress_queue: asyncio.Queue[ProgressEvent | None] = asyncio.Queue(maxsize=SPEEDTEST_PROGRESS_QUEUE_SIZE)
			loop = asyncio.get_running_loop()

			def _safe_put(event: ProgressEvent) -> None:
				"""Drop oldest event if queue full (preserves latest state)."""
				while True:
					try:
						progress_queue.put_nowait(event)
						return
					except asyncio.QueueFull:
						try:
							progress_queue.get_nowait()  # Make space
						except asyncio.QueueEmpty:
							return  # Give up if queue was emptied by consumer

			def progress_callback(event: ProgressEvent) -> None:
				"""Thread-safe callback to enqueue progress events."""
				try:
					loop.call_soon_threadsafe(_safe_put, event)
				except Exception:
					pass  # Scheduling failure (e.g., loop closed)

			async def run_test():
				try:
					nonlocal started_run
					started_run = True
					return await asyncio.wait_for(
						run_speedtest(progress_callback=progress_callback),
						timeout=SPEEDTEST_RUN_TIMEOUT_SECONDS,
					)
				except asyncio.TimeoutError:
					return {"status": "error", "reason": f"Timeout after {SPEEDTEST_RUN_TIMEOUT_SECONDS}s"}
				except Exception as exc:
					_log.error("SPEEDTEST_STREAM_FAILED: %s", exc)
					return {"status": "error", "reason": str(exc)}

			test_task = asyncio.create_task(run_test())
			try:
				while not test_task.done():
					# Check if client disconnected
					if await request.is_disconnected():
						_log.debug("Client disconnected during speedtest stream")
						test_task.cancel()
						break
					
					try:
						event = await asyncio.wait_for(progress_queue.get(), timeout=0.5)
						if event is not None:
							# Serialize progress event (handle dataclass/dict)
							event_data = event if isinstance(event, dict) else event.__dict__
							try:
								yield f"event: progress\ndata: {json.dumps(event_data)}\n\n"
							except RuntimeError:
								# Response already closed (race with disconnect)
								break
					except asyncio.TimeoutError:
						try:
							yield ": keepalive\n\n"
						except RuntimeError:
							break

				while not progress_queue.empty():
					try:
						event = progress_queue.get_nowait()
						if event is not None:
							event_data = event if isinstance(event, dict) else event.__dict__
							try:
								yield f"event: progress\ndata: {json.dumps(event_data)}\n\n"
							except RuntimeError:
								return  # Client disconnected
					except asyncio.QueueEmpty:
						break

				try:
					result = await test_task
				except asyncio.CancelledError:
					# Client disconnected mid-test → exit gracefully
					return

				# Only persist successful results to TSDB (avoid polluting history with error results)
				stored = False
				# Type guard: ensure result is a dict before accessing .get()
				if not isinstance(result, dict):
					_log.warning("SPEEDTEST_UNEXPECTED_RESULT_TYPE: %s", type(result))
					result = {"status": "error", "reason": "Invalid result type"}
				
				is_error = result.get("status") == "error"
				
				if not is_error:
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
				
				# Send final result to client
				result_wrapped = {"stored": stored, **result}
				try:
					yield f"event: result\ndata: {json.dumps(result_wrapped)}\n\n"
				except RuntimeError:
					# Response closed before final result sent
					return
			finally:
				if not test_task.done():
					test_task.cancel()
					try:
						await test_task
					except asyncio.CancelledError:
						pass
				if started_run:
					try:
						await _persist_last_run_to_db(cfg.db_path)
					except Exception as exc:
						_log.warning("SPEEDTEST_LAST_RUN_DB_WRITE_FAILED: %s", exc)

	return StreamingResponse(
		event_generator(),
		media_type="text/event-stream",
		headers={
			"Cache-Control": "no-cache",
			"Connection": "keep-alive",
			"Content-Type": "text/event-stream; charset=utf-8",
			"X-Accel-Buffering": "no",  # Disable nginx buffering
		},
	)


@router.get("/speedtest/history")
async def get_speedtest_history(
	request: Request,
	range_key: Optional[str] = Query(None, pattern="^(6h|24h|7d|30d|90d|180d|y1)$"),
	limit: int = Query(SPEEDTEST_HISTORY_DEFAULT_LIMIT, ge=1, le=SPEEDTEST_HISTORY_MAX_LIMIT),
	node_id: Optional[str] = Query(None, max_length=64, description="Filter by node ID (null=master only, 'all'=all remote nodes)"),
	_: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get speedtest history data for charting.
	
	Args:
		range_key: Time range preset (6h, 24h, 7d, 30d, 90d, 180d, y1)
		limit: Maximum number of points to return
		node_id: Filter results — null or empty = master only, 'all' = all remote nodes (master excluded), otherwise specific node
	
	Returns:
		List of speedtest results with timestamps
		Note: 'truncated' flag may be approximate when filtering by node_id due to fetch heuristics
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

	# Fetch more points when filtering to ensure we have enough after filter
	# Note: We adaptively increase fetch size because TSDB limit applies before
	# filtering by node_id. Without this, frequent node results can push master
	# results out of the initial window.
	MAX_FETCH_LIMIT = 10000
	fetch_limit = min(limit + 1, MAX_FETCH_LIMIT)
	points = []
	filtered_points = []
	
	def _matches_node_filter(pt_node_id: Any) -> bool:
		if node_id is None or node_id == "":
			# Master only (no node_id in record)
			return pt_node_id is None
		if node_id.lower() == "all":
			# All remote nodes — explicitly exclude master
			return pt_node_id is not None
		# Specific node
		return pt_node_id == node_id

	while True:
		points = await run_in_threadpool(
			tsdb.query,
			cfg.tsdb_dir,
			peer_key=SPEEDTEST_TSDB_KEY,
			metric=SPEEDTEST_TSDB_METRIC,
			since=since,
			limit=fetch_limit,
		)

		filtered_points = []
		for pt in points:
			if not isinstance(pt.value, dict):
				continue
			pt_node_id = pt.value.get("node_id")  # None = master
			if _matches_node_filter(pt_node_id):
				filtered_points.append(pt)

		# Stop if we already have enough filtered points, reached max fetch size,
		# or TSDB returned fewer points than requested (no more data available).
		if len(filtered_points) > limit or fetch_limit >= MAX_FETCH_LIMIT or len(points) < fetch_limit:
			break

		fetch_limit = min(fetch_limit * 2, MAX_FETCH_LIMIT)
	
	# Truncate to actual limit and detect if more data exists
	truncated = len(filtered_points) > limit
	if truncated:
		filtered_points = filtered_points[:limit]

	history = []
	for pt in filtered_points:
		# Shallow copy to avoid mutating original MetricPoint.value
		entry = dict(pt.value) if isinstance(pt.value, dict) else {}
		entry["ts"] = pt.ts.isoformat()
		history.append(entry)

	return ok_response(data={
		"history": history,
		"limit": limit,
		"truncated": truncated,
	})


@router.get("/speedtest/nodes")
async def get_speedtest_nodes(
	request: Request,
	_: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get list of nodes with their most recent speedtest result.
	
	Returns:
		- List of nodes with their last speedtest metrics for the filter dropdown and badges
	"""
	from ..db import tsdb
	from ..db.sqlite_nodes import get_all_nodes
	
	cfg = get_config(request)
	
	# Get all nodes from DB
	nodes = await run_in_threadpool(get_all_nodes, conn)
	
	# Get recent speedtest history (last 90 days should be enough to find each node's latest)
	since = datetime.now(timezone.utc) - timedelta(days=90)
	points = await run_in_threadpool(
		tsdb.query,
		cfg.tsdb_dir,
		peer_key=SPEEDTEST_TSDB_KEY,
		metric=SPEEDTEST_TSDB_METRIC,
		since=since,
		limit=2000,  # Should be enough to cover all nodes
	)
	
	# Build a map of node_id -> latest speedtest
	# Always overwrite to keep the last (newest) result, not the first (oldest)
	latest_by_node: dict[str | None, dict] = {}  # None = master
	for pt in points:
		if not isinstance(pt.value, dict):
			continue
		node_id = pt.value.get("node_id")  # None = master
		latest_by_node[node_id] = {
			"ts": pt.ts.isoformat(),
			**pt.value,
		}
	
	# Build result list, starting with master
	result = []
	
	# Master entry
	master_last = latest_by_node.get(None)
	result.append({
		"node_id": None,
		"name": "Master",
		"status": "online",
		"last_speedtest": master_last,
	})
	
	# Node entries
	for n in nodes:
		node_id = n["id"]
		node_last = latest_by_node.get(node_id)
		result.append({
			"node_id": node_id,
			"name": n["name"],
			"status": n["status"],
			"last_speedtest": node_last,
		})
	
	return ok_response(data={"nodes": result})


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

	# Use async context manager for consistent lease handling
	async with lease:
		try:
			deleted_bytes = await run_in_threadpool(
				tsdb.purge_synthetic_data, cfg.tsdb_dir, SPEEDTEST_TSDB_KEY, force=True
			)
		except OSError as exc:
			_log.warning("Failed to delete speedtest data: %s", exc)
			raise HTTPException(status_code=500, detail="Failed to delete speedtest data") from None

	return ok_response(message=f"Speedtest data deleted ({deleted_bytes} bytes)")
