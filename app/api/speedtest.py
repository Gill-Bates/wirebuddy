#!/usr/bin/env python3
#
# app/api/speedtest.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Speedtest settings and trigger endpoints."""

import asyncio
import logging
import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator
from starlette.concurrency import run_in_threadpool

from ..db import tsdb
from ..db.sqlite_nodes import get_all_nodes
from ..db.sqlite_runtime import close_connection, connect, transaction
from ..db.sqlite_settings import (
	SPEEDTEST_RETENTION_OPTIONS,
	get_speedtest_enabled,
	get_speedtest_last_result,
	get_node_speedtest_last_results,
	get_speedtest_retention_days,
	set_speedtest_enabled,
	set_speedtest_last_result,
	set_speedtest_last_run_at,
	set_speedtest_retention_days,
)
from ..speedtest import (
	DEFAULT_SPEEDTEST_COOLDOWN_SECONDS,
	SpeedtestBusyError,
	SpeedtestCooldownError,
	acquire_speedtest_run_lease,
)
from ..utils.config import Config
from ..utils.deps import get_conn, get_config
from ..utils.rate_limit import RATE_LIMIT_CRITICAL, RATE_LIMIT_HEAVY, limiter
from ..utils.time import utcnow
from ..utils.tsdb_helpers import build_latest_by_node
from ..speedtest.tester import ProgressCallback, ProgressEvent, run_speedtest
from .auth import get_current_user, require_admin
from .response import ok_response
from .sse import stream_with_progress

_log = logging.getLogger(__name__)

router = APIRouter(tags=["speedtest"])

# TSDB synthetic key for speedtest results
SPEEDTEST_TSDB_KEY = "__speedtest__"
SPEEDTEST_TSDB_METRIC = "speedtest_result"
SPEEDTEST_RUN_TIMEOUT_SECONDS = 120
SPEEDTEST_HISTORY_DEFAULT_LIMIT = 500
SPEEDTEST_HISTORY_MAX_LIMIT = 5000
SPEEDTEST_TSDB_FETCH_CAP = 10_000
SPEEDTEST_PROGRESS_QUEUE_SIZE = 32  # SSE progress event queue capacity
SPEEDTEST_SQLITE_TIMEOUT_SECONDS = 5.0
SPEEDTEST_TSDB_TIMEOUT_SECONDS = 10.0

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
	enabled: bool | None = None


async def _run_in_threadpool_with_timeout(
	timeout_seconds: float,
	func: Any,
	*args: Any,
	**kwargs: Any,
) -> Any:
	"""Run blocking work in the threadpool with a bounded deadline."""
	async with asyncio.timeout(timeout_seconds):
		return await run_in_threadpool(func, *args, **kwargs)


def _update_speedtest_settings_sync(
	conn: sqlite3.Connection,
	enabled: bool | None,
) -> dict[str, bool]:
	"""Persist speedtest settings using the request-scoped SQLite connection."""
	with transaction(conn, immediate=True):
		if enabled is not None:
			set_speedtest_enabled(conn, enabled)
		return {
			"enabled": get_speedtest_enabled(conn),
		}


def _persist_speedtest_state_sync(
	db_path: Path,
	result: dict[str, Any] | None,
) -> None:
	"""Persist the latest run timestamp and optional successful result in SQLite."""
	db_conn = connect(db_path)
	try:
		set_speedtest_last_run_at(db_conn)
		if result is not None:
			set_speedtest_last_result(db_conn, result)
	finally:
		close_connection(db_conn)


async def _persist_speedtest_state(
	db_path: Path,
	*,
	result: dict[str, Any] | None = None,
) -> None:
	"""Persist the latest run timestamp and optional successful result in SQLite."""
	try:
		await _run_in_threadpool_with_timeout(
			SPEEDTEST_SQLITE_TIMEOUT_SECONDS,
			_persist_speedtest_state_sync,
			db_path,
			result,
		)
	except TimeoutError:
		_log.warning("SPEEDTEST_STATE_PERSIST_TIMEOUT")
	except Exception as exc:
		_log.warning("SPEEDTEST_STATE_DB_WRITE_FAILED: %s", exc)


def _update_speedtest_retention_sync(conn: sqlite3.Connection, days: int) -> int:
	"""Persist the retention period using the request-scoped SQLite connection."""
	with transaction(conn, immediate=True):
		set_speedtest_retention_days(conn, days)
		return get_speedtest_retention_days(conn)


def _get_latest_speedtest_result_sync(
	tsdb_dir: Path,
	conn: sqlite3.Connection,
) -> dict[str, Any] | None:
	"""Return the latest recorded speedtest result from TSDB, falling back to SQLite."""
	try:
		points = tsdb.query_latest(
			tsdb_dir,
			peer_key=SPEEDTEST_TSDB_KEY,
			metric=SPEEDTEST_TSDB_METRIC,
			count=1,
		)
	except (OSError, ValueError) as exc:
		_log.warning("Failed to read latest speedtest result from TSDB: %s", exc)
		points = []

	if points:
		point = points[0]
		data = dict(point.value) if isinstance(point.value, dict) else {}
		data["ts"] = point.ts.isoformat()
		return data

	return get_speedtest_last_result(conn)


def _matches_node_filter(val: Any, node_id: str | None) -> bool:
	"""Return whether a speedtest TSDB value matches the requested node filter."""
	if not isinstance(val, dict):
		return False
	pt_node_id = val.get("node_id")
	if node_id is None or node_id == "":
		# Master only (no node_id in record)
		return pt_node_id is None
	if node_id.lower() == "all":
		# All remote nodes — explicitly exclude master
		return pt_node_id is not None
	# Specific node
	return pt_node_id == node_id


@router.get("/speedtest/settings")
async def get_speedtest_settings(
	request: Request,
	_: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get speedtest configuration."""
	cfg = get_config(request)
	try:
		last_result = await _run_in_threadpool_with_timeout(
			SPEEDTEST_SQLITE_TIMEOUT_SECONDS,
			_get_latest_speedtest_result_sync,
			cfg.tsdb_dir,
			conn,
		)
	except TimeoutError:
		_log.warning("SPEEDTEST_SETTINGS_READ_TIMEOUT")
		raise HTTPException(status_code=504, detail="Timed out reading speedtest settings") from None
	return ok_response(data={
		"enabled": get_speedtest_enabled(conn),
		"last_result": last_result,
	})


@router.patch("/speedtest/settings")
@limiter.limit(RATE_LIMIT_HEAVY)
async def update_speedtest_settings(
	request: Request,
	payload: SpeedtestSettingsPayload,
	_: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Update speedtest settings (admin only)."""
	_ = request
	try:
		result = await _run_in_threadpool_with_timeout(
			SPEEDTEST_SQLITE_TIMEOUT_SECONDS,
			_update_speedtest_settings_sync,
			conn,
			payload.enabled,
		)
	except TimeoutError:
		_log.warning("SPEEDTEST_SETTINGS_UPDATE_TIMEOUT")
		raise HTTPException(status_code=504, detail="Timed out updating speedtest settings") from None
	except ValueError as exc:
		raise HTTPException(status_code=422, detail=str(exc)) from None
	except (sqlite3.OperationalError, sqlite3.IntegrityError):
		_log.exception("SPEEDTEST_SETTINGS_UPDATE_FAILED")
		raise HTTPException(status_code=500, detail="Failed to persist speedtest settings") from None

	return ok_response(data=result)


async def _acquire_speedtest_lease(
	tsdb_dir: Path,
	*,
	cooldown_seconds: float = DEFAULT_SPEEDTEST_COOLDOWN_SECONDS,
	update_cooldown: bool = True,
):
	"""Acquire the shared speedtest lease or raise the corresponding HTTP error."""
	try:
		return acquire_speedtest_run_lease(
			tsdb_dir,
			cooldown_seconds=cooldown_seconds,
			update_cooldown=update_cooldown,
		)
	except SpeedtestBusyError:
		raise HTTPException(status_code=409, detail="Speed test already in progress") from None
	except SpeedtestCooldownError as exc:
		raise HTTPException(status_code=429, detail=str(exc)) from None


async def _store_speedtest_result(tsdb_dir: Path, result: dict[str, Any]) -> bool:
	"""Persist a successful speedtest result to TSDB."""
	try:
		await _run_in_threadpool_with_timeout(
			SPEEDTEST_TSDB_TIMEOUT_SECONDS,
			tsdb.append_point,
			tsdb_dir,
			peer_key=SPEEDTEST_TSDB_KEY,
			metric=SPEEDTEST_TSDB_METRIC,
			value=result,
		)
		return True
	except TimeoutError:
		_log.warning("SPEEDTEST_TSDB_WRITE_TIMEOUT")
		return False
	except Exception as exc:
		_log.warning("SPEEDTEST_TSDB_WRITE_FAILED: %s", exc)
		return False


async def _run_speedtest_core(
	cfg: Config,
	*,
	progress_callback: ProgressCallback | None = None,
	persist_last_run_on_failure: bool = True,
) -> tuple[dict[str, Any], bool]:
	"""Run the speedtest once while the caller holds the lease."""
	run_completed = False
	result: dict[str, Any] | None = None
	persisted_result: dict[str, Any] | None = None
	try:
		raw_result = await asyncio.wait_for(
			run_speedtest(progress_callback=progress_callback),
			timeout=SPEEDTEST_RUN_TIMEOUT_SECONDS,
		)
		run_completed = True
		if isinstance(raw_result, dict):
			result = raw_result
		else:
			result = {"status": "error", "reason": "Invalid result type"}
		if result.get("status") != "error":
			persisted_result = result
	except asyncio.TimeoutError:
		_log.error("SPEEDTEST_TIMEOUT: test exceeded %ss", SPEEDTEST_RUN_TIMEOUT_SECONDS)
		raise HTTPException(status_code=504, detail="Speed test timed out") from None
	except asyncio.CancelledError:
		raise
	except Exception:
		_log.exception("SPEEDTEST_RUN_FAILED")
		raise HTTPException(status_code=500, detail="Speed test failed") from None
	finally:
		should_persist_last_run = persist_last_run_on_failure or run_completed
		if should_persist_last_run:
			try:
				await _persist_speedtest_state(cfg.db_path, result=persisted_result)
			except Exception as exc:
				_log.warning("SPEEDTEST_STATE_DB_WRITE_FAILED: %s", exc)

	stored = False
	if result is not None and result.get("status") != "error":
		stored = await _store_speedtest_result(cfg.tsdb_dir, result)

	return result or {"status": "error", "reason": "Invalid result type"}, stored


@router.post("/speedtest/run")
@limiter.limit(RATE_LIMIT_HEAVY)
async def trigger_speedtest(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
):
	"""Trigger an immediate speed test (admin only)."""
	# Note: We don't check get_speedtest_enabled() here because that setting
	# controls the *scheduler* only. Manual admin-triggered tests should always work.
	cfg = get_config(request)
	lease = await _acquire_speedtest_lease(cfg.tsdb_dir)
	async with lease:
		result, stored = await _run_speedtest_core(cfg, persist_last_run_on_failure=False)
	return ok_response(data={**result, "stored": stored})


@router.get("/speedtest/run/stream")
@limiter.limit(RATE_LIMIT_HEAVY)
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
	cfg = get_config(request)
	lease = await _acquire_speedtest_lease(cfg.tsdb_dir)

	async def event_generator():
		"""Generate SSE events for speedtest progress."""
		async with lease:
			def _factory(cb):
				return _run_speedtest_core(cfg, progress_callback=cb, persist_last_run_on_failure=False)

			async for event in stream_with_progress(request, _factory, queue_size=SPEEDTEST_PROGRESS_QUEUE_SIZE):
				yield event

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
@limiter.limit(RATE_LIMIT_HEAVY)
async def get_speedtest_history(
	request: Request,
	range_key: str | None = Query(None, pattern="^(6h|24h|7d|30d|90d|180d|y1)$"),
	limit: int = Query(SPEEDTEST_HISTORY_DEFAULT_LIMIT, ge=1, le=SPEEDTEST_HISTORY_MAX_LIMIT),
	node_id: str | None = Query(None, max_length=64, description="Filter by node ID (null=master only, 'all'=all remote nodes)"),
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
	"""
	cfg = get_config(request)

	# Use range_key if provided, otherwise fall back to retention_days
	if range_key:
		hours = SPEEDTEST_RANGE_TO_HOURS[range_key]
		since = utcnow() - timedelta(hours=hours)
	else:
		retention_days = get_speedtest_retention_days(conn)
		since = utcnow() - timedelta(days=retention_days)

	# Fetch more points when filtering to ensure we have enough after filter
	# Note: We adaptively increase fetch size because TSDB limit applies before
	# filtering by node_id. Without this, frequent node results can push master
	# results out of the initial window.
	try:
		points = await _run_in_threadpool_with_timeout(
			SPEEDTEST_TSDB_TIMEOUT_SECONDS,
			tsdb.query,
			cfg.tsdb_dir,
			peer_key=SPEEDTEST_TSDB_KEY,
			metric=SPEEDTEST_TSDB_METRIC,
			since=since,
			limit=limit + 1,  # one extra to detect truncation
			latest=True,
			filter_fn=lambda val: _matches_node_filter(val, node_id),
		)
	except TimeoutError:
		_log.warning("SPEEDTEST_HISTORY_READ_TIMEOUT")
		raise HTTPException(status_code=504, detail="Timed out reading speedtest history") from None

	# Truncate to actual limit and detect if more data exists
	truncated = len(points) > limit
	if truncated:
		points = points[-limit:]

	history = []
	for pt in points:
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
	cfg = get_config(request)
	
	# Get all nodes from DB
	try:
		nodes = await _run_in_threadpool_with_timeout(
			SPEEDTEST_SQLITE_TIMEOUT_SECONDS,
			get_all_nodes,
			conn,
		)
		node_ids = {str(n["id"]) for n in nodes}
		last_results_by_node = await _run_in_threadpool_with_timeout(
			SPEEDTEST_SQLITE_TIMEOUT_SECONDS,
			get_node_speedtest_last_results,
			conn,
			node_ids,
		)
		master_last = await _run_in_threadpool_with_timeout(
			SPEEDTEST_SQLITE_TIMEOUT_SECONDS,
			get_speedtest_last_result,
			conn,
		)
	except TimeoutError:
		_log.warning("SPEEDTEST_NODES_READ_TIMEOUT")
		raise HTTPException(status_code=504, detail="Timed out reading speedtest nodes") from None
	latest_by_node: dict[str | None, dict[str, Any]] = {}
	uncovered_ids = node_ids.difference(last_results_by_node)
	if master_last is None or uncovered_ids:
		since = utcnow() - timedelta(days=90)
		try:
			points = await _run_in_threadpool_with_timeout(
				SPEEDTEST_TSDB_TIMEOUT_SECONDS,
				tsdb.query,
				cfg.tsdb_dir,
				peer_key=SPEEDTEST_TSDB_KEY,
				metric=SPEEDTEST_TSDB_METRIC,
				since=since,
				limit=SPEEDTEST_TSDB_FETCH_CAP,
				latest=True,
			)
		except TimeoutError:
			_log.warning("SPEEDTEST_NODES_TSDB_TIMEOUT")
			raise HTTPException(status_code=504, detail="Timed out reading speedtest nodes") from None
		latest_by_node = build_latest_by_node(points)
	
	# Build result list, starting with master
	result = []
	
	# Master entry
	if master_last is None:
		master_last = latest_by_node.get(None)
	result.append({
		"node_id": None,
		"name": "Master",
		"status": "online",
		"last_speedtest": master_last,
	})
	
	# Node entries
	for n in nodes:
		node_id = str(n["id"])
		node_last = last_results_by_node.get(node_id)
		if node_last is None:
			node_last = latest_by_node.get(node_id)
		result.append({
			"node_id": n["id"],
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
	try:
		stats = await _run_in_threadpool_with_timeout(
			SPEEDTEST_TSDB_TIMEOUT_SECONDS,
			tsdb.get_synthetic_storage_stats,
			cfg.tsdb_dir,
			SPEEDTEST_TSDB_KEY,
		)
	except TimeoutError:
		_log.warning("SPEEDTEST_STORAGE_STATS_TIMEOUT")
		raise HTTPException(status_code=504, detail="Timed out reading speedtest storage stats") from None

	return ok_response(data={
		**stats,
		"retention_days": get_speedtest_retention_days(conn),
		"retention_options": list(SPEEDTEST_RETENTION_OPTIONS),
	})


@router.patch("/speedtest/storage/retention")
@limiter.limit(RATE_LIMIT_HEAVY)
async def update_speedtest_retention(
	request: Request,
	payload: SpeedtestRetentionPayload,
	_: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Update speedtest data retention period (admin only)."""
	_ = request
	days = payload.retention_days
	try:
		result_days = await _run_in_threadpool_with_timeout(
			SPEEDTEST_SQLITE_TIMEOUT_SECONDS,
			_update_speedtest_retention_sync,
			conn,
			days,
		)
	except TimeoutError:
		_log.warning("SPEEDTEST_RETENTION_UPDATE_TIMEOUT")
		raise HTTPException(status_code=504, detail="Timed out updating speedtest retention") from None
	return ok_response(data={
		"retention_days": result_days,
	})


@router.delete("/speedtest/storage")
@limiter.limit(RATE_LIMIT_CRITICAL)
async def purge_speedtest_data(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
):
	"""Delete all speedtest data (admin only)."""
	cfg = get_config(request)
	lease = await _acquire_speedtest_lease(
		cfg.tsdb_dir,
		cooldown_seconds=0.0,
		update_cooldown=False,
	)

	# Use async context manager for consistent lease handling
	async with lease:
		try:
			deleted_bytes = await _run_in_threadpool_with_timeout(
				SPEEDTEST_TSDB_TIMEOUT_SECONDS,
				tsdb.purge_synthetic_data,
				cfg.tsdb_dir,
				SPEEDTEST_TSDB_KEY,
				force=True,
			)
		except TimeoutError:
			_log.warning("SPEEDTEST_STORAGE_PURGE_TIMEOUT")
			raise HTTPException(status_code=504, detail="Timed out deleting speedtest data") from None
		except OSError as exc:
			_log.warning("Failed to delete speedtest data: %s", exc)
			raise HTTPException(status_code=500, detail="Failed to delete speedtest data") from None

	return ok_response(message=f"Speedtest data deleted ({deleted_bytes} bytes)")
