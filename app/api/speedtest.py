#!/usr/bin/env python3
#
# app/api/speedtest.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Speedtest settings and trigger endpoints."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import sqlite3
from datetime import timedelta
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator
from starlette.concurrency import run_in_threadpool

from ..db.sqlite_runtime import close_connection, connect, transaction
from ..db.sqlite_settings import (
	SPEEDTEST_RETENTION_OPTIONS,
	get_speedtest_enabled,
	get_speedtest_ignore_peers,
	get_speedtest_last_result,
	get_node_speedtest_last_results,
	get_speedtest_retention_days,
	set_speedtest_enabled,
	set_speedtest_ignore_peers,
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
from ..utils.deps import get_conn, get_config
from ..utils.time import utcnow
from ..utils.tsdb_helpers import build_latest_by_node
from ..speedtest.tester import ProgressCallback, ProgressEvent, run_speedtest
from .auth import get_current_user, require_admin
from .response import ok_response
from .sse import broadcast_event_to_queues, format_sse_event, format_sse_keepalive, stream_with_progress

_log = logging.getLogger(__name__)

router = APIRouter(tags=["speedtest"])

# TSDB synthetic key for speedtest results
SPEEDTEST_TSDB_KEY = "__speedtest__"
SPEEDTEST_TSDB_METRIC = "speedtest_result"
SPEEDTEST_RUN_TIMEOUT_SECONDS = 120
SPEEDTEST_HISTORY_DEFAULT_LIMIT = 500
SPEEDTEST_HISTORY_MAX_LIMIT = 5000
SPEEDTEST_HISTORY_FETCH_CAP = 10_000
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
	enabled: bool | None = None
	ignore_peers: bool | None = None


@router.get("/speedtest/settings")
async def get_speedtest_settings(
	_: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get speedtest configuration."""
	return ok_response(data={
		"enabled": get_speedtest_enabled(conn),
		"ignore_peers": get_speedtest_ignore_peers(conn),
		"last_result": get_speedtest_last_result(conn),
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
			if payload.ignore_peers is not None:
				set_speedtest_ignore_peers(conn, payload.ignore_peers)
			# Read response data inside transaction to avoid TOCTOU
			result = {
				"enabled": get_speedtest_enabled(conn),
				"ignore_peers": get_speedtest_ignore_peers(conn),
			}
	except ValueError as exc:
		raise HTTPException(status_code=422, detail=str(exc)) from None
	except (sqlite3.OperationalError, sqlite3.IntegrityError):
		_log.exception("SPEEDTEST_SETTINGS_UPDATE_FAILED")
		raise HTTPException(status_code=500, detail="Failed to persist speedtest settings") from None

	return ok_response(data=result)


async def _write_speedtest_setting_to_db(
	db_path: Path,
	writer: Callable[[sqlite3.Connection], None],
) -> None:
	"""Persist a speedtest-related setting using a fresh SQLite connection."""
	def _write() -> None:
		db_conn = connect(db_path)
		try:
			writer(db_conn)
		finally:
			close_connection(db_conn)

	await run_in_threadpool(_write)


async def _persist_last_run_to_db(db_path: Path | None = None) -> None:
	"""Persist the latest completed local speedtest run in SQLite."""
	if db_path is None:
		raise ValueError("db_path is required when conn is not provided")
	await _write_speedtest_setting_to_db(db_path, set_speedtest_last_run_at)


async def _persist_last_result_to_db(
	result: dict[str, Any],
	db_path: Path | None = None,
) -> None:
	"""Persist the latest successful local speedtest result in SQLite."""
	if db_path is None:
		raise ValueError("db_path is required when conn is not provided")
	await _write_speedtest_setting_to_db(db_path, lambda conn: set_speedtest_last_result(conn, result))


async def _acquire_speedtest_lease(tsdb_dir: Any):
	"""Acquire the shared speedtest lease or raise the corresponding HTTP error."""
	try:
		return acquire_speedtest_run_lease(
			tsdb_dir,
			cooldown_seconds=DEFAULT_SPEEDTEST_COOLDOWN_SECONDS,
		)
	except SpeedtestBusyError:
		raise HTTPException(status_code=409, detail="Speed test already in progress") from None
	except SpeedtestCooldownError as exc:
		raise HTTPException(status_code=429, detail=str(exc)) from None


async def _store_speedtest_result(tsdb_dir: Any, result: dict[str, Any]) -> bool:
	"""Persist a successful speedtest result to TSDB."""
	from ..db import tsdb

	try:
		await run_in_threadpool(
			tsdb.append_point,
			tsdb_dir,
			peer_key=SPEEDTEST_TSDB_KEY,
			metric=SPEEDTEST_TSDB_METRIC,
			value=result,
		)
		return True
	except Exception as exc:
		_log.warning("SPEEDTEST_TSDB_WRITE_FAILED: %s", exc)
		return False


async def _run_speedtest_core(
	request: Request,
	*,
	progress_callback: ProgressCallback | None = None,
	persist_last_run_on_failure: bool = True,
) -> tuple[dict[str, Any], bool]:
	"""Run the speedtest once while the caller holds the lease."""
	cfg = get_config(request)
	try:
		result = await asyncio.wait_for(
			run_speedtest(progress_callback=progress_callback),
			timeout=SPEEDTEST_RUN_TIMEOUT_SECONDS,
		)
	except asyncio.TimeoutError:
		_log.error("SPEEDTEST_TIMEOUT: test exceeded %ss", SPEEDTEST_RUN_TIMEOUT_SECONDS)
		raise HTTPException(status_code=504, detail="Speed test timed out") from None
	except Exception:
		_log.exception("SPEEDTEST_RUN_FAILED")
		raise HTTPException(status_code=500, detail="Speed test failed") from None
	finally:
		if persist_last_run_on_failure or 'result' in locals():
			try:
				await _persist_last_run_to_db(cfg.db_path)
			except Exception as exc:
				_log.warning("SPEEDTEST_LAST_RUN_DB_WRITE_FAILED: %s", exc)

	if not isinstance(result, dict):
		result = {"status": "error", "reason": "Invalid result type"}

	stored = False
	if result.get("status") != "error":
		stored = await _store_speedtest_result(cfg.tsdb_dir, result)
		try:
			await _persist_last_result_to_db(result, db_path=cfg.db_path)
		except Exception as exc:
			_log.warning("SPEEDTEST_LAST_RESULT_DB_WRITE_FAILED: %s", exc)

	return result, stored


@router.post("/speedtest/run")
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
		result, stored = await _run_speedtest_core(request, persist_last_run_on_failure=False)
	return ok_response(data={**result, "stored": stored})


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
	cfg = get_config(request)
	lease = await _acquire_speedtest_lease(cfg.tsdb_dir)

	async def event_generator():
		"""Generate SSE events for speedtest progress."""
		async with lease:
			def _factory(cb):
				return _run_speedtest_core(request, progress_callback=cb, persist_last_run_on_failure=False)

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
		Note: 'truncated' flag may be approximate when filtering by node_id due to fetch heuristics
	"""
	from ..db import tsdb

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
	def _matches_node_filter(val: Any) -> bool:
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

	points = await run_in_threadpool(
		tsdb.query,
		cfg.tsdb_dir,
		peer_key=SPEEDTEST_TSDB_KEY,
		metric=SPEEDTEST_TSDB_METRIC,
		since=since,
		limit=limit + 1,  # one extra to detect truncation
		latest=True,
		filter_fn=_matches_node_filter,
	)

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
	from ..db import tsdb
	from ..db.sqlite_nodes import get_all_nodes
	
	cfg = get_config(request)
	
	# Get all nodes from DB
	nodes = await run_in_threadpool(get_all_nodes, conn)
	node_ids = {str(n["id"]) for n in nodes}
	last_results_by_node = get_node_speedtest_last_results(conn, node_ids)
	
	# Get recent speedtest history (last 90 days should be enough to find each node's latest)
	since = utcnow() - timedelta(days=90)
	points = await run_in_threadpool(
		tsdb.query,
		cfg.tsdb_dir,
		peer_key=SPEEDTEST_TSDB_KEY,
		metric=SPEEDTEST_TSDB_METRIC,
		since=since,
		limit=2000,  # Should be enough to cover all nodes
		latest=True,
	)
	
	# Build a map of node_id -> latest speedtest
	latest_by_node = build_latest_by_node(points)
	latest_by_node.update(last_results_by_node)
	
	# Build result list, starting with master
	result = []
	
	# Master entry
	master_last = get_speedtest_last_result(conn)
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
