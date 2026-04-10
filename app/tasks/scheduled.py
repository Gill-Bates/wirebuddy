#!/usr/bin/env python3
#
# app/tasks/scheduled.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Scheduled background tasks for WireBuddy.

This module contains all scheduler task implementations, extracted from the
main lifespan closure to improve testability and maintainability.

Each task accepts a LifespanContext parameter for dependency injection,
making them independently testable without running the full application.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import random
import time
from datetime import date, datetime as dt, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
	from .. import main

_log = logging.getLogger(__name__)

# Re-export constants used by tasks
_PEER_CONNECTION_THRESHOLD = 180  # seconds
_SPEEDTEST_NIGHT_WINDOW_START_HOUR = 2
_SPEEDTEST_NIGHT_WINDOW_END_HOUR = 4
_SPEEDTEST_RETRY_DELAY_MINUTES = 30
_SPEEDTEST_MIN_RUNTIME_SECONDS = 300.0
_SPEEDTEST_EXECUTION_TIMEOUT_SECONDS = 600.0
_WG_CHECK_TIMEOUT_SECONDS = 5.0
_PEER_STATE_MAX_SIZE = 100_000


def _evict_peer_state_entries(peer_connection_state: collections.OrderedDict[str, bool]) -> int:
	"""Evict oldest peer state entries, preferring disconnected peers.
	
	Requires peer_connection_state to support OrderedDict interface
	(move_to_end, popitem with last= parameter).
	"""
	# Defensive check for OrderedDict interface
	if not hasattr(peer_connection_state, "move_to_end"):
		_log.warning("peer_connection_state does not support move_to_end (not an OrderedDict)")
		return 0
	
	evict_target = max(1, _PEER_STATE_MAX_SIZE // 10)
	evicted = 0
	disconnected_keys = [
		public_key for public_key, is_connected in peer_connection_state.items()
		if not is_connected
	]
	for public_key in disconnected_keys[:evict_target]:
		if peer_connection_state.pop(public_key, None) is not None:
			evicted += 1

	while evicted < evict_target and peer_connection_state:
		try:
			peer_connection_state.popitem(last=False)
		except KeyError:
			break
		evicted += 1

	return evicted


def _local_wall_clock_timestamp(day: date, hour: int) -> float:
	"""Return the local timestamp for a wall-clock hour using system DST rules."""
	wall_time = dt(day.year, day.month, day.day, hour, 0, 0)
	return time.mktime(wall_time.timetuple())


async def _sleep_interruptible(seconds: float, chunk_size: float = 60.0) -> None:
	"""Sleep for total seconds, checking cancellation every chunk_size seconds.
	
	Useful for long sleeps that should be responsive to task cancellation.
	"""
	remaining = seconds
	while remaining > 0:
		sleep_time = min(chunk_size, remaining)
		await asyncio.sleep(sleep_time)
		remaining -= sleep_time


async def update_blocklists(ctx: main.LifespanContext) -> None:
	"""Scheduled task: download and apply blocklists."""
	from ..dns import unbound as _unbound
	from ..main import _read_blocklist_enabled_sync, _load_blocklist_update_inputs_sync
	
	if not _unbound.is_unbound_installed():
		return  # Skip if Unbound not installed
	
	try:
		# Skip if blocklist is disabled
		blocklist_enabled = await asyncio.to_thread(_read_blocklist_enabled_sync, ctx.cfg.db_path)
		if not blocklist_enabled:
			return
		
		urls, custom_rules_text = await asyncio.to_thread(
			_load_blocklist_update_inputs_sync,
			ctx.cfg.db_path,
		)
		
		count, msg = await _unbound.update_blocklists(urls, custom_rules_text=custom_rules_text)
		# Use restart instead of reload - reload crashes with large blocklists
		await _unbound.restart()
		_log.info("BLOCKLIST_UPDATE %s", msg)
	except (OSError, RuntimeError, ValueError) as exc:
		_log.error("BLOCKLIST_UPDATE failed: %s", exc)


async def maintain_tsdb(ctx: main.LifespanContext) -> None:
	"""Scheduled task: prune/rotate/compress TSDB series."""
	from ..db import tsdb
	from ..dns import ingestion as dns_ingestion
	from ..main import (
		_read_tsdb_retention_days_sync,
		_read_speedtest_retention_days_sync,
		_read_dns_retention_days_sync,
	)
	
	try:
		# Batch all retention config reads in a single thread hop
		def _read_all_retention():
			return (
				_read_tsdb_retention_days_sync(ctx.cfg.db_path),
				_read_speedtest_retention_days_sync(ctx.cfg.db_path),
				_read_dns_retention_days_sync(ctx.cfg.db_path),
			)
		
		tsdb_retention_days, speedtest_retention_days, dns_retention_days = await asyncio.to_thread(
			_read_all_retention
		)
		
		# Build synthetic key retention mapping
		# network_stats uses 7 days to support 1h sparkline history with headroom
		synthetic_retention = {
			"speedtest": speedtest_retention_days,
			"geo_traffic": tsdb_retention_days,
			"asn_traffic": tsdb_retention_days,
			"network": 7,  # 7 days retention for network stats sparklines
		}
		
		stats = await asyncio.to_thread(
			tsdb.run_maintenance,
			ctx.cfg.tsdb_dir,
			tsdb_retention_days,
			synthetic_retention,
		)
		dns_retention = await asyncio.to_thread(
			dns_ingestion.enforce_dns_log_retention,
			ctx.cfg.dns_dir,
			dns_retention_days,
		)
		stats = stats or {}
		dns_retention = dns_retention or {}
		_log.info(
			"TSDB_MAINTENANCE series=%d rotated=%d pruned=%d dns_deleted=%d dns_remaining=%d dns_days=%d speedtest_days=%d",
			stats.get("series", 0),
			stats.get("rotated", 0),
			stats.get("pruned", 0),
			dns_retention.get("deleted_files", 0),
			dns_retention.get("remaining_files", 0),
			dns_retention_days,
			speedtest_retention_days,
		)
	except (OSError, RuntimeError, ValueError) as exc:
		_log.error("TSDB_MAINTENANCE failed: %s", exc)


async def sample_tsdb_metrics(ctx: main.LifespanContext) -> None:
	"""Scheduled task: sample WireGuard transfer counters into TSDB."""
	from ..db import tsdb
	from ..main import _load_peer_identity_map_sync
	
	try:
		peer_counters = await _get_wg_peer_counters()
		if peer_counters is None:
			_log.debug("TSDB_SAMPLE skipped: wg counter collection failed")
			return
		if not peer_counters:
			_log.debug("TSDB_SAMPLE skipped: no WireGuard peers reported")
			return

		# Offload blocking TSDB writes to thread
		def _write_tsdb_points():
			points = 0
			for public_key, (rx, tx, latest_handshake) in peer_counters.items():
				tsdb.append_point(ctx.cfg.tsdb_dir, peer_key=public_key, metric="rx_bytes", value=rx)
				tsdb.append_point(ctx.cfg.tsdb_dir, peer_key=public_key, metric="tx_bytes", value=tx)
				points += 2
				if latest_handshake > 0:
					tsdb.append_point(ctx.cfg.tsdb_dir, peer_key=public_key, metric="latest_handshake", value=latest_handshake)
					points += 1
			return points

		points = await asyncio.to_thread(_write_tsdb_points)
		_log.debug("TSDB_SAMPLE peers=%d points=%d", len(peer_counters), points)

		# Track connection state changes for logging (on event loop thread)
		now = time.time()
		state_changes: list[tuple[str, bool]] = []  # (public_key, is_now_connected)

		for public_key, (rx, tx, latest_handshake) in peer_counters.items():
			if latest_handshake > 0:
				# Detect connection state changes
				handshake_age = max(0.0, now - latest_handshake)
				is_connected = handshake_age < _PEER_CONNECTION_THRESHOLD
				was_connected = ctx.peer_connection_state.get(public_key, False)

				# Log every active handshake at DEBUG level for visibility
				if is_connected:
					_log.debug(
						"PEER_HANDSHAKE public_key=%s handshake_age=%ds rx=%d tx=%d",
						public_key[:16], int(handshake_age), rx, tx,
					)

				if is_connected != was_connected:
					# LRU eviction: prefer disconnected peers to avoid false reconnect logs.
					if len(ctx.peer_connection_state) >= _PEER_STATE_MAX_SIZE:
						evict = _evict_peer_state_entries(ctx.peer_connection_state)
						_log.warning("PEER_STATE evicted %d oldest entries", evict)
					ctx.peer_connection_state[public_key] = is_connected
					ctx.peer_connection_state.move_to_end(public_key)
					state_changes.append((public_key, is_connected))

		# Log connection state changes with peer names
		if state_changes:
			public_keys = [public_key for public_key, _ in state_changes]
			peer_identity_map = await asyncio.to_thread(
				_load_peer_identity_map_sync,
				ctx.cfg.db_path,
				public_keys,
			)
			for public_key, is_connected in state_changes:
				peer_identity = peer_identity_map.get(public_key)
				if peer_identity:
					peer_name, interface = peer_identity
					if is_connected:
						_log.info("PEER_CONNECTED name=%s interface=%s public_key=%s",
							peer_name, interface, public_key[:16])
					else:
						_log.info("PEER_DISCONNECTED name=%s interface=%s public_key=%s",
							peer_name, interface, public_key[:16])
				else:
					if is_connected:
						_log.info("PEER_CONNECTED public_key=%s (not in database)", public_key[:16])
					else:
						_log.info("PEER_DISCONNECTED public_key=%s (not in database)", public_key[:16])
	except (OSError, RuntimeError, ValueError) as exc:
		_log.error("TSDB_SAMPLE failed: %s", exc)


async def sample_country_traffic(ctx: main.LifespanContext) -> None:
	"""Scheduled task: sample conntrack → country + ASN traffic → TSDB."""
	from ..db import tsdb
	from ..utils.conntrack import sample_country_traffic as do_sample, ASN_TRAFFIC_KEY, ASN_TRAFFIC_METRIC
	from ..api.wireguard_stats_country import GEO_TRAFFIC_KEY, GEO_TRAFFIC_METRIC
	from ..main import _read_country_traffic_inputs_sync
	
	try:
		enabled, peer_ip_map = await asyncio.to_thread(
			_read_country_traffic_inputs_sync,
			ctx.cfg.db_path,
		)
		if not enabled:
			return

		country_deltas, asn_deltas = await asyncio.to_thread(
			do_sample, peer_ip_map
		)

		# Offload TSDB writes to thread
		def _write_country_traffic():
			if country_deltas:
				tsdb.append_point(
					ctx.cfg.tsdb_dir,
					peer_key=GEO_TRAFFIC_KEY,
					metric=GEO_TRAFFIC_METRIC,
					value=country_deltas,
				)
			if asn_deltas:
				tsdb.append_point(
					ctx.cfg.tsdb_dir,
					peer_key=ASN_TRAFFIC_KEY,
					metric=ASN_TRAFFIC_METRIC,
					value=asn_deltas,
				)

		await asyncio.to_thread(_write_country_traffic)

		if country_deltas:
			total_rx = sum(v.get("rx", 0) for v in country_deltas.values())
			total_tx = sum(v.get("tx", 0) for v in country_deltas.values())
			_log.debug(
				"COUNTRY_TRAFFIC countries=%d rx=%.0f tx=%.0f",
				len(country_deltas), total_rx, total_tx,
			)

		if asn_deltas:
			_log.debug(
				"ASN_TRAFFIC asns=%d",
				len(asn_deltas),
			)
	except (OSError, RuntimeError, ValueError) as exc:
		_log.warning("COUNTRY_TRAFFIC sample failed: %s", exc)


async def update_geoip(ctx: main.LifespanContext) -> None:
	"""Scheduled task: check for GeoIP database updates."""
	try:
		from ..utils.geoip import ensure_geoip_databases, eager_init
		result = await asyncio.to_thread(ensure_geoip_databases, ctx.cfg.data_dir)
		_log.info("GEOIP_UPDATE city=%s asn=%s", result["city"], result["asn"])
		# Pre-load readers so first request is instant
		eager_init()
	except (OSError, RuntimeError, ValueError) as exc:
		_log.error("GEOIP_UPDATE failed: %s", exc)


async def dns_watchdog(ctx: main.LifespanContext) -> None:
	"""Scheduled task: restart Unbound if it crashed."""
	from ..dns import unbound as _unbound
	from ..main import _should_unbound_run_sync
	
	if not _unbound.is_unbound_installed():
		return  # Skip if Unbound not installed
	
	try:
		# Pass async callable that re-evaluates the condition on each watchdog check
		async def _should_run():
			return await asyncio.to_thread(_should_unbound_run_sync, ctx.cfg.db_path)
		
		await _unbound.watchdog(_should_run)
	except (OSError, RuntimeError, ValueError) as exc:
		_log.error("DNS_WATCHDOG failed: %s", exc)


async def check_adblocker_timer(ctx: main.LifespanContext) -> None:
	"""Scheduled task: re-enable ad-blocker when timed disable expires."""
	from ..main import _check_adblocker_timer_sync, _reload_unbound_for_adblocker_async
	
	try:
		re_enabled = await asyncio.to_thread(_check_adblocker_timer_sync, ctx.cfg.db_path)
		if re_enabled:
			_log.info("ADBLOCKER_TIMER timer expired, re-enabling ad-blocker")
			await _reload_unbound_for_adblocker_async(ctx.cfg.db_path)
	except (OSError, RuntimeError, ValueError) as exc:
		_log.warning("ADBLOCKER_TIMER check failed: %s", exc)


async def get_speedtest_initial_delay(db_path, tsdb_dir) -> tuple[float, float | None, bool]:
	"""Calculate speedtest initial delay with missed-run detection.
	
	Reads the last run timestamp and calculates the delay to the next
	night window. If the last run was >36h ago, this indicates missed tests.
	
	Args:
		db_path: Path to the SQLite database containing speedtest scheduler metadata.
		tsdb_dir: Path to TSDB directory containing .speedtest.last_run
	
	Returns:
		Tuple of (delay_seconds, hours_since_last_run, is_overdue).
		hours_since_last_run is None if no previous run recorded.
		is_overdue is True if last run was >36h ago (missed at least one night).
	"""
	from ..db.sqlite_runtime import close_connection, connect
	from ..db.sqlite_settings import get_speedtest_last_run_at, set_speedtest_last_run_at
	from pathlib import Path
	from ..speedtest.guard import _cooldown_path, _read_last_run
	
	delay = _seconds_until_night_window()

	def _read_last_run_from_db() -> float | None:
		conn = connect(db_path)
		try:
			stored = get_speedtest_last_run_at(conn)
			return stored.timestamp() if stored is not None else None
		finally:
			close_connection(conn)

	def _migrate_last_run_to_db(last_run_ts: float) -> bool:
		conn = connect(db_path)
		try:
			# Avoid overwriting a newer value that may have been written by
			# another worker between file read and migration.
			stored = get_speedtest_last_run_at(conn)
			if stored is not None:
				return False
			set_speedtest_last_run_at(conn, dt.fromtimestamp(last_run_ts, timezone.utc))
			return True
		finally:
			close_connection(conn)

	# Primary source is the database; legacy file remains as fallback for cooldown guard migration.
	last_run_ts = await asyncio.to_thread(_read_last_run_from_db)
	if last_run_ts is None:
		last_run_ts = _read_last_run(_cooldown_path(Path(tsdb_dir)))
		if last_run_ts is not None:
			try:
				migrated = await asyncio.to_thread(_migrate_last_run_to_db, last_run_ts)
				if migrated:
					_log.info("SPEEDTEST_SCHEDULER migrated last-run timestamp from file to database")
				last_run_ts = await asyncio.to_thread(_read_last_run_from_db)
			except Exception as exc:
				_log.debug("SPEEDTEST_SCHEDULER could not migrate last-run timestamp to database: %s", exc)
	now = time.time()
	
	if last_run_ts is None:
		return delay, None, True  # No previous run = overdue
	
	hours_since_last = (now - last_run_ts) / 3600
	is_overdue = hours_since_last > 36  # >36h means at least one night missed
	
	return delay, hours_since_last, is_overdue


def _seconds_until_night_window() -> float:
	"""Calculate seconds until a jittered start time in the local night window.
	
	The target window is 02:00-04:00 local time. If less than five minutes
	remain in the current window, defer to the next night's window instead
	of starting immediately.
	
	Note: Uses system DST rules via time.mktime(). DST transitions (forward/back)
	may shift actual execution time by up to one hour.
	"""
	now_ts = time.time()
	now_local = dt.fromtimestamp(now_ts)
	today = now_local.date()
	start_today = _local_wall_clock_timestamp(today, _SPEEDTEST_NIGHT_WINDOW_START_HOUR)
	end_today = _local_wall_clock_timestamp(today, _SPEEDTEST_NIGHT_WINDOW_END_HOUR)

	# Currently within night window.
	if start_today <= now_ts < end_today:
		remaining = max(0.0, end_today - now_ts)
		if remaining <= _SPEEDTEST_MIN_RUNTIME_SECONDS:
			next_day = today + timedelta(days=1)
			next_start = _local_wall_clock_timestamp(next_day, _SPEEDTEST_NIGHT_WINDOW_START_HOUR)
			next_end = _local_wall_clock_timestamp(next_day, _SPEEDTEST_NIGHT_WINDOW_END_HOUR)
			window_duration_seconds = max(0.0, next_end - next_start)
			jitter_cap = max(0.0, window_duration_seconds - _SPEEDTEST_MIN_RUNTIME_SECONDS)
			jitter_seconds = random.uniform(0.0, jitter_cap) if jitter_cap > 0 else 0.0
			return max(0.0, (next_start - now_ts) + jitter_seconds)

		# Stay within the current window and leave at least 5 minutes for the test.
		max_jitter = max(0.0, remaining - _SPEEDTEST_MIN_RUNTIME_SECONDS)
		return random.uniform(0.0, min(600.0, max_jitter))

	# Calculate next window start in local wall-clock time.
	if now_ts < start_today:
		next_start = start_today
		next_end = end_today
	else:
		next_day = today + timedelta(days=1)
		next_start = _local_wall_clock_timestamp(next_day, _SPEEDTEST_NIGHT_WINDOW_START_HOUR)
		next_end = _local_wall_clock_timestamp(next_day, _SPEEDTEST_NIGHT_WINDOW_END_HOUR)

	window_duration_seconds = max(0.0, next_end - next_start)
	jitter_cap = max(0.0, window_duration_seconds - _SPEEDTEST_MIN_RUNTIME_SECONDS)
	jitter_seconds = random.uniform(0.0, jitter_cap) if jitter_cap > 0 else 0.0

	return max(0.0, (next_start - now_ts) + jitter_seconds)


def _speedtest_window_state(now_ts: float | None = None) -> tuple[str, float]:
	"""Return the current speedtest window state and remaining/wait seconds.

	Returns:
		("before", wait_seconds): before 02:00 local time.
		("inside", remaining_seconds): inside the 02:00-04:00 window with enough runtime left.
		("closing", remaining_seconds): inside the window but with <=5 minutes remaining.
		("after", 0.0): after the nightly window.
	"""
	current_ts = time.time() if now_ts is None else now_ts
	now_local = dt.fromtimestamp(current_ts)
	today = now_local.date()
	start_today = _local_wall_clock_timestamp(today, _SPEEDTEST_NIGHT_WINDOW_START_HOUR)
	end_today = _local_wall_clock_timestamp(today, _SPEEDTEST_NIGHT_WINDOW_END_HOUR)

	if current_ts < start_today:
		return "before", max(0.0, start_today - current_ts)

	if current_ts < end_today:
		remaining = max(0.0, end_today - current_ts)
		if remaining <= _SPEEDTEST_MIN_RUNTIME_SECONDS:
			return "closing", remaining
		return "inside", remaining

	return "after", 0.0


async def _get_wg_peer_counters() -> dict[str, tuple[int, int, float]] | None:
	"""Get WireGuard peer counters via 'wg show all dump'.
	
	Returns:
		Dict mapping public_key -> (rx_bytes, tx_bytes, latest_handshake_ts).
		Returns an empty dict when wg reports no peers.
		Returns None on command/timeout/parse error.
	"""
	from ..main import _communicate_with_timeout, _parse_wg_dump_counters
	
	try:
		proc = await asyncio.create_subprocess_exec(
			"wg", "show", "all", "dump",
			stdout=asyncio.subprocess.PIPE,
			stderr=asyncio.subprocess.PIPE,
		)
		try:
			stdout_raw, stderr_raw = await _communicate_with_timeout(
				proc,
				timeout_seconds=_WG_CHECK_TIMEOUT_SECONDS,
			)
		except asyncio.TimeoutError:
			# Ensure subprocess is killed and reaped on timeout
			proc.kill()
			try:
				await asyncio.wait_for(proc.communicate(), timeout=1.0)
			except asyncio.TimeoutError:
				_log.error("WG_COUNTERS process did not terminate after SIGKILL")
			_log.debug("WG_COUNTERS timeout after %ds", _WG_CHECK_TIMEOUT_SECONDS)
			return None
		if proc.returncode != 0:
			stderr_text = (stderr_raw or b"").decode("utf-8", errors="replace").strip()
			if stderr_text:
				_log.debug("WG_COUNTERS command failed: returncode=%d stderr=%s", proc.returncode, stderr_text[:200])
			else:
				_log.debug("WG_COUNTERS command failed: returncode=%d", proc.returncode)
			return None
		
		stdout = (stdout_raw or b"").decode("utf-8", errors="replace")
		if not stdout.strip():
			_log.debug("WG_COUNTERS command returned empty output")
			return {}

		try:
			return _parse_wg_dump_counters(stdout)
		except Exception as exc:
			preview = stdout.strip().splitlines()[0][:160] if stdout.strip() else ""
			if preview:
				_log.debug("WG_COUNTERS parse failed: %s (first line: %s)", exc, preview)
			else:
				_log.debug("WG_COUNTERS parse failed: %s", exc)
			return None
	except asyncio.CancelledError:
		raise
	except FileNotFoundError:
		_log.debug("WG_COUNTERS failed: 'wg' binary not found")
		return None
	except (OSError, ValueError) as exc:
		_log.debug("WG_COUNTERS failed: %s", exc)
		return None


async def _has_active_peers() -> bool:
	"""Check if any WireGuard peers are currently connected."""
	peer_counters = await _get_wg_peer_counters()
	if not peer_counters:
		return False
	
	now = time.time()
	for public_key, (rx, tx, latest_handshake) in peer_counters.items():
		age = max(0.0, now - latest_handshake)
		if latest_handshake > 0 and age < _PEER_CONNECTION_THRESHOLD:
			_log.debug(
				"SPEEDTEST_CHECK active peer detected: %s (handshake %ds ago)",
				public_key[:16], int(age)
			)
			return True
	return False


async def run_scheduled_speedtest(ctx: main.LifespanContext) -> None:
	"""Scheduled task: run bandwidth measurement if enabled.

	Waits for the nightly window (02:00-04:00 local time), defers if peers
	are active, and executes the speedtest with timeout protection.

	Persists the result to TSDB and updates the last-run timestamp.
	"""
	from ..db import tsdb
	from ..db.sqlite_settings import get_speedtest_enabled, set_speedtest_last_run_at
	from ..db.sqlite_runtime import connect, close_connection
	from ..speedtest import (
		DEFAULT_SPEEDTEST_COOLDOWN_SECONDS,
		SpeedtestBusyError,
		SpeedtestCooldownError,
		acquire_speedtest_run_lease,
	)
	from ..speedtest.tester import run_speedtest
	from ..api.speedtest import SPEEDTEST_TSDB_KEY, SPEEDTEST_TSDB_METRIC
	
	try:
		# Offload blocking SQLite calls to thread
		def _read_speedtest_enabled():
			conn = connect(ctx.cfg.db_path)
			try:
				return get_speedtest_enabled(conn)
			finally:
				close_connection(conn)

		async def _check_enabled(skip_reason: str) -> bool:
			enabled = await asyncio.to_thread(_read_speedtest_enabled)
			if not enabled:
				_log.info("SPEEDTEST_SCHEDULED skipped: %s", skip_reason)
			return enabled
		
		if not await _check_enabled("disabled"):
			return

		# Only wait when the scheduler fired slightly before the nightly window.
		# If we already drifted past the window, run immediately instead of sleeping
		# nearly a full day and getting cancelled by the scheduler timeout.
		window_state, window_seconds = _speedtest_window_state()
		if window_state == "before":
			_log.info(
				"SPEEDTEST_SCHEDULED waiting %.0f seconds for night window (02:00-04:00)",
				window_seconds
			)
			await _sleep_interruptible(window_seconds)
			if not await _check_enabled("disabled during wait"):
				return
			window_state, window_seconds = _speedtest_window_state()

		if window_state == "closing":
			_log.warning(
				"SPEEDTEST_SCHEDULED starting with only %.0f seconds left in the preferred night window",
				window_seconds,
			)
		elif window_state == "after":
			_log.warning(
				"SPEEDTEST_SCHEDULED triggered outside the preferred 02:00-04:00 window; running immediately"
			)

		# Check for active peers; if any, defer the test
		max_retries = 4  # Max ~2 hours of deferral within the window
		for attempt in range(max_retries):
			if not await _has_active_peers():
				break
			_log.info(
				"SPEEDTEST_SCHEDULED deferred: active peers detected (attempt %d/%d), "
				"retrying in %d minutes",
				attempt + 1, max_retries, _SPEEDTEST_RETRY_DELAY_MINUTES
			)
			# Stop retrying once the preferred window has closed.
			window_state, _ = _speedtest_window_state()
			if window_state != "inside":
				_log.info("SPEEDTEST_SCHEDULED window closed, stopping retries")
				return
			# Use interruptible sleep to handle cancellation gracefully
			await _sleep_interruptible(_SPEEDTEST_RETRY_DELAY_MINUTES * 60)
			if not await _check_enabled("disabled during peer deferral"):
				return
		else:
			# All retries exhausted, peers still active
			_log.warning(
				"SPEEDTEST_SCHEDULED skipped: peers still active after %d retries",
				max_retries
			)
			return

		try:
			lease = acquire_speedtest_run_lease(
				ctx.cfg.tsdb_dir,
				cooldown_seconds=DEFAULT_SPEEDTEST_COOLDOWN_SECONDS,
			)
		except SpeedtestBusyError:
			_log.info("SPEEDTEST_SCHEDULED skipped: another speedtest is already running")
			return
		except SpeedtestCooldownError as exc:
			_log.info("SPEEDTEST_SCHEDULED skipped: cooldown active (%s)", exc)
			return

		async with lease:
			_log.info("SPEEDTEST_SCHEDULED starting bandwidth measurement")
			started_run = False
			try:
				try:
					started_run = True
					result = await asyncio.wait_for(
						run_speedtest(),
						timeout=_SPEEDTEST_EXECUTION_TIMEOUT_SECONDS,
					)
				except asyncio.TimeoutError:
					result = {
						"status": "error",
						"reason": f"Timeout after {_SPEEDTEST_EXECUTION_TIMEOUT_SECONDS:.0f}s",
					}
					_log.warning(
						"SPEEDTEST_SCHEDULED test execution timed out after %.0fs",
						_SPEEDTEST_EXECUTION_TIMEOUT_SECONDS,
					)
				except asyncio.CancelledError:
					raise
				except Exception as exc:
					result = {
						"status": "error",
						"reason": f"{type(exc).__name__}: {exc}",
					}
					_log.warning("SPEEDTEST_SCHEDULED test execution failed: %s", exc)

				# Keep the run lease until the result is persisted to avoid interleaved
				# scheduled/manual speedtest writes.
				await asyncio.to_thread(
					tsdb.append_point,
					ctx.cfg.tsdb_dir,
					peer_key=SPEEDTEST_TSDB_KEY,
					metric=SPEEDTEST_TSDB_METRIC,
					value=result,
				)
			finally:
				if started_run:
					try:
						await asyncio.to_thread(_persist_last_run_to_db, ctx.cfg.db_path)
					except Exception as exc:
						_log.warning("SPEEDTEST_LAST_RUN_DB_WRITE_FAILED: %s", exc)

		if result.get("status") == "ok":
			_log.info(
				"SPEEDTEST_SCHEDULED server=%s dl=%.2f ul=%.2f rtt=%.2fms",
				result.get("server", "?"),
				result.get("download_mbit", 0),
				result.get("upload_mbit", 0),
				result.get("rtt_ms", 0),
			)
		else:
			_log.warning("SPEEDTEST_SCHEDULED status=%s server=%s", result.get("status"), result.get("server"))
	except asyncio.CancelledError:
		raise
	except (OSError, RuntimeError, ValueError) as exc:
		_log.error("SPEEDTEST_SCHEDULED failed: %s", exc)


def _persist_last_run_to_db(db_path) -> None:
	"""Persist the latest local speedtest run timestamp via SQLite helper."""
	from ..db.sqlite_settings import set_speedtest_last_run_at
	from ..db.sqlite_runtime import close_connection, connect
	conn = connect(db_path)
	try:
		set_speedtest_last_run_at(conn)
	finally:
		close_connection(conn)


async def sample_network_stats(ctx: main.LifespanContext) -> None:
	"""Scheduled task: sample network interface throughput rates into TSDB.
	
	Runs every 30 seconds to collect bandwidth data for sparkline history.
	Stores rx_rate, tx_rate, and total for each visible interface.
	"""
	from ..api.network_stats import sample_network_stats as do_sample
	
	try:
		points = await asyncio.to_thread(do_sample, ctx.cfg.tsdb_dir)
		if points > 0:
			_log.debug("NETWORK_STATS_SAMPLE interfaces=%d", points)
	except (OSError, RuntimeError, ValueError) as exc:
		_log.warning("NETWORK_STATS_SAMPLE failed: %s", exc)


async def run_scheduled_backup(ctx: main.LifespanContext) -> None:
	"""Scheduled task: create nightly backup if enabled.
	
	Runs once per day (at night) and:
	- Creates a backup archive in data/backup/
	- Removes backups older than 30 days
	"""
	from ..api.backup import is_scheduled_backup_enabled, run_scheduled_backup as do_backup
	
	try:
		# Check if scheduled backups are enabled
		enabled = await asyncio.to_thread(is_scheduled_backup_enabled, ctx.cfg.db_path)
		if not enabled:
			_log.debug("SCHEDULED_BACKUP skipped: disabled")
			return
		
		_log.info("SCHEDULED_BACKUP starting nightly backup")
		result = await asyncio.to_thread(
			do_backup,
			ctx.cfg.data_dir,
			ctx.cfg.db_path,
		)
		
		_log.info(
			"SCHEDULED_BACKUP completed: %s (%d bytes), deleted %d old backups",
			result.get("filename"),
			result.get("size_bytes", 0),
			result.get("deleted_old_backups", 0),
		)
	except (OSError, RuntimeError, ValueError) as exc:
		_log.error("SCHEDULED_BACKUP failed: %s", exc)


async def monitor_node_health(ctx: main.LifespanContext) -> None:
	"""Scheduled task: mark stale nodes as offline.

	Runs every 60 seconds.  If a node hasn't sent a heartbeat within 90
	seconds, its status is set to 'offline'.
	"""
	from ..db.sqlite_nodes import mark_stale_nodes_offline
	from ..db.sqlite_runtime import connect, close_connection

	try:
		def _mark_stale():
			conn = connect(ctx.cfg.db_path)
			try:
				return mark_stale_nodes_offline(conn, stale_seconds=90)
			finally:
				close_connection(conn)
		
		count = await asyncio.to_thread(_mark_stale)
		if count:
			_log.info("NODE_HEALTH marked %d node(s) offline", count)
	except (OSError, ValueError, RuntimeError) as exc:
		_log.warning("NODE_HEALTH monitor failed: %s", exc)
