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
import logging
import random
import time
from datetime import datetime as dt, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
	from .. import main

_log = logging.getLogger(__name__)

# Re-export constants used by tasks
_PEER_CONNECTION_THRESHOLD = 180  # seconds
_SPEEDTEST_NIGHT_WINDOW_START_HOUR = 2
_SPEEDTEST_NIGHT_WINDOW_END_HOUR = 4
_SPEEDTEST_RETRY_DELAY_MINUTES = 30
_WG_CHECK_TIMEOUT_SECONDS = 5.0
_PEER_STATE_MAX_SIZE = 100_000


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
	except Exception as exc:
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
		tsdb_retention_days = await asyncio.to_thread(_read_tsdb_retention_days_sync, ctx.cfg.db_path)
		speedtest_retention_days = await asyncio.to_thread(_read_speedtest_retention_days_sync, ctx.cfg.db_path)
		
		# Build synthetic key retention mapping
		synthetic_retention = {
			"speedtest": speedtest_retention_days,
			"geo_traffic": tsdb_retention_days,
			"asn_traffic": tsdb_retention_days,
		}
		
		stats = await asyncio.to_thread(
			tsdb.run_maintenance,
			ctx.cfg.tsdb_dir,
			tsdb_retention_days,
			synthetic_retention,
		)
		dns_retention_days = await asyncio.to_thread(_read_dns_retention_days_sync, ctx.cfg.db_path)
		dns_retention = await asyncio.to_thread(
			dns_ingestion.enforce_dns_log_retention,
			ctx.cfg.dns_dir,
			dns_retention_days,
		)
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
	except Exception as exc:
		_log.error("TSDB_MAINTENANCE failed: %s", exc)


async def sample_tsdb_metrics(ctx: main.LifespanContext) -> None:
	"""Scheduled task: sample WireGuard transfer counters into TSDB."""
	from ..db import tsdb
	from ..main import (
		_communicate_with_timeout,
		_parse_wg_dump_counters,
		_load_peer_identity_map_sync,
	)
	
	try:
		proc = await asyncio.create_subprocess_exec(
			"wg", "show", "all", "dump",
			stdout=asyncio.subprocess.PIPE,
			stderr=asyncio.subprocess.PIPE,
		)
		stdout_raw, stderr_raw = await _communicate_with_timeout(
			proc,
			timeout_seconds=_WG_CHECK_TIMEOUT_SECONDS,
		)
	except asyncio.TimeoutError:
		_log.warning("TSDB_SAMPLE timed out while executing 'wg show all dump'")
		return
	except FileNotFoundError:
		_log.warning("TSDB_SAMPLE skipped: 'wg' binary not found")
		return
	except Exception as exc:
		_log.warning("TSDB_SAMPLE failed to execute wg dump: %s", exc)
		return

	if proc.returncode != 0:
		stderr = (stderr_raw or b"").decode("utf-8", errors="replace").strip()
		_log.info("TSDB_SAMPLE wg dump returned code=%s: %s", proc.returncode, stderr)
		return

	stdout = (stdout_raw or b"").decode("utf-8", errors="replace")
	if not stdout.strip():
		_log.debug("TSDB_SAMPLE wg dump returned empty output (no active interfaces?)")
		return

	peer_counters = _parse_wg_dump_counters(stdout)
	if not peer_counters:
		_log.debug("TSDB_SAMPLE no peers found in wg dump output")
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
			is_connected = (now - latest_handshake) < _PEER_CONNECTION_THRESHOLD
			was_connected = ctx.peer_connection_state.get(public_key, False)

			# Log every active handshake at DEBUG level for visibility
			if is_connected:
				handshake_age = int(now - latest_handshake)
				_log.debug(
					"PEER_HANDSHAKE public_key=%s handshake_age=%ds rx=%d tx=%d",
					public_key[:16], handshake_age, rx, tx,
				)

			if is_connected != was_connected:
				# LRU eviction: drop oldest 10 % when near capacity
				if len(ctx.peer_connection_state) >= _PEER_STATE_MAX_SIZE:
					evict = _PEER_STATE_MAX_SIZE // 10
					for _ in range(evict):
						ctx.peer_connection_state.popitem(last=False)
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
	except Exception as exc:
		_log.warning("COUNTRY_TRAFFIC sample failed: %s", exc)


async def update_geoip(ctx: main.LifespanContext) -> None:
	"""Scheduled task: check for GeoIP database updates."""
	try:
		from ..utils.geoip import ensure_geoip_databases, eager_init
		result = await asyncio.to_thread(ensure_geoip_databases, ctx.cfg.data_dir)
		_log.info("GEOIP_UPDATE city=%s asn=%s", result["city"], result["asn"])
		# Pre-load readers so first request is instant
		eager_init()
	except Exception as exc:
		_log.error("GEOIP_UPDATE failed: %s", exc)


async def dns_watchdog(ctx: main.LifespanContext) -> None:
	"""Scheduled task: restart Unbound if it crashed."""
	from ..dns import unbound as _unbound
	from ..main import _should_unbound_run_sync
	
	if not _unbound.is_unbound_installed():
		return  # Skip if Unbound not installed
	
	# Pass async callable that re-evaluates the condition on each watchdog check
	async def _should_run():
		return await asyncio.to_thread(_should_unbound_run_sync, ctx.cfg.db_path)
	
	await _unbound.watchdog(_should_run)


async def check_adblocker_timer(ctx: main.LifespanContext) -> None:
	"""Scheduled task: re-enable ad-blocker when timed disable expires."""
	from ..main import _check_adblocker_timer_sync, _reload_unbound_for_adblocker_async
	
	try:
		re_enabled = await asyncio.to_thread(_check_adblocker_timer_sync, ctx.cfg.db_path)
		if re_enabled:
			_log.info("ADBLOCKER_TIMER timer expired, re-enabling ad-blocker")
			await _reload_unbound_for_adblocker_async(ctx.cfg.db_path)
	except Exception as exc:
		_log.warning("ADBLOCKER_TIMER check failed: %s", exc)


def _seconds_until_night_window() -> float:
	"""Calculate seconds until the next speedtest night window with random jitter.
	
	Returns 0 if currently within the window, otherwise seconds until
	a random point within the next window (02:00-04:00 local time).
	"""
	now = dt.now()  # Local time (UTC in Docker unless TZ is set)
	current_hour = now.hour
	
	# Currently within night window - return small random offset, clamped to avoid overshooting
	if _SPEEDTEST_NIGHT_WINDOW_START_HOUR <= current_hour < _SPEEDTEST_NIGHT_WINDOW_END_HOUR:
		remaining = (now.replace(hour=_SPEEDTEST_NIGHT_WINDOW_END_HOUR, minute=0,
		                        second=0, microsecond=0) - now).total_seconds()
		# Leave at least 5 min for the test itself
		max_jitter = max(0, remaining - 300)
		return random.uniform(0, min(600, max_jitter))
	
	# Calculate next window start
	if current_hour < _SPEEDTEST_NIGHT_WINDOW_START_HOUR:
		next_window = now.replace(
			hour=_SPEEDTEST_NIGHT_WINDOW_START_HOUR,
			minute=0, second=0, microsecond=0
		)
	else:
		next_window = (now + timedelta(days=1)).replace(
			hour=_SPEEDTEST_NIGHT_WINDOW_START_HOUR,
			minute=0, second=0, microsecond=0
		)
	
	# Add random jitter: spread load across the 2-hour window
	window_duration_seconds = (_SPEEDTEST_NIGHT_WINDOW_END_HOUR - _SPEEDTEST_NIGHT_WINDOW_START_HOUR) * 3600
	jitter_seconds = random.uniform(0, window_duration_seconds - 300)
	
	return (next_window - now).total_seconds() + jitter_seconds


async def _has_active_peers() -> bool:
	"""Check if any WireGuard peers are currently connected."""
	from ..main import _communicate_with_timeout, _parse_wg_dump_counters
	
	try:
		proc = await asyncio.create_subprocess_exec(
			"wg", "show", "all", "dump",
			stdout=asyncio.subprocess.PIPE,
			stderr=asyncio.subprocess.PIPE,
		)
		stdout_raw, _ = await _communicate_with_timeout(
			proc,
			timeout_seconds=_WG_CHECK_TIMEOUT_SECONDS,
		)
		if proc.returncode != 0:
			return False
		
		stdout = (stdout_raw or b"").decode("utf-8", errors="replace")
		if not stdout.strip():
			return False
		
		peer_counters = _parse_wg_dump_counters(stdout)
		now = time.time()
		
		for public_key, (rx, tx, latest_handshake) in peer_counters.items():
			if latest_handshake > 0:
				if (now - latest_handshake) < _PEER_CONNECTION_THRESHOLD:
					_log.debug(
						"SPEEDTEST_CHECK active peer detected: %s (handshake %ds ago)",
						public_key[:16], int(now - latest_handshake)
					)
					return True
		return False
	except Exception as exc:
		_log.debug("SPEEDTEST_CHECK peer check failed: %s", exc)
		return False  # Assume no peers on error; proceed with test


async def run_scheduled_speedtest(ctx: main.LifespanContext) -> None:
	"""Scheduled task: run bandwidth measurement if enabled."""
	from ..db import tsdb
	from ..db.sqlite_settings import get_speedtest_enabled, get_speedtest_target, SPEEDTEST_SERVER_MAP
	from ..db.sqlite_runtime import connect, close_connection
	from ..speedtest import (
		DEFAULT_SPEEDTEST_COOLDOWN_SECONDS,
		SpeedtestBusyError,
		SpeedtestCooldownError,
		acquire_speedtest_run_lease,
	)
	from ..speedtest.tester import BandwidthTester
	from ..api.speedtest import SPEEDTEST_TSDB_KEY, SPEEDTEST_TSDB_METRIC
	
	try:
		# Offload blocking SQLite calls to thread
		def _read_speedtest_settings():
			conn = connect(ctx.cfg.db_path)
			try:
				return get_speedtest_enabled(conn), get_speedtest_target(conn)
			finally:
				close_connection(conn)
		
		enabled, target = await asyncio.to_thread(_read_speedtest_settings)
		if not enabled:
			_log.debug("SPEEDTEST_SCHEDULED skipped: disabled")
			return

		# Wait until night window if not already there
		wait_seconds = _seconds_until_night_window()
		if wait_seconds > 0:
			_log.info(
				"SPEEDTEST_SCHEDULED waiting %.0f seconds for night window (02:00-04:00)",
				wait_seconds
			)
			await asyncio.sleep(wait_seconds)

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
			await asyncio.sleep(_SPEEDTEST_RETRY_DELAY_MINUTES * 60)
		else:
			# All retries exhausted, peers still active
			_log.warning(
				"SPEEDTEST_SCHEDULED skipped: peers still active after %d retries",
				max_retries
			)
			return

		servers = None
		if target != "auto":
			server_info = SPEEDTEST_SERVER_MAP.get(target)
			if server_info:
				servers = [server_info["url"]]

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
			tester = BandwidthTester(servers=servers)
			result = await tester.run()

		# Offload TSDB write to thread
		await asyncio.to_thread(
			tsdb.append_point,
			ctx.cfg.tsdb_dir,
			peer_key=SPEEDTEST_TSDB_KEY,
			metric=SPEEDTEST_TSDB_METRIC,
			value=result,
		)

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
	except Exception as exc:
		_log.error("SPEEDTEST_SCHEDULED failed: %s", exc)
