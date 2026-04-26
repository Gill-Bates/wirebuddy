#!/usr/bin/env python3
#
# app/tasks/scheduled.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Scheduled background tasks for WireBuddy.

This module contains all scheduler task implementations, extracted from the
main lifespan closure to improve testability and maintainability.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import random
import time
from datetime import UTC, date, datetime as dt, timedelta
from typing import TYPE_CHECKING

from ..utils.subprocess import run_command

if TYPE_CHECKING:
    from .. import main

_log = logging.getLogger(__name__)

# Constants
_PEER_CONNECTION_THRESHOLD = 180  # seconds
_SPEEDTEST_NIGHT_WINDOW_START_HOUR = 2
_SPEEDTEST_NIGHT_WINDOW_END_HOUR = 4
_SPEEDTEST_RETRY_DELAY_MINUTES = 30
_SPEEDTEST_MIN_RUNTIME_SECONDS = 300.0
_SPEEDTEST_EXECUTION_TIMEOUT_SECONDS = 600.0
_WG_CHECK_TIMEOUT_SECONDS = 5.0
_PEER_STATE_MAX_SIZE = 100_000


def _evict_peer_state_entries(peer_connection_state: collections.OrderedDict[str, bool]) -> int:
    """Evict oldest peer state entries efficiently (O(1) pops)."""
    if not hasattr(peer_connection_state, "move_to_end"):
        return 0
    
    evict_target = max(1, _PEER_STATE_MAX_SIZE // 10)
    evicted = 0
    
    while evicted < evict_target and peer_connection_state:
        try:
            peer_connection_state.popitem(last=False)
            evicted += 1
        except KeyError:
            break
    return evicted


from ..utils.speedtest_window import (
    local_wall_clock_timestamp as _local_wall_clock_timestamp,
    seconds_until_night_window as _seconds_until_night_window,
)


async def _sleep_with_cancellation_check(seconds: float, chunk_size: float = 60.0) -> None:
    """Sleep for total seconds, checking cancellation every chunk_size seconds."""
    remaining = seconds
    while remaining > 0:
        sleep_time = min(chunk_size, remaining)
        await asyncio.sleep(sleep_time)
        remaining -= sleep_time


# Backwards compatibility: main.py imports this name
_sleep_interruptible = _sleep_with_cancellation_check


def _db_read(db_path, fn, /, *args, **kwargs):
    """Open a thread-local DB connection, call fn(conn, *args, **kwargs), close it.

    Designed for use with asyncio.to_thread::

        result = await asyncio.to_thread(_db_read, db_path, my_getter)
    """
    from ..db.sqlite_runtime import thread_connection
    with thread_connection(db_path) as conn:
        return fn(conn, *args, **kwargs)


async def update_blocklists(ctx: main.LifespanContext) -> None:
    """Scheduled task: download and apply blocklists."""
    from ..dns import unbound as _unbound
    from ..main import _read_blocklist_enabled_sync, _load_blocklist_update_inputs_sync
    
    if not _unbound.is_unbound_installed():
        return
    
    try:
        def _read_inputs():
            enabled = _read_blocklist_enabled_sync(ctx.cfg.db_path)
            if not enabled:
                return None
            return _load_blocklist_update_inputs_sync(ctx.cfg.db_path)
            
        inputs = await asyncio.to_thread(_read_inputs)
        if not inputs:
            return
        
        urls, custom_rules_text = inputs
        _, msg = await _unbound.update_blocklists(urls, custom_rules_text=custom_rules_text)
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
        def _read_all_retention():
            return (
                _read_tsdb_retention_days_sync(ctx.cfg.db_path),
                _read_speedtest_retention_days_sync(ctx.cfg.db_path),
                _read_dns_retention_days_sync(ctx.cfg.db_path),
            )
        
        tsdb_ret, speed_ret, dns_ret = await asyncio.to_thread(_read_all_retention)
        
        synthetic_retention = {
            "speedtest": speed_ret,
            "geo_traffic": tsdb_ret,
            "asn_traffic": tsdb_ret,
            "network": 7,
        }
        
        stats = await asyncio.to_thread(tsdb.run_maintenance, ctx.cfg.tsdb_dir, tsdb_ret, synthetic_retention)
        dns_retention = await asyncio.to_thread(dns_ingestion.enforce_dns_log_retention, ctx.cfg.dns_dir, dns_ret)
        
        _log.info(
            "TSDB_MAINTENANCE series=%d rotated=%d pruned=%d dns_deleted=%d",
            stats.get("series", 0), stats.get("rotated", 0), stats.get("pruned", 0),
            (dns_retention or {}).get("deleted_files", 0),
        )
    except Exception as exc:
        _log.error("TSDB_MAINTENANCE failed: %s", exc)


async def sample_tsdb_metrics(ctx: main.LifespanContext) -> None:
    """Scheduled task: sample WireGuard transfer counters into TSDB."""
    from ..db import tsdb
    from ..main import _load_peer_identity_map_sync
    
    try:
        peer_counters = await _get_wg_peer_counters()
        if not peer_counters:
            return

        now = time.time()
        # Snapshot for thread-safe comparison — mutations happen in async context below
        state_snapshot = dict(ctx.peer_connection_state)

        def _write_and_detect_changes():
            points = 0
            candidates: list[tuple[str, bool]] = []
            for public_key, (rx, tx, latest_handshake) in peer_counters.items():
                tsdb.append_point(ctx.cfg.tsdb_dir, peer_key=public_key, metric="rx_bytes", value=rx)
                tsdb.append_point(ctx.cfg.tsdb_dir, peer_key=public_key, metric="tx_bytes", value=tx)
                points += 2
                if latest_handshake > 0:
                    tsdb.append_point(ctx.cfg.tsdb_dir, peer_key=public_key, metric="latest_handshake", value=latest_handshake)
                    points += 1
                    handshake_age = max(0.0, now - latest_handshake)
                    is_connected = handshake_age < _PEER_CONNECTION_THRESHOLD
                    if is_connected != state_snapshot.get(public_key, False):
                        candidates.append((public_key, is_connected))
            return points, candidates

        points, candidates = await asyncio.to_thread(_write_and_detect_changes)

        # Apply mutations in async context (no concurrent writers)
        state_changes: list[tuple[str, bool]] = []
        for public_key, is_connected in candidates:
            if is_connected != ctx.peer_connection_state.get(public_key, False):
                if len(ctx.peer_connection_state) >= _PEER_STATE_MAX_SIZE:
                    _evict_peer_state_entries(ctx.peer_connection_state)
                ctx.peer_connection_state[public_key] = is_connected
                ctx.peer_connection_state.move_to_end(public_key)
                state_changes.append((public_key, is_connected))

        if state_changes:
            peer_identity_map = await asyncio.to_thread(
                _load_peer_identity_map_sync, ctx.cfg.db_path, [pk for pk, _ in state_changes]
            )
            for public_key, is_connected in state_changes:
                identity = peer_identity_map.get(public_key)
                status = "CONNECTED" if is_connected else "DISCONNECTED"
                if identity:
                    _log.info("PEER_%s name=%s interface=%s public_key=%s", status, identity[0], identity[1], public_key[:16])
                else:
                    _log.info("PEER_%s public_key=%s (not in database)", status, public_key[:16])
    except Exception as exc:
        _log.error("TSDB_SAMPLE failed: %s", exc)


async def sample_country_traffic(ctx: main.LifespanContext) -> None:
    """Scheduled task: sample conntrack -> country + ASN traffic -> TSDB."""
    from ..db import tsdb
    from ..utils.conntrack import sample_country_traffic as do_sample, ASN_TRAFFIC_KEY, ASN_TRAFFIC_METRIC
    from ..api.wireguard_stats_country import GEO_TRAFFIC_KEY, GEO_TRAFFIC_METRIC
    from ..main import _read_country_traffic_inputs_sync
    
    try:
        def _run():
            enabled, peer_ip_map = _read_country_traffic_inputs_sync(ctx.cfg.db_path)
            if not enabled:
                return
            country_deltas, asn_deltas = do_sample(peer_ip_map)
            if country_deltas:
                tsdb.append_point(ctx.cfg.tsdb_dir, peer_key=GEO_TRAFFIC_KEY, metric=GEO_TRAFFIC_METRIC, value=country_deltas)
            if asn_deltas:
                tsdb.append_point(ctx.cfg.tsdb_dir, peer_key=ASN_TRAFFIC_KEY, metric=ASN_TRAFFIC_METRIC, value=asn_deltas)

        await asyncio.to_thread(_run)
    except Exception as exc:
        _log.warning("COUNTRY_TRAFFIC sample failed: %s", exc)


async def update_geoip(ctx: main.LifespanContext) -> None:
    """Scheduled task: check for GeoIP database updates."""
    try:
        from ..utils.geoip import ensure_geoip_databases, eager_init
        result = await asyncio.to_thread(ensure_geoip_databases, ctx.cfg.data_dir)
        _log.info("GEOIP_UPDATE city=%s asn=%s", result["city"], result["asn"])
        eager_init()
    except Exception as exc:
        _log.error("GEOIP_UPDATE failed: %s", exc)


async def dns_watchdog(ctx: main.LifespanContext) -> None:
    """Scheduled task: restart Unbound if it crashed."""
    from ..dns import unbound as _unbound
    from ..main import _should_unbound_run_sync
    
    if not _unbound.is_unbound_installed():
        return
    
    try:
        async def _should_run():
            return await asyncio.to_thread(_should_unbound_run_sync, ctx.cfg.db_path)
        await _unbound.watchdog(_should_run)
    except Exception as exc:
        _log.error("DNS_WATCHDOG failed: %s", exc)


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


async def get_speedtest_initial_delay(db_path, tsdb_dir) -> tuple[float, float | None, bool]:
    """Calculate speedtest initial delay with missed-run detection."""
    from ..db.sqlite_settings import get_speedtest_last_run_at

    delay = _seconds_until_night_window()

    def _read_last_run_from_db() -> float | None:
        stored = _db_read(db_path, get_speedtest_last_run_at)
        return stored.timestamp() if stored is not None else None

    last_run_ts = await asyncio.to_thread(_read_last_run_from_db)
    now = time.time()
    
    if last_run_ts is None:
        return delay, None, True
    
    hours_since_last = (now - last_run_ts) / 3600
    is_overdue = hours_since_last > 36
    
    return delay, hours_since_last, is_overdue


def _speedtest_window_state(now_ts: float | None = None) -> tuple[str, float]:
    """Return the current speedtest window state."""
    current_ts = time.time() if now_ts is None else now_ts
    now_local = dt.fromtimestamp(current_ts)
    today = now_local.date()
    start_today = _local_wall_clock_timestamp(today, _SPEEDTEST_NIGHT_WINDOW_START_HOUR)
    end_today = _local_wall_clock_timestamp(today, _SPEEDTEST_NIGHT_WINDOW_END_HOUR)

    if current_ts < start_today:
        return "before", max(0.0, start_today - current_ts)
    if current_ts < end_today:
        remaining = max(0.0, end_today - current_ts)
        return ("closing", remaining) if remaining <= _SPEEDTEST_MIN_RUNTIME_SECONDS else ("inside", remaining)
    return "after", 0.0


async def _get_wg_peer_counters() -> dict[str, tuple[int, int, float]] | None:
    """Get WireGuard peer counters via generic subprocess helper."""
    from ..main import _parse_wg_dump_counters
    try:
        res = await run_command("wg", "show", "all", "dump", timeout=_WG_CHECK_TIMEOUT_SECONDS)
        if res.returncode != 0:
            return None
        return _parse_wg_dump_counters(res.stdout) if res.stdout.strip() else {}
    except Exception as exc:
        _log.debug("WG_COUNTERS failed: %s", exc)
        return None


async def _has_active_peers() -> bool:
    """Check if any WireGuard peers are currently connected."""
    peer_counters = await _get_wg_peer_counters()
    if not peer_counters:
        return False
    
    now = time.time()
    for public_key, (_, _, latest_handshake) in peer_counters.items():
        if latest_handshake > 0 and (now - latest_handshake) < _PEER_CONNECTION_THRESHOLD:
            return True
    return False


async def run_scheduled_speedtest(ctx: main.LifespanContext) -> None:
    """Scheduled task: run bandwidth measurement safely in the nightly window."""
    if not await _is_speedtest_enabled(ctx):
        return

    # 1. Ensure we are in (or wait for) the nightly window (02:00-04:00)
    delay = _seconds_until_night_window()
    if delay > 0:
        _log.info("SPEEDTEST_SCHEDULED waiting %.0f seconds for night window", delay)
        await _sleep_with_cancellation_check(delay)
        # Re-check enabled state after potentially long sleep
        if not await _is_speedtest_enabled(ctx):
            return

    # 2. Defer while peers are active (within window)
    if not await _is_speedtest_ignore_peers(ctx) and not await _wait_for_idle_peers():
        _log.warning("SPEEDTEST_SCHEDULED skipped: peers active or window expired")
        return

    # 3. Execution (protected by cross-process lease)
    await _execute_scheduled_speedtest_run(ctx)


async def _is_speedtest_enabled(ctx: main.LifespanContext) -> bool:
    from ..db.sqlite_settings import get_speedtest_enabled
    return await asyncio.to_thread(_db_read, ctx.cfg.db_path, get_speedtest_enabled)


async def _is_speedtest_ignore_peers(ctx: main.LifespanContext) -> bool:
    from ..db.sqlite_settings import get_speedtest_ignore_peers
    return await asyncio.to_thread(_db_read, ctx.cfg.db_path, get_speedtest_ignore_peers)


async def _wait_for_idle_peers() -> bool:
    """Defer execution if peers are active, as long as we are still in window."""
    max_retries = 4
    for attempt in range(max_retries):
        if not await _has_active_peers():
            return True
        
        _log.info("SPEEDTEST_SCHEDULED deferred: active peers detected (attempt %d/%d)", attempt + 1, max_retries)
        
        # Check if we are still in a valid window segment
        window_state, _ = _speedtest_window_state()
        if window_state != "inside":
            _log.info("SPEEDTEST_SCHEDULED window closed during deferral")
            return False
            
        await _sleep_with_cancellation_check(_SPEEDTEST_RETRY_DELAY_MINUTES * 60)
    return False


async def _execute_scheduled_speedtest_run(ctx: main.LifespanContext) -> None:
    """Actual speedtest execution within a lease."""
    from ..speedtest.guard import (
        DEFAULT_SPEEDTEST_COOLDOWN_SECONDS,
        SpeedtestBusyError,
        SpeedtestCooldownError,
        acquire_speedtest_run_lease,
    )
    from ..speedtest.tester import run_speedtest
    from ..db import tsdb
    from ..api.speedtest import SPEEDTEST_TSDB_KEY, SPEEDTEST_TSDB_METRIC
    
    try:
        # acquire_speedtest_run_lease uses LOCK_NB — safe to call directly in async code
        lease = acquire_speedtest_run_lease(
            ctx.cfg.tsdb_dir,
            cooldown_seconds=DEFAULT_SPEEDTEST_COOLDOWN_SECONDS,
        )
        async with lease:
            _log.info("SPEEDTEST_SCHEDULED starting bandwidth measurement")
            try:
                async with asyncio.timeout(_SPEEDTEST_EXECUTION_TIMEOUT_SECONDS):
                    result = await run_speedtest()
            except asyncio.TimeoutError:
                result = {"status": "error", "reason": "Timeout"}
            except Exception as exc:
                result = {"status": "error", "reason": str(exc)}

            await asyncio.to_thread(
                tsdb.append_point,
                ctx.cfg.tsdb_dir,
                peer_key=SPEEDTEST_TSDB_KEY,
                metric=SPEEDTEST_TSDB_METRIC,
                value=result,
            )
            await asyncio.to_thread(_persist_last_run_to_db, ctx.cfg.db_path)
            
            if result.get("status") == "ok":
                _log.info(
                    "SPEEDTEST_SCHEDULED result: ↓%.2f ↑%.2f",
                    result.get("download_mbit"),
                    result.get("upload_mbit"),
                )
    except (SpeedtestBusyError, SpeedtestCooldownError) as exc:
        _log.info("SPEEDTEST_SCHEDULED skipped: %s", exc)


def _persist_last_run_to_db(db_path) -> None:
    from ..db.sqlite_settings import set_speedtest_last_run_at
    _db_read(db_path, set_speedtest_last_run_at)


async def sample_network_stats(ctx: main.LifespanContext) -> None:
    from ..api.network_stats import sample_network_stats as do_sample
    try:
        points = await asyncio.to_thread(do_sample, ctx.cfg.tsdb_dir)
        if points > 0:
            _log.debug("NETWORK_STATS_SAMPLE interfaces=%d", points)
    except Exception as exc:
        _log.warning("NETWORK_STATS_SAMPLE failed: %s", exc)


async def run_scheduled_backup(ctx: main.LifespanContext) -> None:
    from ..api.backup import is_scheduled_backup_enabled, run_scheduled_backup as do_backup
    try:
        enabled = await asyncio.to_thread(is_scheduled_backup_enabled, ctx.cfg.db_path)
        if not enabled:
            return
        result = await asyncio.to_thread(do_backup, ctx.cfg.data_dir, ctx.cfg.db_path)
        _log.info("SCHEDULED_BACKUP completed: %s", result.get("filename"))
    except Exception as exc:
        _log.error("SCHEDULED_BACKUP failed: %s", exc)


async def monitor_node_health(ctx: main.LifespanContext) -> None:
    from ..db.sqlite_nodes import mark_stale_nodes_offline
    try:
        count = await asyncio.to_thread(
            _db_read, ctx.cfg.db_path,
            lambda conn: mark_stale_nodes_offline(conn, stale_seconds=90),
        )
        if count:
            _log.info("NODE_HEALTH marked %d node(s) offline", count)
    except Exception as exc:
        _log.warning("NODE_HEALTH monitor failed: %s", exc)