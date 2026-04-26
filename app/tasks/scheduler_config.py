#!/usr/bin/env python3
#
# app/tasks/scheduler_config.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Configuration and registration of background scheduler tasks."""

from __future__ import annotations

import asyncio
import collections.abc
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Awaitable

from ..dns import unbound
from . import scheduled as scheduled_tasks
from .maintenance import cleanup_stale_sessions, sqlite_integrity_check, sqlite_maintenance, tsdb_retention_cleanup
from ..utils.conntrack import init_conntrack_accounting

if TYPE_CHECKING:
    from ..utils.scheduler import Scheduler
    from ..main import LifespanContext

_log = logging.getLogger(__name__)

# Constants for scheduling intervals
INTERVAL_ONE_MINUTE = 60.0
INTERVAL_THIRTY_SECONDS = 30.0
INTERVAL_FIFTEEN_SECONDS = 15.0
INTERVAL_HOURLY = 3600.0
INTERVAL_SIX_HOURS = 21600.0
INTERVAL_DAILY = 86400.0
INTERVAL_WEEKLY = 604800.0

BACKUP_NIGHT_HOUR = 3  # Run backups at 03:00 local time

def _seconds_until_backup_time(tz: str = "UTC") -> float:
    """Calculate seconds until next 03:00 in given timezone (default UTC)."""
    try:
        from zoneinfo import ZoneInfo
        tzinfo = ZoneInfo(tz)
    except Exception as exc:
        _log.warning("Invalid timezone %r for scheduled backup; falling back to UTC: %s", tz, exc)
        tzinfo = UTC

    now = datetime.now(tzinfo)
    target = now.replace(hour=BACKUP_NIGHT_HOUR, minute=0, second=0, microsecond=0)
    if now >= target:
        target += timedelta(days=1)
    return max(0.0, (target - now).total_seconds())

def _bind(ctx: LifespanContext, coro_fn: collections.abc.Callable[[LifespanContext], Awaitable[None]]) -> collections.abc.Callable[[], Awaitable[None]]:
    """Return a null-ary async function that calls *coro_fn* with *ctx*."""
    async def _wrapper() -> None:
        await coro_fn(ctx)
    return _wrapper

async def register_all_tasks(scheduler: Scheduler, ctx: LifespanContext) -> None:
    """Register all scheduled tasks based on current configuration."""
    
    # Needs to import this specific function directly to avoid circular / heavy imports
    from ..main import _read_blocklist_enabled_sync
    
    unbound_installed = unbound.is_unbound_installed()
    
    # 1. Blocklist Update
    blocklist_enabled_startup = unbound_installed and await asyncio.to_thread(_read_blocklist_enabled_sync, ctx.cfg.db_path)
    blocklist_jitter_pct = 0.1
    blocklist_run_on_start = False
    
    if blocklist_enabled_startup:
        try:
            blocklist_run_on_start = unbound.get_blocklist_count() <= 0
        except Exception:
            _log.warning("BLOCKLIST_STARTUP could not inspect local blocklist; scheduling startup update")
            blocklist_run_on_start = True
            
        if blocklist_run_on_start:
            _log.info("BLOCKLIST_STARTUP no cached blocklist found - scheduling immediate update")
        else:
            min_delay_h = (INTERVAL_DAILY * (1.0 - blocklist_jitter_pct)) / 3600.0
            max_delay_h = (INTERVAL_DAILY * (1.0 + blocklist_jitter_pct)) / 3600.0
            _log.info("BLOCKLIST_STARTUP cached blocklist found - deferring first update to %.1f-%.1f hours (interval=24h, jitter=±10%%)", min_delay_h, max_delay_h)
    else:
        if unbound_installed:
            _log.info("BLOCKLIST_STARTUP skipped: ad-blocker is disabled")
        else:
            _log.info("BLOCKLIST_STARTUP skipped: Unbound not installed")

    if unbound_installed:
        blocklist_initial_delay = 15.0 if blocklist_run_on_start else 0.0
        scheduler.add(
            "blocklist-update",
            interval_seconds=INTERVAL_DAILY,
            func=_bind(ctx, scheduled_tasks.update_blocklists),
            run_on_start=blocklist_run_on_start,
            initial_delay=blocklist_initial_delay,
            jitter_pct=blocklist_jitter_pct
        )

    # 2. TSDB
    scheduler.add(
        "tsdb-maintenance",
        interval_seconds=INTERVAL_SIX_HOURS,
        func=_bind(ctx, scheduled_tasks.maintain_tsdb),
        run_on_start=True,
        initial_delay=30.0
    )
    
    scheduler.add(
        "tsdb-sample",
        interval_seconds=INTERVAL_THIRTY_SECONDS,
        func=_bind(ctx, scheduled_tasks.sample_tsdb_metrics),
        run_on_start=True,
        initial_delay=10.0
    )

    # 3. Traffic Analysis
    try:
        await asyncio.to_thread(init_conntrack_accounting)
    except Exception as exc:
        _log.warning("COUNTRY_TRAFFIC could not enable conntrack accounting: %s", exc)

    scheduler.add(
        "country-traffic",
        interval_seconds=INTERVAL_THIRTY_SECONDS,
        func=_bind(ctx, scheduled_tasks.sample_country_traffic),
        run_on_start=True,
        initial_delay=15.0
    )

    # 4. Network Stats
    scheduler.add(
        "network-stats",
        interval_seconds=INTERVAL_THIRTY_SECONDS,
        func=_bind(ctx, scheduled_tasks.sample_network_stats),
        run_on_start=True,
        initial_delay=12.0
    )

    # 5. GeoIP
    scheduler.add(
        "geoip-update",
        interval_seconds=INTERVAL_WEEKLY,
        func=_bind(ctx, scheduled_tasks.update_geoip),
        run_on_start=True,
        initial_delay=20.0
    )

    # 6. Database Maintenance
    scheduler.add(
        "sqlite-maintenance",
        interval_seconds=INTERVAL_SIX_HOURS,
        func=sqlite_maintenance,
        run_on_start=True,
        initial_delay=60.0,
        timeout=60.0
    )
    scheduler.add(
        "sqlite-integrity",
        interval_seconds=INTERVAL_WEEKLY,
        func=sqlite_integrity_check,
        run_on_start=False,
        timeout=300.0
    )
    scheduler.add(
        "tsdb-retention",
        interval_seconds=INTERVAL_DAILY,
        func=tsdb_retention_cleanup,
        run_on_start=True,
        initial_delay=90.0,
        timeout=120.0
    )
    scheduler.add(
        "session-cleanup",
        interval_seconds=INTERVAL_HOURLY,
        func=cleanup_stale_sessions,
        run_on_start=True,
        initial_delay=120.0,
        timeout=30.0
    )

    # 7. DNS Watchdog
    if unbound_installed:
        scheduler.add(
            "dns-watchdog",
            interval_seconds=INTERVAL_THIRTY_SECONDS,
            func=_bind(ctx, scheduled_tasks.dns_watchdog),
            run_on_start=True,
            initial_delay=60.0,
            timeout=30.0
        )
        
        scheduler.add(
            "adblocker-timer-check",
            interval_seconds=INTERVAL_FIFTEEN_SECONDS,
            func=_bind(ctx, scheduled_tasks.check_adblocker_timer),
            run_on_start=False,
            timeout=30.0
        )

    # 8. Speedtest
    initial_speedtest_delay, hours_since_last, speedtest_overdue = await scheduled_tasks.get_speedtest_initial_delay(ctx.cfg.db_path, ctx.cfg.tsdb_dir)
    if hours_since_last is not None:
        if speedtest_overdue:
            _log.warning("SPEEDTEST_SCHEDULER last run was %.1f hours ago (>36h) - missed tests detected!", hours_since_last)
        else:
            _log.info("SPEEDTEST_SCHEDULER last run was %.1f hours ago", hours_since_last)
    else:
        _log.info("SPEEDTEST_SCHEDULER no previous run recorded")

    if initial_speedtest_delay > 0:
        from datetime import datetime as dt, timedelta
        scheduled_time = dt.now() + timedelta(seconds=initial_speedtest_delay)
        _log.info("SPEEDTEST_SCHEDULER first run in %.1f hours (at ~%s)", initial_speedtest_delay / 3600, scheduled_time.strftime("%H:%M"))

    scheduler.add(
        "speedtest",
        interval_seconds=INTERVAL_DAILY,
        func=_bind(ctx, scheduled_tasks.run_scheduled_speedtest),
        run_on_start=True,
        initial_delay=initial_speedtest_delay,
        timeout=7500.0,
        jitter_pct=0.05
    )

    # 9. Backup
    initial_backup_delay = _seconds_until_backup_time(os.environ.get("TZ", "UTC"))
    _log.info("SCHEDULED_BACKUP first run in %.1f hours (at ~%02d:00)", initial_backup_delay / 3600, BACKUP_NIGHT_HOUR)
    
    scheduler.add(
        "scheduled-backup",
        interval_seconds=INTERVAL_DAILY,
        func=_bind(ctx, scheduled_tasks.run_scheduled_backup),
        run_on_start=True,
        initial_delay=initial_backup_delay,
        timeout=300.0,
        jitter_pct=0.05
    )

    # 10. Node Health
    scheduler.add(
        "node-health",
        interval_seconds=INTERVAL_ONE_MINUTE,
        func=_bind(ctx, scheduled_tasks.monitor_node_health),
        run_on_start=False,
        timeout=15.0
    )
