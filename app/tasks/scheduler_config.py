#!/usr/bin/env python3
#
# app/tasks/scheduler_config.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Configuration and registration of background scheduler tasks."""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..dns import unbound
from . import scheduled as scheduled_tasks
from .maintenance import cleanup_stale_sessions, sqlite_integrity_check, sqlite_maintenance, tsdb_retention_cleanup
from ..utils.conntrack import init_conntrack_accounting

if TYPE_CHECKING:
    from ..utils.scheduler import Scheduler
    from ..main import LifespanContext

_log = logging.getLogger(__name__)

# Constants for scheduling intervals
INTERVAL_FIFTEEN_SECONDS = 15.0
INTERVAL_THIRTY_SECONDS = INTERVAL_FIFTEEN_SECONDS * 2
INTERVAL_ONE_MINUTE = INTERVAL_THIRTY_SECONDS * 2
INTERVAL_HOURLY = INTERVAL_ONE_MINUTE * 60
INTERVAL_SIX_HOURS = INTERVAL_HOURLY * 6
INTERVAL_DAILY = INTERVAL_HOURLY * 24
INTERVAL_WEEKLY = INTERVAL_DAILY * 7

# Run backups at 03:00 in the resolved application timezone.
BACKUP_NIGHT_HOUR = 3
_BLOCKLIST_STARTUP_DELAY_SECONDS = 15.0


def _valid_timezone_or_none(value: str) -> str | None:
    """Return a normalized timezone name or None when invalid."""
    tz_name = value.strip()
    if not tz_name:
        return None
    try:
        ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        _log.warning("Ignoring invalid configured timezone: %r", value)
        return None
    return tz_name


def _get_configured_backup_timezone() -> str:
    """Resolve the timezone used for scheduled backup wall-clock calculations.

    Resolution order mirrors the UI display path closely:
    1. ``TZ`` environment variable
    2. ``/etc/timezone``
    3. ``/etc/localtime`` symlink relative to ``/usr/share/zoneinfo``
    4. ``UTC`` fallback
    """
    tz_name = _valid_timezone_or_none(os.getenv("TZ", ""))
    if tz_name:
        return tz_name

    tz_file = Path("/etc/timezone")
    try:
        tz_text = _valid_timezone_or_none(tz_file.read_text(encoding="utf-8"))
        if tz_text:
            return tz_text
    except OSError:
        pass

    try:
        localtime_path = Path("/etc/localtime").resolve()
        zoneinfo_root = Path("/usr/share/zoneinfo")
        if zoneinfo_root in localtime_path.parents:
            return str(localtime_path.relative_to(zoneinfo_root))
    except OSError:
        pass

    return "UTC"


def _seconds_until_backup_time(tz: str = "UTC") -> float:
    """Return seconds until the next 03:00 wall-clock time in the given timezone.

    Args:
        tz: IANA timezone name such as ``Europe/Berlin``. Invalid values fall
            back to UTC and emit a warning.

    Returns:
        A non-negative number of seconds until the next configured backup hour.
        The target is advanced until it is strictly in the future, which keeps
        DST transition days from producing a stale or negative delay.
    """
    try:
        tzinfo = ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        _log.warning("Invalid timezone %r for scheduled backup; falling back to UTC: %s", tz, exc)
        tzinfo = UTC

    now = datetime.now(tzinfo)
    target = now.replace(hour=BACKUP_NIGHT_HOUR, minute=0, second=0, microsecond=0)
    while target <= now:
        target += timedelta(days=1)
    return max(0.0, (target - now).total_seconds())


def _bind(
    ctx: LifespanContext,
    coro_fn: Callable[[LifespanContext], Coroutine[None, None, None]],
) -> Callable[[], Coroutine[None, None, None]]:
    """Bind ``ctx`` to a context-aware async task function.

    Returns a zero-argument async callable compatible with the scheduler's job
    interface.
    """
    async def _wrapper() -> None:
        await coro_fn(ctx)
    return _wrapper


async def _init_country_traffic_accounting() -> None:
    """Best-effort one-shot conntrack accounting initialization."""
    try:
        await asyncio.to_thread(init_conntrack_accounting)
    except Exception as exc:
        _log.warning("COUNTRY_TRAFFIC could not enable conntrack accounting: %s", exc)


async def register_all_tasks(scheduler: Scheduler, ctx: LifespanContext) -> None:
    """Register all background jobs for the application scheduler.

    This performs startup-side configuration reads and lightweight environment
    inspection before mutating ``scheduler`` with the full job set.
    """
    
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
        except Exception as exc:
            _log.warning("BLOCKLIST_STARTUP could not inspect local blocklist (%s); scheduling startup update", exc)
            blocklist_run_on_start = True
            
        if blocklist_run_on_start:
            _log.info("BLOCKLIST_STARTUP no cached blocklist found - scheduling immediate update")
        else:
            min_delay_h = (INTERVAL_DAILY * (1.0 - blocklist_jitter_pct)) / 3600.0
            max_delay_h = (INTERVAL_DAILY * (1.0 + blocklist_jitter_pct)) / 3600.0
            _log.info(
                "BLOCKLIST_STARTUP cached blocklist found - deferring first update to %.1f-%.1f hours (interval=24h, jitter=±%.0f%%)",
                min_delay_h,
                max_delay_h,
                blocklist_jitter_pct * 100,
            )
    else:
        if unbound_installed:
            _log.info("BLOCKLIST_STARTUP skipped: ad-blocker is disabled")
        else:
            _log.info("BLOCKLIST_STARTUP skipped: Unbound not installed")

    if unbound_installed:
        blocklist_initial_delay = _BLOCKLIST_STARTUP_DELAY_SECONDS if blocklist_run_on_start else 0.0
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
    scheduler.add(
        "country-traffic-init",
        interval_seconds=INTERVAL_DAILY,
        func=_init_country_traffic_accounting,
        run_on_start=True,
        initial_delay=0.0,
        timeout=30.0,
    )

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
    initial_speedtest_delay, hours_since_last, speedtest_overdue = await scheduled_tasks.get_speedtest_initial_delay(ctx.cfg.db_path)
    if hours_since_last is not None:
        if speedtest_overdue:
            _log.warning("SPEEDTEST_SCHEDULER last run was %.1f hours ago (>36h) - missed tests detected!", hours_since_last)
        else:
            _log.info("SPEEDTEST_SCHEDULER last run was %.1f hours ago", hours_since_last)
    else:
        _log.info("SPEEDTEST_SCHEDULER no previous run recorded")

    if initial_speedtest_delay > 0:
        scheduled_time = datetime.now() + timedelta(seconds=initial_speedtest_delay)
        _log.info("SPEEDTEST_SCHEDULER first run in %.1f hours (at ~%s)", initial_speedtest_delay / 3600, scheduled_time.strftime("%H:%M"))

    scheduler.add(
        "speedtest",
        interval_seconds=INTERVAL_DAILY,
        func=_bind(ctx, scheduled_tasks.run_scheduled_speedtest),
        run_on_start=False,
        initial_delay=initial_speedtest_delay,
        timeout=7500.0,
        jitter_pct=0.05
    )

    # 9. Backup
    backup_timezone = await asyncio.to_thread(_get_configured_backup_timezone)
    initial_backup_delay = await asyncio.to_thread(_seconds_until_backup_time, backup_timezone)
    _log.info("SCHEDULED_BACKUP first run in %.1f hours (at ~%02d:00)", initial_backup_delay / 3600, BACKUP_NIGHT_HOUR)
    
    scheduler.add(
        "scheduled-backup",
        interval_seconds=INTERVAL_DAILY,
        func=_bind(ctx, scheduled_tasks.run_scheduled_backup),
        run_on_start=False,
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
