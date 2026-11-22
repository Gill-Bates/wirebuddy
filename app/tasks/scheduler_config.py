#!/usr/bin/env python3
#
# app/tasks/scheduler_config.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Configuration and registration of background scheduler tasks."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from ..dns import unbound
from ..utils.conntrack import init_conntrack_accounting
from . import scheduled as scheduled_tasks
from .db_inputs import read_blocklist_enabled_sync
from .maintenance import (
	cleanup_acked_node_commands,
	cleanup_expired_passkey_challenges,
	cleanup_login_attempts,
	cleanup_stale_sessions,
	sqlite_integrity_check,
	sqlite_maintenance,
	tsdb_retention_cleanup,
)

if TYPE_CHECKING:
	from ..main import LifespanContext
	from ..utils.scheduler import Scheduler

_log = logging.getLogger(__name__)

# Constants for scheduling intervals
INTERVAL_FIFTEEN_SECONDS = 15.0
INTERVAL_THIRTY_SECONDS = INTERVAL_FIFTEEN_SECONDS * 2
INTERVAL_ONE_MINUTE = INTERVAL_THIRTY_SECONDS * 2
INTERVAL_HOURLY = INTERVAL_ONE_MINUTE * 60
INTERVAL_SIX_HOURS = INTERVAL_HOURLY * 6
INTERVAL_DAILY = INTERVAL_HOURLY * 24
INTERVAL_WEEKLY = INTERVAL_DAILY * 7

# Run backups at 03:00 UTC.
BACKUP_NIGHT_HOUR = 3
_BLOCKLIST_STARTUP_DELAY_SECONDS = 15.0


def _seconds_until_backup_time(*, now: datetime | None = None, min_gap: float = 0.0) -> float:
	"""Return seconds until the next 03:00 UTC.

	Args:
	    now: Reference instant (timezone-aware); defaults to the current time.
	    min_gap: The target must lie more than this many seconds ahead. The
	        scheduler uses it so a run that finishes right before 03:00 does not
	        trigger a second run for the same night.

	Returns:
	    A positive number of seconds. UTC has no DST, so the result is always
	    within ``(min_gap, min_gap + 86400]``.
	"""
	now_utc = (now if now is not None else datetime.now(UTC)).astimezone(UTC)
	for offset in range(3):
		day = now_utc.date() + timedelta(days=offset)
		target = datetime(day.year, day.month, day.day, BACKUP_NIGHT_HOUR, tzinfo=UTC)
		if (target - now_utc).total_seconds() > min_gap:
			return (target - now_utc).total_seconds()
	raise RuntimeError("no backup time found within three days")  # pragma: no cover


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
	unbound_installed = unbound.is_unbound_installed()

	# 1. Blocklist Update
	blocklist_enabled_startup = unbound_installed and await asyncio.to_thread(read_blocklist_enabled_sync, ctx.cfg.db_path)
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
	elif unbound_installed:
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
			jitter_pct=blocklist_jitter_pct,
		)

	# 2. TSDB
	scheduler.add(
		"tsdb-maintenance", interval_seconds=INTERVAL_SIX_HOURS, func=_bind(ctx, scheduled_tasks.maintain_tsdb), run_on_start=True, initial_delay=30.0
	)

	scheduler.add(
		"tsdb-sample", interval_seconds=INTERVAL_THIRTY_SECONDS, func=_bind(ctx, scheduled_tasks.sample_tsdb_metrics), run_on_start=True, initial_delay=10.0
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
		initial_delay=15.0,
	)

	# 4. Network Stats
	scheduler.add(
		"network-stats", interval_seconds=INTERVAL_THIRTY_SECONDS, func=_bind(ctx, scheduled_tasks.sample_network_stats), run_on_start=True, initial_delay=12.0
	)

	# 5. GeoIP
	scheduler.add(
		"geoip-update",
		interval_seconds=INTERVAL_WEEKLY,
		func=_bind(ctx, scheduled_tasks.update_geoip),
		run_on_start=True,
		initial_delay=20.0,
		next_delay=lambda: scheduled_tasks.geoip_next_delay(INTERVAL_WEEKLY),
	)

	# 6. Database Maintenance
	scheduler.add("sqlite-maintenance", interval_seconds=INTERVAL_SIX_HOURS, func=sqlite_maintenance, run_on_start=True, initial_delay=60.0, timeout=60.0)
	scheduler.add("sqlite-integrity", interval_seconds=INTERVAL_WEEKLY, func=sqlite_integrity_check, run_on_start=False, timeout=300.0)
	scheduler.add("tsdb-retention", interval_seconds=INTERVAL_DAILY, func=tsdb_retention_cleanup, run_on_start=True, initial_delay=90.0, timeout=120.0)
	scheduler.add("session-cleanup", interval_seconds=INTERVAL_HOURLY, func=cleanup_stale_sessions, run_on_start=True, initial_delay=120.0, timeout=30.0)
	scheduler.add("login-attempts-cleanup", interval_seconds=INTERVAL_HOURLY, func=cleanup_login_attempts, run_on_start=True, initial_delay=150.0, timeout=30.0)
	scheduler.add(
		"passkey-challenge-cleanup",
		interval_seconds=INTERVAL_HOURLY,
		func=cleanup_expired_passkey_challenges,
		run_on_start=True,
		initial_delay=165.0,
		timeout=30.0,
	)
	scheduler.add(
		"node-commands-cleanup", interval_seconds=INTERVAL_DAILY, func=cleanup_acked_node_commands, run_on_start=True, initial_delay=180.0, timeout=30.0
	)

	# 7. DNS Watchdog
	if unbound_installed:
		scheduler.add(
			"dns-watchdog",
			interval_seconds=INTERVAL_THIRTY_SECONDS,
			func=_bind(ctx, scheduled_tasks.dns_watchdog),
			run_on_start=True,
			initial_delay=60.0,
			timeout=30.0,
		)

		scheduler.add(
			"adblocker-timer-check",
			interval_seconds=INTERVAL_FIFTEEN_SECONDS,
			func=_bind(ctx, scheduled_tasks.check_adblocker_timer),
			run_on_start=False,
			timeout=30.0,
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
		scheduled_time = datetime.now(UTC) + timedelta(seconds=initial_speedtest_delay)
		_log.info("SPEEDTEST_SCHEDULER first run in %.1f hours (at ~%s UTC)", initial_speedtest_delay / 3600, scheduled_time.strftime("%H:%M"))

	scheduler.add(
		"speedtest",
		interval_seconds=INTERVAL_DAILY,
		func=_bind(ctx, scheduled_tasks.run_scheduled_speedtest),
		run_on_start=False,
		initial_delay=initial_speedtest_delay,
		timeout=7500.0,
		next_delay=scheduled_tasks.seconds_until_next_speedtest,
	)

	# 9. Backup
	initial_backup_delay = _seconds_until_backup_time()
	_log.info("SCHEDULED_BACKUP first run in %.1f hours (at ~%02d:00 UTC)", initial_backup_delay / 3600, BACKUP_NIGHT_HOUR)

	scheduler.add(
		"scheduled-backup",
		interval_seconds=INTERVAL_DAILY,
		func=_bind(ctx, scheduled_tasks.run_scheduled_backup),
		run_on_start=False,
		initial_delay=initial_backup_delay,
		timeout=300.0,
		next_delay=lambda: _seconds_until_backup_time(min_gap=60.0),
	)

	# 10. Node Health
	scheduler.add("node-health", interval_seconds=INTERVAL_ONE_MINUTE, func=_bind(ctx, scheduled_tasks.monitor_node_health), run_on_start=False, timeout=15.0)
