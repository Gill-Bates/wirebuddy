#!/usr/bin/env python3
#
# app/utils/speedtest_window.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Speedtest scheduling calculations shared between master and nodes (UTC only)."""

import random
import time
from datetime import UTC, date, datetime, timedelta


def utc_hour_timestamp(day: date, hour: int) -> float:
	"""Return the epoch timestamp of ``hour``:00 UTC on ``day``.

	UTC has no DST, so every day has exactly one such slot and the result does
	not depend on the process time zone.
	"""
	return datetime(day.year, day.month, day.day, hour, 0, 0, tzinfo=UTC).timestamp()


def seconds_until_night_window(
	start_hour: int = 2,
	end_hour: int = 4,
	min_runtime: float = 300.0,
	now_ts: float | None = None,
) -> float:
	"""Calculate seconds until a jittered start time in the UTC night window.

	If currently inside the window with enough remaining time, returns 0.0
	to allow immediate start.
	"""
	now_time = time.time() if now_ts is None else now_ts
	today = datetime.fromtimestamp(now_time, UTC).date()

	start_today = utc_hour_timestamp(today, start_hour)
	end_today = utc_hour_timestamp(today, end_hour)

	if start_today <= now_time < end_today:
		remaining = end_today - now_time
		if remaining >= min_runtime:
			return 0.0
		# Too late in current window, defer to next day
		today += timedelta(days=1)

	start_next = utc_hour_timestamp(today, start_hour)
	if now_time >= start_next:
		today += timedelta(days=1)
		start_next = utc_hour_timestamp(today, start_hour)

	# Calculate delay with jitter (0-10 min)
	jitter = random.uniform(0.0, 600.0)  # noqa: S311  (timing jitter, not security-relevant)
	return max(0.0, (start_next - now_time) + jitter)


def seconds_until_next_day_window(
	start_hour: int = 2,
	now_ts: float | None = None,
) -> float:
	"""Seconds until the *next* calendar day's window start.

	Used after a run has already completed today: unlike
	:func:`seconds_until_night_window`, this never returns 0.0 while inside the
	current window, so the caller skips the rest of today's window instead of
	re-running back-to-back.
	"""
	now_time = time.time() if now_ts is None else now_ts
	tomorrow = datetime.fromtimestamp(now_time, UTC).date() + timedelta(days=1)
	start_next = utc_hour_timestamp(tomorrow, start_hour)
	jitter = random.uniform(0.0, 600.0)  # noqa: S311  (timing jitter, not security-relevant)
	return max(0.0, (start_next - now_time) + jitter)
