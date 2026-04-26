#!/usr/bin/env python3
#
# app/utils/speedtest_window.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Speedtest scheduling calculations shared between master and nodes."""

import random
import time
from datetime import datetime as dt, timedelta


def local_wall_clock_timestamp(day, hour: int) -> float:
    """Return the local timestamp for a wall-clock hour using system DST rules."""
    wall_time = dt(day.year, day.month, day.day, hour, 0, 0)
    return time.mktime(wall_time.timetuple())


def seconds_until_night_window(
    start_hour: int = 2,
    end_hour: int = 4,
    min_runtime: float = 300.0,
    now_ts: float | None = None,
) -> float:
    """Calculate seconds until a jittered start time in the local night window.
    
    If currently inside the window with enough remaining time, returns 0.0
    to allow immediate start.
    """
    now_time = time.time() if now_ts is None else now_ts
    now_local = dt.fromtimestamp(now_time)
    today = now_local.date()
    
    start_today = local_wall_clock_timestamp(today, start_hour)
    end_today = local_wall_clock_timestamp(today, end_hour)

    if start_today <= now_time < end_today:
        remaining = end_today - now_time
        if remaining >= min_runtime:
            return 0.0
        # Too late in current window, defer to next day
        today += timedelta(days=1)
    
    start_next = local_wall_clock_timestamp(today, start_hour)
    if now_time >= start_next:
        today += timedelta(days=1)
        start_next = local_wall_clock_timestamp(today, start_hour)
    
    # Calculate delay with jitter (0-10 min)
    jitter = random.uniform(0.0, 600.0)
    return max(0.0, (start_next - now_time) + jitter)
