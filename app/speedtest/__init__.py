#!/usr/bin/env python3
#
# app/speedtest/__init__.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Lightweight bandwidth measurement module."""

from .guard import (
	DEFAULT_SPEEDTEST_COOLDOWN_SECONDS,
	SpeedtestBusyError,
	SpeedtestCooldownError,
	acquire_speedtest_run_lease,
)
from .tester import ProgressCallback, ProgressEvent, run_speedtest

__all__ = [
	"ProgressCallback",
	"ProgressEvent",
	"run_speedtest",
	"DEFAULT_SPEEDTEST_COOLDOWN_SECONDS",
	"SpeedtestBusyError",
	"SpeedtestCooldownError",
	"acquire_speedtest_run_lease",
]
