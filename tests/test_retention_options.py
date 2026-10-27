#!/usr/bin/env python3
#
# tests/test_retention_options.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Retention option sets: TSDB rejects keep-nothing, DNS/speedtest keep it (P3.3).

The TSDB storage layer coerces any retention below 1 day up to 1
(MIN_RETENTION_DAYS), so offering 0 at the setting is dishonest: it would
silently become 1. TSDB must therefore not list 0, while DNS-log and speedtest
retention legitimately support 0 (keep-nothing) and keep it.
"""

from __future__ import annotations

from app.db.sqlite_settings import (
	DNS_LOG_RETENTION_OPTIONS,
	SPEEDTEST_RETENTION_OPTIONS,
	TSDB_RETENTION_OPTIONS,
)


def test_tsdb_retention_excludes_keep_nothing():
	assert 0 not in TSDB_RETENTION_OPTIONS
	# The published long ranges stay available.
	assert TSDB_RETENTION_OPTIONS == (7, 30, 90, 180, 365)


def test_dns_and_speedtest_retention_keep_zero():
	assert 0 in DNS_LOG_RETENTION_OPTIONS
	assert 0 in SPEEDTEST_RETENTION_OPTIONS
