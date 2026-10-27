#!/usr/bin/env python3
#
# tests/test_dns_trend_tsdb.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""DNS trend from the TSDB must cover the whole requested window.

The per-minute DNS counters used to be read with ``tsdb.query()``, which
clamps to ``MAX_QUERY_POINTS`` and silently dropped the oldest minutes of a
long window. The trend now streams through ``tsdb.query_bucketed()``; short
ranges must keep producing exactly the same buckets.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.api.dns import _compute_trend_data_tsdb_sync, _make_bucket_start
from app.db import tsdb
from app.dns.ingestion_writer import DNS_METRIC_BLOCKED, DNS_METRIC_TOTAL, DNS_STATS_PEER_KEY


def _seed(tmp_path: Path, minutes: int) -> None:
	"""Write one total (2) and, every third minute, one blocked (1) counter per minute."""
	base = datetime.now(UTC).replace(second=0, microsecond=0)
	for i in range(minutes):
		at = base - timedelta(minutes=i)
		tsdb.append_point(tmp_path, peer_key=DNS_STATS_PEER_KEY, metric=DNS_METRIC_TOTAL, value=2, at=at)
		if i % 3 == 0:
			tsdb.append_point(tmp_path, peer_key=DNS_STATS_PEER_KEY, metric=DNS_METRIC_BLOCKED, value=1, at=at)


def _reference_trend(tmp_path: Path, hours: int, bucket_minutes: int) -> dict[datetime, tuple[int, int]]:
	"""Bucket the raw points the straightforward way (valid while under the query cap)."""
	now = datetime.now(UTC)
	since = now - timedelta(hours=hours)
	bucket_start = _make_bucket_start(bucket_minutes)
	out: dict[datetime, list[int]] = {}
	for idx, metric in enumerate((DNS_METRIC_TOTAL, DNS_METRIC_BLOCKED)):
		for pt in tsdb.query(tmp_path, peer_key=DNS_STATS_PEER_KEY, metric=metric, since=since, until=now, limit=tsdb.MAX_QUERY_POINTS):
			out.setdefault(bucket_start(pt.ts), [0, 0])[idx] += int(pt.value)
	return {k: (v[0], v[1]) for k, v in out.items()}


def test_short_range_matches_raw_bucketing(tmp_path: Path):
	_seed(tmp_path, 180)

	data = _compute_trend_data_tsdb_sync(tmp_path, 4, 15)

	reference = _reference_trend(tmp_path, 4, 15)
	by_label = {datetime.fromisoformat(lbl): (t, b) for lbl, t, b in zip(data["labels"], data["total"], data["blocked"], strict=True)}
	for ts, counts in reference.items():
		assert by_label[ts] == counts
	assert sum(data["total"]) == 2 * 180
	assert sum(data["blocked"]) == 60
	assert data["hours"] == 4
	assert data["bucket_minutes"] == 15


def test_long_range_is_not_capped_at_query_limit(tmp_path: Path):
	# More one-minute points than MAX_QUERY_POINTS, over ~7.3 days, queried as 10 days.
	minutes = tsdb.MAX_QUERY_POINTS + 500
	_seed(tmp_path, minutes)

	data = _compute_trend_data_tsdb_sync(tmp_path, 240, 1440)

	assert sum(data["total"]) == 2 * minutes
	assert sum(data["blocked"]) == len(range(0, minutes, 3))
