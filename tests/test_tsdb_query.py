#!/usr/bin/env python3
#
# tests/test_tsdb_query.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""TSDB query honesty and bucketed aggregation (P2.1).

query() must never silently pretend it returned a full long-range window:
in strict mode an over-cap limit raises instead of being clamped, while the
default path keeps clamping (short-range callers rely on it) but now warns.
query_bucketed() serves long ranges by streaming raw points into fixed-width
buckets, so it is not bound by MAX_QUERY_POINTS.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from app.db import tsdb
from app.utils.time import utcnow

_KEY = "peer-under-test"
_METRIC = "rx_bytes"


def _seed(tmp_path: Path, count: int, *, span_hours: float, value: int = 1) -> None:
	now = utcnow()
	step = timedelta(hours=span_hours / max(count - 1, 1))
	for i in range(count):
		tsdb.append_point(tmp_path, peer_key=_KEY, metric=_METRIC, value=value, at=now - step * i)


def test_strict_limit_raises_above_cap(tmp_path: Path):
	_seed(tmp_path, 10, span_hours=1.0)
	with pytest.raises(ValueError, match="MAX_QUERY_POINTS"):
		tsdb.query(tmp_path, peer_key=_KEY, metric=_METRIC, limit=tsdb.MAX_QUERY_POINTS + 1, strict_limit=True)


def test_default_path_still_clamps_without_raising(tmp_path: Path):
	# The already-adapted country/DNS callers depend on the capped, non-raising
	# behaviour; this guards against a future unconditional raise.
	over_cap = tsdb.MAX_QUERY_POINTS + 50
	_seed(tmp_path, over_cap, span_hours=48.0)

	points = tsdb.query(tmp_path, peer_key=_KEY, metric=_METRIC, limit=100_000)
	assert len(points) == tsdb.MAX_QUERY_POINTS


def test_strict_limit_within_cap_does_not_raise(tmp_path: Path):
	_seed(tmp_path, 100, span_hours=2.0)
	points = tsdb.query(tmp_path, peer_key=_KEY, metric=_METRIC, limit=tsdb.MAX_QUERY_POINTS, strict_limit=True)
	assert len(points) == 100


def test_bucketed_sum_covers_full_window_beyond_cap(tmp_path: Path):
	# More raw points than the query cap, each value 1, spread over 10 hours.
	over_cap = tsdb.MAX_QUERY_POINTS + 500
	_seed(tmp_path, over_cap, span_hours=10.0, value=1)

	buckets = tsdb.query_bucketed(tmp_path, peer_key=_KEY, metric=_METRIC, bucket_seconds=3600, reducer="sum")

	# One point per hour-bucket (~11 buckets), far fewer than the cap, and the
	# summed values account for every seeded raw point (no truncation).
	assert 0 < len(buckets) <= 12
	assert sum(b.value for b in buckets) == over_cap
	# Bucketed coverage exceeds what the capped raw query can return.
	assert len(tsdb.query(tmp_path, peer_key=_KEY, metric=_METRIC, limit=100_000)) == tsdb.MAX_QUERY_POINTS


def test_bucketed_last_keeps_one_snapshot_per_bucket(tmp_path: Path):
	now = utcnow()
	# Two points a minute apart, in a wide (1-day) bucket; "last" keeps the newer.
	tsdb.append_point(tmp_path, peer_key=_KEY, metric=_METRIC, value=1, at=now - timedelta(minutes=2))
	tsdb.append_point(tmp_path, peer_key=_KEY, metric=_METRIC, value=2, at=now - timedelta(minutes=1))

	buckets = tsdb.query_bucketed(tmp_path, peer_key=_KEY, metric=_METRIC, bucket_seconds=86_400, reducer="last")
	# Both points can straddle a day boundary; the final (newest) value must win
	# in whichever bucket holds it, so the last bucket carries value 2.
	assert buckets[-1].value == 2


def test_bucketed_rejects_bad_arguments(tmp_path: Path):
	_seed(tmp_path, 5, span_hours=1.0)
	with pytest.raises(ValueError):
		tsdb.query_bucketed(tmp_path, peer_key=_KEY, metric=_METRIC, bucket_seconds=0, reducer="sum")
	with pytest.raises(ValueError):
		tsdb.query_bucketed(tmp_path, peer_key=_KEY, metric=_METRIC, bucket_seconds=60, reducer="median")


def test_reduce_fn_streams_all_points_and_string_reducers_stay_unchanged(tmp_path: Path):
	# Over the query cap: a custom reducer must see every raw point of the window.
	count = tsdb.MAX_QUERY_POINTS + 25
	_seed(tmp_path, count, span_hours=10.0, value=3)

	def _count_and_sum(acc, value):
		acc = acc or {"n": 0, "sum": 0}
		acc["n"] += 1
		acc["sum"] += value
		return acc

	custom = tsdb.query_bucketed(tmp_path, peer_key=_KEY, metric=_METRIC, bucket_seconds=10**6, reduce_fn=_count_and_sum)
	assert sum(p.value["n"] for p in custom) == count
	assert sum(p.value["sum"] for p in custom) == 3 * count

	# Built-in reducers behave exactly as before and reject unknown names.
	summed = tsdb.query_bucketed(tmp_path, peer_key=_KEY, metric=_METRIC, bucket_seconds=10**6, reducer="sum")
	assert sum(p.value for p in summed) == 3 * count
	assert tsdb.query_bucketed(tmp_path, peer_key=_KEY, metric=_METRIC, bucket_seconds=10**6, reducer="max")[0].value == 3
	with pytest.raises(ValueError):
		tsdb.query_bucketed(tmp_path, peer_key=_KEY, metric=_METRIC, bucket_seconds=60, reducer="median")
