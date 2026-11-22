#!/usr/bin/env python3
#
# tests/test_tsdb_query.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
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


# ─── corrupt files, first prune, fsync cache (DB-layer review) ────────────────


def test_query_skips_corrupt_archive_and_invalid_utf8_but_keeps_readable_points(tmp_path: Path):
	import zlib

	_seed(tmp_path, 3, span_hours=1)
	series = tsdb._series_path(tmp_path, _KEY, _METRIC)
	# A gzip member whose deflate stream is damaged raises zlib.error while reading.
	import gzip

	good = gzip.compress(b'{"ts": "2020-01-01T00:00:00+00:00", "value": 7}\n' * 50)
	bad = good[:20] + bytes(b ^ 0xFF for b in good[20:40]) + good[40:]
	with pytest.raises((zlib.error, OSError, EOFError)):
		gzip.decompress(bad)
	(series.parent / (series.name + ".20200101T000000Z.gz")).write_bytes(bad)
	with series.open("ab") as f:  # undecodable bytes in the active file
		f.write(b"\xff\xfe not utf-8\n")
	points = tsdb.query(tmp_path, peer_key=_KEY, metric=_METRIC, limit=100)
	assert len(points) == 3


def test_prune_survives_invalid_utf8_in_active_file(tmp_path: Path):
	_seed(tmp_path, 2, span_hours=1)
	series = tsdb._series_path(tmp_path, _KEY, _METRIC)
	with series.open("ab") as f:
		f.write(b"\xff\xfe broken\n")
	assert tsdb._prune_series_locked(series, 30) is True
	assert len(tsdb.query(tmp_path, peer_key=_KEY, metric=_METRIC, limit=100)) == 2


def test_should_prune_runs_on_first_call_then_respects_interval(tmp_path: Path):
	series = tmp_path / "series.jsonl"
	assert tsdb._should_prune(series) is True  # freshly created marker is no prune history
	assert tsdb._should_prune(series) is False  # the claim just made now counts


def test_fsync_batch_cache_is_consistent_under_concurrent_eviction(tmp_path: Path, monkeypatch):
	import threading

	monkeypatch.setattr(tsdb, "_fsync_batch_state", tsdb._BoundedLRU(8))
	errors: list[BaseException] = []

	def _worker(n: int) -> None:
		try:
			for i in range(2000):
				tsdb._should_fsync_batch(tmp_path / f"s{n}-{i % 50}")
		except BaseException as exc:
			errors.append(exc)

	threads = [threading.Thread(target=_worker, args=(n,)) for n in range(8)]
	for t in threads:
		t.start()
	for t in threads:
		t.join()
	assert errors == []


# ─── UTC-only storage ────────────────────────────────────────────────────────
def test_append_point_rejects_naive_and_stores_utc(tmp_path: Path):
	from datetime import datetime, timezone

	with pytest.raises(ValueError, match="Naive"):
		tsdb.append_point(tmp_path, peer_key=_KEY, metric=_METRIC, value=1, at=datetime(2026, 6, 15, 12, 0, 0))  # noqa: DTZ001 - naive input is the case under test
	# A non-UTC aware instant is normalised to UTC on disk.
	plus_two = timezone(timedelta(hours=2))
	tsdb.append_point(tmp_path, peer_key=_KEY, metric=_METRIC, value=1, at=datetime(2026, 6, 15, 14, 0, tzinfo=plus_two))
	stored = tsdb._series_path(tmp_path, _KEY, _METRIC).read_text(encoding="utf-8")
	assert '"ts": "2026-06-15T12:00:00+00:00"' in stored


def test_query_skips_zone_less_lines(tmp_path: Path):
	"""A line without a zone is dropped instead of being read as local time."""
	import json

	now = utcnow()
	tsdb.append_point(tmp_path, peer_key=_KEY, metric=_METRIC, value=1, at=now)
	path = tsdb._series_path(tmp_path, _KEY, _METRIC)
	with path.open("a", encoding="utf-8") as handle:
		handle.write(json.dumps({"ts": "2026-06-15T12:00:00", "value": 99}) + "\n")
	points = tsdb.query(tmp_path, peer_key=_KEY, metric=_METRIC)
	assert [p.value for p in points] == [1]
	assert all(p.ts.tzinfo is not None and p.ts.utcoffset() == timedelta(0) for p in points)
