#!/usr/bin/env python3
#
# tests/test_dns_ingestion_durability.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""DNS ingestion stays consistent across partial write failures.

Covers two durability fixes:

  P2.1 — TSDB minute-bucket aggregates must not be left permanently skewed
         when one of the two per-bucket counters fails to persist. The trend
         query SUMS all points in a bucket, so a retry must re-add nothing for
         a counter already written; a bucket is retained (not dropped) until
         both counters are durable.

  Offset writer — a forced offset save that fails is surfaced to the caller
         instead of being swallowed, so the writer retries instead of advancing
         past data whose durable offset was never written.
"""

from __future__ import annotations

import asyncio

from app.db import tsdb
from app.dns import ingestion_writer
from app.dns.ingestion_tailer import OffsetTracker
from app.dns.ingestion_writer import (
	DNS_METRIC_BLOCKED,
	DNS_METRIC_TOTAL,
	DNS_STATS_PEER_KEY,
	DnsTsdbWriter,
)


def _make_writer(tmp_path) -> DnsTsdbWriter:
	tsdb_dir = tmp_path / "tsdb"
	tsdb.init_tsdb(tsdb_dir)
	tracker = OffsetTracker(tmp_path / "offset.json")
	return DnsTsdbWriter(
		dns_dir=tmp_path / "dns",
		blocked_domains_func=set,
		retention_days_func=lambda: 7,
		offset_tracker=tracker,
		stop_event=asyncio.Event(),
		tsdb_dir=tsdb_dir,
	)


def _sum_metric(tsdb_dir, metric: str) -> int:
	points = tsdb.query(tsdb_dir, peer_key=DNS_STATS_PEER_KEY, metric=metric, limit=10_000)
	return sum(int(p.value) for p in points)


def test_aggregate_flush_writes_both_counters(tmp_path):
	writer = _make_writer(tmp_path)
	writer._minute_buckets = {"2026-04-01T12:05": {"total": 5, "blocked": 2}}

	writer._flush_tsdb_aggregates()

	assert writer._minute_buckets == {}
	assert _sum_metric(writer._tsdb_dir, DNS_METRIC_TOTAL) == 5
	assert _sum_metric(writer._tsdb_dir, DNS_METRIC_BLOCKED) == 2


def test_partial_failure_retains_bucket_without_double_counting(tmp_path, monkeypatch):
	writer = _make_writer(tmp_path)
	writer._minute_buckets = {"2026-04-01T12:05": {"total": 5, "blocked": 2}}

	real_append = tsdb.append_point

	def _fail_on_blocked(*args, **kwargs):
		if kwargs.get("metric") == DNS_METRIC_BLOCKED:
			raise OSError("simulated TSDB write failure")
		return real_append(*args, **kwargs)

	monkeypatch.setattr(ingestion_writer.tsdb, "append_point", _fail_on_blocked)
	writer._flush_tsdb_aggregates()

	# The bucket is retained, with the already-written total zeroed so a retry
	# re-adds nothing for it; only the blocked remainder is still pending.
	assert writer._minute_buckets == {"2026-04-01T12:05": {"total": 0, "blocked": 2}}
	assert _sum_metric(writer._tsdb_dir, DNS_METRIC_TOTAL) == 5
	assert _sum_metric(writer._tsdb_dir, DNS_METRIC_BLOCKED) == 0

	# Retry with a healthy TSDB: total must NOT be double-counted.
	monkeypatch.setattr(ingestion_writer.tsdb, "append_point", real_append)
	writer._flush_tsdb_aggregates()

	assert writer._minute_buckets == {}
	assert _sum_metric(writer._tsdb_dir, DNS_METRIC_TOTAL) == 5
	assert _sum_metric(writer._tsdb_dir, DNS_METRIC_BLOCKED) == 2


def test_unparseable_bucket_is_dropped_not_retained(tmp_path):
	writer = _make_writer(tmp_path)
	writer._minute_buckets = {"not-a-timestamp": {"total": 3, "blocked": 1}}

	writer._flush_tsdb_aggregates()

	assert writer._minute_buckets == {}


def test_save_if_needed_reports_persist_failure(tmp_path, monkeypatch):
	tracker = OffsetTracker(tmp_path / "offset.json")
	tracker.commit(inode=1, offset=100)

	def _boom(*args, **kwargs):
		raise OSError("disk full")

	# Force the atomic write to fail inside save_if_needed.
	monkeypatch.setattr("app.dns.ingestion_tailer.os.open", _boom)

	assert tracker.save_if_needed(force=True) is False


def test_save_if_needed_noop_returns_true(tmp_path):
	tracker = OffsetTracker(tmp_path / "offset.json")
	# Nothing committed → not dirty → no-op success.
	assert tracker.save_if_needed(force=True) is True
