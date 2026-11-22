#!/usr/bin/env python3
#
# tests/test_dns_ingestion_durability.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
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


def test_tailer_drains_rotated_file_beyond_chunk_limit_before_switching(tmp_path, monkeypatch):
	import queue

	from app.dns import ingestion_tailer
	from app.dns.ingestion_tailer import UnboundLogTailer

	monkeypatch.setattr(ingestion_tailer, "CHUNK_LINE_LIMIT", 5)
	log = tmp_path / "queries.log"
	log.write_text("".join(f"old-{i}\n" for i in range(12)))
	tailer = UnboundLogTailer(log, OffsetTracker(tmp_path / "offset.json"), asyncio.Event())
	q: queue.Queue = queue.Queue()

	tailer._tail_once(q)  # first cycle reads 5 of 12 old lines
	log.rename(tmp_path / "queries.log.1")  # rotation while 7 old lines are still unread
	log.write_text("".join(f"new-{i}\n" for i in range(3)))
	for _ in range(6):
		tailer._tail_once(q)

	seen = []
	while not q.empty():
		seen.append(q.get_nowait().line.strip())
	assert seen == [f"old-{i}" for i in range(12)] + [f"new-{i}" for i in range(3)]


def _write_day(tmp_path, entries: list[dict]) -> None:
	import json

	queries_dir = tmp_path / "dns" / "queries"
	queries_dir.mkdir(parents=True)
	(queries_dir / "2099-01-01.jsonl").write_text("".join(json.dumps(e) + "\n" for e in entries))


def test_read_recent_queries_empty_or_invalid_client_filter_returns_nothing(tmp_path):
	_write_day(tmp_path, [{"ts": "2099-01-01T00:00:00+00:00", "client": "10.0.0.2", "domain": "a.example"}])
	dns_dir = tmp_path / "dns"
	assert len(ingestion_writer.read_recent_queries(dns_dir, 10)) == 1  # None = no filter
	assert ingestion_writer.read_recent_queries(dns_dir, 10, set()) == []
	assert ingestion_writer.read_recent_queries(dns_dir, 10, {"not-an-ip"}) == []
	assert len(ingestion_writer.read_recent_queries(dns_dir, 10, {"10.0.0.2"})) == 1


def test_read_recent_queries_fills_limit_despite_duplicate_event_ids(tmp_path):
	# Partly failed flushes may rewrite entries with the same _event_id.
	entries = [{"ts": "2099-01-01T00:00:00+00:00", "client": "10.0.0.2", "domain": f"d{i}.example", "_event_id": f"e{i}"} for i in range(6)]
	_write_day(tmp_path, entries + entries[3:])  # last 3 duplicated at the end
	result = ingestion_writer.read_recent_queries(tmp_path / "dns", 5)
	assert [q["_event_id"] for q in result] == ["e5", "e4", "e3", "e2", "e1"]
