#!/usr/bin/env python3
#
# app/dns/ingestion_writer.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Batch writer for DNS query ingestion."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import queue
import time
from collections import deque
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path

from .ingestion_parser import DnsQueryPoint, parse_unbound_line
from .ingestion_retention import DEFAULT_DNS_LOG_RETENTION_DAYS, normalize_dns_log_retention_days
from .ingestion_tailer import OffsetTracker
from .unbound_blocklist import get_custom_rules_cache
from ..db import tsdb
from ..utils.network import parse_ip_str

_log = logging.getLogger(__name__)

# Constants
BATCH_SIZE = 500  # Points per flush
FLUSH_INTERVAL = 1.0  # Seconds between forced flushes
SETTINGS_REFRESH_INTERVAL = 5.0  # Seconds between dynamic settings refreshes
MAX_BATCH_SIZE = 10_000  # Memory safety: drop oldest if exceeded
MAX_FLUSH_RETRIES = 3  # Clear batch after N consecutive failures
JSONL_SCHEMA_VERSION = 1  # For future schema migrations
MAX_DRAIN_TIME = 0.05  # Seconds: time-bound queue draining to avoid event loop starvation

# TSDB metric constants for DNS stats
DNS_STATS_PEER_KEY = "__dns_stats__"
DNS_METRIC_TOTAL = "queries_total"  # Counter: total DNS queries per minute bucket
DNS_METRIC_BLOCKED = "queries_blocked"  # Counter: blocked DNS queries per minute bucket

__all__ = ["DnsTsdbWriter", "read_recent_queries"]


class DnsTsdbWriter:
	"""Batch writer that flushes parsed DNS queries to TSDB.
	
	Features:
	- Batches writes for efficiency
	- Flushes on batch size or time interval
	- fsync for durability before offset commit
	- Graceful shutdown support
	- Per-peer DNS logging control
	
	Notes:
	- NOT thread-safe: assumes single writer execution (sequential to_thread calls)
	- Lossy under pressure: oldest entries dropped when batch exceeds MAX_BATCH_SIZE
	- Lossy on persistent failure: batch dropped after MAX_FLUSH_RETRIES consecutive failures
	"""
	
	def __init__(
		self,
		dns_dir: Path,
		blocked_domains_func: Callable[[], set[str]],
		retention_days_func: Callable[[], int] | None,
		offset_tracker: OffsetTracker,
		stop_event: asyncio.Event,
		dns_logging_disabled_ips_func: Callable[[], set[str]] | None = None,
		tsdb_dir: Path | None = None,
	):
		self.dns_dir = dns_dir
		self.blocked_domains_func = blocked_domains_func
		self.retention_days_func = retention_days_func
		self.tracker = offset_tracker
		self._stop = stop_event
		self._tsdb_dir = tsdb_dir
		# Use deque for O(1) append and efficient maxlen dropping (vs O(n) list delete)
		self.batch: deque[DnsQueryPoint] = deque(maxlen=MAX_BATCH_SIZE)
		self.last_flush: float = time.monotonic()
		self._blocked_domains: set[str] = set()
		self._custom_allow_rules: list = []
		self._custom_block_rules: list = []
		self._log_retention_days: int = DEFAULT_DNS_LOG_RETENTION_DAYS
		self._last_settings_refresh: float = 0.0
		self._consecutive_flush_failures: int = 0
		self._dns_logging_disabled_ips_func = dns_logging_disabled_ips_func
		self._dns_logging_disabled_ips: set[str] = set()
		# Minute-bucket aggregates for TSDB (key: ISO minute string, value: {total, blocked})
		self._minute_buckets: dict[str, dict[str, int]] = {}
	
	async def run(self, q: queue.Queue[str]) -> None:
		"""Run writer loop until stopped."""
		_log.info("DNS_WRITER starting")
		
		try:
			while True:
				try:
					processed = await asyncio.to_thread(self._drain_and_process, q)
					
					# Flush if needed
					if self._should_flush():
						await asyncio.to_thread(self._flush)

					# Graceful shutdown: drain remaining queue before exit.
					if self._stop.is_set():
						if not processed and q.empty():
							break
						continue

					if not processed:
						await asyncio.sleep(0.1)
				except Exception:
					_log.exception("DNS_WRITER crash in processing")
		finally:
			# Final flush on shutdown
			if self.batch:
				await asyncio.to_thread(self._flush)
			_log.info("DNS_WRITER stopped")
	
	def _maybe_refresh_settings(self) -> None:
		"""Refresh blocklist/retention settings at a fixed interval."""
		now = time.monotonic()
		if (now - self._last_settings_refresh) < SETTINGS_REFRESH_INTERVAL:
			return
		try:
			self._blocked_domains = self.blocked_domains_func()
		except Exception as e:
			_log.warning("DNS_WRITER failed to refresh blocklist: %s", e)
		try:
			self._custom_allow_rules, self._custom_block_rules = get_custom_rules_cache()
		except Exception as e:
			_log.warning("DNS_WRITER failed to refresh custom rules: %s", e)
		if self.retention_days_func is not None:
			try:
				self._log_retention_days = normalize_dns_log_retention_days(self.retention_days_func())
			except Exception as e:
				_log.warning("DNS_WRITER failed to refresh retention: %s", e)
		if self._dns_logging_disabled_ips_func is not None:
			try:
				self._dns_logging_disabled_ips = self._dns_logging_disabled_ips_func()
			except Exception as e:
				_log.warning("DNS_WRITER failed to refresh logging-disabled IPs: %s", e)
		self._last_settings_refresh = now

	def _drain_and_process(self, q: queue.Queue[str]) -> bool:
		"""Drain up to BATCH_SIZE lines from queue and process in one thread call.
		
		Time-bounded to avoid event loop starvation from expensive parsing.
		"""
		self._maybe_refresh_settings()
		processed = False
		start_time = time.monotonic()
		
		for _ in range(BATCH_SIZE):
			# Time-bound: prevent expensive parsing from blocking event loop
			if time.monotonic() - start_time > MAX_DRAIN_TIME:
				break
			
			try:
				line = q.get_nowait()
			except queue.Empty:
				break
			self._process_line(line)
			processed = True
		# Periodically save offset even when lines are skipped (no flush)
		if processed:
			self.tracker.save_if_needed(force=False)
		return processed

	def _process_line(self, line: str) -> None:
		"""Parse and add line to batch (called from thread worker)."""

		# "Keine Logs": skip persistence when retention=0.
		# Use force=False to avoid data loss if retention toggles back to >0 before offset flush.
		if self._log_retention_days == 0:
			self.tracker.save_if_needed(force=False)
			return
		
		point = parse_unbound_line(
			line,
			self._blocked_domains,
			allow_rules=self._custom_allow_rules or None,
			block_rules=self._custom_block_rules or None,
		)
		
		if not point:
			return
		
		# Only persist reply lines (skip queries)
		# Replies have rcode and represent actual DNS resolutions
		# Note: rcode=0 means NOERROR, which is valid - check for None explicitly
		if point.rcode is None:
			return
		
		# Skip logging for peers with DNS logging disabled
		if point.client in self._dns_logging_disabled_ips:
			return
		
		# deque with maxlen automatically drops oldest when full (O(1) operation)
		if len(self.batch) >= MAX_BATCH_SIZE:
			_log.warning("DNS_WRITER batch at capacity, oldest entry will be dropped")
		
		self.batch.append(point)
		
		# Update minute bucket aggregates for TSDB (independent of JSONL batching)
		# Extract minute bucket from ISO timestamp: "2026-04-01T12:05:23Z" -> "2026-04-01T12:05"
		minute_bucket = point.ts[:16] if len(point.ts) >= 16 else point.ts[:10] + "T00:00"
		if minute_bucket not in self._minute_buckets:
			self._minute_buckets[minute_bucket] = {"total": 0, "blocked": 0}
		self._minute_buckets[minute_bucket]["total"] += 1
		if point.blocked:
			self._minute_buckets[minute_bucket]["blocked"] += 1
	
	def _should_flush(self) -> bool:
		"""Check if batch should be flushed."""
		if not self.batch:
			return False
		
		# Throttle retries on consecutive failures to prevent busy loop
		if self._consecutive_flush_failures > 0:
			if time.monotonic() - self.last_flush < FLUSH_INTERVAL:
				return False
		
		if len(self.batch) >= BATCH_SIZE:
			return True
		
		if time.monotonic() - self.last_flush >= FLUSH_INTERVAL:
			return True
		
		return False
	
	def _flush(self) -> None:
		"""Write batch to TSDB with fsync for durability (blocking, run in thread)."""
		if not self.batch:
			return
		
		count = len(self.batch)
		start = time.monotonic()
		
		try:
			# Group by day for efficient writes
			by_day: dict[str, list[dict]] = {}
			
			for point in self.batch:
				# Extract date from ISO timestamp: 2026-02-19T10:15:23Z -> 2026-02-19
				# Use split() instead of slicing for robustness against format changes
				date_str = point.ts.split("T", 1)[0] if "T" in point.ts else point.ts[:10]
				
				entry = {
					'_v': JSONL_SCHEMA_VERSION,
					'ts': point.ts,
					'client': point.client,
					'domain': point.domain,
					'qtype': point.qtype,
					'rcode': point.rcode,
					'blocked': point.blocked,
				}
				# Only include custom_rule if True (saves space)
				if point.custom_rule:
					entry['custom_rule'] = True
				
				by_day.setdefault(date_str, []).append(entry)
			
			# Write each day's queries
			# NOTE: Partial flush failure can cause duplicates (first day written, second fails).
			# This is acceptable since downstream queries are idempotent (no aggregations).
			# Alternative: Use transaction log or single-file batches (adds complexity).
			for date_str, points in by_day.items():
				self._write_day_file(date_str, points)
			
			# Persist offset AFTER fsync (crash-safe ordering)
			self.tracker.save_if_needed(force=True)
			
			# Flush aggregated minute buckets to TSDB for fast trend queries
			self._flush_tsdb_aggregates()
			
			elapsed = time.monotonic() - start
			_log.debug("DNS_WRITER flushed %d queries in %.3fs (%d days)", count, elapsed, len(by_day))
			# Clear deque
			self.batch.clear()
			self._consecutive_flush_failures = 0
			# Update flush timer only on success
			self.last_flush = time.monotonic()
		except Exception:
			self._consecutive_flush_failures += 1
			if self._consecutive_flush_failures >= MAX_FLUSH_RETRIES:
				_log.error("DNS_WRITER flush failed %d times, dropping %d points", MAX_FLUSH_RETRIES, count)
				self.batch.clear()
				self._minute_buckets.clear()  # Clear aggregates when batch is dropped
				self._consecutive_flush_failures = 0
				# Still save offset to prevent re-reading dropped data on restart
				try:
					self.tracker.save_if_needed(force=True)
				except Exception:
					_log.warning("DNS_WRITER failed to save offset after dropping batch")
			else:
				_log.exception("DNS_WRITER flush failed, retaining %d points for retry (%d/%d)", count, self._consecutive_flush_failures, MAX_FLUSH_RETRIES)
			# Update last_flush on failure too, to enable throttled retries
			self.last_flush = time.monotonic()
	
	def _flush_tsdb_aggregates(self) -> None:
		"""Write minute bucket aggregates to TSDB for fast trend queries.
		
		Writes two separate counter metrics per bucket:
		- queries_total: total DNS queries
		- queries_blocked: blocked DNS queries
		
		Separate counters are more flexible than a single dict value:
		- Standard TSDB pattern (one integer per point)
		- No precision issues
		- UI computes blockrate from raw counters
		
		Best-effort: failures are logged but don't fail the main flush.
		TSDB provides read optimization; JSONL remains the primary durability layer.
		"""
		if not self._minute_buckets or not self._tsdb_dir:
			self._minute_buckets.clear()
			return
		
		bucket_count = len(self._minute_buckets)
		try:
			for minute_bucket, counts in self._minute_buckets.items():
				# Parse minute bucket to datetime for TSDB
				# Format: "2026-04-01T12:05" -> datetime
				try:
					bucket_dt = datetime.fromisoformat(minute_bucket + ":00+00:00")
				except ValueError:
					continue
				
				# Write total counter
				tsdb.append_point(
					self._tsdb_dir,
					peer_key=DNS_STATS_PEER_KEY,
					metric=DNS_METRIC_TOTAL,
					value=counts["total"],
					retention_days=self._log_retention_days,
					at=bucket_dt,
					sync=False,
				)
				# Write blocked counter
				tsdb.append_point(
					self._tsdb_dir,
					peer_key=DNS_STATS_PEER_KEY,
					metric=DNS_METRIC_BLOCKED,
					value=counts["blocked"],
					retention_days=self._log_retention_days,
					at=bucket_dt,
					sync=False,
				)
			_log.debug("DNS_WRITER flushed %d minute buckets to TSDB", bucket_count)
		except Exception as e:
			# Best-effort: log warning but don't fail the main flush
			_log.warning("DNS_WRITER failed to flush TSDB aggregates: %s", e)
		finally:
			self._minute_buckets.clear()
	
	def _write_day_file(self, date_str: str, points: list[dict]) -> None:
		"""Append points to day-specific JSONL file with fsync.
		
		Note: O(n) in number of points per batch, but append-only (no rewrite).
		Assumes single-writer process (no file locking).
		
		Performance consideration: Multiple day writes per flush = multiple fsyncs.
		This is expensive on SSD/cloud storage but necessary for durability.
		Optimization: Could batch writes to temp file then split, but adds complexity.
		"""
		day_dir = self.dns_dir / 'queries'
		day_dir.mkdir(parents=True, exist_ok=True)
		
		day_file = day_dir / f'{date_str}.jsonl'
		
		with day_file.open('a', encoding='utf-8') as f:
			for point in points:
				# Compact JSON format saves ~10% disk space
				f.write(json.dumps(point, separators=(',', ':')) + '\n')
			f.flush()
			os.fsync(f.fileno())  # Ensure data on disk before offset update


def _read_tail_lines(path: Path, max_lines: int) -> list[str]:
	"""Read up to *max_lines* from end of file without loading entire file."""
	if max_lines <= 0:
		return []

	# Use deque for O(1) prepend operations (vs O(n²) list concatenation)
	lines: deque[bytes] = deque()
	buffer = b""

	with path.open("rb") as f:
		f.seek(0, os.SEEK_END)
		position = f.tell()
		if position <= 0:
			return []

		chunk_size = 8192
		while position > 0 and len(lines) < max_lines:
			read_size = min(chunk_size, position)
			position -= read_size
			f.seek(position)
			chunk = f.read(read_size)
			if not chunk:
				break

			data = chunk + buffer
			parts = data.split(b"\n")
			buffer = parts[0]
			complete = parts[1:]
			if complete:
				# O(1) prepend with deque (vs O(n) list concatenation)
				lines.extendleft(reversed(complete))

		if position == 0 and buffer:
			lines.appendleft(buffer)

	# Drop synthetic trailing empty segment when file ends with '\n'.
	if lines and lines[-1] == b"":
			lines.pop()

	# Take last max_lines entries from deque
	decoded: list[str] = []
	for raw in list(lines)[-max_lines:]:
		decoded.append(raw.decode("utf-8", errors="replace"))
	return decoded


def _iter_lines_reverse(path: Path) -> Iterator[str]:
	"""Yield file lines newest-first without loading the whole file into memory."""
	with path.open("rb") as f:
		f.seek(0, os.SEEK_END)
		position = f.tell()
		if position <= 0:
			return

		buffer = b""
		chunk_size = 8192
		while position > 0:
			read_size = min(chunk_size, position)
			position -= read_size
			f.seek(position)
			chunk = f.read(read_size)
			if not chunk:
				break

			data = chunk + buffer
			parts = data.split(b"\n")
			buffer = parts[0]
			for raw in reversed(parts[1:]):
				if not raw:
					continue
				yield raw.decode("utf-8", errors="replace")

		if buffer:
			yield buffer.decode("utf-8", errors="replace")


def _normalize_client_filter(client_filter: set[str] | None) -> set[str] | None:
	"""Canonicalize filter IPs so IPv6 compression differences still match."""
	if not client_filter:
		return None
	normalized = set()
	for value in client_filter:
		candidate = parse_ip_str(value)
		if candidate:
			normalized.add(candidate)
		else:
			_log.warning("DNS_READ invalid client filter IP (ignored): %s", value)
	return normalized or None


def _query_matches_client_filter(query: dict, client_filter: set[str]) -> bool:
	"""Return True when a stored query belongs to one of the requested clients."""
	client_raw = str(query.get("client", "")).strip()
	if client_raw in client_filter:
		return True
	client = parse_ip_str(client_raw)
	return bool(client and client in client_filter)


def _parse_query_timestamp(raw: str) -> datetime | None:
	"""Parse stored ISO timestamps to UTC datetimes for cutoff checks."""
	value = str(raw or "").strip()
	if not value:
		return None
	try:
		if value.endswith("Z"):
			value = value[:-1] + "+00:00"
		dt = datetime.fromisoformat(value)
		if dt.tzinfo is None:
			return dt.replace(tzinfo=timezone.utc)
		return dt.astimezone(timezone.utc)
	except ValueError:
		return None


def read_recent_queries(
	dns_dir: Path,
	max_queries: int = 5000,
	client_filter: set[str] | None = None,
	since: datetime | None = None,
) -> list[dict]:
	"""Read recent DNS queries from DNS logs, newest first.
	
	Args:
		dns_dir: DNS base directory
		max_queries: Maximum number of queries to return
		client_filter: Optional set of client IPs to filter by
		since: Optional UTC cutoff; older entries are skipped and scanning stops early
	
	Returns:
		List of query dicts with keys: ts, client, domain, qtype, rcode, blocked.
		Order is timestamp-descending (newest first).
	"""
	if max_queries <= 0:
		return []

	queries_dir = dns_dir / 'queries'
	if not queries_dir.exists():
		return []
	
	queries: list[dict] = []
	remaining = max_queries
	normalized_filter = _normalize_client_filter(client_filter)
	since_utc = since.astimezone(timezone.utc) if since is not None else None
	since_day = since_utc.date().isoformat() if since_utc is not None else None
	
	# Get all day files sorted by date (newest first)
	# Explicit key ensures correct ordering regardless of path structure (YYYY-MM-DD format)
	day_files = sorted(queries_dir.glob('*.jsonl'), key=lambda p: p.stem, reverse=True)
	
	for day_file in day_files:
		if remaining <= 0:
			break
		if since_day is not None and day_file.stem < since_day:
			break
		
		try:
			if normalized_filter is None and since_utc is None:
				tail_lines = _read_tail_lines(day_file, remaining)
				# Parse in reverse order (newest first)
				for line in reversed(tail_lines):
					if remaining <= 0:
						break
					try:
						query = json.loads(line)
						queries.append(query)
						remaining -= 1
					except json.JSONDecodeError:
						continue
				continue

			if normalized_filter is None and since_utc is not None and day_file.stem > since_day:
				tail_lines = _read_tail_lines(day_file, remaining)
				for line in reversed(tail_lines):
					if remaining <= 0:
						break
					try:
						query = json.loads(line)
						queries.append(query)
						remaining -= 1
					except json.JSONDecodeError:
						continue
				continue

			stop_reading = False
			check_cutoff = since_utc is not None and day_file.stem == since_day
			for line in _iter_lines_reverse(day_file):
				if remaining <= 0:
					break
				try:
					query = json.loads(line)
				except json.JSONDecodeError:
					continue
				if check_cutoff:
					ts = _parse_query_timestamp(str(query.get("ts", "")))
					if ts is None:
						continue
					if ts < since_utc:
						stop_reading = True
						break
				if normalized_filter is not None and not _query_matches_client_filter(query, normalized_filter):
					continue
				queries.append(query)
				remaining -= 1
			if stop_reading:
				break
		except Exception as e:
			_log.warning("DNS_READ failed to read %s: %s", day_file, e)
			continue
	
	return queries
