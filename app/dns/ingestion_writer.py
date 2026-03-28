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
from collections.abc import Callable
from pathlib import Path

from .ingestion_parser import DnsQueryPoint, parse_unbound_line
from .ingestion_retention import DEFAULT_DNS_LOG_RETENTION_DAYS, normalize_dns_log_retention_days
from .ingestion_tailer import OffsetTracker
from .unbound_blocklist import get_custom_rules_cache

_log = logging.getLogger(__name__)

# Constants
BATCH_SIZE = 500  # Points per flush
FLUSH_INTERVAL = 1.0  # Seconds between forced flushes
SETTINGS_REFRESH_INTERVAL = 5.0  # Seconds between dynamic settings refreshes
MAX_BATCH_SIZE = 10_000  # Memory safety: drop oldest if exceeded
MAX_FLUSH_RETRIES = 3  # Clear batch after N consecutive failures
JSONL_SCHEMA_VERSION = 1  # For future schema migrations

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
	):
		self.dns_dir = dns_dir
		self.blocked_domains_func = blocked_domains_func
		self.retention_days_func = retention_days_func
		self.tracker = offset_tracker
		self._stop = stop_event
		self.batch: list[DnsQueryPoint] = []
		self.last_flush: float = time.monotonic()
		self._blocked_domains: set[str] = set()
		self._custom_allow_rules: list = []
		self._custom_block_rules: list = []
		self._log_retention_days: int = DEFAULT_DNS_LOG_RETENTION_DAYS
		self._last_settings_refresh: float = 0.0
		self._consecutive_flush_failures: int = 0
		self._dns_logging_disabled_ips_func = dns_logging_disabled_ips_func
		self._dns_logging_disabled_ips: set[str] = set()
	
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
		"""Drain up to BATCH_SIZE lines from queue and process in one thread call."""
		self._maybe_refresh_settings()
		processed = False
		for _ in range(BATCH_SIZE):
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

		# "Keine Logs": parse but do not persist, but still advance offset.
		# force=True ensures offset is persisted immediately to avoid re-reading on restart.
		if self._log_retention_days == 0:
			self.tracker.save_if_needed(force=True)
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
		
		self.batch.append(point)
		
		# Memory safety: drop oldest entries if batch grows too large
		if len(self.batch) > MAX_BATCH_SIZE:
			drop_count = len(self.batch) - MAX_BATCH_SIZE
			del self.batch[:drop_count]  # O(n) in-place delete, more efficient than slice copy
			_log.warning("DNS_WRITER dropped %d oldest entries (batch overflow)", drop_count)
	
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
				date_str = point.ts[:10]
				
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
			
			# Write each day's queries with fsync
			for date_str, points in by_day.items():
				self._write_day_file(date_str, points)
			
			# Persist offset AFTER fsync (crash-safe ordering)
			self.tracker.save_if_needed(force=True)
			
			elapsed = time.monotonic() - start
			_log.debug("DNS_WRITER flushed %d queries in %.3fs (%d days)", count, elapsed, len(by_day))
			self.batch.clear()
			self._consecutive_flush_failures = 0
			# Update flush timer only on success
			self.last_flush = time.monotonic()
		except Exception:
			self._consecutive_flush_failures += 1
			if self._consecutive_flush_failures >= MAX_FLUSH_RETRIES:
				_log.error("DNS_WRITER flush failed %d times, dropping %d points", MAX_FLUSH_RETRIES, count)
				self.batch.clear()
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
	
	def _write_day_file(self, date_str: str, points: list[dict]) -> None:
		"""Append points to day-specific JSONL file with fsync.
		
		Note: O(n) in number of points per batch, but append-only (no rewrite).
		Assumes single-writer process (no file locking).
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

	lines: list[bytes] = []
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
				lines = complete + lines

		if position == 0 and buffer:
			lines = [buffer] + lines

	# Drop synthetic trailing empty segment when file ends with '\n'.
	if lines and lines[-1] == b"":
		lines = lines[:-1]

	decoded: list[str] = []
	for raw in lines[-max_lines:]:
		decoded.append(raw.decode("utf-8", errors="replace"))
	return decoded


def read_recent_queries(dns_dir: Path, max_queries: int = 5000) -> list[dict]:
	"""Read recent DNS queries from DNS logs, newest first.
	
	Args:
		dns_dir: DNS base directory
		max_queries: Maximum number of queries to return
	
	Returns:
		List of query dicts with keys: ts, client, domain, qtype, rcode, blocked.
		Order is timestamp-descending (newest first).
	"""
	queries_dir = dns_dir / 'queries'
	if not queries_dir.exists():
		return []
	
	queries: list[dict] = []
	remaining = max_queries
	
	# Get all day files sorted by date (newest first)
	# Explicit key ensures correct ordering regardless of path structure (YYYY-MM-DD format)
	day_files = sorted(queries_dir.glob('*.jsonl'), key=lambda p: p.stem, reverse=True)
	
	for day_file in day_files:
		if remaining <= 0:
			break
		
		try:
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
		except Exception as e:
			_log.warning("DNS_READ failed to read %s: %s", day_file, e)
			continue
	
	return queries
