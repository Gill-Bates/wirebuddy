#!/usr/bin/env python3
#
# app/dns/ingestion_writer.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""TSDB batch writer for DNS query ingestion."""

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

_log = logging.getLogger(__name__)

BATCH_SIZE = 500  # Points per flush
FLUSH_INTERVAL = 1.0  # Seconds between forced flushes
SETTINGS_REFRESH_INTERVAL = 5.0  # Seconds between dynamic settings refreshes

__all__ = ["DnsTsdbWriter", "read_recent_queries"]


class DnsTsdbWriter:
	"""Batch writer that flushes parsed DNS queries to TSDB.
	
	Features:
	- Batches writes for efficiency
	- Flushes on batch size or time interval
	- fsync for durability before offset commit
	- Graceful shutdown support
	"""
	
	def __init__(
		self,
		tsdb_dir: Path,
		blocked_domains_func: Callable[[], set[str]],
		retention_days_func: Callable[[], int] | None,
		offset_tracker: OffsetTracker,
		stop_event: asyncio.Event,
	):
		self.tsdb_dir = tsdb_dir
		self.blocked_domains_func = blocked_domains_func
		self.retention_days_func = retention_days_func
		self.tracker = offset_tracker
		self._stop = stop_event
		self.batch: list[DnsQueryPoint] = []
		self.last_flush: float = time.monotonic()
		self._blocked_domains: set[str] = set()
		self._log_retention_days: int = DEFAULT_DNS_LOG_RETENTION_DAYS
		self._last_settings_refresh: float = 0.0
	
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
		if self.retention_days_func is not None:
			try:
				self._log_retention_days = normalize_dns_log_retention_days(self.retention_days_func())
			except Exception as e:
				_log.warning("DNS_WRITER failed to refresh retention: %s", e)
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
		return processed

	def _process_line(self, line: str) -> None:
		"""Parse and add line to batch (called from thread worker)."""

		# "Keine Logs": parse but do not persist.
		if self._log_retention_days == 0:
			return
		
		point = parse_unbound_line(line, self._blocked_domains)
		
		if not point:
			return
		
		# Only persist reply lines (skip queries)
		# Replies have rcode and represent actual DNS resolutions
		if not point.rcode:
			return
		
		self.batch.append(point)
	
	def _should_flush(self) -> bool:
		"""Check if batch should be flushed."""
		if not self.batch:
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
				
				if date_str not in by_day:
					by_day[date_str] = []
				
				by_day[date_str].append({
					'ts': point.ts,
					'client': point.client,
					'domain': point.domain,
					'qtype': point.qtype,
					'rcode': point.rcode,
					'blocked': point.blocked,
				})
			
			# Write each day's queries with fsync
			for date_str, points in by_day.items():
				self._write_day_file(date_str, points)
			
			# Persist offset AFTER fsync (crash-safe ordering)
			self.tracker.save_if_needed(force=True)
			
			elapsed = time.monotonic() - start
			_log.info("DNS_WRITER flushed %d queries in %.3fs (%d days)", count, elapsed, len(by_day))
			self.batch.clear()
		except Exception:
			_log.exception("DNS_WRITER flush failed, retaining %d points for retry", count)
		finally:
			self.last_flush = time.monotonic()
	
	def _write_day_file(self, date_str: str, points: list[dict]) -> None:
		"""Append points to day-specific JSONL file with fsync.
		
		Note: O(n) in number of points per batch, but append-only (no rewrite).
		"""
		day_dir = self.tsdb_dir / 'dns_queries'
		day_dir.mkdir(parents=True, exist_ok=True)
		
		day_file = day_dir / f'{date_str}.jsonl'
		
		with day_file.open('a', encoding='utf-8') as f:
			for point in points:
				f.write(json.dumps(point) + '\n')
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


def read_recent_queries(tsdb_dir: Path, max_queries: int = 5000) -> list[dict]:
	"""Read recent DNS queries from TSDB, newest first.
	
	Args:
		tsdb_dir: TSDB base directory
		max_queries: Maximum number of queries to return
	
	Returns:
		List of query dicts with keys: ts, client, domain, qtype, rcode, blocked.
		Order is timestamp-descending (newest first).
	"""
	dns_dir = tsdb_dir / 'dns_queries'
	if not dns_dir.exists():
		return []
	
	queries: list[dict] = []
	remaining = max_queries
	
	# Get all day files sorted by date (newest first)
	day_files = sorted(dns_dir.glob('*.jsonl'), reverse=True)
	
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
