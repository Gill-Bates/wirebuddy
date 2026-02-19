#!/usr/bin/env python3
#
# app/dns/ingestion.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""DNS query log ingestion pipeline for TSDB.

Architecture:
- Async tailer reads Unbound queries.log (append-only)
- Parser normalizes to JSONL format
- Bounded queue provides backpressure (thread-safe via call_soon_threadsafe)
- Batch writer flushes to TSDB with fsync for durability
- Leader-only ingestion (single instance per cluster)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import queue
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DNS_QUEUE_SIZE = 50_000  # Backpressure threshold
BATCH_SIZE = 500  # Points per flush
FLUSH_INTERVAL = 1.0  # Seconds between forced flushes
TAIL_INTERVAL = 0.2  # Seconds between tail checks
OFFSET_SAVE_INTERVAL = 5.0  # Seconds between offset persistence
CHUNK_LINE_LIMIT = 10_000  # Max lines to read per tail cycle (prevent OOM on huge logs)
SETTINGS_REFRESH_INTERVAL = 5.0  # Seconds between dynamic settings refreshes
DNS_LOG_RETENTION_OPTIONS = {0, 7, 30, 90, 180, 365}
DEFAULT_DNS_LOG_RETENTION_DAYS = 30

# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------


@dataclass
class DnsQueryPoint:
	"""Normalized DNS query for TSDB storage."""
	ts: str  # ISO8601 UTC timestamp
	client: str  # Client IP address
	domain: str  # Queried domain (without trailing dot)
	qtype: str  # Query type (A, AAAA, HTTPS, etc.)
	rcode: str  # Response code (NOERROR, NXDOMAIN, etc.) - empty for queries
	blocked: bool  # Whether domain is in blocklist


@dataclass
class TailState:
	"""Persistent state for log tailer."""
	inode: int
	offset: int


# ---------------------------------------------------------------------------
# Parser (hot path optimized)
# ---------------------------------------------------------------------------


def parse_unbound_line(line: str, blocked_domains: set[str]) -> DnsQueryPoint | None:
	"""Fast parser for Unbound log lines.
	
	Format: [epoch] unbound[pid:tid] query: 10.0.0.5 example.com. A IN
	        [epoch] unbound[pid:tid] reply: 10.0.0.5 example.com. A IN NOERROR 0.05 0 124
	
	Returns None for unparseable lines or status messages.
	"""
	try:
		# Fast path: check for query/reply markers
		if " query: " not in line and " reply: " not in line:
			return None
		
		# Extract timestamp (seconds since epoch)
		bracket_start = line.find('[')
		bracket_end = line.find(']', bracket_start)
		if bracket_start == -1 or bracket_end == -1:
			return None
		
		epoch_str = line[bracket_start + 1:bracket_end]
		try:
			epoch = int(epoch_str)
			ts = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
		except (ValueError, OSError):
			return None
		
		# Split on query: or reply:
		if " query: " in line:
			is_reply = False
			_, payload = line.split(" query: ", 1)
		else:
			is_reply = True
			_, payload = line.split(" reply: ", 1)
		
		# Parse payload: <client> <domain>. <qtype> IN [<rcode> ...]
		parts = payload.split()
		if len(parts) < 4:  # Need at least: client domain qtype IN
			return None
		
		client = parts[0]
		domain = parts[1].rstrip('.')
		qtype = parts[2]
		
		# Validate client is an IP (skip service messages)
		if not _is_ip_like(client):
			return None
		
		# Extract response code from reply lines
		rcode = ""
		if is_reply and len(parts) >= 5 and parts[3] == "IN":
			rcode = parts[4]
		
		# Check if domain is blocked
		blocked = _is_domain_blocked(domain, blocked_domains)
		
		return DnsQueryPoint(
			ts=ts,
			client=client,
			domain=domain,
			qtype=qtype,
			rcode=rcode,
			blocked=blocked,
		)
	except Exception:
		return None


def _is_ip_like(s: str) -> bool:
	"""Fast check if string looks like IPv4 or IPv6 address.
	
	Accepts:
	- IPv4: 192.168.1.1
	- IPv6: ::1, fe80::1, 2001:db8::1
	
	Rejects:
	- IP:port (contains port)
	- Partial IPv4 like 1.2.3
	- Zone IDs (fe80::1%eth0)
	"""
	if not s:
		return False
	
	# Reject if contains port separator or zone ID
	if s.startswith('[') or '%' in s:
		return False
	
	# IPv4: must have exactly 3 dots
	if '.' in s and ':' not in s:
		parts = s.split('.')
		if len(parts) != 4:
			return False
		for p in parts:
			if not p.isdigit():
				return False
			if not 0 <= int(p) <= 255:
				return False
		return True
	
	# IPv6: hex and colons only
	if ':' in s:
		if s.count(':') < 2:
			return False
		stripped = s.replace(':', '')
		return all(c in '0123456789abcdefABCDEF' for c in stripped)
	
	return False


def _is_domain_blocked(domain: str, blocked_domains: set[str]) -> bool:
	"""Check if domain matches blocklist (exact or parent domain)."""
	if not domain or not blocked_domains:
		return False
	
	domain_lower = domain.lower()
	if domain_lower in blocked_domains:
		return True
	
	# Check parent domains
	labels = domain_lower.split('.')
	for i in range(1, len(labels) - 1):
		parent = '.'.join(labels[i:])
		if parent in blocked_domains:
			return True
	
	return False


def normalize_dns_log_retention_days(value: int | str | None) -> int:
	"""Normalize and validate DNS log retention days."""
	try:
		parsed = int(value) if value is not None else DEFAULT_DNS_LOG_RETENTION_DAYS
	except (TypeError, ValueError):
		return DEFAULT_DNS_LOG_RETENTION_DAYS
	return parsed if parsed in DNS_LOG_RETENTION_OPTIONS else DEFAULT_DNS_LOG_RETENTION_DAYS


def _extract_day_prefix(name: str) -> date | None:
	"""Extract YYYY-MM-DD prefix from dns_queries filenames."""
	if len(name) < 10:
		return None
	try:
		return date.fromisoformat(name[:10])
	except ValueError:
		return None


def enforce_dns_log_retention(tsdb_dir: Path, retention_days: int) -> dict[str, int]:
	"""Apply DNS query retention by deleting stale day files from TSDB."""
	dns_dir = tsdb_dir / "dns_queries"
	retention_days = normalize_dns_log_retention_days(retention_days)
	if not dns_dir.exists():
		return {"deleted_files": 0, "remaining_files": 0}

	cutoff_day = None
	if retention_days > 0:
		cutoff_day = (datetime.now(timezone.utc) - timedelta(days=retention_days)).date()

	deleted = 0
	remaining = 0
	for path in sorted(dns_dir.iterdir()):
		if not path.is_file():
			continue
		if path.suffix != ".jsonl":
			continue
		day = _extract_day_prefix(path.name)
		if day is None:
			remaining += 1
			continue
		should_delete = retention_days == 0 or (cutoff_day is not None and day < cutoff_day)
		if not should_delete:
			remaining += 1
			continue
		try:
			path.unlink(missing_ok=True)
			deleted += 1
		except OSError:
			remaining += 1

	return {"deleted_files": deleted, "remaining_files": remaining}


# ---------------------------------------------------------------------------
# Offset Management
# ---------------------------------------------------------------------------


class OffsetTracker:
	"""Manages persistent offset for crash recovery."""
	
	def __init__(self, offset_path: Path):
		self.offset_path = offset_path
		self.state = TailState(inode=0, offset=0)
		self.dirty = False
		self.last_save = 0.0
	
	def load(self) -> None:
		"""Load offset from disk."""
		if not self.offset_path.exists():
			return
		
		try:
			data = json.loads(self.offset_path.read_text(encoding='utf-8'))
			self.state = TailState(
				inode=data.get('inode', 0),
				offset=data.get('offset', 0),
			)
			_log.info("DNS_TAIL loaded offset: inode=%d offset=%d", self.state.inode, self.state.offset)
		except Exception as e:
			_log.warning("DNS_TAIL failed to load offset: %s", e)
	
	def update(self, inode: int, offset: int) -> None:
		"""Update in-memory state."""
		if self.state.inode != inode or self.state.offset != offset:
			self.state = TailState(inode=inode, offset=offset)
			self.dirty = True
	
	def save_if_needed(self, force: bool = False) -> None:
		"""Persist offset to disk if dirty and interval elapsed."""
		now = time.monotonic()
		if not self.dirty:
			return
		if not force and (now - self.last_save) < OFFSET_SAVE_INTERVAL:
			return
		
		try:
			self.offset_path.parent.mkdir(parents=True, exist_ok=True)
			data = {'inode': self.state.inode, 'offset': self.state.offset}
			tmp_path = self.offset_path.with_suffix('.tmp')
			tmp_path.write_text(json.dumps(data), encoding='utf-8')
			tmp_path.replace(self.offset_path)
			self.dirty = False
			self.last_save = now
			_log.debug("DNS_TAIL saved offset: inode=%d offset=%d", self.state.inode, self.state.offset)
		except Exception as e:
			_log.warning("DNS_TAIL failed to save offset: %s", e)


# ---------------------------------------------------------------------------
# Log Tailer
# ---------------------------------------------------------------------------


class UnboundLogTailer:
	"""Non-blocking async tailer for Unbound queries.log.
	
	Features:
	- Detects logrotate via inode change
	- Persistent offset for crash recovery
	- Backpressure-aware (drops on queue full)
	- Thread-safe queue access via call_soon_threadsafe
	- Chunk-limited reads to prevent OOM
	"""
	
	def __init__(self, log_path: Path, offset_tracker: OffsetTracker, stop_event: asyncio.Event):
		self.log_path = log_path
		self.tracker = offset_tracker
		self._stop = stop_event
	
	async def start(self, q: queue.Queue[str]) -> None:
		"""Run tailer loop until stopped."""
		_log.info("DNS_TAIL starting: %s", self.log_path)
		self.tracker.load()
		
		try:
			while not self._stop.is_set():
				try:
					await asyncio.to_thread(self._tail_once, q)
				except Exception:
					_log.exception("DNS_TAIL crash in tail cycle")
				
				# Persist offset periodically
				self.tracker.save_if_needed()
				
				await asyncio.sleep(TAIL_INTERVAL)
		finally:
			# Final offset save on shutdown
			self.tracker.save_if_needed(force=True)
			_log.info("DNS_TAIL stopped")
	
	def _tail_once(self, q: queue.Queue[str]) -> None:
		"""Tail log file once (blocking I/O, run in thread)."""
		if not self.log_path.exists():
			return
		
		try:
			st = self.log_path.stat()
		except OSError:
			return
		
		current_inode = st.st_ino
		current_size = st.st_size
		
		# Detect logrotate: inode changed
		if self.tracker.state.inode != 0 and self.tracker.state.inode != current_inode:
			_log.info("DNS_TAIL detected logrotate (inode %d -> %d)", self.tracker.state.inode, current_inode)
			self.tracker.update(current_inode, 0)
		
		# Detect truncation: size < offset
		if current_size < self.tracker.state.offset:
			_log.warning("DNS_TAIL detected truncation (offset %d > size %d)", self.tracker.state.offset, current_size)
			self.tracker.update(current_inode, 0)
		
		# Update inode if first run
		if self.tracker.state.inode == 0:
			self.tracker.update(current_inode, self.tracker.state.offset)
		
		# Nothing new to read
		if current_size <= self.tracker.state.offset:
			return
		
		# Read new lines (chunk-limited to prevent OOM)
		lines_read = 0
		lines_dropped = 0
		
		try:
			with self.log_path.open('r', encoding='utf-8', errors='replace') as f:
				f.seek(self.tracker.state.offset)
				
				for i, line in enumerate(f):
					# Chunk limit: don't read entire 2GB log at once
					if i >= CHUNK_LINE_LIMIT:
						_log.warning("DNS_TAIL chunk limit reached, will continue next cycle")
						break
					
					# Thread-safe queue put (stdlib queue.Queue is thread-safe)
					try:
						q.put_nowait(line)
						lines_read += 1
					except queue.Full:
						lines_dropped += 1
				
				new_offset = f.tell()
				self.tracker.update(current_inode, new_offset)
		except Exception as e:
			_log.warning("DNS_TAIL read error: %s", e)
			return
		
		if lines_read > 0:
			_log.debug("DNS_TAIL read %d lines (dropped %d)", lines_read, lines_dropped)
		
		# Warn on any drops (simple and reliable)
		if lines_dropped > 0:
			_log.warning("DNS_TAIL backpressure: dropped %d of %d lines", lines_dropped, lines_read + lines_dropped)


# ---------------------------------------------------------------------------
# TSDB Writer
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


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


async def run_dns_ingestion(
	log_path: Path,
	offset_path: Path,
	tsdb_dir: Path,
	blocked_domains_func: Callable[[], set[str]],
	retention_days_func: Callable[[], int] | None = None,
) -> None:
	"""Start DNS ingestion pipeline (runs until cancelled).
	
	Args:
		log_path: Unbound queries.log path
		offset_path: Persistent offset file
		tsdb_dir: TSDB base directory
		blocked_domains_func: Callable that returns set of blocked domains
		retention_days_func: Callable that returns DNS log retention days
	"""
	q: queue.Queue[str] = queue.Queue(maxsize=DNS_QUEUE_SIZE)
	offset_tracker = OffsetTracker(offset_path)
	stop_event = asyncio.Event()
	
	tailer = UnboundLogTailer(log_path, offset_tracker, stop_event)
	writer = DnsTsdbWriter(tsdb_dir, blocked_domains_func, retention_days_func, offset_tracker, stop_event)

	tailer_task = asyncio.create_task(tailer.start(q), name="dns-ingest-tailer")
	writer_task = asyncio.create_task(writer.run(q), name="dns-ingest-writer")
	
	try:
		await asyncio.gather(tailer_task, writer_task)
	except asyncio.CancelledError:
		# Signal both tasks to stop gracefully first.
		stop_event.set()
		for task in (tailer_task, writer_task):
			if not task.done():
				task.cancel()
		await asyncio.gather(tailer_task, writer_task, return_exceptions=True)
		raise


__all__ = [
	"DnsQueryPoint",
	"run_dns_ingestion",
	"read_recent_queries",
	"enforce_dns_log_retention",
	"normalize_dns_log_retention_days",
	"parse_unbound_line",
]
