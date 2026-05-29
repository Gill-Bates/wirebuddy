#!/usr/bin/env python3
#
# app/dns/ingestion_tailer.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Log tailer for Unbound queries.log with crash recovery."""

from __future__ import annotations

import asyncio
import json
import logging
import queue
import threading
import time
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger(__name__)

# Constants
TAIL_INTERVAL = 0.2  # Seconds between tail checks
OFFSET_SAVE_INTERVAL = 5.0  # Seconds between offset persistence
CHUNK_LINE_LIMIT = 10_000  # Max lines to read per tail cycle (prevent OOM on huge logs)

__all__ = ["TailItem", "TailState", "OffsetTracker", "UnboundLogTailer"]


@dataclass(slots=True)
class TailItem:
	"""One tailed log line with the durable offset after that line."""
	line: str
	inode: int
	end_offset: int


@dataclass(slots=True)
class TailState:
	"""Persistent state for log tailer."""
	inode: int
	offset: int


class OffsetTracker:
	"""Manages persistent offset for crash recovery."""
	
	def __init__(self, offset_path: Path):
		self.offset_path = offset_path
		self.state = TailState(inode=0, offset=0)
		self.read_state = TailState(inode=0, offset=0)
		self.dirty = False
		self.last_save = 0.0
		self._lock = threading.Lock()
		self._save_seq = 0
	
	def load(self) -> None:
		"""Load offset from disk."""
		if not self.offset_path.exists():
			return
		
		try:
			data = json.loads(self.offset_path.read_text(encoding='utf-8'))
			state = TailState(inode=data.get('inode', 0), offset=data.get('offset', 0))
			with self._lock:
				self.state = state
				self.read_state = TailState(inode=state.inode, offset=state.offset)
				self.dirty = False
				self._save_seq = 0
			_log.info("DNS_TAIL loaded offset: inode=%d offset=%d", self.state.inode, self.state.offset)
		except Exception as e:
			_log.warning("DNS_TAIL failed to load offset: %s", e)
	
	def current_read_state(self) -> TailState:
		"""Return the current in-memory read cursor."""
		with self._lock:
			return TailState(inode=self.read_state.inode, offset=self.read_state.offset)

	def advance_read(self, inode: int, offset: int) -> None:
		"""Advance the transient read cursor without committing it durably."""
		with self._lock:
			self.read_state = TailState(inode=inode, offset=offset)

	def commit(self, inode: int, offset: int) -> None:
		"""Commit a durably processed offset for later persistence."""
		with self._lock:
			if self.state.inode == inode and self.state.offset == offset:
				return
			self.state = TailState(inode=inode, offset=offset)
			self.dirty = True
			self._save_seq += 1
	
	def save_if_needed(self, force: bool = False) -> None:
		"""Persist offset to disk if dirty and interval elapsed."""
		now = time.monotonic()
		with self._lock:
			if not self.dirty:
				return
			if not force and (now - self.last_save) < OFFSET_SAVE_INTERVAL:
				return
			state = TailState(inode=self.state.inode, offset=self.state.offset)
			save_seq = self._save_seq
		
		try:
			parent = self.offset_path.parent
			parent.mkdir(parents=True, exist_ok=True)
			data = {'inode': state.inode, 'offset': state.offset}
			content = json.dumps(data)
			tmp_path = self.offset_path.with_suffix('.tmp')
			tmp_path.write_text(content, encoding='utf-8')
			try:
				tmp_path.replace(self.offset_path)
			except OSError:
				# Fallback: atomic replace can fail on some filesystems (overlayfs, Docker volumes).
				# Write directly instead.
				self.offset_path.write_text(content, encoding='utf-8')
				tmp_path.unlink(missing_ok=True)
			with self._lock:
				if self._save_seq == save_seq:
					self.dirty = False
				self.last_save = now
			_log.debug("DNS_TAIL saved offset: inode=%d offset=%d", state.inode, state.offset)
		except Exception as e:
			_log.warning("DNS_TAIL failed to save offset: %s", e)


def _put_with_shutdown(
	q: queue.Queue[TailItem],
	item: TailItem,
	stop_event: asyncio.Event,
) -> bool:
	"""Put an item into the queue unless shutdown was requested."""
	while not stop_event.is_set():
		try:
			q.put(item, timeout=0.25)
			return True
		except queue.Full:
			continue
	return False


class UnboundLogTailer:
	"""Non-blocking async tailer for Unbound queries.log.
	
	Features:
	- Detects logrotate via inode change
	- Persistent offset for crash recovery
	- Backpressure-aware (blocks when queue is full)
	- Thread-safe queue access (runs in thread pool)
	- Chunk-limited reads to prevent OOM
	"""
	
	def __init__(self, log_path: Path, offset_tracker: OffsetTracker, stop_event: asyncio.Event):
		self.log_path = log_path
		self.tracker = offset_tracker
		self._stop = stop_event
	
	async def start(self, q: queue.Queue[TailItem]) -> None:
		"""Run tailer loop until stopped."""
		_log.info("DNS_TAIL starting: %s", self.log_path)
		self.tracker.load()
		
		try:
			while not self._stop.is_set():
				try:
					await asyncio.to_thread(self._tail_once, q)
				except Exception:
					_log.exception("DNS_TAIL crash in tail cycle")
				
				await asyncio.sleep(TAIL_INTERVAL)
		finally:
			_log.info("DNS_TAIL stopped")
	
	def _tail_once(self, q: queue.Queue[TailItem]) -> None:
		"""Tail log file once (blocking I/O, run in thread)."""
		if not self.log_path.exists():
			return
		
		try:
			st = self.log_path.stat()
		except OSError:
			return
		
		current_inode = st.st_ino
		current_size = st.st_size
		
		read_state = self.tracker.current_read_state()

		# Detect logrotate: inode changed
		if read_state.inode != 0 and read_state.inode != current_inode:
			_log.info("DNS_TAIL detected logrotate (inode %d -> %d)", read_state.inode, current_inode)
			self.tracker.advance_read(current_inode, 0)
			read_state = self.tracker.current_read_state()
		
		# Detect truncation: size < offset
		if current_size < read_state.offset:
			_log.warning("DNS_TAIL detected truncation (offset %d > size %d)", read_state.offset, current_size)
			self.tracker.advance_read(current_inode, 0)
			read_state = self.tracker.current_read_state()
		
		# Update inode if first run
		if read_state.inode == 0:
			self.tracker.advance_read(current_inode, read_state.offset)
			read_state = self.tracker.current_read_state()
		
		# Nothing new to read
		if current_size <= read_state.offset:
			return
		
		# Read new lines (chunk-limited to prevent OOM)
		lines_read = 0
		blocked_time = 0.0
		
		try:
			with self.log_path.open('r', encoding='utf-8', errors='replace') as f:
				f.seek(read_state.offset)
				
				# Use readline() instead of iterator to allow f.tell()
				for _ in range(CHUNK_LINE_LIMIT):
					before = f.tell()
					line = f.readline()
					if not line:
						break  # EOF
					if not line.endswith('\n') and f.tell() >= current_size:
						f.seek(before)
						break
					end_offset = f.tell()
					item = TailItem(line=line, inode=current_inode, end_offset=end_offset)
					
					# Blocking put: prefer stalling over dropping data
					# Runs in thread pool, so blocking is safe here
					start = time.monotonic()
					if not _put_with_shutdown(q, item, self._stop):
						break
					delay = time.monotonic() - start
					if delay > 0.01:
						blocked_time += delay
					lines_read += 1
					self.tracker.advance_read(current_inode, end_offset)
				else:
					# Chunk limit reached (loop completed without break)
					_log.debug("DNS_TAIL chunk limit reached, will continue next cycle")
		except Exception as e:
			_log.warning("DNS_TAIL read error: %s", e)
			return
		
		if lines_read > 0:
			_log.debug("DNS_TAIL read %d lines", lines_read)
		
		# Log backpressure for observability (queue was full, we blocked)
		if blocked_time > 0.1:
			_log.warning("DNS_TAIL backpressure: blocked %.2fs while enqueuing %d lines", blocked_time, lines_read)
