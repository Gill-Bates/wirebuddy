#!/usr/bin/env python3
#
# app/dns/ingestion_tailer.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Log tailer for Unbound queries.log with crash recovery."""

from __future__ import annotations

import asyncio
import json
import logging
import queue
import time
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger(__name__)

# Constants
TAIL_INTERVAL = 0.2  # Seconds between tail checks
OFFSET_SAVE_INTERVAL = 5.0  # Seconds between offset persistence
CHUNK_LINE_LIMIT = 10_000  # Max lines to read per tail cycle (prevent OOM on huge logs)

__all__ = ["TailState", "OffsetTracker", "UnboundLogTailer"]


@dataclass
class TailState:
	"""Persistent state for log tailer."""
	inode: int
	offset: int


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
				
				# Use readline() instead of iterator to allow f.tell()
				for _ in range(CHUNK_LINE_LIMIT):
					line = f.readline()
					if not line:
						break  # EOF
					
					# Thread-safe queue put (stdlib queue.Queue is thread-safe)
					try:
						q.put_nowait(line)
						lines_read += 1
					except queue.Full:
						lines_dropped += 1
				else:
					# Chunk limit reached (loop completed without break)
					_log.debug("DNS_TAIL chunk limit reached, will continue next cycle")
				
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
