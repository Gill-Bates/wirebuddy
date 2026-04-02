#!/usr/bin/env python3
#
# app/dns/ingestion_daemon.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""DNS ingestion pipeline orchestrator."""

from __future__ import annotations

import asyncio
import logging
import queue
import time
from collections.abc import Callable
from pathlib import Path

from .ingestion_tailer import OffsetTracker, UnboundLogTailer
from .ingestion_writer import DnsTsdbWriter

_log = logging.getLogger(__name__)

DNS_QUEUE_SIZE = 50_000  # Backpressure threshold
SHUTDOWN_TIMEOUT = 10.0  # Seconds to wait for writer drain on shutdown
QUEUE_PRESSURE_THRESHOLD = 0.8  # Log warning when queue exceeds this fraction

__all__ = ["run_dns_ingestion"]


async def run_dns_ingestion(
	log_path: Path,
	offset_path: Path,
	dns_dir: Path,
	blocked_domains_func: Callable[[], set[str]],
	retention_days_func: Callable[[], int] | None = None,
	dns_logging_disabled_ips_func: Callable[[], set[str]] | None = None,
	tsdb_dir: Path | None = None,
) -> None:
	"""Start DNS ingestion pipeline (runs until cancelled).
	
	Architecture:
	- Uses queue.Queue (not asyncio.Queue) because both tailer and writer
	  run blocking I/O in thread pool via asyncio.to_thread()
	- This is a Thread→Thread bridge pattern, not async→async
	
	Shutdown semantics:
	- On cancellation, tailer is stopped first (no new data)
	- Writer drains remaining queue (checks stop_event + q.empty())
	- Timeout ensures clean exit if writer hangs
	
	Backpressure:
	- Queue is bounded (DNS_QUEUE_SIZE)
	- Tailer blocks on q.put() when queue is full (runs in thread, safe to block)
	- This preserves data integrity over throughput
	
	Args:
		log_path: Unbound queries.log path
		offset_path: Persistent offset file
		dns_dir: DNS base directory
		blocked_domains_func: Callable that returns set of blocked domains
		retention_days_func: Callable that returns DNS log retention days
		dns_logging_disabled_ips_func: Callable that returns set of IPs with DNS logging disabled
		tsdb_dir: Optional TSDB directory for aggregated metrics (enables fast trend queries)
	"""
	q: queue.Queue[str] = queue.Queue(maxsize=DNS_QUEUE_SIZE)
	offset_tracker = OffsetTracker(offset_path)
	stop_event = asyncio.Event()
	
	tailer = UnboundLogTailer(log_path, offset_tracker, stop_event)
	writer = DnsTsdbWriter(
		dns_dir,
		blocked_domains_func,
		retention_days_func,
		offset_tracker,
		stop_event,
		dns_logging_disabled_ips_func,
		tsdb_dir,
	)

	tailer_task = asyncio.create_task(tailer.start(q), name="dns-ingest-tailer")
	writer_task = asyncio.create_task(writer.run(q), name="dns-ingest-writer")
	
	# Monitor queue pressure periodically
	monitor_task = asyncio.create_task(
		_monitor_queue_pressure(q, stop_event),
		name="dns-ingest-monitor"
	)
	
	try:
		# Wait for first task to fail (exception isolation)
		done, pending = await asyncio.wait(
			[tailer_task, writer_task],
			return_when=asyncio.FIRST_EXCEPTION,
		)
		
		# Re-raise exception from failed task
		for task in done:
			if exc := task.exception():
				_log.error("DNS ingestion task failed: %s", task.get_name())
				# Cancel pending tasks before re-raising
				for pending_task in pending:
					pending_task.cancel()
				raise exc
		
		# Both completed successfully (shouldn't happen, pipeline runs forever)
		_log.warning("DNS ingestion pipeline exited unexpectedly")
		
	except asyncio.CancelledError:
		_log.info("DNS ingestion shutdown requested")
		
		# Signal graceful stop
		stop_event.set()
		
		# Stop tailer first (no new data)
		if not tailer_task.done():
			tailer_task.cancel()
			try:
				await tailer_task
			except asyncio.CancelledError:
				pass
		
		# Let writer drain remaining queue with timeout
		if not writer_task.done():
			try:
				await asyncio.wait_for(writer_task, timeout=SHUTDOWN_TIMEOUT)
				_log.info("DNS writer drained successfully")
			except asyncio.TimeoutError:
				_log.warning("DNS writer drain timeout, forcing cancellation (may lose last batch)")
				writer_task.cancel()
				try:
					await writer_task
				except asyncio.CancelledError:
					pass
		
		# Clean up monitor
		monitor_task.cancel()
		try:
			await monitor_task
		except asyncio.CancelledError:
			pass
		
		raise
	
	finally:
		# Ensure all tasks are cleaned up
		for task in (tailer_task, writer_task, monitor_task):
			if not task.done():
				task.cancel()
		await asyncio.gather(tailer_task, writer_task, monitor_task, return_exceptions=True)


async def _monitor_queue_pressure(q: queue.Queue[str], stop_event: asyncio.Event) -> None:
	"""Monitor queue pressure and log warnings when near capacity."""
	threshold = int(DNS_QUEUE_SIZE * QUEUE_PRESSURE_THRESHOLD)
	last_warning = 0.0
	warning_interval = 30.0  # seconds between warnings
	
	while not stop_event.is_set():
		try:
			size = q.qsize()
			if size >= threshold:
				now = time.monotonic()
				if now - last_warning > warning_interval:
					_log.warning(
						"DNS ingestion queue pressure high: %d/%d (%.1f%%)",
						size, DNS_QUEUE_SIZE, 100 * size / DNS_QUEUE_SIZE
					)
					last_warning = now
			await asyncio.sleep(1.0)
		except Exception:
			# Don't let monitor crash the pipeline
			_log.exception("DNS queue monitor error")
			await asyncio.sleep(5.0)
