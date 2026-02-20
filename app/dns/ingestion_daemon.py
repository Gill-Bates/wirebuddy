#!/usr/bin/env python3
#
# app/dns/ingestion_daemon.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""DNS ingestion pipeline orchestrator."""

from __future__ import annotations

import asyncio
import queue
from collections.abc import Callable
from pathlib import Path

from .ingestion_tailer import OffsetTracker, UnboundLogTailer
from .ingestion_writer import DnsTsdbWriter

DNS_QUEUE_SIZE = 50_000  # Backpressure threshold

__all__ = ["run_dns_ingestion"]


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
