#!/usr/bin/env python3
#
# tests/test_dns_ingestion_shutdown.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""A crashed DNS writer must not leave the tailer thread hanging forever (P2.2).

The tailer runs via ``asyncio.to_thread``, so ``Task.cancel()`` cannot interrupt
its blocking ``queue.put``. When the writer dies, nothing drains the 50k queue,
so the daemon must set the shared ``stop_event`` BEFORE cancelling the tailer;
``_put_with_shutdown`` then observes it on its next bounded put and the thread
exits. This drives ``run_dns_ingestion`` with a writer that crashes immediately
and a tailer that is wedged on a full queue, and asserts it returns promptly.
"""

from __future__ import annotations

import asyncio
import contextlib
import queue

import pytest

from app.dns import ingestion_daemon
from app.dns.ingestion_daemon import run_dns_ingestion
from app.dns.ingestion_tailer import TailItem, _put_with_shutdown


class _CrashingWriter:
	def __init__(self, *args, **kwargs):
		# Signature-compatible with DnsTsdbWriter; args are ignored.
		pass

	async def run(self, q):
		raise RuntimeError("simulated writer crash")


class _WedgedTailer:
	"""Tailer whose worker thread is stuck on a full queue until stop_event."""

	def __init__(self, log_path, offset_tracker, stop_event):
		self._stop = stop_event

	async def start(self, q: queue.Queue[TailItem]) -> None:
		# Fill the queue to capacity, then block exactly like the real tailer.
		item = TailItem(line="x", inode=1, end_offset=1)
		with contextlib.suppress(queue.Full):
			while True:
				q.put_nowait(item)
		# Runs in a worker thread; returns only once stop_event is observed.
		await asyncio.to_thread(_put_with_shutdown, q, item, self._stop)


def test_writer_crash_releases_wedged_tailer(monkeypatch, tmp_path):
	monkeypatch.setattr(ingestion_daemon, "DnsTsdbWriter", _CrashingWriter)
	monkeypatch.setattr(ingestion_daemon, "UnboundLogTailer", _WedgedTailer)
	# Tiny queue so the tailer wedges immediately.
	monkeypatch.setattr(ingestion_daemon, "DNS_QUEUE_SIZE", 2)

	async def _run():
		with pytest.raises(RuntimeError, match="simulated writer crash"):
			await run_dns_ingestion(
				log_path=tmp_path / "queries.log",
				offset_path=tmp_path / "offset.json",
				dns_dir=tmp_path / "dns",
				blocked_domains_func=set,
			)

	# If stop_event were not set before cancelling the tailer, the wedged
	# worker thread would block forever and this would hit the timeout.
	asyncio.run(asyncio.wait_for(_run(), timeout=8))
