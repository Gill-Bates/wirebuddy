#!/usr/bin/env python3
#
# app/utils/scheduler.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Lightweight async background scheduler for periodic tasks."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable, TypedDict

_log = logging.getLogger(__name__)

__all__ = ["Scheduler", "JobStatus"]

# Minimum allowed interval to prevent CPU-pinning tight loops
_MIN_INTERVAL = 1.0


class JobStatus(TypedDict):
	"""Status information for a scheduled job."""
	name: str
	interval_seconds: float
	last_success: str | None  # ISO timestamp of last successful run
	last_attempt: str | None  # ISO timestamp of last attempt (success or failure)
	is_running: bool  # Task is active and not done
	run_count: int
	fail_count: int


@dataclass
class _Job:
	"""A scheduled repeating job (internal implementation detail)."""
	name: str
	interval_seconds: float
	func: Callable[[], Awaitable[None]]
	run_on_start: bool = False
	initial_delay: float = 0.0
	timeout: float | None = None  # Per-job execution timeout (None = no limit)
	last_success: datetime | None = None
	last_attempt: datetime | None = None
	run_count: int = 0
	fail_count: int = 0


class Scheduler:
	"""Simple async scheduler that runs jobs at fixed intervals.

	Usage::

		scheduler = Scheduler()
		scheduler.add("blocklist-update", 86400, update_blocklists, run_on_start=True)

		# In lifespan:
		await scheduler.start()   # on startup (async)
		await scheduler.stop_graceful()  # on shutdown (async)
	
	Note on restart: After stop() → start(), tasks are recreated but _Job objects
	retain their state (run_count, fail_count, last_success). This is intentional
	for continuity across restarts.
	"""

	def __init__(self) -> None:
		self._jobs: dict[str, _Job] = {}
		self._tasks: dict[str, asyncio.Task] = {}
		self._stop_event: asyncio.Event | None = None
		self._started = False

	def add(
		self,
		name: str,
		interval_seconds: float,
		func: Callable[[], Awaitable[None]],
		*,
		run_on_start: bool = False,
		initial_delay: float = 0.0,
		timeout: float | None = None,
	) -> None:
		"""Register a periodic job.
		
		Args:
			name: Unique identifier for the job
			interval_seconds: Seconds between executions (minimum 1.0)
			func: Async callable to execute
			run_on_start: Execute once immediately on start (after initial_delay)
			initial_delay: Seconds to wait before first execution (requires run_on_start=True)
			timeout: Per-execution timeout in seconds (None = no limit)
		
		Raises:
			RuntimeError: If scheduler is already running
			ValueError: If name is duplicate, interval is invalid, or initial_delay without run_on_start
		"""
		if self._started:
			raise RuntimeError(f"Cannot add job {name!r} while scheduler is running")
		
		if name in self._jobs:
			raise ValueError(f"Job {name!r} is already registered")
		
		if interval_seconds < _MIN_INTERVAL:
			raise ValueError(
				f"interval_seconds must be ≥ {_MIN_INTERVAL}, got {interval_seconds}"
			)
		
		if initial_delay < 0:
			raise ValueError(f"initial_delay must be ≥ 0, got {initial_delay}")
		
		if initial_delay > 0 and not run_on_start:
			raise ValueError("initial_delay requires run_on_start=True")
		
		self._jobs[name] = _Job(
			name=name,
			interval_seconds=interval_seconds,
			func=func,
			run_on_start=run_on_start,
			initial_delay=initial_delay,
			timeout=timeout,
		)

	def remove(self, name: str) -> None:
		"""Unregister a job. Only allowed when scheduler is stopped.
		
		Args:
			name: Name of the job to remove
		
		Raises:
			RuntimeError: If scheduler is currently running
			KeyError: If job does not exist
		"""
		if self._started:
			raise RuntimeError(f"Cannot remove job {name!r} while scheduler is running")
		
		if name not in self._jobs:
			raise KeyError(f"Job {name!r} not found")
		
		del self._jobs[name]
		_log.info("SCHEDULER job=%s removed", name)

	async def start(self) -> None:
		"""Start all registered jobs as background tasks.
		
		Must be called from within an async context (running event loop).
		"""
		if self._started:
			return
		
		self._started = True
		self._stop_event = asyncio.Event()
		
		for job in self._jobs.values():
			self._tasks[job.name] = asyncio.create_task(self._run_loop(job))
			_log.info("SCHEDULER job=%s interval=%ds started", job.name, job.interval_seconds)

	def stop(self) -> None:
		"""Cancel all running jobs immediately (non-graceful).
		
		WARNING: NOT thread-safe. Must be called from the same thread as the
		event loop. Leaves unawaited cancelled tasks.
		
		DEPRECATED: Use stop_graceful() instead for proper async cleanup.
		This method exists only for emergency sync shutdown scenarios.
		"""
		if not self._started:
			return
		
		self._started = False
		
		if self._stop_event is not None:
			self._stop_event.set()
		
		for name, task in self._tasks.items():
			if not task.done():
				task.cancel()
				_log.info("SCHEDULER job=%s stopped", name)
		
		self._tasks.clear()

	async def stop_graceful(self, timeout: float = 5.0) -> None:
		"""Gracefully stop all jobs, waiting up to timeout for clean exit.
		
		Phase 1: Set stop event and wait for tasks to finish gracefully.
		Phase 2: Cancel any stubborn tasks that didn't stop in time.
		
		Args:
			timeout: Maximum seconds to wait for tasks to finish gracefully
		"""
		if not self._started:
			return
		
		self._started = False
		
		# Signal all loops to stop (they should exit their while loops)
		if self._stop_event is not None:
			self._stop_event.set()
		
		# Phase 1: Wait for tasks to finish gracefully
		pending = [t for t in self._tasks.values() if not t.done()]
		if pending:
			_log.info("SCHEDULER waiting for %d tasks to finish gracefully", len(pending))
			done, not_done = await asyncio.wait(pending, timeout=timeout)
			
			# Phase 2: Force cancel stubborn tasks
			if not_done:
				_log.warning("SCHEDULER %d tasks did not stop gracefully, forcing cancel", len(not_done))
				for task in not_done:
					task.cancel()
				# Await cancelled tasks to prevent 'Task was destroyed' warnings
				await asyncio.gather(*not_done, return_exceptions=True)
		
		self._tasks.clear()
		_log.info("SCHEDULER stopped")

	async def _run_loop(self, job: _Job) -> None:
		"""Internal loop that executes a job at its interval with retry/backoff."""
		# Defense: _stop_event should always be set by start(), but assert for safety
		assert self._stop_event is not None, "Bug: _run_loop called without start()"
		stop_event = self._stop_event  # Local reference to avoid repeated None-checks
		loop = asyncio.get_running_loop()
		
		consecutive_failures = 0
		max_backoff = 300  # 5 minutes
		next_run = loop.time() + job.interval_seconds
		
		try:
			# Initial execution if requested
			if job.run_on_start:
				if job.initial_delay > 0:
					_log.debug("SCHEDULER job=%s waiting %.1fs before first run", job.name, job.initial_delay)
					try:
						await asyncio.wait_for(
							stop_event.wait(),
							timeout=job.initial_delay,
						)
						# Stop signaled during initial delay
						return
					except asyncio.TimeoutError:
						pass  # Initial delay elapsed, proceed

				if not self._started or stop_event.is_set():
					return

				success = await self._execute(job)
				now = loop.time()
				if success:
					consecutive_failures = 0
					next_run = now + job.interval_seconds
				else:
					consecutive_failures += 1
					backoff = min(2 ** consecutive_failures, max_backoff)
					_log.error(
						"SCHEDULER job=%s failed (%d consecutive), backing off %.0fs",
						job.name, consecutive_failures, backoff,
					)
					next_run = max(next_run, now + backoff)

			while self._started and not stop_event.is_set():
				now = loop.time()
				delay = max(0, next_run - now)
				
				try:
					# Wait for interval or stop signal
					await asyncio.wait_for(
						stop_event.wait(),
						timeout=delay,
					)
					# Stop signaled
					break
				except asyncio.TimeoutError:
					# Interval elapsed, execute job
					pass
				
				if not self._started or stop_event.is_set():
					break
				
				success = await self._execute(job)
				now = loop.time()
				
				if success:
					consecutive_failures = 0
					# Skip any missed intervals (prevents burst execution after long jobs)
					if next_run <= now:
						skipped = int((now - next_run) / job.interval_seconds)
						next_run += (skipped + 1) * job.interval_seconds
						if skipped > 0:
							_log.warning("SCHEDULER job=%s skipped %d intervals", job.name, skipped)
					else:
						next_run += job.interval_seconds
				else:
					# Job failed – apply exponential backoff
					consecutive_failures += 1
					backoff = min(2 ** consecutive_failures, max_backoff)
					_log.error(
						"SCHEDULER job=%s failed (%d consecutive), backing off %.0fs",
						job.name, consecutive_failures, backoff,
					)
					# Schedule next attempt after backoff
					# Keep original rhythm by computing next regular slot after backoff
					backoff_until = now + backoff
					while next_run < backoff_until:
						next_run += job.interval_seconds
		
		except asyncio.CancelledError:
			_log.debug("SCHEDULER job=%s cancelled", job.name)
		except Exception:
			_log.exception("SCHEDULER job=%s fatal error in run loop", job.name)

	async def _execute(self, job: _Job) -> bool:
		"""Execute a single job with error handling and optional timeout.
		
		Returns:
			True if execution succeeded, False if it failed or timed out
		"""
		try:
			_log.debug("SCHEDULER job=%s executing", job.name)
			
			if job.timeout is not None:
				await asyncio.wait_for(job.func(), timeout=job.timeout)
			else:
				await job.func()
			
			now = datetime.now(timezone.utc)
			job.last_success = now
			job.last_attempt = now
			job.run_count += 1
			_log.info("SCHEDULER job=%s completed (run #%d)", job.name, job.run_count)
			return True
		except asyncio.TimeoutError:
			job.last_attempt = datetime.now(timezone.utc)
			job.fail_count += 1
			_log.error("SCHEDULER job=%s timed out after %.1fs (fail #%d)", job.name, job.timeout, job.fail_count)
			return False
		except Exception:
			job.last_attempt = datetime.now(timezone.utc)
			job.fail_count += 1
			_log.exception("SCHEDULER job=%s failed (fail #%d)", job.name, job.fail_count)
			return False

	def get_status(self) -> list[JobStatus]:
		"""Return status of all jobs (for monitoring/API).
		
		Safe to call from any context. Does not access async task state.
		"""
		return [
			{
				"name": job.name,
				"interval_seconds": job.interval_seconds,
				"last_success": job.last_success.isoformat() if job.last_success else None,
				"last_attempt": job.last_attempt.isoformat() if job.last_attempt else None,
				"is_running": job.name in self._tasks and not self._tasks[job.name].done(),
				"run_count": job.run_count,
				"fail_count": job.fail_count,
			}
			for job in self._jobs.values()
		]
