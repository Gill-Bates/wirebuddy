#!/usr/bin/env python3
#
# app/utils/scheduler.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Lightweight async background scheduler for periodic tasks."""

from __future__ import annotations

import asyncio
import inspect
import logging
import random
import warnings
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
	func: Callable[[], object]
	run_on_start: bool = False
	initial_delay: float = 0.0
	timeout: float | None = None  # Per-job execution timeout (None = no limit)
	jitter_pct: float = 0.0  # Random jitter as percentage of interval (0.0 to 0.5)
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
		self._cancel_drain_task: asyncio.Task | None = None
		self._stop_event: asyncio.Event | None = None
		self._started = False

	def add(
		self,
		name: str,
		interval_seconds: float,
		func: Callable[[], object],
		*,
		run_on_start: bool = False,
		initial_delay: float = 0.0,
		timeout: float | None = None,
		jitter_pct: float = 0.0,
	) -> None:
		"""Register a periodic job.
		
		Args:
			name: Unique identifier for the job
			interval_seconds: Seconds between executions (minimum 1.0)
			func: Callable that must return an awaitable when invoked
			run_on_start: Execute once immediately on start (after initial_delay)
			initial_delay: Seconds to wait before first execution
			timeout: Per-execution timeout in seconds (None = no limit)
			jitter_pct: Random jitter as percentage of interval (0.0 to 0.5, e.g. 0.1 = ±10%)
		
		Raises:
			RuntimeError: If scheduler is already running
			ValueError: If name is duplicate or interval/timing inputs are invalid
			TypeError: If func is not callable
		"""
		if not callable(func):
			raise TypeError(f"func must be callable, got {type(func).__name__}")
		if not inspect.iscoroutinefunction(func):
			_log.warning(
				"SCHEDULER job=%s uses a non-coroutine callable; it must return an awaitable when called",
				name,
			)
		
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
		
		if not 0.0 <= jitter_pct <= 0.5:
			raise ValueError(f"jitter_pct must be between 0.0 and 0.5, got {jitter_pct}")
		
		self._jobs[name] = _Job(
			name=name,
			interval_seconds=interval_seconds,
			func=func,
			run_on_start=run_on_start,
			initial_delay=initial_delay,
			timeout=timeout,
			jitter_pct=jitter_pct,
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
			_log.debug("SCHEDULER job=%s interval=%.1fs started", job.name, job.interval_seconds)

	async def _await_cancelled_tasks(self, tasks: list[asyncio.Task]) -> None:
		"""Drain cancelled tasks to avoid pending-task warnings."""
		await asyncio.gather(*tasks, return_exceptions=True)

	def stop(self) -> None:
		"""Cancel all running jobs immediately (non-graceful).
		
		WARNING: NOT thread-safe. Must be called from the same thread as the
		event loop. Leaves unawaited cancelled tasks.
		
		DEPRECATED: Use stop_graceful() instead for proper async cleanup.
		This method exists only for emergency sync shutdown scenarios.
		"""
		warnings.warn(
			"Scheduler.stop() is deprecated; use await stop_graceful() instead",
			DeprecationWarning,
			stacklevel=2,
		)
		if not self._started:
			return
		
		self._started = False
		
		if self._stop_event is not None:
			self._stop_event.set()

		cancelled_tasks: list[asyncio.Task] = []
		for name, task in self._tasks.items():
			if not task.done():
				task.cancel()
				cancelled_tasks.append(task)
				_log.info("SCHEDULER job=%s stopped", name)

		if cancelled_tasks:
			loop: asyncio.AbstractEventLoop | None
			try:
				loop = asyncio.get_running_loop()
			except RuntimeError:
				loop = None
			if loop is not None:
				self._cancel_drain_task = loop.create_task(self._await_cancelled_tasks(cancelled_tasks))
			else:
				self._cancel_drain_task = None
		
		self._tasks.clear()
		self._stop_event = None

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
		self._cancel_drain_task = None
		self._stop_event = None
		_log.info("SCHEDULER stopped")

	@staticmethod
	def _compute_next_run(
		*,
		now: float,
		next_candidate: float,
		success: bool,
		consecutive_failures: int,
		interval_seconds: float,
		max_backoff: float,
		min_interval: float,
		jittered_interval: float,
		failure_jitter: float = 0.0,
	) -> tuple[float, int, float]:
		"""Compute next execution slot and updated failure state.

		Returns ``(next_run, consecutive_failures, backoff_seconds)`` where
		``backoff_seconds`` is ``0.0`` on success.
		"""
		if success:
			return now + jittered_interval, 0, 0.0

		updated_failures = consecutive_failures + 1
		backoff = min(2 ** updated_failures, max_backoff)
		backoff_until = now + backoff
		if next_candidate < backoff_until:
			skips = max(1, int((backoff_until - next_candidate) / interval_seconds) + 1)
			next_candidate += skips * interval_seconds
		next_candidate += failure_jitter
		return max(now + min_interval, next_candidate), updated_failures, backoff

	async def _run_loop(self, job: _Job) -> None:
		"""Internal loop that executes a job at its interval with retry/backoff."""
		stop_event = self._stop_event
		if stop_event is None:
			_log.debug("SCHEDULER job=%s exiting before start completed", job.name)
			return
		loop = asyncio.get_running_loop()
		
		def _jittered_interval() -> float:
			"""Return interval with random jitter applied."""
			if job.jitter_pct <= 0:
				return job.interval_seconds
			jitter_range = job.interval_seconds * job.jitter_pct
			return max(_MIN_INTERVAL, job.interval_seconds + random.uniform(-jitter_range, jitter_range))

		def _failure_jitter() -> float:
			"""Return additive jitter used only for failure rescheduling."""
			if job.jitter_pct <= 0:
				return 0.0
			jitter_range = job.interval_seconds * job.jitter_pct
			return random.uniform(-jitter_range, jitter_range)

		def _schedule_next(now: float, next_candidate: float, success: bool) -> float:
			"""Compute and log the next run slot using job-local scheduling context."""
			nonlocal consecutive_failures
			next_run_local, consecutive_failures, backoff = self._compute_next_run(
				now=now,
				next_candidate=next_candidate,
				success=success,
				consecutive_failures=consecutive_failures,
				interval_seconds=job.interval_seconds,
				max_backoff=max_backoff,
				min_interval=_MIN_INTERVAL,
				jittered_interval=_jittered_interval(),
				failure_jitter=_failure_jitter(),
			)
			if backoff > 0:
				_log.error(
					"SCHEDULER job=%s failed (%d consecutive), backing off %.0fs",
					job.name, consecutive_failures, backoff,
				)
			return next_run_local
		
		consecutive_failures = 0
		max_backoff: float = 300.0  # 5 minutes
		initial_interval = _jittered_interval()
		first_interval = job.initial_delay if job.initial_delay > 0 and not job.run_on_start else initial_interval
		next_run = loop.time() + first_interval
		
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
				next_run = _schedule_next(now, next_run, success)
				if success:
					_log.debug(
						"SCHEDULER job=%s completed initial run (run #%d), next in %.0fs",
						job.name, job.run_count, next_run - now,
					)
			else:
				# No run_on_start: log when first execution is scheduled
				_log.info(
					"SCHEDULER job=%s first run scheduled in %.0fs (%.1fh)",
					job.name, first_interval, first_interval / 3600,
				)

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
				next_run = _schedule_next(now, next_run, success)
				if success:
					_log.debug(
						"SCHEDULER job=%s completed (run #%d), next in %.0fs",
						job.name, job.run_count, next_run - now,
					)
		
		except asyncio.CancelledError:
			_log.debug("SCHEDULER job=%s cancelled", job.name)
		except Exception:
			_log.exception("SCHEDULER job=%s fatal error in run loop", job.name)

	def _create_job_awaitable(self, job: _Job) -> Awaitable[None]:
		"""Invoke a job and validate that it returned an awaitable."""
		result = job.func()
		if not inspect.isawaitable(result):
			raise TypeError(
				f"Job {job.name!r} must return an awaitable, got {type(result).__name__}"
			)
		return result

	async def _execute(self, job: _Job) -> bool:
		"""Execute a single job with error handling and optional timeout.
		
		Returns:
			True if execution succeeded, False if it failed or timed out
		"""
		try:
			_log.debug("SCHEDULER job=%s executing", job.name)
			awaitable = self._create_job_awaitable(job)

			if job.timeout is not None:
				await asyncio.wait_for(awaitable, timeout=job.timeout)
			else:
				await awaitable
			
			now = datetime.now(timezone.utc)
			job.last_success = now
			job.last_attempt = now
			job.run_count += 1
			return True
		except asyncio.CancelledError:
			job.last_attempt = datetime.now(timezone.utc)
			raise
		except asyncio.TimeoutError:
			job.last_attempt = datetime.now(timezone.utc)
			job.fail_count += 1
			limit = job.timeout if job.timeout is not None else 0.0
			_log.error("SCHEDULER job=%s timed out after %.1fs (fail #%d)", job.name, limit, job.fail_count)
			return False
		except Exception:
			job.last_attempt = datetime.now(timezone.utc)
			job.fail_count += 1
			_log.exception("SCHEDULER job=%s failed (fail #%d)", job.name, job.fail_count)
			return False

	def get_status(self) -> list[JobStatus]:
		"""Return status of all jobs (for monitoring/API).
		
		Safe to call from the scheduler's event-loop context.
		For cross-thread callers, schedule this via loop.call_soon_threadsafe().
		"""
		statuses: list[JobStatus] = []
		for job in self._jobs.values():
			task = self._tasks.get(job.name)
			statuses.append(
				{
					"name": job.name,
					"interval_seconds": job.interval_seconds,
					"last_success": job.last_success.isoformat() if job.last_success else None,
					"last_attempt": job.last_attempt.isoformat() if job.last_attempt else None,
					"is_running": task is not None and not task.done(),
					"run_count": job.run_count,
					"fail_count": job.fail_count,
				}
			)
		return statuses
