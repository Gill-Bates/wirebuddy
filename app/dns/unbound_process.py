#!/usr/bin/env python3
#
# app/dns/unbound_process.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Unbound DNS process management (start, stop, restart, reload)."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from dataclasses import dataclass, field

from .unbound_constants import UNBOUND_CONF, UNBOUND_PID_FILE, run_exec

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_START_TIMEOUT = 3.0  # seconds
_START_POLL_INTERVAL = 0.15  # seconds
_IS_RUNNING_CACHE_TTL = 5.0  # seconds

# ---------------------------------------------------------------------------
# Process State
# ---------------------------------------------------------------------------

@dataclass
class _RunningState:
	"""State tracking for is_running() cache."""
	last_check: float = 0.0
	last_result: bool = False

	def invalidate(self) -> None:
		"""Force re-check on next is_running() call."""
		self.last_check = 0.0

	def is_stale(self, ttl: float = _IS_RUNNING_CACHE_TTL) -> bool:
		"""Check if cached result has expired."""
		return time.monotonic() - self.last_check >= ttl

	def update(self, result: bool) -> None:
		"""Update cache with new result."""
		self.last_result = result
		self.last_check = time.monotonic()

# Process handle for unbound daemon (to prevent zombie processes)
_unbound_proc: asyncio.subprocess.Process | None = None
_running_state = _RunningState()

# Lock for all state-changing operations to prevent race conditions
_proc_lock = asyncio.Lock()


# ---------------------------------------------------------------------------
# PID Management
# ---------------------------------------------------------------------------

def _read_unbound_pid() -> int | None:
	"""Read and parse unbound PID file."""
	try:
		raw = UNBOUND_PID_FILE.read_text(encoding="utf-8").strip()
		if not raw.isdigit():
			return None
		return int(raw)
	except Exception:
		return None


def _pid_is_running(pid: int) -> bool:
	"""Return True if the PID currently exists."""
	if pid <= 0:
		return False
	try:
		os.kill(pid, 0)
		return True
	except ProcessLookupError:
		return False
	except PermissionError:
		# Process exists but belongs to another user.
		# Relevant for is_running(); _kill_pid will fail gracefully.
		return True
	except Exception:
		return False


def _remove_stale_pid_file() -> None:
	"""Delete unbound PID file when it points to a dead process."""
	pid = _read_unbound_pid()
	if pid and _pid_is_running(pid):
		return
	try:
		UNBOUND_PID_FILE.unlink(missing_ok=True)
	except Exception:
		pass


async def _reap_managed_proc() -> None:
	"""Wait for managed unbound proc and clear the handle."""
	global _unbound_proc
	if _unbound_proc is None:
		return
	try:
		await _unbound_proc.wait()
	except Exception:
		pass
	_unbound_proc = None


async def _kill_pid(pid: int, *, timeout: float = 3.0) -> bool:
	"""SIGTERM then SIGKILL a PID; returns True when no longer running."""
	try:
		os.kill(pid, signal.SIGTERM)
	except ProcessLookupError:
		return True
	except Exception as exc:
		_log.debug("DNS_STOP failed to SIGTERM pid=%s: %s", pid, exc)

	deadline = time.monotonic() + timeout
	while time.monotonic() < deadline:
		if not _pid_is_running(pid):
			return True
		await asyncio.sleep(0.15)

	try:
		os.kill(pid, signal.SIGKILL)
	except ProcessLookupError:
		return True
	except Exception as exc:
		_log.debug("DNS_STOP failed to SIGKILL pid=%s: %s", pid, exc)
	await asyncio.sleep(0.3)
	return not _pid_is_running(pid)


# ---------------------------------------------------------------------------
# Running State
# ---------------------------------------------------------------------------

def invalidate_running_cache() -> None:
	"""Force the next is_running() call to re-check (after start/stop)."""
	_running_state.invalidate()


async def is_running() -> bool:
	"""Check if unbound is running (cached for 5 s to avoid subprocess spam).

	Fast path: PID file + os.kill(pid, 0) — no subprocess, ~0 ms.
	Slow path (fallback): pgrep — only when PID file is missing/stale.
	Both results are cached for ``_IS_RUNNING_CACHE_TTL`` seconds so that
	parallel requests (dashboard, peer list, QR, config) don't each spawn
	their own pgrep subprocess.
	"""
	if not _running_state.is_stale():
		return _running_state.last_result

	# Fast path: PID file check (pure syscall, no subprocess)
	pid = _read_unbound_pid()
	if pid and _pid_is_running(pid):
		_running_state.update(True)
		return True

	# Slow path: pgrep fallback (only when PID file is absent/stale)
	_remove_stale_pid_file()
	code, _, _ = await run_exec("pgrep", "-x", "unbound")
	result = code == 0
	_running_state.update(result)
	return result


# ---------------------------------------------------------------------------
# Supervisor Task
# ---------------------------------------------------------------------------

async def _supervise_unbound() -> None:
	"""Background task: reap managed unbound process on unexpected exit."""
	global _unbound_proc
	proc = _unbound_proc
	if proc is None:
		return
	try:
		await proc.wait()
	except Exception:
		pass
	# Only clear handle if it's still the same process we're supervising
	if _unbound_proc is proc:
		_unbound_proc = None
		invalidate_running_cache()
		_log.warning(
			"DNS_SUPERVISOR unbound exited unexpectedly (code=%s)",
			proc.returncode,
		)

# ---------------------------------------------------------------------------
# Process Control (Internal Implementations)
# ---------------------------------------------------------------------------

async def _start_impl() -> tuple[bool, str]:
	"""Start unbound (internal implementation without lock)."""
	from .unbound_config import write_config  # Avoid circular import
	
	global _unbound_proc
	invalidate_running_cache()
	
	# Reap stale managed process from previous run
	if _unbound_proc is not None and _unbound_proc.returncode is not None:
		await _reap_managed_proc()
	
	if await is_running():
		return True, "Unbound is already running"
	_remove_stale_pid_file()
	
	# Ensure config exists
	if not UNBOUND_CONF.exists():
		write_config()
	
	# First check config is valid
	code, _, stderr = await run_exec("unbound-checkconf", str(UNBOUND_CONF))
	if code != 0:
		return False, f"Config check failed: {stderr}"
	
	# Start unbound in foreground mode with stderr captured for diagnostics
	try:
		_unbound_proc = await asyncio.create_subprocess_exec(
			"unbound", "-d", "-c", str(UNBOUND_CONF),
			stdout=asyncio.subprocess.DEVNULL,
			stderr=asyncio.subprocess.PIPE,
			start_new_session=True,
		)

		deadline = time.monotonic() + _START_TIMEOUT
		while time.monotonic() < deadline:
			invalidate_running_cache()
			if await is_running():
				_log.info("DNS_START unbound started")
				# Start supervisor task to reap process on unexpected exit
				asyncio.create_task(
					_supervise_unbound(),
					name="unbound-supervisor",
				)
				return True, "Unbound started"
			if _unbound_proc.returncode is not None:
				# Process exited — capture stderr for diagnostics
				stderr_bytes = b""
				if _unbound_proc.stderr:
					try:
						stderr_bytes = await asyncio.wait_for(
							_unbound_proc.stderr.read(), timeout=1.0,
						)
					except Exception:
						pass
				detail = stderr_bytes.decode(errors="replace").strip()
				msg = f"Failed to start (exit code {_unbound_proc.returncode})"
				if detail:
					# Log full output, return last line to user
					_log.error("DNS_START stderr: %s", detail)
					last_line = detail.splitlines()[-1]
					msg += f": {last_line[:200]}"
				return False, msg
			await asyncio.sleep(_START_POLL_INTERVAL)

		return False, "Unbound failed to start (timeout)"
	except Exception as e:
		return False, f"Failed to start: {e}"


async def _stop_impl() -> tuple[bool, str]:
	"""Stop unbound (internal implementation without lock)."""
	invalidate_running_cache()

	# 1. Try managed process handle first
	if _unbound_proc is not None and _unbound_proc.returncode is None:
		if await _kill_pid(_unbound_proc.pid):
			await _reap_managed_proc()
			_remove_stale_pid_file()
			_log.info("DNS_STOP unbound stopped (managed proc)")
			return True, "Unbound stopped"

	# 2. Try PID file
	pid = _read_unbound_pid()
	if pid and _pid_is_running(pid):
		if await _kill_pid(pid):
			_remove_stale_pid_file()
			await _reap_managed_proc()
			_log.info("DNS_STOP unbound stopped (pid file)")
			return True, "Unbound stopped"

	# 3. Fallback: pgrep to find PID, then targeted kill
	code, stdout, _ = await run_exec("pgrep", "-x", "unbound")
	if code == 0:
		for line in stdout.strip().splitlines():
			if line.strip().isdigit():
				await _kill_pid(int(line.strip()))
		_remove_stale_pid_file()
		await _reap_managed_proc()
		invalidate_running_cache()
		if not await is_running():
			_log.info("DNS_STOP unbound stopped (pgrep fallback)")
			return True, "Unbound stopped"

	return False, "Failed to stop unbound"


async def _reload_impl() -> tuple[bool, str]:
	"""Reload unbound config (internal implementation without lock)."""
	pid = _read_unbound_pid()
	if pid and _pid_is_running(pid):
		try:
			os.kill(pid, signal.SIGHUP)
			_log.info("DNS_RELOAD config reloaded (pid=%d)", pid)
			return True, "Configuration reloaded"
		except ProcessLookupError:
			invalidate_running_cache()
			return False, "Reload failed: unbound is not running"
		except Exception as e:
			invalidate_running_cache()
			return False, f"Reload failed: {e}"

	invalidate_running_cache()
	code, _, stderr = await run_exec("pkill", "-HUP", "-x", "unbound")
	if code == 0:
		_log.info("DNS_RELOAD config reloaded")
		return True, "Configuration reloaded"
	return False, "Reload failed: unbound not running"

# ---------------------------------------------------------------------------
# Public API (with concurrency protection)
# ---------------------------------------------------------------------------

async def start() -> tuple[bool, str]:
	"""Start unbound."""
	async with _proc_lock:
		return await _start_impl()


async def stop() -> tuple[bool, str]:
	"""Stop unbound."""
	async with _proc_lock:
		return await _stop_impl()


async def restart() -> tuple[bool, str]:
	"""Restart unbound."""
	async with _proc_lock:
		await _stop_impl()
		return await _start_impl()


async def reload_config() -> tuple[bool, str]:
	"""Send SIGHUP to unbound to reload configuration."""
	async with _proc_lock:
		return await _reload_impl()


__all__ = [
	"invalidate_running_cache",
	"is_running",
	"start",
	"stop",
	"restart",
	"reload_config",
]
