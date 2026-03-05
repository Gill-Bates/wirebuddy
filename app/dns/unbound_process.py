#!/usr/bin/env python3
#
# app/dns/unbound_process.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Unbound DNS process management (start, stop, restart, reload)."""

from __future__ import annotations

import asyncio
import errno
import logging
import os
import shutil
import signal
import time
from dataclasses import dataclass

from .unbound_constants import UNBOUND_CONF, UNBOUND_PID_FILE, run_exec
from pathlib import Path

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_START_TIMEOUT = 3.0  # seconds
_START_POLL_INTERVAL = 0.15  # seconds
_IS_RUNNING_CACHE_TTL = 5.0  # seconds
_RESOLV_CONF = Path("/etc/resolv.conf")


# ---------------------------------------------------------------------------
# Binary Availability Check
# ---------------------------------------------------------------------------

# Cached result of unbound installation check (None = not yet checked)
_unbound_installed: bool | None = None


def is_unbound_installed() -> bool:
	"""Check if unbound binaries are available on the system.
	
	Result is cached after first check since binaries don't appear/disappear
	at runtime. This prevents repeated shutil.which() calls in the watchdog.
	"""
	global _unbound_installed
	if _unbound_installed is None:
		_unbound_installed = shutil.which("unbound") is not None and shutil.which("unbound-checkconf") is not None
		if not _unbound_installed:
			_log.warning("DNS_INIT unbound not installed, DNS features disabled")
	return _unbound_installed


def _configure_resolv_conf(wg_dns_ip: str | None = None) -> None:
	"""Configure /etc/resolv.conf to use local Unbound resolver.
	
	This ensures the container itself (not just VPN clients) can resolve DNS
	via the local Unbound instance. Required for update checks, blocklist
	downloads, and other outbound connections.
	
	Args:
		wg_dns_ip: WireGuard interface IP where Unbound is listening.
		           If None, reads from unbound.conf to find the first interface IP.
	"""
	# Determine which IP to use for DNS resolution
	dns_ip = wg_dns_ip
	if not dns_ip:
		# Try to read from unbound.conf to find the first interface IP
		try:
			if UNBOUND_CONF.exists():
				for line in UNBOUND_CONF.read_text(encoding="utf-8").splitlines():
					line = line.strip()
					if line.startswith("interface:"):
						ip = line.split(":", 1)[1].strip()
						# Skip localhost (would conflict with host DNS)
						if ip and ip not in ("127.0.0.1", "::1"):
							dns_ip = ip
							break
		except Exception as exc:
			_log.debug("DNS_RESOLV failed to read unbound.conf: %s", exc)
	
	if not dns_ip:
		_log.debug("DNS_RESOLV no WireGuard DNS IP available, skipping resolv.conf config")
		return
	
	try:
		# Read current content to check if already configured
		current = ""
		if _RESOLV_CONF.exists():
			current = _RESOLV_CONF.read_text(encoding="utf-8", errors="replace")
		
		# Only update if not already pointing to our DNS IP
		if f"nameserver {dns_ip}" in current:
			_log.debug("DNS_RESOLV /etc/resolv.conf already configured for %s", dns_ip)
			return
		
		# Write new resolv.conf with WireGuard DNS
		# Preserve search domains if present
		lines = [f"# Configured by WireBuddy for local Unbound DNS", f"nameserver {dns_ip}"]
		for line in current.splitlines():
			if line.strip().startswith("search ") or line.strip().startswith("domain "):
				lines.append(line.strip())
		
		# Atomic write using temporary file + rename to reduce TOCTOU window
		tmp_path = _RESOLV_CONF.with_suffix(".tmp")
		tmp_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
		tmp_path.replace(_RESOLV_CONF)
		_log.info("DNS_RESOLV configured /etc/resolv.conf to use %s", dns_ip)
	except PermissionError:
		_log.debug("DNS_RESOLV cannot write /etc/resolv.conf (read-only filesystem)")
	except OSError as exc:
		# EBUSY is expected in Docker host networking when resolv.conf is a mount
		if exc.errno == errno.EBUSY:
			_log.debug("DNS_RESOLV /etc/resolv.conf is mounted (host networking), skipping")
		else:
			_log.warning("DNS_RESOLV failed to configure /etc/resolv.conf: %s", exc)
	except Exception as exc:
		_log.warning("DNS_RESOLV failed to configure /etc/resolv.conf: %s", exc)

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
_supervisor_task: asyncio.Task | None = None
_running_state = _RunningState()

# Lock for all state-changing operations to prevent race conditions
_proc_lock = asyncio.Lock()
# Lock for status checks to avoid parallel pgrep storms when cache expires
_is_running_lock = asyncio.Lock()


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
	except FileNotFoundError:
		return None
	except OSError as exc:
		_log.debug("DNS_PID failed to read PID file: %s", exc)
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
	except Exception as exc:
		_log.debug("DNS_PID failed to remove stale PID file: %s", exc)


async def _reap_managed_proc() -> None:
	"""Wait for managed unbound proc and clear the handle."""
	global _unbound_proc, _supervisor_task
	if _unbound_proc is None:
		return
	try:
		await _unbound_proc.wait()
	except Exception as exc:
		_log.debug("DNS_REAP exception during wait: %s", exc)
	_unbound_proc = None
	if _supervisor_task is not None:
		if not _supervisor_task.done():
			_supervisor_task.cancel()
		_supervisor_task = None


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
	
	# Brief poll after SIGKILL for slow process termination
	kill_deadline = time.monotonic() + 1.0
	while time.monotonic() < kill_deadline:
		if not _pid_is_running(pid):
			return True
		await asyncio.sleep(0.15)
	return not _pid_is_running(pid)


# ---------------------------------------------------------------------------
# Running State
# ---------------------------------------------------------------------------

def invalidate_running_cache() -> None:
	"""Force the next is_running() call to re-check (after start/stop).
	
	NOTE: Not concurrency-safe in general, but safe in single-threaded asyncio
	because the mutation (setting a float) happens atomically between await points.
	External callers should prefer using start()/stop() which handle cache
	invalidation automatically under _proc_lock.
	"""
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

	async with _is_running_lock:
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
	global _unbound_proc, _supervisor_task
	proc = _unbound_proc
	if proc is None:
		_supervisor_task = None
		return
	try:
		await proc.wait()
	except Exception:
		pass
	# Acquire lock to safely clear the handle
	async with _proc_lock:
		# Only clear handle if it's still the same process we're supervising
		if _unbound_proc is proc:
			_unbound_proc = None
			invalidate_running_cache()
			_log.warning(
				"DNS_SUPERVISOR unbound exited unexpectedly (code=%s)",
				proc.returncode,
			)
	if _supervisor_task is asyncio.current_task():
		_supervisor_task = None


def _ensure_supervisor_task() -> None:
	"""Start (or restart) supervisor task for current managed process."""
	global _supervisor_task
	if _supervisor_task is not None and not _supervisor_task.done():
		return
	_supervisor_task = asyncio.create_task(
		_supervise_unbound(),
		name="unbound-supervisor",
	)

# ---------------------------------------------------------------------------
# Process Control (Internal Implementations)
# ---------------------------------------------------------------------------

async def _start_impl() -> tuple[bool, str]:
	"""Start unbound (internal implementation without lock)."""
	from .unbound_config import write_config  # Avoid circular import
	
	# Check if unbound is installed
	if not is_unbound_installed():
		return False, "Unbound is not installed"
	
	global _unbound_proc
	invalidate_running_cache()
	
	# Reap stale managed process from previous run
	if _unbound_proc is not None and _unbound_proc.returncode is not None:
		await _reap_managed_proc()
	
	if await is_running():
		return True, "Unbound is already running"
	_remove_stale_pid_file()
	
	# Ensure config exists (write minimal config without localhost binding
	# to avoid conflicts with host DNS in Docker host network mode)
	if not UNBOUND_CONF.exists():
		write_config(listen_addrs_ipv4=[])
	
	# First check config is valid (30s timeout for large blocklists)
	code, _, stderr = await run_exec("unbound-checkconf", str(UNBOUND_CONF), timeout=30.0)
	if code != 0:
		return False, f"Config check failed: {stderr}"
	
	# Start unbound in foreground mode
	# NOTE: stderr=DEVNULL to prevent pipe deadlock (Unbound logs continuously
	# and fills the pipe buffer if not drained; it already logs to its own file)
	try:
		_unbound_proc = await asyncio.create_subprocess_exec(
			"unbound", "-d", "-c", str(UNBOUND_CONF),
			stdout=asyncio.subprocess.DEVNULL,
			stderr=asyncio.subprocess.DEVNULL,
			start_new_session=True,
		)

		deadline = time.monotonic() + _START_TIMEOUT
		while time.monotonic() < deadline:
			invalidate_running_cache()
			if await is_running():
				_log.info("DNS_START unbound started")
				# Configure /etc/resolv.conf so container can use local DNS
				_configure_resolv_conf()
				# Start supervisor task to reap process on unexpected exit
				_ensure_supervisor_task()
				return True, "Unbound started"
			if _unbound_proc.returncode is not None:
				# Process exited during startup
				msg = f"Failed to start (exit code {_unbound_proc.returncode})"
				_log.error("DNS_START %s", msg)
				# Clean up dead process handle
				await _reap_managed_proc()
				return False, msg
			await asyncio.sleep(_START_POLL_INTERVAL)

		# Timeout: kill process before reaping to prevent deadlock
		if _unbound_proc is not None and _unbound_proc.returncode is None:
			await _kill_pid(_unbound_proc.pid)
		await _reap_managed_proc()
		return False, "Unbound failed to start (timeout)"
	except Exception as e:
		_log.exception("DNS_START unexpected error")
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

	invalidate_running_cache()
	if not await is_running():
		return True, "Unbound is not running"

	return False, "Failed to stop unbound"


async def _reload_impl() -> tuple[bool, str]:
	"""Reload unbound config (internal implementation without lock).
	
	Pre-validates config with unbound-checkconf before sending SIGHUP.
	If validation fails, returns error without reloading (prevents crash).
	"""
	# First validate config to prevent crash on reload
	code, _, stderr = await run_exec("unbound-checkconf", str(UNBOUND_CONF), timeout=30.0)
	if code != 0:
		error_msg = stderr.strip().split("\n")[-1] if stderr.strip() else "unknown error"
		_log.error("DNS_RELOAD config validation failed: %s", error_msg)
		return False, f"Config validation failed: {error_msg[:200]}"
	
	# Check PID file first, then fall back to managed process handle
	pid = _read_unbound_pid()
	if pid is None and _unbound_proc is not None and _unbound_proc.returncode is None:
		pid = _unbound_proc.pid
	
	if pid and _pid_is_running(pid):
		try:
			os.kill(pid, signal.SIGHUP)
			# Give unbound a moment to process the reload before declaring success
			await asyncio.sleep(0.5)
			# Verify it's still running after the reload
			if _pid_is_running(pid):
				_log.info("DNS_RELOAD config reloaded (pid=%d)", pid)
				return True, "Configuration reloaded"
			else:
				invalidate_running_cache()
				_log.error("DNS_RELOAD unbound crashed during reload (pid=%d)", pid)
				return False, "Unbound crashed during reload - will be auto-restarted by watchdog"
		except ProcessLookupError:
			invalidate_running_cache()
			return False, "Reload failed: unbound is not running"
		except Exception as e:
			invalidate_running_cache()
			return False, f"Reload failed: {e}"

	invalidate_running_cache()
	code, _, stderr = await run_exec("pkill", "-HUP", "-x", "unbound")
	if code == 0:
		await asyncio.sleep(0.5)
		invalidate_running_cache()
		if await is_running():
			_log.info("DNS_RELOAD config reloaded (pkill fallback)")
			return True, "Configuration reloaded"
		_log.error("DNS_RELOAD unbound not running after pkill fallback reload")
		return False, "Reload failed: unbound stopped after SIGHUP"
	return False, "Reload failed: unbound not running"

# ---------------------------------------------------------------------------
# Public API (with concurrency protection)
# ---------------------------------------------------------------------------

async def start() -> tuple[bool, str]:
	"""Start unbound."""
	async with _proc_lock:
		result = await _start_impl()
		if result[0]:
			# Reset watchdog failures on successful start
			reset_watchdog_failures()
		return result


async def stop() -> tuple[bool, str]:
	"""Stop unbound."""
	async with _proc_lock:
		return await _stop_impl()


async def restart() -> tuple[bool, str]:
	"""Restart unbound."""
	async with _proc_lock:
		await _stop_impl()
		result = await _start_impl()
		if result[0]:
			reset_watchdog_failures()
		return result


async def reload_config() -> tuple[bool, str]:
	"""Send SIGHUP to unbound to reload configuration."""
	async with _proc_lock:
		return await _reload_impl()


# ---------------------------------------------------------------------------
# Watchdog
# ---------------------------------------------------------------------------

# Consecutive restart failures before giving up (reset on success)
_MAX_WATCHDOG_FAILURES = 5
_watchdog_failures = 0


async def watchdog(should_be_running_func) -> None:
	"""Health check: restart unbound if it crashed unexpectedly.
	
	Args:
		should_be_running_func: Callable that returns True if DNS service
			is enabled (i.e., unbound should be running).
			Must be synchronous (not async).
	
	This is designed to be called periodically by the scheduler.
	It will only attempt restart if:
	1. Unbound binaries are installed
	2. DNS service is enabled (user hasn't manually disabled it)
	3. Unbound is not currently running
	4. We haven't exceeded max consecutive failures
	"""
	global _watchdog_failures
	
	# Skip if unbound is not installed
	if not is_unbound_installed():
		return
	
	# Check if DNS service should be running
	if not should_be_running_func():
		# User disabled DNS, don't auto-restart
		async with _proc_lock:
			_watchdog_failures = 0  # Reset failure counter
		return
	
	async with _proc_lock:
		# Check if already running (under lock to avoid TOCTOU with start/stop)
		if await is_running():
			_watchdog_failures = 0  # Reset on success
			return

		# Unbound is down but should be up
		if _watchdog_failures >= _MAX_WATCHDOG_FAILURES:
			# Too many failures, stop trying (prevent log spam)
			# Will reset if manually started or DNS toggled
			return

		_log.warning(
			"DNS_WATCHDOG unbound not running, attempting restart (attempt %d/%d)",
			_watchdog_failures + 1,
			_MAX_WATCHDOG_FAILURES,
		)

		ok, msg = await _start_impl()
		if ok:
			_log.info("DNS_WATCHDOG unbound restarted successfully")
			_watchdog_failures = 0
		else:
			_watchdog_failures += 1
			_log.error(
				"DNS_WATCHDOG restart failed (%d/%d): %s",
				_watchdog_failures,
				_MAX_WATCHDOG_FAILURES,
				msg,
			)
			if _watchdog_failures >= _MAX_WATCHDOG_FAILURES:
				_log.critical(
					"DNS_WATCHDOG max restart attempts reached, giving up. "
					"Manual intervention required."
				)


def reset_watchdog_failures() -> None:
	"""Reset the watchdog failure counter (called on manual start)."""
	global _watchdog_failures
	_watchdog_failures = 0


__all__ = [
	"invalidate_running_cache",
	"is_running",
	"is_unbound_installed",
	"start",
	"stop",
	"restart",
	"reload_config",
	"watchdog",
	"reset_watchdog_failures",
]
