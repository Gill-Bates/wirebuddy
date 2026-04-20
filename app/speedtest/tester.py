#!/usr/bin/env python3
#
# app/speedtest/tester.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Bandwidth measurement via librespeed-cli.

Wraps the librespeed-cli binary (--json) for download, upload, ping and jitter
measurement.  Server selection is handled by librespeed-cli itself (nearest
server by ping RTT).

NOTE: librespeed-cli has TTY detection and behaves differently in non-TTY mode
(text output stops after server selection). Using --json mode avoids this issue
and provides reliable structured output.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import shlex
import shutil
from typing import Any, Callable, NotRequired, TypedDict

from ..utils.formatting import format_bandwidth_mbit

_log = logging.getLogger(__name__)

# Path probe at import time; runtime resolution is done per call.
LIBRESPEED_CLI = shutil.which("librespeed-cli")
if not LIBRESPEED_CLI:
	_log.warning("librespeed-cli not found in PATH at module load time")
	LIBRESPEED_CLI = "librespeed-cli"  # Fallback for error message clarity

# Default CLI flags tuned for VPN server monitoring:
# - 4 streams saturate the link better than the default 3
# - 8s duration: sweet spot between accuracy and resource usage
# - 4 MiB upload payload: default 1 MiB is too small for fast links
# - 30s HTTP timeout: allows for slow TLS handshakes and server selection
_DEFAULT_DURATION = 8
_DEFAULT_CONCURRENT = 4
_DEFAULT_UPLOAD_SIZE = 4096  # KiB
_DEFAULT_TIMEOUT = 30  # seconds (HTTP timeout, must exceed TLS handshake + server ping)
_STDERR_LOG_MAX = 500
_STDERR_MSG_MAX = 200
_PROCESS_CLEANUP_TIMEOUT_S = 5.0


class ProgressEvent(TypedDict):
	"""Progress event emitted during speedtest execution."""
	phase: str  # Current phase name
	progress: float  # 0.0 - 1.0
	message: str  # Human-readable status
	detail: NotRequired[dict[str, Any] | None]  # Optional extra data


# Type alias for progress callback
ProgressCallback = Callable[[ProgressEvent], None]


def _safe_float(value: Any) -> float | None:
	"""Safely convert value to float with explicit None on failure.
	
	Returning None (instead of 0.0) allows distinction between parsing errors
	and actual zero values. Also rejects NaN and infinity.
	"""
	try:
		result = float(value)
		if math.isnan(result) or math.isinf(result):
			return None
		return result
	except (TypeError, ValueError, AttributeError):
		return None


def _resolve_librespeed_cli() -> str | None:
	"""Resolve librespeed-cli path at runtime.

	Prefers the canonical binary name lookup each run and falls back to an
	explicit override stored in ``LIBRESPEED_CLI`` (useful for tests).
	"""
	resolved = shutil.which("librespeed-cli")
	if resolved:
		return resolved
	if LIBRESPEED_CLI and LIBRESPEED_CLI != "librespeed-cli":
		return shutil.which(LIBRESPEED_CLI)
	return None


def _fmt_speed(mbit: float) -> str:
	"""Format speed values consistently for progress messages."""
	return format_bandwidth_mbit(mbit, gbit_digits=2, mbit_digits=2)


def _error_result(msg: str, cb: ProgressCallback | None, *, skip_log: bool = False) -> dict[str, Any]:
	"""Create error result and emit error event.
	
	Args:
		msg: Error message
		cb: Progress callback to notify
		skip_log: Skip logging (if already logged with more detail)
	"""
	if not skip_log:
		_log.error("SPEEDTEST %s", msg)
	_emit(cb, "error", 1.0, msg)
	return {"status": "error", "reason": msg}


def _emit(cb: ProgressCallback | None, phase: str, progress: float, message: str, detail: dict[str, Any] | None = None) -> None:
	"""Emit a progress event if a callback is registered."""
	if cb is None:
		return
	event: ProgressEvent = {"phase": phase, "progress": progress, "message": message}
	if detail is not None:
		event["detail"] = detail
	try:
		cb(event)
	except Exception as exc:
		_log.debug("Progress callback failed: %s", exc)


async def run_speedtest(
	*,
	progress_callback: ProgressCallback | None = None,
	duration: int = _DEFAULT_DURATION,
	concurrent: int = _DEFAULT_CONCURRENT,
	upload_size: int = _DEFAULT_UPLOAD_SIZE,
) -> dict[str, Any]:
	"""Run a bandwidth measurement via librespeed-cli.

	Returns a dict with keys compatible with the existing TSDB/chart format::

		{
			"status": "ok",
			"server": "Nuremberg, Germany (4) (Hetzner)",
			"rtt_ms": 23.09,
			"jitter_ms": 1.64,
			"download_mbit": 120.39,
			"upload_mbit": 1.12,
		}

	On failure the dict contains ``"status": "error"`` and a ``"reason"`` key.
	
	Progress Events (time-based estimation since --json provides no live output):
		- init (0%): Starting
		- server_select (10-30%): Selecting server and running ping test
		- download (30-65%): Running download test  
		- upload (65-95%): Running upload test
		- complete (100%): Test finished
	"""
	_emit(progress_callback, "init", 0.0, "Starting librespeed-cli…")

	# Resolve binary at runtime (supports late installation and test overrides).
	resolved_cli = _resolve_librespeed_cli()
	if not resolved_cli:
		msg = "librespeed-cli not found in PATH"
		return _error_result(msg, progress_callback)

	# Use --json mode for reliable output (text mode has TTY detection issues)
	cmd = [
		resolved_cli,
		"--json",
		"--no-icmp",
		"--secure",
		"--duration", str(duration),
		"--concurrent", str(concurrent),
		"--upload-size", str(upload_size),
		"--timeout", str(_DEFAULT_TIMEOUT),
	]

	_log.info("SPEEDTEST cmd=%s", shlex.join(cmd))

	# Total timeout: HTTP timeout + test duration (download + upload) + margin
	process_timeout = _DEFAULT_TIMEOUT + (duration * 2) + 30

	_emit(progress_callback, "server_select", 0.10, "Selecting fastest server…")

	proc: asyncio.subprocess.Process | None = None
	progress_task: asyncio.Task[None] | None = None
	stdout_bytes = b""
	stderr_bytes = b""
	was_cancelled = False

	try:
		proc = await asyncio.create_subprocess_exec(
			*cmd,
			stdout=asyncio.subprocess.PIPE,
			stderr=asyncio.subprocess.PIPE,
		)

		# Start progress simulation task (time-based estimation)
		progress_task = asyncio.create_task(_emit_progress_simulation(progress_callback, duration))

		try:
			stdout_bytes, stderr_bytes = await asyncio.wait_for(
				proc.communicate(),
				timeout=process_timeout,
			)
		except asyncio.TimeoutError:
			msg = f"librespeed-cli process timeout ({process_timeout}s)"
			return _error_result(msg, progress_callback)
		except asyncio.CancelledError:
			was_cancelled = True
	except FileNotFoundError:
		msg = f"librespeed-cli not found at {resolved_cli}"
		return _error_result(msg, progress_callback)
	except OSError as exc:
		msg = f"Failed to start librespeed-cli: {exc}"
		return _error_result(msg, progress_callback)
	finally:
		if progress_task is not None:
			progress_task.cancel()
			try:
				await progress_task
			except asyncio.CancelledError:
				pass

		if proc is not None and proc.returncode is None:
			proc.kill()
			try:
				# Wait for process exit and drain pipes; shield so cancellation does not
				# interrupt cleanup and leave a zombie process behind.
				await asyncio.wait_for(
					asyncio.shield(proc.communicate()),
					timeout=_PROCESS_CLEANUP_TIMEOUT_S,
				)
			except (asyncio.TimeoutError, asyncio.CancelledError):
				pass

	if was_cancelled:
		raise asyncio.CancelledError

	if proc.returncode != 0:
		stderr_summary = stderr_bytes.decode("utf-8", errors="replace").strip()
		if stderr_summary:
			_log.error("SPEEDTEST stderr: %s", stderr_summary[:_STDERR_LOG_MAX])
		msg = f"librespeed-cli exited with code {proc.returncode}: {stderr_summary[:_STDERR_MSG_MAX]}"
		return _error_result(msg, progress_callback, skip_log=True)

	# Parse JSON output
	stdout_text = stdout_bytes.decode("utf-8", errors="replace").strip()
	try:
		data = json.loads(stdout_text)
	except (json.JSONDecodeError, ValueError) as exc:
		msg = f"Failed to parse JSON output: {exc}"
		_log.error("SPEEDTEST %s (raw=%s)", msg, stdout_text[:300])
		return _error_result(msg, progress_callback, skip_log=True)

	# librespeed-cli returns a JSON array with one element
	if isinstance(data, list):
		if not data:
			return _error_result("Empty result array from librespeed-cli", progress_callback)
		data = data[0]

	if not isinstance(data, dict):
		return _error_result(f"Unexpected JSON type: {type(data).__name__}", progress_callback)

	# Extract server name (may be dict or string depending on version)
	server_name = ""
	server_data = data.get("server", "")
	if isinstance(server_data, dict):
		server_name = server_data.get("name", "")
	elif isinstance(server_data, str):
		server_name = server_data

	# Extract metrics with validation
	download_mbit = _safe_float(data.get("download"))
	upload_mbit = _safe_float(data.get("upload"))
	rtt_ms = _safe_float(data.get("ping"))
	jitter_ms = _safe_float(data.get("jitter"))

	# Validate we got meaningful results
	if download_mbit is None and upload_mbit is None:
		return _error_result(
			"No download/upload speeds in JSON response",
			progress_callback
		)

	# Apply defaults for missing values and round
	download_mbit = round(download_mbit or 0.0, 2)
	upload_mbit = round(upload_mbit or 0.0, 2)
	rtt_ms = round(rtt_ms or 0.0, 2)
	jitter_ms = round(jitter_ms or 0.0, 2)

	_emit(
		progress_callback, "complete", 1.0,
		f"Complete: ↓ {_fmt_speed(download_mbit)} / ↑ {_fmt_speed(upload_mbit)}",
		{"download_mbit": download_mbit, "upload_mbit": upload_mbit},
	)

	_log.info(
		"SPEEDTEST server=%s dl=%.2f ul=%.2f rtt=%.2fms jitter=%.2fms",
		server_name, download_mbit, upload_mbit, rtt_ms, jitter_ms,
	)

	return {
		"status": "ok",
		"server": server_name,
		"rtt_ms": rtt_ms,
		"jitter_ms": jitter_ms,
		"download_mbit": download_mbit,
		"upload_mbit": upload_mbit,
	}


async def _emit_progress_simulation(
	cb: ProgressCallback | None,
	duration: int,
) -> None:
	"""Emit time-based progress events during speedtest execution.
	
	Since --json mode doesn't provide live output, we estimate progress based on
	expected timing:
	- Server selection: ~5s (progress 10-30%)
	- Download test: ~duration seconds (progress 30-65%)
	- Upload test: ~duration seconds (progress 65-95%)
	
	This provides better UX than a static progress bar while being honest that
	it's a time-based estimation.
	"""
	if cb is None:
		return
	
	# Estimated phase timings (in seconds)
	server_select_time = 5.0
	download_time = float(duration)
	upload_time = float(duration)
	
	phases = [
		# (start_progress, end_progress, duration, phase_name, message)
		(0.10, 0.30, server_select_time, "server_select", "Selecting fastest server…"),
		(0.30, 0.65, download_time, "download", "Running download test…"),
		(0.65, 0.95, upload_time, "upload", "Running upload test…"),
	]
	
	for start_pct, end_pct, phase_duration, phase_name, message in phases:
		steps = max(1, int(phase_duration * 2))  # ~2 updates per second
		step_duration = phase_duration / steps
		step_progress = (end_pct - start_pct) / steps
		
		for i in range(steps):
			progress = start_pct + (step_progress * i)
			_emit(cb, phase_name, progress, message)
			await asyncio.sleep(step_duration)
