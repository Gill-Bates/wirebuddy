#!/usr/bin/env python3
#
# app/speedtest/tester.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Bandwidth measurement via librespeed-cli.

Wraps the librespeed-cli binary (--json) for download, upload, ping and jitter
measurement.  Server selection is handled by librespeed-cli itself (nearest
server by ping RTT).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import math
import shlex
import shutil
from typing import Any, Callable, NotRequired, TypedDict

from ..utils.formatting import format_bandwidth_mbit
from ..utils.geoip import resolve_country_from_url as _resolve_country_from_url
from ..utils.subprocess import run_command

_log = logging.getLogger(__name__)

# Default CLI flags tuned for VPN server monitoring:
_DEFAULT_DURATION = 8
_DEFAULT_CONCURRENT = 4
_DEFAULT_UPLOAD_SIZE = 4096  # KiB
_DEFAULT_TIMEOUT = 30  # seconds (HTTP timeout)
_PROGRESS_UPDATES_PER_SECOND = 2

# Explicit runtime override for tests.
_LIBRESPEED_CLI_OVERRIDE: str | None = None

class ProgressEvent(TypedDict):
    """Progress event emitted during speedtest execution."""
    phase: str  # Current phase name
    progress: float  # 0.0 - 1.0
    message: str  # Human-readable status
    detail: NotRequired[dict[str, Any] | None]  # Optional extra data

# Type alias for progress callback
ProgressCallback = Callable[[ProgressEvent], None]

def _safe_float(value: Any) -> float | None:
    """Safely convert value to float with explicit None on failure."""
    try:
        result = float(value)
        if not math.isfinite(result):
            return None
        return result
    except (TypeError, ValueError, AttributeError):
        return None

def _round_metric(value: float | None, ndigits: int = 2) -> float:
    """Round a metric, treating None as 0.0 for persistence and display."""
    return round(value if value is not None else 0.0, ndigits)

async def _lookup_country_from_url(server_url: str) -> str | None:
    """Resolve server URL to country code via GeoIP lookup (async-safe)."""
    if not server_url:
        return None
    return await asyncio.to_thread(_resolve_country_from_url, server_url)

def _resolve_librespeed_cli() -> str | None:
    """Resolve librespeed-cli path at runtime."""
    if _LIBRESPEED_CLI_OVERRIDE is not None:
        return _LIBRESPEED_CLI_OVERRIDE
    return shutil.which("librespeed-cli")

def _error_result(
    msg: str,
    cb: ProgressCallback | None,
    *,
    log_level: int = logging.ERROR,
    stderr: str | None = None,
) -> dict[str, Any]:
    """Create error result and emit error event."""
    if stderr:
        _log.log(log_level, "SPEEDTEST error: %s (stderr: %s)", msg, stderr[:200])
    else:
        _log.log(log_level, "SPEEDTEST %s", msg)
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
    """Run a bandwidth measurement via librespeed-cli."""
    _emit(progress_callback, "init", 0.0, "Starting librespeed-cli\u2026")

    resolved_cli = _resolve_librespeed_cli()
    if not resolved_cli:
        return _error_result("librespeed-cli not found in PATH", progress_callback, log_level=logging.WARNING)

    cmd = [
        resolved_cli, "--json", "--no-icmp", "--secure",
        "--duration", str(duration),
        "--concurrent", str(concurrent),
        "--upload-size", str(upload_size),
        "--timeout", str(_DEFAULT_TIMEOUT),
    ]

    _log.info("SPEEDTEST cmd=%s", shlex.join(cmd))
    timeout = _DEFAULT_TIMEOUT + (duration * 2) + 30

    _emit(progress_callback, "server_select", 0.10, "Selecting fastest server\u2026")

    progress_task: asyncio.Task[None] | None = None
    try:
        if progress_callback:
            progress_task = asyncio.create_task(_emit_progress_simulation(progress_callback, duration))
        
        res = await run_command(*cmd, timeout=timeout)
        
        if res.returncode != 0:
            return _error_result(f"librespeed-cli exited with code {res.returncode}", progress_callback, stderr=res.stderr)

        # Parse JSON output
        stdout = res.stdout.strip()
        if len(stdout) > 5_000_000:
            return _error_result("CLI output unexpectedly large", progress_callback)
        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                data = data[0] if data else {}
        except json.JSONDecodeError as exc:
            return _error_result(f"Failed to parse JSON output: {exc}", progress_callback)

        if not isinstance(data, dict):
            return _error_result(f"Unexpected JSON type: {type(data).__name__}", progress_callback)

        # Extract server info
        server_name = ""
        server_url = ""
        server_data = data.get("server", "")
        if isinstance(server_data, dict):
            server_name = server_data.get("name", "")
            server_url = server_data.get("url", "")
        else:
            server_name = str(server_data)

        # Country lookup (async-safe)
        country_code = await _lookup_country_from_url(server_url)

        # Extract and validate metrics
        metrics = {
            "download_mbit": _round_metric(_safe_float(data.get("download"))),
            "upload_mbit": _round_metric(_safe_float(data.get("upload"))),
            "rtt_ms": _round_metric(_safe_float(data.get("ping"))),
            "jitter_ms": _round_metric(_safe_float(data.get("jitter"))),
        }

        if metrics["download_mbit"] == 0 and metrics["upload_mbit"] == 0:
            return _error_result("No download/upload speeds in JSON response", progress_callback)

        _emit(
            progress_callback, "complete", 1.0,
            f"Complete: \u2193 {format_bandwidth_mbit(metrics['download_mbit'])} / \u2191 {format_bandwidth_mbit(metrics['upload_mbit'])}",
            metrics,
        )

        return {
            "status": "ok",
            "server": server_name,
            "server_url": server_url or None,
            "country_code": country_code,
            **metrics
        }

    except asyncio.TimeoutError:
        return _error_result(f"librespeed-cli process timeout ({timeout}s)", progress_callback)
    except Exception as exc:
        if isinstance(exc, asyncio.CancelledError):
            raise
        return _error_result(f"Speedtest failed: {exc}", progress_callback)
    finally:
        if progress_task:
            progress_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await progress_task

async def _emit_progress_simulation(cb: ProgressCallback, duration: int) -> None:
    """Emit time-based progress events during speedtest execution (UX helper)."""
    server_select_time = 5.0
    download_time = float(duration)
    upload_time = float(duration)
    
    phases = [
        (0.10, 0.30, server_select_time, "server_select", "Selecting fastest server\u2026"),
        (0.30, 0.65, download_time, "download", "Running download test\u2026"),
        (0.65, 0.95, upload_time, "upload", "Running upload test\u2026"),
    ]
    
    for start_pct, end_pct, phase_duration, phase_name, message in phases:
        steps = max(1, int(phase_duration * _PROGRESS_UPDATES_PER_SECOND))
        step_duration = phase_duration / steps
        step_progress = (end_pct - start_pct) / steps
        
        for i in range(1, steps + 1):
            await asyncio.sleep(step_duration)
            progress = min(start_pct + (step_progress * i), end_pct)
            _emit(cb, phase_name, progress, message)
