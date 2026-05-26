#!/usr/bin/env python3
#
# app/speedtest/tester.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Bandwidth measurement via librespeed-cli.

Wraps the librespeed-cli binary (--json) for download, upload, ping and jitter
measurement.  Server selection is handled by librespeed-cli itself (nearest
server by ping RTT).

Default measurement parameters are tuned for VPN server monitoring and can be
overridden via ``run_speedtest()`` keyword arguments.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import math
import shlex
import shutil
from functools import cache
from collections.abc import Callable
from typing import Any, NotRequired, TypedDict
from urllib.parse import urlsplit

from ..utils.formatting import format_bandwidth_mbit
from ..utils.geoip import resolve_country_from_url as _resolve_country_from_url
from ..utils.subprocess import run_command

_log = logging.getLogger(__name__)

# Default CLI flags tuned for VPN server monitoring:
_DEFAULT_DURATION = 8
_DEFAULT_CONCURRENT = 4
_DEFAULT_UPLOAD_SIZE_KIB = 4096
_CLI_HTTP_TIMEOUT_SECONDS = 30
_SUBPROCESS_TIMEOUT_BUFFER_SECONDS = 30
_PROGRESS_UPDATES_PER_SECOND = 2
_SIMULATED_SERVER_SELECT_SECONDS = 5.0

class ProgressEvent(TypedDict):
    """Progress event emitted during speedtest execution."""
    phase: str  # Current phase name
    progress: float  # 0.0 - 1.0
    message: str  # Human-readable status
    detail: NotRequired[dict[str, Any] | None]  # Optional extra data

# Type alias for progress callback
ProgressCallback = Callable[[ProgressEvent], None]


def _safe_float(value: Any) -> float | None:
    """Convert a value to a finite float, or return ``None``.

    ``None`` is returned both for conversion failures and for non-finite values
    such as ``NaN`` or infinity, which are not meaningful speedtest metrics.
    """
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


def _extract_metric(data: dict[str, Any], key: str, ndigits: int = 2) -> float:
    """Extract, safely convert, and round a librespeed metric from JSON output."""
    return _round_metric(_safe_float(data.get(key)), ndigits)


async def _lookup_country_from_url(server_url: str) -> str | None:
    """Resolve server URL to country code via GeoIP lookup (async-safe)."""
    if not server_url:
        return None

    country_code = await asyncio.to_thread(_resolve_country_from_url, server_url)
    if country_code:
        return country_code

    raw_url = server_url.strip()
    parsed = urlsplit(raw_url if "://" in raw_url else f"https://{raw_url}")
    hostname = (parsed.hostname or "").strip().rstrip(".").lower()
    if not hostname:
        return None

    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass

    labels = [label for label in hostname.split(".") if label]
    if not labels:
        return None

    cc_tld = labels[-1]
    if len(cc_tld) == 2 and cc_tld.isalpha():
        return cc_tld
    return None


async def _validate_tunable_int(
    value: int,
    *,
    name: str,
    minimum: int,
    maximum: int,
    cb: ProgressCallback | None,
) -> int | None:
    """Validate public speedtest tunables before spawning the subprocess."""
    if isinstance(value, bool) or not isinstance(value, int):
        await _error_result(f"{name} must be an integer", cb, log_level=logging.WARNING)
        return None
    if not (minimum <= value <= maximum):
        await _error_result(f"{name} must be {minimum}-{maximum}", cb, log_level=logging.WARNING)
        return None
    return value


@cache
def _resolve_librespeed_cli(override: str | None = None) -> str | None:
    """Return the librespeed-cli path.

    Uses the explicit runtime override for tests when set; otherwise resolves
    the binary lazily on first use and caches the result.
    """
    if override is not None:
        return override
    return shutil.which("librespeed-cli")


async def _error_result(
    msg: str,
    cb: ProgressCallback | None,
    *,
    log_level: int = logging.ERROR,
    stderr: str | None = None,
) -> dict[str, Any]:
    """Log an error, emit an error progress event, and return an error result.

    ``stderr`` is truncated before logging to keep log lines bounded.
    """
    if stderr:
        safe_stderr = stderr[:200].replace("\n", "\\n").replace("\r", "\\r")
        _log.log(log_level, "SPEEDTEST error: %s (stderr: %s)", msg, safe_stderr)
    else:
        _log.log(log_level, "SPEEDTEST %s", msg)
    await _emit(cb, "error", 1.0, msg)
    return {"status": "error", "reason": msg}


async def _emit(cb: ProgressCallback | None, phase: str, progress: float, message: str, detail: dict[str, Any] | None = None) -> None:
    """Emit a progress event if a callback is registered."""
    if cb is None:
        return
    event: ProgressEvent = {"phase": phase, "progress": progress, "message": message}
    if detail is not None:
        event["detail"] = detail
    try:
        await asyncio.to_thread(cb, event)
    except Exception:
        _log.warning("Progress callback failed", exc_info=True)


async def run_speedtest(
    *,
    progress_callback: ProgressCallback | None = None,
    duration: int = _DEFAULT_DURATION,
    concurrent: int = _DEFAULT_CONCURRENT,
    upload_size: int = _DEFAULT_UPLOAD_SIZE_KIB,
) -> dict[str, Any]:
    """Run librespeed-cli and return a normalized speedtest result dictionary.

    Optionally emits progress events while the subprocess is running. On
    success, returns a dict containing normalized bandwidth and latency fields.
    On failure, returns ``{"status": "error", "reason": ...}``.

    Args:
        progress_callback: Optional callback receiving progress events.
        duration: Per-phase measurement duration passed to librespeed-cli.
        concurrent: Number of parallel streams passed to librespeed-cli.
        upload_size: Upload payload size in KiB passed to librespeed-cli.

    ``asyncio.CancelledError`` is not swallowed and propagates to the caller.
    """
    validated_duration = await _validate_tunable_int(
        duration,
        name="duration",
        minimum=1,
        maximum=300,
        cb=progress_callback,
    )
    if validated_duration is None:
        return {"status": "error", "reason": "duration must be 1-300"}

    validated_concurrent = await _validate_tunable_int(
        concurrent,
        name="concurrent",
        minimum=1,
        maximum=64,
        cb=progress_callback,
    )
    if validated_concurrent is None:
        return {"status": "error", "reason": "concurrent must be 1-64"}

    validated_upload_size = await _validate_tunable_int(
        upload_size,
        name="upload_size",
        minimum=1,
        maximum=1_048_576,
        cb=progress_callback,
    )
    if validated_upload_size is None:
        return {"status": "error", "reason": "upload_size must be 1-1048576 KiB"}

    await _emit(progress_callback, "init", 0.0, "Starting librespeed-cli\u2026")

    resolved_cli = _resolve_librespeed_cli()
    if not resolved_cli:
        return await _error_result("librespeed-cli not found in PATH", progress_callback, log_level=logging.WARNING)

    cmd = [
        resolved_cli, "--json", "--no-icmp", "--secure",
        "--duration", str(validated_duration),
        "--concurrent", str(validated_concurrent),
        "--upload-size", str(validated_upload_size),
        "--timeout", str(_CLI_HTTP_TIMEOUT_SECONDS),
    ]

    _log.info("SPEEDTEST cmd=%s", shlex.join(cmd))
    timeout = _CLI_HTTP_TIMEOUT_SECONDS + (validated_duration * 2) + _SUBPROCESS_TIMEOUT_BUFFER_SECONDS

    await _emit(progress_callback, "server_select", 0.10, "Selecting fastest server\u2026")

    progress_task: asyncio.Task[None] | None = None
    try:
        if progress_callback:
            progress_task = asyncio.create_task(_emit_progress_simulation(progress_callback, validated_duration))

        # run_command() must terminate child processes on cancellation.
        # It raises asyncio.TimeoutError when the subprocess exceeds the timeout.
        res = await run_command(*cmd, timeout=timeout)
        
        if res.returncode != 0:
            return await _error_result(f"librespeed-cli exited with code {res.returncode}", progress_callback, stderr=res.stderr)

        # Parse JSON output
        stdout = res.stdout.strip()
        stdout_bytes = stdout.encode("utf-8", errors="ignore")
        if len(stdout_bytes) > 5_000_000:
            return await _error_result("CLI output unexpectedly large", progress_callback)
        if stdout.count("{") + stdout.count("[") > 10_000:
            return await _error_result("JSON structure unexpectedly complex", progress_callback)
        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                data = data[0] if data else {}
        except json.JSONDecodeError as exc:
            return await _error_result(f"Failed to parse JSON output: {exc}", progress_callback)

        if not isinstance(data, dict):
            return await _error_result(f"Unexpected JSON type: {type(data).__name__}", progress_callback)

        # Extract server info
        server_data = data.get("server", "")
        if isinstance(server_data, dict):
            server_name = str(server_data.get("name") or "")[:256]
            server_url = str(server_data.get("url") or "")[:2048]
        else:
            server_name = str(server_data or "")[:256]
            server_url = ""

        # Country lookup (async-safe)
        country_code = await _lookup_country_from_url(server_url)

        # Extract and validate metrics
        metrics = {
            "download_mbit": _extract_metric(data, "download"),
            "upload_mbit": _extract_metric(data, "upload"),
            "rtt_ms": _extract_metric(data, "ping"),
            "jitter_ms": _extract_metric(data, "jitter"),
        }

        if metrics["download_mbit"] == 0 and metrics["upload_mbit"] == 0:
            return await _error_result("No download/upload speeds in JSON response", progress_callback)

        await _emit(
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
        return await _error_result(f"librespeed-cli process timeout ({timeout}s)", progress_callback)
    except Exception:
        _log.exception("SPEEDTEST_EXECUTION_FAILED")
        return await _error_result("Speedtest execution failed", progress_callback)
    finally:
        if progress_task:
            progress_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await progress_task


async def _emit_progress_simulation(cb: ProgressCallback, duration: int) -> None:
    """Emit synthetic progress updates while the speedtest subprocess runs.

    This coroutine is intended to run as a separate asyncio task and be
    cancelled by the caller once the speedtest completes or fails. Progress is
    time-based UX simulation, not a reflection of actual librespeed internals.
    """
    server_select_time = _SIMULATED_SERVER_SELECT_SECONDS
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
            try:
                await asyncio.sleep(step_duration)
            except asyncio.CancelledError:
                return
            progress = min(start_pct + (step_progress * i), end_pct)
            try:
                await _emit(cb, phase_name, progress, message)
            except asyncio.CancelledError:
                return
