#!/usr/bin/env python3
#
# app/utils/subprocess.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Generic subprocess management with timeout and graceful shutdown."""

import asyncio
import logging
import os
import signal
from dataclasses import dataclass

_log = logging.getLogger(__name__)

_MAX_OUTPUT_BYTES = 5_000_000
_READ_CHUNK_BYTES = 65_536

@dataclass(slots=True)
class ProcResult:
    stdout: str
    stderr: str
    returncode: int


async def _read_stream_limited(
    stream: asyncio.StreamReader | None,
    *,
    label: str,
) -> bytes:
    """Read one subprocess stream with a hard memory limit."""
    if stream is None:
        return b""

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await stream.read(_READ_CHUNK_BYTES)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > _MAX_OUTPUT_BYTES:
            raise RuntimeError(f"Subprocess {label} exceeded safety limit")
        chunks.append(chunk)


async def _terminate_process_group(
    proc: asyncio.subprocess.Process,
    *,
    kill_timeout: float,
) -> None:
    """Terminate the full subprocess group with SIGTERM and SIGKILL fallback."""
    if proc.pid is None:
        return

    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return

    try:
        await asyncio.wait_for(proc.wait(), timeout=kill_timeout)
        return
    except asyncio.TimeoutError:
        _log.debug("Process group %s did not terminate, sending SIGKILL", proc.pid)

    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    await proc.wait()

async def run_command(
    *cmd: str,
    timeout: float,
    kill_timeout: float = 2.0,
) -> ProcResult:
    """Run a command with timeout, SIGTERM grace period, and SIGKILL fallback.

    Args:
        *cmd: Command and arguments
        timeout: Execution timeout in seconds
        kill_timeout: Grace period between SIGTERM and SIGKILL

    Returns:
        ProcResult object

    Raises:
        asyncio.TimeoutError: If process exceeds timeout and kill_timeout
        FileNotFoundError: If command not found
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )

    stdout_task = asyncio.create_task(_read_stream_limited(proc.stdout, label="stdout"))
    stderr_task = asyncio.create_task(_read_stream_limited(proc.stderr, label="stderr"))
    wait_task = asyncio.create_task(proc.wait())

    try:
        await asyncio.wait_for(
            asyncio.gather(wait_task, stdout_task, stderr_task),
            timeout=timeout,
        )
    except (asyncio.TimeoutError, asyncio.CancelledError):
        await _terminate_process_group(proc, kill_timeout=kill_timeout)
        await asyncio.gather(wait_task, stdout_task, stderr_task, return_exceptions=True)
        raise
    except Exception:
        await _terminate_process_group(proc, kill_timeout=kill_timeout)
        await asyncio.gather(wait_task, stdout_task, stderr_task, return_exceptions=True)
        raise

    stdout_raw = stdout_task.result()
    stderr_raw = stderr_task.result()
        
    return ProcResult(
        stdout=stdout_raw.decode("utf-8", errors="replace"),
        stderr=stderr_raw.decode("utf-8", errors="replace"),
        returncode=proc.returncode if proc.returncode is not None else -1,
    )
