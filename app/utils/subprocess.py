#!/usr/bin/env python3
#
# app/utils/subprocess.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Generic subprocess management with timeout and graceful shutdown."""

import asyncio
import logging
import math
import os
import signal
from collections.abc import Callable
from dataclasses import dataclass

_log = logging.getLogger(__name__)

_MAX_OUTPUT_BYTES = 5_000_000
_READ_CHUNK_BYTES = 65_536
# Hard bound for the post-kill drain. The readers only need to observe EOF
# here, so this never gates on the command itself making progress.
_CLEANUP_DRAIN_SECONDS = 5.0

@dataclass(slots=True)
class ProcResult:
    stdout: str
    stderr: str
    returncode: int


async def _read_stream_limited(
    stream: asyncio.StreamReader | None,
    *,
    label: str,
    on_limit: Callable[[], None],
) -> bytes:
    """Read one subprocess stream with a hard memory limit.

    Reading deliberately continues past the limit with the surplus discarded.
    Abandoning a filled pipe blocks the child in write() and, worse, wedges
    ``proc.wait()``: asyncio only reports the process as exited once *every*
    pipe transport has seen EOF, so an unread stream can outlive even SIGKILL.
    ``on_limit`` stops the producer so that EOF actually arrives.
    """
    if stream is None:
        return b""

    chunks: list[bytes] = []
    total = 0
    exceeded = False
    while True:
        chunk = await stream.read(_READ_CHUNK_BYTES)
        if not chunk:
            break
        if exceeded:
            continue
        total += len(chunk)
        if total > _MAX_OUTPUT_BYTES:
            chunks.clear()
            exceeded = True
            on_limit()
            continue
        chunks.append(chunk)

    if exceeded:
        raise RuntimeError(f"Subprocess {label} exceeded safety limit")
    return b"".join(chunks)


def _signal_process_group(proc: asyncio.subprocess.Process, sig: int) -> bool:
    """Best-effort signal to the whole process group; False when it is gone."""
    if proc.pid is None:
        return False
    try:
        os.killpg(proc.pid, sig)
    except (ProcessLookupError, PermissionError):
        return False
    return True


async def _terminate_process_group(
    proc: asyncio.subprocess.Process,
    *,
    kill_timeout: float,
) -> None:
    """Terminate the full subprocess group with SIGTERM and SIGKILL fallback."""
    if not _signal_process_group(proc, signal.SIGTERM):
        return

    try:
        await asyncio.wait_for(proc.wait(), timeout=kill_timeout)
        return
    except asyncio.TimeoutError:
        _log.debug("Process group %s did not terminate, sending SIGKILL", proc.pid)

    if not _signal_process_group(proc, signal.SIGKILL):
        return

    # Bounded on purpose: proc.wait() resolves only after every pipe transport
    # has disconnected, so it can hang past SIGKILL if a reader stopped early.
    try:
        await asyncio.wait_for(proc.wait(), timeout=kill_timeout)
    except asyncio.TimeoutError:
        _log.warning("Process group %s not reaped after SIGKILL", proc.pid)


async def _cleanup(
    proc: asyncio.subprocess.Process,
    tasks: list[asyncio.Task],
    *,
    kill_timeout: float,
) -> None:
    """Kill the process group, then let the readers finish under a hard bound."""
    await _terminate_process_group(proc, kill_timeout=kill_timeout)
    _, still_pending = await asyncio.wait(tasks, timeout=_CLEANUP_DRAIN_SECONDS)
    for task in still_pending:
        task.cancel()
    if still_pending:
        await asyncio.gather(*still_pending, return_exceptions=True)


def _first_task_exception(tasks: list[asyncio.Task]) -> BaseException | None:
    """Return the first task exception, retrieving all of them en route.

    Every exception must be consumed, otherwise the tasks we do not re-raise
    log "exception was never retrieved" on garbage collection.
    """
    first: BaseException | None = None
    for task in tasks:
        if task.cancelled() or not task.done():
            continue
        exc = task.exception()
        if exc is not None and first is None:
            first = exc
    return first


def _require_positive(value: float, name: str) -> float:
    """Reject timeouts that would disable the guarantees documented below."""
    numeric = float(value)
    if not math.isfinite(numeric) or numeric <= 0:
        raise ValueError(f"{name} must be finite and greater than zero")
    return numeric


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
        ValueError: If cmd is empty or a timeout is not finite and positive
        asyncio.TimeoutError: If process exceeds timeout and kill_timeout
        FileNotFoundError: If command not found
    """
    if not cmd:
        raise ValueError("Command must not be empty")
    timeout = _require_positive(timeout, "timeout")
    kill_timeout = _require_positive(kill_timeout, "kill_timeout")

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )

    def _stop_runaway() -> None:
        """Stop a process that blew the output limit so its pipes reach EOF."""
        if proc.returncode is None:
            _signal_process_group(proc, signal.SIGTERM)

    stdout_task = asyncio.create_task(
        _read_stream_limited(proc.stdout, label="stdout", on_limit=_stop_runaway)
    )
    stderr_task = asyncio.create_task(
        _read_stream_limited(proc.stderr, label="stderr", on_limit=_stop_runaway)
    )
    wait_task = asyncio.create_task(proc.wait())
    tasks = [wait_task, stdout_task, stderr_task]

    try:
        done, pending = await asyncio.wait(
            tasks, timeout=timeout, return_when=asyncio.FIRST_EXCEPTION
        )
    except BaseException:
        # Caller cancellation must not leak the child process group.
        await _cleanup(proc, tasks, kill_timeout=kill_timeout)
        _first_task_exception(tasks)
        raise

    if pending:
        # Either the timeout elapsed or a reader failed while the rest ran on.
        # The readers are never cancelled before the kill, so the pipes keep
        # draining and the process can actually be reaped.
        await _cleanup(proc, tasks, kill_timeout=kill_timeout)
        exc = _first_task_exception(tasks)
        if exc is not None:
            raise exc
        raise asyncio.TimeoutError(
            f"Command timed out after {timeout}s: {cmd[0]}"
        )

    stdout_raw = stdout_task.result()
    stderr_raw = stderr_task.result()

    return ProcResult(
        stdout=stdout_raw.decode("utf-8", errors="replace"),
        stderr=stderr_raw.decode("utf-8", errors="replace"),
        returncode=proc.returncode if proc.returncode is not None else -1,
    )
