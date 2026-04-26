#!/usr/bin/env python3
#
# app/utils/subprocess.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Generic subprocess management with timeout and graceful shutdown."""

import asyncio
import logging
from dataclasses import dataclass

_log = logging.getLogger(__name__)

@dataclass(slots=True)
class ProcResult:
    stdout: str
    stderr: str
    returncode: int

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
    )
    
    try:
        stdout_raw, stderr_raw = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except (asyncio.TimeoutError, asyncio.CancelledError):
        # Attempt graceful termination first
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=kill_timeout)
        except asyncio.TimeoutError:
            # Force kill if still running
            _log.debug("Process %s did not terminate, sending SIGKILL", cmd[0])
            proc.kill()
            await proc.wait()
        raise
        
    return ProcResult(
        stdout=stdout_raw.decode("utf-8", errors="replace"),
        stderr=stderr_raw.decode("utf-8", errors="replace"),
        returncode=proc.returncode if proc.returncode is not None else -1,
    )
