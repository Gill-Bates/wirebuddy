#!/usr/bin/env python3
#
# tests/test_subprocess_limits.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Tests for the subprocess helper's timeout and output-limit guarantees.

The central promise is that ``run_command`` always returns within roughly
``timeout + kill_timeout``. That held only for well-behaved children: abandoning
a filled pipe used to wedge ``proc.wait()``, which asyncio resolves only after
every pipe transport has seen EOF — so an unread stream outlived even SIGKILL.

Driven through ``asyncio.run`` rather than an async pytest plugin, since the
suite carries no such dependency.
"""

from __future__ import annotations

import asyncio

import pytest

from app.utils.subprocess import run_command

# Generous headroom over timeout + kill_timeout; a regression hangs outright
# rather than finishing a little late.
_GUARD_SECONDS = 25.0

_IGNORES_SIGTERM = "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\n"


def _run(coro):
    """Run ``coro`` to completion under a hard guard against hanging.

    Deliberately not ``wait_for``: run_command signals its own timeout with
    ``asyncio.TimeoutError`` too, and a guard built on ``wait_for`` cannot tell
    that expected result apart from an actual hang.
    """

    async def _guarded():
        task = asyncio.ensure_future(coro)
        _, pending = await asyncio.wait([task], timeout=_GUARD_SECONDS)
        if pending:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise AssertionError(f"run_command did not return within {_GUARD_SECONDS}s")
        return task.result()

    return asyncio.run(_guarded())


# ─── normal operation ────────────────────────────────────────────────────────


def test_captures_stdout_stderr_and_returncode():
    result = _run(run_command("sh", "-c", "echo out; echo err >&2; exit 3", timeout=5.0))
    assert result.stdout == "out\n"
    assert result.stderr == "err\n"
    assert result.returncode == 3


def test_output_just_under_the_limit_is_returned():
    result = _run(
        run_command("python3", "-c", "import sys; sys.stdout.write('x' * 4_000_000)", timeout=20.0)
    )
    assert len(result.stdout) == 4_000_000
    assert result.returncode == 0


# ─── timeout guarantees ──────────────────────────────────────────────────────


def test_timeout_terminates_a_well_behaved_child():
    with pytest.raises(asyncio.TimeoutError):
        _run(run_command("sleep", "30", timeout=1.0))


def test_timeout_is_honoured_when_the_child_ignores_sigterm():
    """SIGKILL must still land, and the call must not outlive its budget."""
    with pytest.raises(asyncio.TimeoutError):
        _run(
            run_command(
                "python3", "-c", _IGNORES_SIGTERM + "time.sleep(60)\n",
                timeout=1.0,
                kill_timeout=1.0,
            )
        )


def test_runaway_output_does_not_hang_the_caller():
    """A child that ignores SIGTERM while flooding stdout must still be reaped.

    Regression: the readers were cancelled before the kill, so nothing drained
    the pipe and the process was never reported as exited.
    """
    with pytest.raises(RuntimeError, match="exceeded safety limit"):
        _run(
            run_command(
                "python3", "-c",
                _IGNORES_SIGTERM
                + "import sys\nd = 'x' * 65536\nwhile True:\n"
                  "    sys.stdout.write(d)\n    sys.stdout.flush()\n    time.sleep(0.01)\n",
                timeout=2.0,
                kill_timeout=1.0,
            )
        )


def test_output_limit_is_enforced_on_stderr_too():
    with pytest.raises(RuntimeError, match="stderr exceeded safety limit"):
        _run(
            run_command(
                "python3", "-c", "import sys; sys.stderr.write('x' * 6_000_000)", timeout=20.0
            )
        )


def test_caller_cancellation_propagates():
    async def _cancel_midway():
        task = asyncio.create_task(run_command("sleep", "30", timeout=30.0))
        await asyncio.sleep(0.3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(asyncio.wait_for(_cancel_midway(), timeout=_GUARD_SECONDS))


# ─── input validation ────────────────────────────────────────────────────────


def test_empty_command_is_rejected():
    with pytest.raises(ValueError, match="must not be empty"):
        _run(run_command(timeout=5.0))


@pytest.mark.parametrize("bad", [0, -1.0, float("nan"), float("inf")])
def test_non_positive_timeouts_are_rejected(bad):
    with pytest.raises(ValueError, match="finite and greater than zero"):
        _run(run_command("echo", "hi", timeout=bad))


def test_missing_binary_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        _run(run_command("wirebuddy-no-such-binary", timeout=5.0))
