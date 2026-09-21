#!/usr/bin/env python3
#
# tests/test_dns_run_exec.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""``run_exec`` never raises: every failure comes back as ``(-1, "", reason)``.

The Unbound supervisor relies on that contract, so it is locked here
independently of how the command is actually run.
"""

from __future__ import annotations

import asyncio
import sys

from app.dns.unbound_constants import run_exec


def test_success_returns_code_and_decoded_output():
	code, stdout, stderr = asyncio.run(run_exec(sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr)"))

	assert (code, stdout, stderr) == (0, "out\n", "err\n")


def test_nonzero_exit_is_returned_not_raised():
	code, _, _ = asyncio.run(run_exec(sys.executable, "-c", "raise SystemExit(3)"))

	assert code == 3


def test_missing_binary_is_reported_as_failure():
	code, stdout, stderr = asyncio.run(run_exec("/nonexistent/wirebuddy-test-binary"))

	assert (code, stdout) == (-1, "")
	assert stderr


def test_timeout_is_reported_as_failure():
	code, stdout, stderr = asyncio.run(run_exec(sys.executable, "-c", "import time; time.sleep(30)", timeout=0.3))

	assert (code, stdout, stderr) == (-1, "", "Command timed out after 0.3s")
