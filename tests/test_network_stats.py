#!/usr/bin/env python3
#
# tests/test_network_stats.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Interface counter deltas: a decrease is a reset and never a fabricated spike."""

from __future__ import annotations

import pytest

from app.api.network_stats import _counter_delta

_GIB = 2**30


@pytest.mark.parametrize(
	("current", "previous", "expected"),
	[
		(1_500, 1_000, 500),  # normal growth
		(1_000, 1_000, 0),  # unchanged
		(10, 5_000, 0),  # reset below 2**32
		(int(4.4 * _GIB), int(4.5 * _GIB), 0),  # reset above 2**32, deficit within 2**32
		(100, 2**40, 0),  # reset from a large 64-bit value
		(2**33 + 7, 2**33, 7),  # growth across the 32-bit boundary
	],
)
def test_counter_delta(current: int, previous: int, expected: int) -> None:
	assert _counter_delta(current, previous) == expected
