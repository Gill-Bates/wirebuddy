#!/usr/bin/env python3
#
# app/utils/formatting.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Formatting helpers shared across frontend and backend layers."""

from __future__ import annotations


def format_bandwidth_mbit(value: float | int, gbit_digits: int = 2, mbit_digits: int | None = None) -> str:
	"""Render a bandwidth value stored in Mbit/s as Mbit/s or Gbit/s.

	Args:
		value: Raw bandwidth value in Mbit/s.
		gbit_digits: Decimal places when the value is shown as Gbit/s.
		mbit_digits: Decimal places when the value is shown as Mbit/s.
			Defaults to ``gbit_digits`` when omitted.
	"""
	gb_digits = max(int(gbit_digits), 0)
	mb_digits = gb_digits if mbit_digits is None else max(int(mbit_digits), 0)
	numeric = float(value)
	if numeric >= 1000:
		return f"{numeric / 1000:.{gb_digits}f} Gbit/s"
	return f"{numeric:.{mb_digits}f} Mbit/s"


def format_optional_bandwidth_mbit(value: object, gbit_digits: int = 2, mbit_digits: int | None = None) -> str | None:
	"""Like format_bandwidth_mbit(), but returns None for non-numeric inputs."""
	if isinstance(value, bool) or not isinstance(value, (int, float)):
		return None
	return format_bandwidth_mbit(value, gbit_digits=gbit_digits, mbit_digits=mbit_digits)
