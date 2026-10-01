#!/usr/bin/env python3
#
# app/utils/binaries.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
# SPDX-License-Identifier: MIT
#

"""Resolve trusted executables from fixed candidate lists (stdlib only)."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path


def first_executable(candidates: Iterable[str | Path]) -> str | None:
	"""Return the first candidate that is an executable regular file, or None."""
	for candidate in candidates:
		path = Path(candidate)
		if path.is_file() and os.access(path, os.X_OK):
			return str(path)
	return None
