#!/usr/bin/env python3
#
# app/utils/fs.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Small filesystem durability helpers."""

from __future__ import annotations

import os
from pathlib import Path

__all__ = ["fsync_dir"]


def fsync_dir(path: Path) -> None:
	"""Fsync a directory so preceding renames are durable across crashes."""
	flags = os.O_RDONLY
	if hasattr(os, "O_DIRECTORY"):
		flags |= os.O_DIRECTORY
	dir_fd = os.open(path, flags)
	try:
		os.fsync(dir_fd)
	finally:
		os.close(dir_fd)
