#!/usr/bin/env python3
#
# app/utils/version.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Version and build information for WireBuddy."""

from __future__ import annotations

from pathlib import Path

_VERSION_CACHE: str | None = None
_BUILD_INFO_CACHE: str | None = None
APP_NAME = "WireBuddy"


def get_build_info() -> str:
	"""Get build info (Git commit hash) from BUILD_INFO file. Falls back to 'dev'."""
	global _BUILD_INFO_CACHE
	if _BUILD_INFO_CACHE is not None:
		return _BUILD_INFO_CACHE
	try:
		build_file = Path(__file__).resolve().parent.parent.parent / "BUILD_INFO"
		if not build_file.exists():
			build_file = Path("/app/BUILD_INFO")
		if build_file.exists():
			_BUILD_INFO_CACHE = build_file.read_text(encoding="utf-8").strip()
		else:
			_BUILD_INFO_CACHE = "dev"
	except Exception:
		_BUILD_INFO_CACHE = "dev"
	return _BUILD_INFO_CACHE


def get_version() -> str:
	"""Get application version from VERSION file. Falls back to 'dev'."""
	global _VERSION_CACHE
	if _VERSION_CACHE is not None:
		return _VERSION_CACHE
	try:
		version_file = Path(__file__).resolve().parent.parent.parent / "VERSION"
		if not version_file.exists():
			version_file = Path("/app/VERSION")
		if version_file.exists():
			_VERSION_CACHE = version_file.read_text(encoding="utf-8").strip()
		else:
			_VERSION_CACHE = "dev"
	except Exception:
		_VERSION_CACHE = "dev"
	return _VERSION_CACHE


VERSION = get_version()
BUILD_INFO = get_build_info()
