#!/usr/bin/env python3
#
# app/utils/version.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Version and build information for WireBuddy."""

from __future__ import annotations

import json
import logging
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import TypedDict

_log = logging.getLogger(__name__)

_VERSION_CACHE: str | None = None
_BUILD_INFO_CACHE: str | None = None
APP_NAME = "WireBuddy"
GITHUB_REPO = "Gill-Bates/wirebuddy"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

# Cache update check result for 1 hour
_UPDATE_CHECK_CACHE: dict | None = None
_UPDATE_CHECK_TIME: float = 0
_UPDATE_CHECK_TTL = 3600  # 1 hour


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


class UpdateInfo(TypedDict):
	"""Update check result."""
	update_available: bool
	current_version: str
	latest_version: str | None
	release_url: str | None
	release_notes: str | None
	published_at: str | None
	error: str | None


def _parse_version(version_str: str) -> tuple[int, ...]:
	"""Parse version string to tuple of integers for comparison.
	
	Handles formats like '1.2.3', 'v1.2.3', '1.2.3-beta', etc.
	"""
	if not version_str:
		return (0,)
	# Remove 'v' prefix if present
	clean = version_str.lstrip('v').strip()
	# Extract numeric parts
	match = re.match(r'^(\d+(?:\.\d+)*)', clean)
	if not match:
		return (0,)
	parts = match.group(1).split('.')
	return tuple(int(p) for p in parts)


def _is_newer_version(current: str, latest: str) -> bool:
	"""Check if latest version is newer than current."""
	if current == "dev":
		return False  # Dev versions don't need updates
	current_parts = _parse_version(current)
	latest_parts = _parse_version(latest)
	return latest_parts > current_parts


def check_for_updates(force: bool = False) -> UpdateInfo:
	"""Check GitHub for newer releases.
	
	Args:
		force: Bypass cache and fetch fresh data
		
	Returns:
		UpdateInfo dict with update availability and details
	"""
	global _UPDATE_CHECK_CACHE, _UPDATE_CHECK_TIME
	
	current_version = get_version()
	
	# Return cached result if still valid (unless forced)
	if not force and _UPDATE_CHECK_CACHE is not None:
		if time.time() - _UPDATE_CHECK_TIME < _UPDATE_CHECK_TTL:
			return _UPDATE_CHECK_CACHE
	
	result: UpdateInfo = {
		"update_available": False,
		"current_version": current_version,
		"latest_version": None,
		"release_url": None,
		"release_notes": None,
		"published_at": None,
		"error": None,
	}
	
	# Don't check for dev versions
	if current_version == "dev":
		result["error"] = "Development version - update check disabled"
		_UPDATE_CHECK_CACHE = result
		_UPDATE_CHECK_TIME = time.time()
		return result
	
	import httpx
	_TIMEOUT = 10.0  # Hard ceiling for DNS + connect + read
	try:
		with httpx.Client(timeout=httpx.Timeout(_TIMEOUT)) as client:
			response = client.get(
				GITHUB_API_URL,
				headers={
					"Accept": "application/vnd.github.v3+json",
					"User-Agent": f"WireBuddy/{current_version}",
				},
				follow_redirects=True,
			)
			response.raise_for_status()
			data = response.json()
		
		latest_tag = data.get("tag_name", "").lstrip("v")
		result["latest_version"] = latest_tag
		result["release_url"] = data.get("html_url")
		result["release_notes"] = data.get("body")
		result["published_at"] = data.get("published_at")
		
		if _is_newer_version(current_version, latest_tag):
			result["update_available"] = True
			_log.info("Update available: %s -> %s", current_version, latest_tag)
		else:
			_log.debug("No update available (current: %s, latest: %s)", current_version, latest_tag)
			
	except httpx.HTTPStatusError as e:
		result["error"] = f"GitHub API error: {e.response.status_code}"
		_log.warning("Update check failed: %s", e)
	except httpx.TimeoutException:
		result["error"] = "Connection timeout"
		_log.warning("Update check timed out after %.1fs", _TIMEOUT)
	except httpx.RequestError as e:
		result["error"] = f"Network error: {e}"
		_log.warning("Update check failed: %s", e)
	except json.JSONDecodeError as e:
		result["error"] = f"Invalid response: {e}"
		_log.warning("Update check failed: %s", e)
	except Exception as e:
		result["error"] = str(e)
		_log.warning("Update check failed: %s", e)
	
	_UPDATE_CHECK_CACHE = result
	_UPDATE_CHECK_TIME = time.time()
	return result
