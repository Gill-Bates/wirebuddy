#!/usr/bin/env python3
#
# app/utils/time.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Timezone-aware time utilities."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def utcnow() -> datetime:
	"""Return the current UTC time as a timezone-aware datetime."""
	return datetime.now(timezone.utc)


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
	"""Ensure a datetime is timezone-aware and in UTC.
	
	Args:
		dt: A datetime object (may be naive or timezone-aware)
	
	Returns:
		The datetime converted to UTC, or None if input was None
	
	Raises:
		ValueError: If the datetime is naive (no timezone info)
	"""
	if dt is None:
		return None
	if dt.tzinfo is None:
		raise ValueError("Naive datetime not allowed - must be timezone-aware")
	return dt.astimezone(timezone.utc)


def parse_utc(s: str) -> Optional[datetime]:
	"""Parse an ISO-8601 timestamp string to a UTC datetime.
	
	Handles both 'Z' suffix and '+00:00' offset notation.
	Returns None for invalid/unparseable or naive (timezone-less) timestamps.
	"""
	if not s:
		return None
	try:
		# Handle Z suffix
		if s.endswith("Z"):
			s = s[:-1] + "+00:00"
		dt = datetime.fromisoformat(s)
		if dt.tzinfo is None:
			return None
		return dt.astimezone(timezone.utc)
	except (ValueError, TypeError):
		return None
