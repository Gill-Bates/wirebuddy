#!/usr/bin/env python3
#
# app/utils/time.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Timezone-aware time utilities."""

from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
	"""Return the current UTC time as a timezone-aware datetime."""
	return datetime.now(timezone.utc)


def _is_aware(dt: datetime) -> bool:
	"""Return True only when *dt* is genuinely timezone-aware.

	A datetime is aware iff ``tzinfo`` is set *and* yields a concrete UTC offset.
	Checking ``tzinfo is None`` alone misses tzinfos whose ``utcoffset()`` is
	``None`` (which would then blow up later in ``astimezone``).
	"""
	return dt.tzinfo is not None and dt.utcoffset() is not None


def ensure_utc(dt: datetime | None) -> datetime | None:
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
	if not _is_aware(dt):
		raise ValueError("Naive datetime not allowed - must be timezone-aware")
	return dt.astimezone(timezone.utc)


def parse_utc(s: str) -> datetime | None:
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
		if not _is_aware(dt):
			return None
		return dt.astimezone(timezone.utc)
	except (ValueError, TypeError):
		return None


def parse_db_timestamp(value: object) -> datetime | None:
	"""Normalize a database timestamp value to a timezone-aware UTC datetime.

	Single source for reading SQLite timestamp columns, which may surface as a
	``datetime`` (via the registered converter) or as an ISO string:

	* ``None`` / unsupported types -> ``None``
	* ``datetime`` -> normalized to UTC; a naive value is tolerated as UTC
	* ``str`` -> parsed via :func:`parse_utc`, so a naive string is rejected
	  (``None``). This matches the storage contract: ``_adapt_datetime`` never
	  writes naive timestamps, so a naive string should not occur and failing
	  closed is the safe choice for callers (e.g. token expiry checks).
	"""
	if value is None:
		return None
	if isinstance(value, datetime):
		if not _is_aware(value):
			return value.replace(tzinfo=timezone.utc)
		return value.astimezone(timezone.utc)
	if isinstance(value, str):
		return parse_utc(value)
	return None
