#!/usr/bin/env python3
#
# app/utils/time.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Timezone-aware time utilities."""

from __future__ import annotations

import calendar
from datetime import UTC, datetime


def utcnow() -> datetime:
	"""Return the current UTC time as a timezone-aware datetime."""
	return datetime.now(UTC)


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
	return dt.astimezone(UTC)


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
		return dt.astimezone(UTC)
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
			return value.replace(tzinfo=UTC)
		return value.astimezone(UTC)
	if isinstance(value, str):
		return parse_utc(value)
	return None


def to_utc_iso(value: object) -> str:
	"""Render a timestamp as ISO-8601 UTC with a ``Z`` suffix, or ``""`` if unusable.

	Single wire format for server-rendered ``<time datetime>`` values; the browser
	does the localisation. A naive datetime is read as UTC (storage contract).
	"""
	dt = parse_db_timestamp(value)
	if dt is None:
		return ""
	return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def subtract_months(dt: datetime, months: int) -> datetime:
	"""Subtract calendar months from an aware datetime, clamping the day to the target month."""
	if not _is_aware(dt):
		raise ValueError("Naive datetime not allowed - must be timezone-aware")
	index = dt.year * 12 + (dt.month - 1) - months
	year, month = divmod(index, 12)
	month += 1
	day = min(dt.day, calendar.monthrange(year, month)[1])
	return dt.replace(year=year, month=month, day=day)


def is_peer_stale(last_seen: object, stale_months: int, now: datetime | None = None) -> bool:
	"""Return True when *last_seen* is at least *stale_months* calendar months before *now*.

	*last_seen* is epoch seconds (``peers.last_handshake_at``) or a datetime;
	missing or non-positive values are never stale.
	"""
	if isinstance(last_seen, bool):
		return False
	if isinstance(last_seen, (int, float)):
		if last_seen <= 0:
			return False
		try:
			seen = datetime.fromtimestamp(last_seen, UTC)
		except (OverflowError, OSError, ValueError):
			return False
	else:
		seen = parse_db_timestamp(last_seen)
		if seen is None:
			return False
	current = ensure_utc(now) if now is not None else utcnow()
	return seen <= subtract_months(current, stale_months)
