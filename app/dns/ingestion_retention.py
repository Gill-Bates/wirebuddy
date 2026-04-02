#!/usr/bin/env python3
#
# app/dns/ingestion_retention.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""DNS log retention management."""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

_log = logging.getLogger(__name__)

__all__ = [
	"DNS_LOG_RETENTION_OPTIONS",
	"DEFAULT_DNS_LOG_RETENTION_DAYS",
	"normalize_dns_log_retention_days",
	"enforce_dns_log_retention",
]

DNS_LOG_RETENTION_OPTIONS = {0, 7, 30, 90, 180, 365}
DEFAULT_DNS_LOG_RETENTION_DAYS = 30
# Safety limit to prevent runaway deletion on corrupted setups
MAX_DELETE_PER_RUN = 10_000


def normalize_dns_log_retention_days(value: int | str | None) -> int:
	"""Normalize and validate DNS log retention days."""
	try:
		parsed = int(value) if value is not None else DEFAULT_DNS_LOG_RETENTION_DAYS
	except (TypeError, ValueError):
		return DEFAULT_DNS_LOG_RETENTION_DAYS
	return parsed if parsed in DNS_LOG_RETENTION_OPTIONS else DEFAULT_DNS_LOG_RETENTION_DAYS


def _extract_day_prefix(name: str) -> date | None:
	"""Extract YYYY-MM-DD prefix from dns_queries filenames."""
	if len(name) < 10:
		return None
	try:
		return date.fromisoformat(name[:10])
	except ValueError:
		return None


def enforce_dns_log_retention(dns_dir: Path, retention_days: int) -> dict[str, int]:
	"""Apply DNS query retention by deleting stale day files from DNS logs.
	
	Note: TSDB retention is handled automatically via tsdb.append_point() during writes.
	This function only manages JSONL raw log files.
	"""
	queries_dir = dns_dir / "queries"
	retention_days = normalize_dns_log_retention_days(retention_days)
	if not queries_dir.exists():
		return {"deleted_files": 0, "remaining_files": 0}

	cutoff_day = None
	if retention_days > 0:
		cutoff_day = (datetime.now(timezone.utc) - timedelta(days=retention_days)).date()

	deleted = 0
	remaining = 0
	# No sorted() - iteration order doesn't matter for delete, saves RAM
	for path in queries_dir.iterdir():
		# Safety limit: prevent runaway deletion on corrupted setups
		if deleted >= MAX_DELETE_PER_RUN:
			_log.warning("DNS_RETENTION hit safety limit (%d deletes), stopping", MAX_DELETE_PER_RUN)
			break
		if not path.is_file():
			continue
		if path.suffix != ".jsonl":
			continue
		day = _extract_day_prefix(path.name)
		if day is None:
			remaining += 1
			continue
		should_delete = retention_days == 0 or (cutoff_day is not None and day < cutoff_day)
		if not should_delete:
			remaining += 1
			continue
		try:
			path.unlink(missing_ok=True)
			deleted += 1
		except OSError as e:
			_log.warning("DNS_RETENTION delete failed for %s: %s", path.name, e)
			remaining += 1

	return {"deleted_files": deleted, "remaining_files": remaining}
