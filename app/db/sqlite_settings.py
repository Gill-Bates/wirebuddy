#!/usr/bin/env python3
#
# app/db/sqlite_settings.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Application settings and DNS-related database helpers."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from ..utils.time import utcnow
from .sqlite_runtime import transaction


# ---------------------------------------------------------------------------
# Settings operations
# ---------------------------------------------------------------------------

def get_setting(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
	"""Get a setting value by key."""
	cur = conn.execute("SELECT value FROM settings WHERE key = ?", (key,))
	row = cur.fetchone()
	return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
	"""Set a setting value."""
	now = utcnow()
	with transaction(conn):
		conn.execute(
			"""
			INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
			""",
			(key, value, now),
		)


DNS_LOG_RETENTION_OPTIONS = {0, 7, 30, 90, 180, 365}
DEFAULT_DNS_LOG_RETENTION_DAYS = 30
DEFAULT_DNS_UPSTREAM_SERVERS = [
	"1.1.1.1@853#cloudflare-dns.com",
	"9.9.9.9@853#dns.quad9.net",
	"91.239.100.100@853#anycast.censurfridns.dk",
	"45.90.28.0@853#dns.nextdns.io",
	"194.242.2.2@853#dns.mullvad.net",
]


def _setting_is_truthy(value: Any, default: bool = False) -> bool:
	"""Parse boolean-ish setting values from strings."""
	if value is None:
		return default
	return str(value).strip().lower() in {"1", "true", "yes", "on"}


def get_enabled_blocklists(conn: sqlite3.Connection) -> list[str]:
	"""Get list of enabled blocklist URLs from settings."""
	value = get_setting(conn, "dns_blocklists")
	if value:
		try:
			return json.loads(value)
		except Exception:
			pass
	# Return default blocklists if not set
	from ..dns import constants as dns_constants

	return dns_constants.DEFAULT_BLOCKLISTS


def set_enabled_blocklists(conn: sqlite3.Connection, urls: list[str]) -> None:
	"""Save list of enabled blocklist URLs to settings."""
	set_setting(conn, "dns_blocklists", json.dumps(urls))


def get_dns_upstream_servers(conn: sqlite3.Connection) -> list[str]:
	"""Get list of custom upstream DNS servers from settings."""
	value = get_setting(conn, "dns_upstream_servers")
	if value:
		try:
			parsed = json.loads(value)
			if isinstance(parsed, list) and parsed:
				return parsed
		except Exception:
			pass
	# Return default upstream servers if not set
	return list(DEFAULT_DNS_UPSTREAM_SERVERS)


def set_dns_upstream_servers(conn: sqlite3.Connection, servers: list[str]) -> None:
	"""Save list of custom upstream DNS servers to settings."""
	set_setting(conn, "dns_upstream_servers", json.dumps(servers))


def get_dns_log_retention_days(conn: sqlite3.Connection) -> int:
	"""Return DNS query log retention period in days.

	Allowed values:
	- 0 (disabled / keep no DNS logs)
	- 7
	- 30
	- 90
	- 180
	- 365
	"""
	raw = get_setting(conn, "dns_log_retention_days", str(DEFAULT_DNS_LOG_RETENTION_DAYS))
	try:
		parsed = int(str(raw).strip())
	except (TypeError, ValueError):
		return DEFAULT_DNS_LOG_RETENTION_DAYS
	return parsed if parsed in DNS_LOG_RETENTION_OPTIONS else DEFAULT_DNS_LOG_RETENTION_DAYS


def set_dns_log_retention_days(conn: sqlite3.Connection, days: int) -> None:
	"""Persist DNS query log retention period in days."""
	if days not in DNS_LOG_RETENTION_OPTIONS:
		raise ValueError(f"Invalid DNS log retention days: {days}")
	set_setting(conn, "dns_log_retention_days", str(days))


def get_dnssec_enabled(conn: sqlite3.Connection) -> bool:
	"""Get whether DNSSEC validation should be enabled."""
	return _setting_is_truthy(get_setting(conn, "dnssec_enabled", "1"), default=True)


def set_dnssec_enabled(conn: sqlite3.Connection, enabled: bool) -> None:
	"""Persist DNSSEC enabled setting."""
	set_setting(conn, "dnssec_enabled", "1" if enabled else "0")


def get_dns_query_logging_enabled(conn: sqlite3.Connection) -> bool:
	"""Get whether Unbound query logging is enabled."""
	return _setting_is_truthy(get_setting(conn, "dns_enable_logging", "1"), default=True)


def set_dns_query_logging_enabled(conn: sqlite3.Connection, enabled: bool) -> None:
	"""Persist Unbound query logging enabled setting."""
	set_setting(conn, "dns_enable_logging", "1" if enabled else "0")


def get_dns_blocklist_enabled(conn: sqlite3.Connection) -> bool:
	"""Get whether DNS blocklist include is enabled in Unbound config."""
	return _setting_is_truthy(get_setting(conn, "dns_enable_blocklist", "1"), default=True)


def set_dns_blocklist_enabled(conn: sqlite3.Connection, enabled: bool) -> None:
	"""Persist DNS blocklist enabled setting."""
	set_setting(conn, "dns_enable_blocklist", "1" if enabled else "0")


def get_dns_service_enabled(conn: sqlite3.Connection) -> bool:
	"""Get whether Unbound service should be auto-started on application startup."""
	return _setting_is_truthy(get_setting(conn, "dns_service_enabled", "1"), default=True)


def set_dns_service_enabled(conn: sqlite3.Connection, enabled: bool) -> None:
	"""Persist desired Unbound service state across restarts."""
	set_setting(conn, "dns_service_enabled", "1" if enabled else "0")
