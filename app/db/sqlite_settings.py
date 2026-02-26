#!/usr/bin/env python3
#
# app/db/sqlite_settings.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Application settings and DNS-related database helpers."""

from __future__ import annotations

from contextlib import closing
import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

from ..utils.time import utcnow
from .sqlite_runtime import transaction

_log = logging.getLogger(__name__)


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


_GLOBAL_SETTINGS_RECOVERY_KEYS = [
	"wg_fqdn",
	"wg_port",
	"wg_mtu",
	"wg_persistent_keepalive",
	"wg_use_psk",
	"gui_port",
	"gui_localhost_only",
	"enable_status_page",
	"wg_global_psk",
]


def recover_missing_global_settings(
	conn: sqlite3.Connection,
	candidate_db_paths: list[Path],
) -> int:
	"""Recover missing global settings from alternate WireBuddy DB files.

	Only fills keys that are currently missing/empty in the active DB and where a
	non-empty value exists in one of the candidate DB files.
	"""
	try:
		raw_current = str(conn.execute("PRAGMA database_list").fetchone()[2] or "").strip()
		current_db_path = str(Path(raw_current).resolve()) if raw_current else ""
	except Exception:
		_log.debug("Failed to resolve current DB path for settings recovery", exc_info=True)
		current_db_path = ""

	missing_keys = [
		key
		for key in _GLOBAL_SETTINGS_RECOVERY_KEYS
		if not str(get_setting(conn, key, "") or "").strip()
	]
	if not missing_keys:
		return 0

	updated = 0
	seen_paths: set[str] = set()
	allowed_names = {"wirebuddy.db"}
	for candidate in candidate_db_paths:
		path = str(Path(candidate).resolve())
		if not path or path in seen_paths:
			continue
		seen_paths.add(path)
		if current_db_path and path == current_db_path:
			continue
		candidate_file = Path(path)
		if candidate_file.name not in allowed_names:
			_log.debug("Skipping recovery candidate with disallowed filename: %s", candidate_file)
			continue
		if not candidate_file.exists() or not candidate_file.is_file():
			continue

		try:
			with closing(sqlite3.connect(path)) as src:
				src.row_factory = sqlite3.Row
				for key in list(missing_keys):
					row = src.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
					if not row:
						continue
					value = str(row["value"] or "").strip()
					if not value:
						continue
					set_setting(conn, key, value)
					missing_keys.remove(key)
					updated += 1
		except Exception:
			_log.debug("Failed reading recovery DB candidate: %s", path, exc_info=True)
			continue

		if not missing_keys:
			break

	return updated


DNS_LOG_RETENTION_OPTIONS = (0, 7, 30, 90, 180, 365)
DEFAULT_DNS_LOG_RETENTION_DAYS = 30
MAX_CUSTOM_RULES_LENGTH = 256_000
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
			parsed = json.loads(value)
			if isinstance(parsed, list):
				return [str(item) for item in parsed if str(item).strip()]
		except Exception:
			_log.debug("Failed to parse dns_blocklists setting", exc_info=True)
	# Return default blocklists if not set
	from ..dns import constants as dns_constants

	return dns_constants.DEFAULT_BLOCKLISTS


def set_enabled_blocklists(conn: sqlite3.Connection, urls: list[str]) -> None:
	"""Save list of enabled blocklist URLs to settings."""
	if not isinstance(urls, list) or not all(isinstance(url, str) and url.strip() for url in urls):
		raise TypeError("urls must be a list of non-empty strings")
	set_setting(conn, "dns_blocklists", json.dumps(urls))


def get_dns_upstream_servers(conn: sqlite3.Connection) -> list[str]:
	"""Get list of custom upstream DNS servers from settings."""
	value = get_setting(conn, "dns_upstream_servers")
	if value:
		try:
			parsed = json.loads(value)
			if isinstance(parsed, list) and parsed:
				return [str(item).strip() for item in parsed if str(item).strip()]
		except Exception:
			_log.debug("Failed to parse dns_upstream_servers setting", exc_info=True)
	# Return default upstream servers if not set
	return list(DEFAULT_DNS_UPSTREAM_SERVERS)


def set_dns_upstream_servers(conn: sqlite3.Connection, servers: list[str]) -> None:
	"""Save list of custom upstream DNS servers to settings."""
	if not isinstance(servers, list) or not all(isinstance(server, str) and server.strip() for server in servers):
		raise TypeError("servers must be a list of non-empty strings")
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


# ---------------------------------------------------------------------------
# Custom DNS Rules
# ---------------------------------------------------------------------------

# Default example rules shown when no custom rules exist yet
DEFAULT_DNS_CUSTOM_RULES = """\
! ─────────────────────────────────────────────────────────────
! Custom DNS Rules (AdGuard Syntax)
! ─────────────────────────────────────────────────────────────
! Lines starting with ! are comments and will be ignored.
!
! BLOCK a domain (and all subdomains):
! ||ads.example.com^
!
! ALLOW (whitelist) a domain:
! @@||safe.example.com^
!
! WILDCARD block (matches any subdomain):
! ||tracker*.example.com^
!
! REGEX block:
! /^ad[0-9]+\\.example\\.com$/
!
! CLIENT-SPECIFIC rule (only for specific VPN client):
! ||social.example.com^$client=10.0.0.5
! ─────────────────────────────────────────────────────────────
"""


def get_dns_custom_rules(conn: sqlite3.Connection) -> str:
	"""Get the raw custom DNS rules text (AdGuard syntax)."""
	stored = get_setting(conn, "dns_custom_rules", None)
	# Return default examples if nothing stored yet
	if stored is None:
		return DEFAULT_DNS_CUSTOM_RULES
	return stored or ""


def set_dns_custom_rules(conn: sqlite3.Connection, rules_text: str) -> None:
	"""Persist the raw custom DNS rules text."""
	if len(rules_text) > MAX_CUSTOM_RULES_LENGTH:
		raise ValueError("Custom rules text exceeds maximum allowed size")
	normalized_rules = "" if not rules_text.strip() else rules_text
	set_setting(conn, "dns_custom_rules", normalized_rules)
