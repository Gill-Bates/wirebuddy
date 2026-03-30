#!/usr/bin/env python3
#
# app/db/sqlite_settings.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Application settings and DNS-related database helpers."""

from __future__ import annotations

import ipaddress
from contextlib import closing
import json
import logging
import re
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..utils import vault
from ..utils.config import get_config
from ..utils.time import utcnow
from .sqlite_runtime import transaction

_log = logging.getLogger(__name__)

__all__ = [
	"get_setting",
	"set_setting",
	"delete_setting",
	"validate_secret_key",
	"recover_missing_global_settings",
	"get_enabled_blocklists",
	"set_enabled_blocklists",
	"get_dns_upstream_servers",
	"set_dns_upstream_servers",
	"get_dns_log_retention_days",
	"set_dns_log_retention_days",
	"get_tsdb_retention_days",
	"set_tsdb_retention_days",
	"get_speedtest_retention_days",
	"set_speedtest_retention_days",
	"get_dnssec_enabled",
	"set_dnssec_enabled",
	"get_dns_query_logging_enabled",
	"set_dns_query_logging_enabled",
	"get_dns_blocklist_enabled",
	"set_dns_blocklist_enabled",
	"get_blocklist_disabled_until",
	"set_blocklist_disabled_until",
	"clear_blocklist_disabled_until",
	"get_dns_service_enabled",
	"set_dns_service_enabled",
	"get_dns_custom_rules",
	"set_dns_custom_rules",
	"DNS_LOG_RETENTION_OPTIONS",
	"DEFAULT_DNS_LOG_RETENTION_DAYS",
	"TSDB_RETENTION_OPTIONS",
	"DEFAULT_TSDB_RETENTION_DAYS",
	"SPEEDTEST_RETENTION_OPTIONS",
	"DEFAULT_SPEEDTEST_RETENTION_DAYS",
	"MAX_CUSTOM_RULES_LENGTH",
	"DEFAULT_DNS_UPSTREAM_SERVERS",
	"DEFAULT_DNS_CUSTOM_RULES",
	"SPEEDTEST_SERVER_LIST",
	"SPEEDTEST_SERVER_MAP",
	"get_speedtest_enabled",
	"set_speedtest_enabled",
	"get_speedtest_target",
	"set_speedtest_target",
]

# Constant for key validation
_KEY_VALIDATION_TOKEN_KEY = "_key_validation_token"
_KEY_VALIDATION_PLAINTEXT = "WIREBUDDY_KEY_VALID_v1"
_ALLOWED_RECOVERY_FILENAMES = {"wirebuddy.db"}
_RECOVERY_ALLOWED_BASES = (Path("/app/data"), Path("/opt/wirebuddy/data"))
_MAX_RECOVERY_VALUE_LEN = 1024
_SECRET_SETTING_KEYS = frozenset({"wg_global_psk", _KEY_VALIDATION_TOKEN_KEY})
_DNS_UPSTREAM_SERVER_RE = re.compile(
	r"^(?P<ip>\[[0-9A-Fa-f:.]+\]|[0-9A-Fa-f:.]+)@(?P<port>\d{1,5})#(?P<host>[A-Za-z0-9.-]{1,253})$"
)


# ---------------------------------------------------------------------------
# Key Validation
# ---------------------------------------------------------------------------

def validate_secret_key(conn: sqlite3.Connection, pepper: str) -> bool:
	"""Validate that the secret key matches the one used to encrypt the database.
	
	On first run (no token exists), creates and stores a validation token.
	On subsequent runs, attempts to decrypt the stored token.
	
	Returns:
		True if key is valid, False if there's a mismatch.
	"""
	from ..utils.vault import encrypt as vault_encrypt, decrypt as vault_decrypt
	
	stored_token = get_setting(conn, _KEY_VALIDATION_TOKEN_KEY)
	
	if stored_token is None:
		# Only initialize token on genuinely fresh DBs.
		row = conn.execute(
			"SELECT COUNT(*) FROM settings WHERE key != ?",
			(_KEY_VALIDATION_TOKEN_KEY,),
		).fetchone()
		other_settings = int(row[0] or 0) if row else 0
		if other_settings > 0:
			_log.error(
				"KEY_VALIDATION: validation token missing while %d settings exist; refusing auto-reinit",
				other_settings,
			)
			return False

		# First run - create and store validation token
		encrypted_token = vault_encrypt(_KEY_VALIDATION_PLAINTEXT, pepper)
		set_setting(conn, _KEY_VALIDATION_TOKEN_KEY, encrypted_token)
		_log.debug("KEY_VALIDATION: Created new validation token (fresh DB)")
		return True
	
	# Token exists - try to decrypt and validate
	try:
		decrypted = vault_decrypt(stored_token, pepper)
		if decrypted == _KEY_VALIDATION_PLAINTEXT:
			return True
		else:
			_log.error("KEY_VALIDATION: Decrypted token does not match expected value")
			return False
	except ValueError as e:
		_log.error("KEY_VALIDATION: Failed to decrypt validation token: %s", e)
		return False
	except Exception:
		_log.exception("KEY_VALIDATION: Unexpected error during token validation")
		return False


# ---------------------------------------------------------------------------
# Settings operations
# ---------------------------------------------------------------------------

def get_setting(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
	"""Get a setting value by key."""
	with closing(conn.execute("SELECT value FROM settings WHERE key = ?", (key,))) as cur:
		row = cur.fetchone()
	return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
	"""Set a setting value."""
	now = utcnow()
	stored_value = value
	if key in _SECRET_SETTING_KEYS:
		stored_value = vault.encrypt_if_needed(value, get_config().secret_key) or ""
	with transaction(conn):
		conn.execute(
			"""
			INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
			""",
			(key, stored_value, now),
		)


def delete_setting(conn: sqlite3.Connection, key: str) -> bool:
	"""Delete a setting value by key. Returns True if a row was removed."""
	with transaction(conn):
		cur = conn.execute("DELETE FROM settings WHERE key = ?", (key,))
		return cur.rowcount > 0


_GLOBAL_SETTINGS_RECOVERY_KEYS = [
	"wg_fqdn",
	"wg_port",
	"wg_mtu",
	"wg_persistent_keepalive",
	"wg_use_psk",
	"gui_port",
	"gui_external_port",
	"gui_localhost_only",
	"enable_status_page",
	"enable_swagger",
]


def _normalize_recovery_value(key: str, value: str) -> str | None:
	"""Validate and normalize recovered global settings values."""
	text = str(value or "").strip()
	if not text or len(text) > _MAX_RECOVERY_VALUE_LEN:
		return None

	def _normalize_bool(raw: str) -> str | None:
		lowered = raw.strip().lower()
		if lowered in {"1", "true", "yes", "on"}:
			return "1"
		if lowered in {"0", "false", "no", "off"}:
			return "0"
		return None

	if key in {"wg_port", "gui_port", "gui_external_port"}:
		if not text.isdigit():
			return None
		port = int(text)
		return str(port) if 1 <= port <= 65535 else None

	if key == "wg_mtu":
		if not text.isdigit():
			return None
		mtu = int(text)
		return str(mtu) if 1280 <= mtu <= 9000 else None

	if key == "wg_persistent_keepalive":
		if not text.isdigit():
			return None
		keepalive = int(text)
		return str(keepalive) if 0 <= keepalive <= 3600 else None

	if key in {"wg_use_psk", "gui_localhost_only", "enable_status_page", "enable_swagger"}:
		return _normalize_bool(text)

	if key == "wg_fqdn":
		# Allow hostnames and literal IPs; reject whitespace/control characters.
		if any(ch.isspace() for ch in text):
			return None
		if re.fullmatch(r"[A-Za-z0-9.:\-\[\]]{1,253}", text) is None:
			return None
		return text

	return text


def _is_recovery_candidate_allowed(
	original: Path,
	resolved: Path,
	current_db_dir: Path | None,
) -> bool:
	"""Validate recovery candidate path and base-directory constraints."""
	if resolved.name not in _ALLOWED_RECOVERY_FILENAMES:
		_log.debug("Skipping recovery candidate with disallowed filename: %s", resolved)
		return False

	if original.is_symlink():
		_log.warning("Skipping symlink recovery candidate: %s", original)
		return False

	allowed_bases = [base.resolve() for base in _RECOVERY_ALLOWED_BASES]
	if current_db_dir is not None:
		allowed_bases.append(current_db_dir.resolve())

	for base in allowed_bases:
		try:
			resolved.relative_to(base)
			return True
		except ValueError:
			continue

	_log.warning("Skipping recovery candidate outside allowed base: %s", resolved)
	return False


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
		current_db_file = Path(raw_current).resolve() if raw_current else None
	except Exception:
		_log.debug("Failed to resolve current DB path for settings recovery", exc_info=True)
		current_db_file = None
	current_db_dir = current_db_file.parent if current_db_file is not None else None

	missing_keys = {
		key
		for key in _GLOBAL_SETTINGS_RECOVERY_KEYS
		if not str(get_setting(conn, key, "") or "").strip()
	}
	if not missing_keys:
		return 0

	updated = 0
	seen_paths: set[Path] = set()
	for candidate in candidate_db_paths:
		candidate_path = Path(candidate)
		resolved = candidate_path.resolve()
		if resolved in seen_paths:
			continue
		seen_paths.add(resolved)
		if current_db_file is not None and resolved == current_db_file:
			continue
		if not _is_recovery_candidate_allowed(candidate_path, resolved, current_db_dir):
			continue
		if not resolved.exists() or not resolved.is_file():
			continue

		try:
			recovered_keys: set[str] = set()
			with closing(sqlite3.connect(str(resolved))) as src:
				src.row_factory = sqlite3.Row
				for key in tuple(missing_keys):
					row = src.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
					if not row:
						continue
					value = str(row["value"] or "").strip()
					normalized = _normalize_recovery_value(key, value)
					if normalized is None:
						_log.warning("Skipping invalid recovered value for %s from %s", key, resolved)
						continue
					set_setting(conn, key, normalized)
					recovered_keys.add(key)
			if recovered_keys:
				missing_keys -= recovered_keys
				updated += len(recovered_keys)
		except Exception:
			_log.debug("Failed reading recovery DB candidate: %s", resolved, exc_info=True)
			continue

		if not missing_keys:
			break

	return updated


DNS_LOG_RETENTION_OPTIONS = (0, 7, 30, 90, 180, 365)
DEFAULT_DNS_LOG_RETENTION_DAYS = 7

TSDB_RETENTION_OPTIONS = (0, 7, 30, 90, 180, 365)
DEFAULT_TSDB_RETENTION_DAYS = 7

# Speedtest data retention (longer default since data is sparse)
SPEEDTEST_RETENTION_OPTIONS = (0, 7, 30, 90, 180, 365)
DEFAULT_SPEEDTEST_RETENTION_DAYS = 365

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
				return [str(item).strip() for item in parsed if str(item).strip()]
		except Exception:
			_log.debug("Failed to parse dns_blocklists setting", exc_info=True)
	# Return default blocklists if not set
	from ..dns import constants as dns_constants

	return dns_constants.DEFAULT_BLOCKLISTS


def set_enabled_blocklists(conn: sqlite3.Connection, urls: list[str]) -> None:
	"""Save list of enabled blocklist URLs to settings."""
	if not isinstance(urls, list):
		raise TypeError("urls must be a list")
	normalized: list[str] = []
	for idx, url in enumerate(urls):
		if not isinstance(url, str):
			raise TypeError(f"urls[{idx}] must be a string, got {type(url).__name__}")
		value = url.strip()
		if not value:
			raise ValueError(f"urls[{idx}] must be non-empty")
		parsed = urlparse(value)
		if parsed.scheme != "https" or not parsed.hostname:
			raise ValueError(f"urls[{idx}] must be a valid HTTPS URL")
		normalized.append(value)
	set_setting(conn, "dns_blocklists", json.dumps(normalized))


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
	if not isinstance(servers, list):
		raise TypeError("servers must be a list")

	normalized: list[str] = []
	for idx, server in enumerate(servers):
		if not isinstance(server, str):
			raise TypeError(f"servers[{idx}] must be a string, got {type(server).__name__}")
		value = server.strip()
		if not value:
			raise ValueError(f"servers[{idx}] must be non-empty")

		match = _DNS_UPSTREAM_SERVER_RE.fullmatch(value)
		if not match:
			raise ValueError(f"Invalid DNS server format: {value}")

		ip_part = match.group("ip")
		if ip_part.startswith("[") and ip_part.endswith("]"):
			ip_part = ip_part[1:-1]
		try:
			ipaddress.ip_address(ip_part)
		except ValueError as exc:
			raise ValueError(f"Invalid upstream IP literal: {value}") from exc

		port = int(match.group("port"))
		if not 1 <= port <= 65535:
			raise ValueError(f"Invalid upstream port: {value}")

		host = match.group("host").strip(".").lower()
		if not host:
			raise ValueError(f"Invalid upstream hostname: {value}")
		labels = host.split(".")
		if any((not label) or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
			raise ValueError(f"Invalid upstream hostname: {value}")

		normalized.append(f"{ip_part}@{port}#{host}")

	set_setting(conn, "dns_upstream_servers", json.dumps(normalized))


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


def get_tsdb_retention_days(conn: sqlite3.Connection) -> int:
	"""Return TSDB (traffic metrics) retention period in days.

	Allowed values: 7, 30, 90, 180, 365
	"""
	raw = get_setting(conn, "tsdb_retention_days", str(DEFAULT_TSDB_RETENTION_DAYS))
	try:
		parsed = int(str(raw).strip())
	except (TypeError, ValueError):
		return DEFAULT_TSDB_RETENTION_DAYS
	return parsed if parsed in TSDB_RETENTION_OPTIONS else DEFAULT_TSDB_RETENTION_DAYS


def set_tsdb_retention_days(conn: sqlite3.Connection, days: int) -> None:
	"""Persist TSDB (traffic metrics) retention period in days."""
	if days not in TSDB_RETENTION_OPTIONS:
		raise ValueError(f"Invalid TSDB retention days: {days}")
	set_setting(conn, "tsdb_retention_days", str(days))


def get_speedtest_retention_days(conn: sqlite3.Connection) -> int:
	"""Return speedtest data retention period in days.

	Allowed values: 0, 7, 30, 90, 180, 365
	Default is 365 days since speedtest data is sparse.
	"""
	raw = get_setting(conn, "speedtest_retention_days", str(DEFAULT_SPEEDTEST_RETENTION_DAYS))
	try:
		parsed = int(str(raw).strip())
	except (TypeError, ValueError):
		return DEFAULT_SPEEDTEST_RETENTION_DAYS
	return parsed if parsed in SPEEDTEST_RETENTION_OPTIONS else DEFAULT_SPEEDTEST_RETENTION_DAYS


def set_speedtest_retention_days(conn: sqlite3.Connection, days: int) -> None:
	"""Persist speedtest data retention period in days."""
	if days not in SPEEDTEST_RETENTION_OPTIONS:
		raise ValueError(f"Invalid speedtest retention days: {days}")
	set_setting(conn, "speedtest_retention_days", str(days))


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
	return _setting_is_truthy(get_setting(conn, "dns_enable_blocklist", "0"), default=False)


def set_dns_blocklist_enabled(conn: sqlite3.Connection, enabled: bool) -> None:
	"""Persist DNS blocklist enabled setting."""
	set_setting(conn, "dns_enable_blocklist", "1" if enabled else "0")


def get_blocklist_disabled_until(conn: sqlite3.Connection) -> int:
	"""Return epoch timestamp until which the blocklist is temporarily disabled.

	Returns 0 if no timer is active.
	"""
	raw = get_setting(conn, "blocklist_disabled_until", "0")
	try:
		return max(0, int(str(raw).strip()))
	except (TypeError, ValueError):
		return 0


def set_blocklist_disabled_until(conn: sqlite3.Connection, until_epoch: int) -> None:
	"""Set the epoch timestamp until which the blocklist should be disabled."""
	set_setting(conn, "blocklist_disabled_until", str(max(0, int(until_epoch))))


def clear_blocklist_disabled_until(conn: sqlite3.Connection) -> None:
	"""Remove the blocklist disable timer."""
	delete_setting(conn, "blocklist_disabled_until")


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


# ---------------------------------------------------------------------------
# Speedtest / Bandwidth Measurement
# ---------------------------------------------------------------------------

_SPEEDTEST_SERVERS = [
	{"id": "hetzner", "name": "Hetzner", "url": "https://speed.hetzner.de/100MB.bin"},
	{"id": "ovh", "name": "OVH", "url": "http://proof.ovh.net/files/100Mb.dat"},
	{"id": "cachefly", "name": "CacheFly", "url": "http://cachefly.cachefly.net/100mb.test"},
	{"id": "cloudflare", "name": "Cloudflare", "url": "https://speed.cloudflare.com/__down"},
	{"id": "wtnet", "name": "wilhelm.tel (Hamburg)", "url": "https://speedtest.wtnet.de/backend/garbage.php?ckSize=100"},
]

SPEEDTEST_SERVER_MAP: dict[str, dict[str, str]] = {s["id"]: s for s in _SPEEDTEST_SERVERS}
SPEEDTEST_SERVER_LIST: list[dict[str, str]] = list(_SPEEDTEST_SERVERS)


def get_speedtest_enabled(conn: sqlite3.Connection) -> bool:
	"""Return True if scheduled speed tests are enabled."""
	return get_setting(conn, "speedtest_enabled", "0") == "1"


def set_speedtest_enabled(conn: sqlite3.Connection, enabled: bool) -> None:
	set_setting(conn, "speedtest_enabled", "1" if enabled else "0")


def get_speedtest_target(conn: sqlite3.Connection) -> str:
	"""Return the speed test target id (or 'auto' for RTT-based selection)."""
	return get_setting(conn, "speedtest_target", "auto") or "auto"


def set_speedtest_target(conn: sqlite3.Connection, target: str) -> None:
	if target != "auto" and target not in SPEEDTEST_SERVER_MAP:
		raise ValueError(f"Unknown speedtest target: {target}")
	set_setting(conn, "speedtest_target", target)



