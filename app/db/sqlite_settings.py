#!/usr/bin/env python3
#
# app/db/sqlite_settings.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Application settings and DNS-related database helpers."""

from __future__ import annotations

import ipaddress
from contextlib import closing
from datetime import datetime
import json
import logging
import re
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..utils import vault
from ..utils.config import get_config
from ..utils.time import ensure_utc, parse_utc, utcnow
from .sqlite_runtime import transaction

_log = logging.getLogger(__name__)

# Maximum JSON payload size to prevent DB bloat / DoS
_MAX_JSON_SETTING_LENGTH = 65_536

# Shared retention choices across DNS, TSDB, and speedtest settings.
_RETENTION_OPTIONS = (0, 7, 30, 90, 180, 365)

__all__ = [
	# Core operations
	"delete_setting",
	"get_setting",
	"recover_missing_global_settings",
	"set_setting",
	"validate_secret_key",
	# Blocklist
	"clear_blocklist_disabled_until",
	"get_blocklist_disabled_until",
	"get_dns_blocklist_enabled",
	"get_enabled_blocklists",
	"set_blocklist_disabled_until",
	"set_dns_blocklist_enabled",
	"set_enabled_blocklists",
	# DNS
	"get_dns_custom_rules",
	"get_dns_log_retention_days",
	"get_dns_query_logging_enabled",
	"get_dns_service_enabled",
	"get_dns_upstream_servers",
	"get_dnssec_enabled",
	"set_dns_custom_rules",
	"set_dns_log_retention_days",
	"set_dns_query_logging_enabled",
	"set_dns_service_enabled",
	"set_dns_upstream_servers",
	"set_dnssec_enabled",
	# Speedtest
	"get_speedtest_enabled",
	"get_speedtest_ignore_peers",
	"get_speedtest_last_result",
	"get_node_speedtest_last_result",
	"get_node_speedtest_last_results",
	"get_speedtest_last_run_at",
	"get_speedtest_retention_days",
	"set_speedtest_enabled",
	"set_speedtest_ignore_peers",
	"set_speedtest_last_result",
	"set_node_speedtest_last_result",
	"set_speedtest_last_run_at",
	"set_speedtest_retention_days",
	# TSDB
	"get_tsdb_retention_days",
	"set_tsdb_retention_days",
	# Constants
	"DEFAULT_DNS_CUSTOM_RULES",
	"DEFAULT_DNS_LOG_RETENTION_DAYS",
	"DEFAULT_DNS_UPSTREAM_SERVERS",
	"DEFAULT_SPEEDTEST_RETENTION_DAYS",
	"DEFAULT_TSDB_RETENTION_DAYS",
	"DNS_LOG_RETENTION_OPTIONS",
	"MAX_CUSTOM_RULES_LENGTH",
	"SPEEDTEST_RETENTION_OPTIONS",
	"TSDB_RETENTION_OPTIONS",
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
# Validation helpers (reused across recovery and setters)
# ---------------------------------------------------------------------------

def _validate_port(text: str) -> int | None:
	"""Parse and validate a port number string.
	
	Returns the port as int if valid (1-65535), or None if invalid.
	"""
	if not text.isdigit():
		return None
	port = int(text)
	return port if 1 <= port <= 65535 else None


def _validate_hostname(text: str) -> str | None:
	"""Validate and normalize a hostname or IP address.
	
	Returns the normalized hostname/IP if valid, or None if invalid.
	Accepts:
	- IPv4/IPv6 literals (including bracketed IPv6)
	- DNS hostnames (FQDN)
	"""
	text = str(text or "").strip()
	if not text or len(text) > 253:
		return None
	
	# Try parsing as IP address first
	try:
		ipaddress.ip_address(text.strip("[]"))
		return text  # Valid IP literal
	except ValueError:
		pass  # Not an IP, try hostname validation
	
	# Validate as hostname (FQDN)
	if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", text):
		return None
	labels = text.strip(".").split(".")
	if any(
		(not label) or len(label) > 63 or label.startswith("-") or label.endswith("-")
		for label in labels
	):
		return None
	return text


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
		# Note: set_setting auto-encrypts since _KEY_VALIDATION_TOKEN_KEY is in _SECRET_SETTING_KEYS
		set_setting(conn, _KEY_VALIDATION_TOKEN_KEY, _KEY_VALIDATION_PLAINTEXT)
		_log.debug("KEY_VALIDATION: Created new validation token (fresh DB)")
		return True
	
	# Token exists - try to decrypt and validate
	try:
		decrypted = vault.decrypt(stored_token, pepper)
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
	if row is None:
		return default
	if isinstance(row, sqlite3.Row):
		return row["value"]
	return row[0]


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
	"""Set a setting value.
	
	Note: Requires conn.row_factory = sqlite3.Row for get_setting to work correctly.
	"""
	now = utcnow()
	stored_value = value
	if key in _SECRET_SETTING_KEYS:
		# Always encrypt secrets (not idempotent - caller must provide plaintext)
		cfg = get_config()
		stored_value = vault.encrypt(value, cfg.secret_key)
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
		port = _validate_port(text)
		return str(port) if port is not None else None

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
		# Reject whitespace/control characters before validation.
		if any(map(str.isspace, text)):
			return None
		return _validate_hostname(text)

	return text


def _verify_recovery_db_schema(db_path: Path) -> bool:
	"""Verify that a recovery candidate has the expected schema."""
	try:
		with closing(sqlite3.connect(str(db_path))) as test_conn:
			row = test_conn.execute(
				"SELECT name FROM sqlite_master WHERE type='table' AND name='settings'"
			).fetchone()
			return row is not None
	except Exception:
		_log.debug("Schema verification failed for %s", db_path, exc_info=True)
		return False


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
		# Verify schema before trusting the DB
		if not _verify_recovery_db_schema(resolved):
			_log.debug("Skipping recovery candidate with invalid schema: %s", resolved)
			continue

		try:
			recovered_keys: dict[str, str] = {}
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
					recovered_keys[key] = normalized
			# Apply all recovered values in a single transaction
			if recovered_keys:
				with transaction(conn):
					for key, normalized in recovered_keys.items():
						set_setting(conn, key, normalized)
				missing_keys -= set(recovered_keys.keys())
				updated += len(recovered_keys)
		except Exception:
			_log.debug("Failed reading recovery DB candidate: %s", resolved, exc_info=True)
			continue

		if not missing_keys:
			break

	return updated


DNS_LOG_RETENTION_OPTIONS = _RETENTION_OPTIONS
DEFAULT_DNS_LOG_RETENTION_DAYS = 7

TSDB_RETENTION_OPTIONS = _RETENTION_OPTIONS
DEFAULT_TSDB_RETENTION_DAYS = 7

# Speedtest data retention (longer default since data is sparse)
SPEEDTEST_RETENTION_OPTIONS = _RETENTION_OPTIONS
DEFAULT_SPEEDTEST_RETENTION_DAYS = 365

MAX_CUSTOM_RULES_LENGTH = 256_000
DEFAULT_DNS_UPSTREAM_SERVERS = (
	"1.1.1.1@853#cloudflare-dns.com",
	"9.9.9.9@853#dns.quad9.net",
	"91.239.100.100@853#anycast.censurfridns.dk",
	"45.90.28.0@853#dns.nextdns.io",
	"194.242.2.2@853#dns.mullvad.net",
)


def _parse_retention_days(
	raw: str | None,
	options: tuple[int, ...],
	default: int,
) -> int:
	"""Parse and validate retention period.
	
	Returns the parsed value if it's in the allowed options, otherwise the default.
	"""
	try:
		parsed = int(str(raw).strip())
	except (TypeError, ValueError):
		return default
	return parsed if parsed in options else default


def _setting_is_truthy(value: Any, default: bool = False) -> bool:
	"""Parse boolean-ish setting values from strings."""
	if value is None:
		return default
	return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _get_bool_setting(conn: sqlite3.Connection, key: str, *, default: bool = False) -> bool:
	"""Get a boolean setting from the database."""
	return _setting_is_truthy(get_setting(conn, key, "1" if default else "0"), default=default)


def _set_bool_setting(conn: sqlite3.Connection, key: str, enabled: bool) -> None:
	"""Persist a boolean setting as canonical 0/1 text."""
	set_setting(conn, key, "1" if enabled else "0")


def _get_retention_days(
	conn: sqlite3.Connection,
	key: str,
	options: tuple[int, ...],
	default: int,
) -> int:
	"""Read a retention setting with a shared fallback parser."""
	raw = get_setting(conn, key, str(default))
	return _parse_retention_days(raw, options, default)


def _set_retention_days(
	conn: sqlite3.Connection,
	key: str,
	days: int,
	options: tuple[int, ...],
) -> None:
	"""Persist a retention setting after validating against the allowed values."""
	if days not in options:
		raise ValueError(f"Invalid retention days: {days}")
	set_setting(conn, key, str(days))


def _get_json_list(
	conn: sqlite3.Connection,
	key: str,
	*,
	allow_empty: bool = True,
	default: list[str] | None = None,
) -> list[str]:
	"""Read a JSON list setting with best-effort normalization."""
	raw = get_setting(conn, key)
	if raw:
		try:
			parsed = json.loads(raw)
			if isinstance(parsed, list) and (allow_empty or parsed):
				return [str(item).strip() for item in parsed if str(item).strip()]
		except json.JSONDecodeError:
			_log.warning("Failed to parse JSON list setting %s", key)
	return list(default) if default is not None else []


def _get_json_dict(conn: sqlite3.Connection, key: str) -> dict[str, Any] | None:
	"""Read a JSON dict setting with best-effort validation."""
	raw = get_setting(conn, key)
	if raw is None:
		return None
	try:
		parsed = json.loads(raw)
	except json.JSONDecodeError:
		_log.warning("Failed to parse JSON dict setting %s", key)
		return None
	return parsed if isinstance(parsed, dict) else None


def _set_json_dict(conn: sqlite3.Connection, key: str, value: dict[str, Any] | None) -> None:
	"""Persist a JSON dict setting or delete it when value is None."""
	if value is None:
		delete_setting(conn, key)
		return
	payload = {**value, "ts": value.get("ts") or utcnow().isoformat()}
	set_setting(conn, key, json.dumps(payload, ensure_ascii=False, default=str))


def get_enabled_blocklists(conn: sqlite3.Connection) -> list[str]:
	"""Get list of enabled blocklist URLs from settings."""
	value = _get_json_list(conn, "dns_blocklists")
	if value:
		return value
	# Return default blocklists if not set or invalid
	from ..dns import constants as dns_constants

	return list(dns_constants.DEFAULT_BLOCKLISTS)


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
	json_str = json.dumps(normalized)
	if len(json_str) > _MAX_JSON_SETTING_LENGTH:
		raise ValueError(f"Blocklist JSON payload exceeds {_MAX_JSON_SETTING_LENGTH} bytes")
	set_setting(conn, "dns_blocklists", json_str)


def get_dns_upstream_servers(conn: sqlite3.Connection) -> list[str]:
	"""Get list of custom upstream DNS servers from settings."""
	value = _get_json_list(conn, "dns_upstream_servers", allow_empty=False)
	if value:
		return value
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

		port = _validate_port(match.group("port"))
		if port is None:
			raise ValueError(f"Invalid upstream port: {value}")

		host = match.group("host").strip(".").lower()
		if _validate_hostname(host) is None:
			raise ValueError(f"Invalid upstream hostname: {value}")

		# Preserve IPv6 brackets
		if ":" in ip_part:
			ip_part = f"[{ip_part}]"
		normalized.append(f"{ip_part}@{port}#{host}")

	json_str = json.dumps(normalized)
	if len(json_str) > _MAX_JSON_SETTING_LENGTH:
		raise ValueError(f"DNS upstream JSON payload exceeds {_MAX_JSON_SETTING_LENGTH} bytes")
	set_setting(conn, "dns_upstream_servers", json_str)


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
	return _get_retention_days(conn, "dns_log_retention_days", DNS_LOG_RETENTION_OPTIONS, DEFAULT_DNS_LOG_RETENTION_DAYS)


def set_dns_log_retention_days(conn: sqlite3.Connection, days: int) -> None:
	"""Persist DNS query log retention period in days."""
	_set_retention_days(conn, "dns_log_retention_days", days, DNS_LOG_RETENTION_OPTIONS)


def get_tsdb_retention_days(conn: sqlite3.Connection) -> int:
	"""Return TSDB (traffic metrics) retention period in days.

	Allowed values: 7, 30, 90, 180, 365
	"""
	return _get_retention_days(conn, "tsdb_retention_days", TSDB_RETENTION_OPTIONS, DEFAULT_TSDB_RETENTION_DAYS)


def set_tsdb_retention_days(conn: sqlite3.Connection, days: int) -> None:
	"""Persist TSDB (traffic metrics) retention period in days."""
	_set_retention_days(conn, "tsdb_retention_days", days, TSDB_RETENTION_OPTIONS)


def get_speedtest_retention_days(conn: sqlite3.Connection) -> int:
	"""Return speedtest data retention period in days.

	Allowed values: 0, 7, 30, 90, 180, 365
	Default is 365 days since speedtest data is sparse.
	"""
	return _get_retention_days(conn, "speedtest_retention_days", SPEEDTEST_RETENTION_OPTIONS, DEFAULT_SPEEDTEST_RETENTION_DAYS)


def set_speedtest_retention_days(conn: sqlite3.Connection, days: int) -> None:
	"""Persist speedtest data retention period in days."""
	_set_retention_days(conn, "speedtest_retention_days", days, SPEEDTEST_RETENTION_OPTIONS)


def get_dnssec_enabled(conn: sqlite3.Connection) -> bool:
	"""Get whether DNSSEC validation should be enabled."""
	return _get_bool_setting(conn, "dnssec_enabled", default=True)


def set_dnssec_enabled(conn: sqlite3.Connection, enabled: bool) -> None:
	"""Persist DNSSEC enabled setting."""
	_set_bool_setting(conn, "dnssec_enabled", enabled)


def get_dns_query_logging_enabled(conn: sqlite3.Connection) -> bool:
	"""Get whether Unbound query logging is enabled."""
	return _get_bool_setting(conn, "dns_enable_logging", default=True)


def set_dns_query_logging_enabled(conn: sqlite3.Connection, enabled: bool) -> None:
	"""Persist Unbound query logging enabled setting."""
	_set_bool_setting(conn, "dns_enable_logging", enabled)


def get_dns_blocklist_enabled(conn: sqlite3.Connection) -> bool:
	"""Get whether DNS blocklist include is enabled in Unbound config."""
	return _get_bool_setting(conn, "dns_enable_blocklist", default=False)


def set_dns_blocklist_enabled(conn: sqlite3.Connection, enabled: bool) -> None:
	"""Persist DNS blocklist enabled setting."""
	_set_bool_setting(conn, "dns_enable_blocklist", enabled)


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
	return _get_bool_setting(conn, "dns_service_enabled", default=True)


def set_dns_service_enabled(conn: sqlite3.Connection, enabled: bool) -> None:
	"""Persist desired Unbound service state across restarts."""
	_set_bool_setting(conn, "dns_service_enabled", enabled)


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
	normalized_rules = "" if not rules_text.strip() else rules_text.strip()
	if len(normalized_rules) > MAX_CUSTOM_RULES_LENGTH:
		raise ValueError("Custom rules text exceeds maximum allowed size")
	set_setting(conn, "dns_custom_rules", normalized_rules)


# ---------------------------------------------------------------------------
# Speedtest / Bandwidth Measurement
# ---------------------------------------------------------------------------

def get_speedtest_enabled(conn: sqlite3.Connection) -> bool:
	"""Return True if scheduled speed tests are enabled."""
	return _get_bool_setting(conn, "speedtest_enabled", default=False)


def set_speedtest_enabled(conn: sqlite3.Connection, enabled: bool) -> None:
	"""Persist scheduled speedtest enabled setting."""
	_set_bool_setting(conn, "speedtest_enabled", enabled)


def get_speedtest_ignore_peers(conn: sqlite3.Connection) -> bool:
	"""Return True if scheduled tests should run even when peers are connected."""
	return _get_bool_setting(conn, "speedtest_ignore_peers", default=False)


def set_speedtest_ignore_peers(conn: sqlite3.Connection, ignore_peers: bool) -> None:
	"""Persist whether scheduled tests skip the peer-idle check."""
	_set_bool_setting(conn, "speedtest_ignore_peers", ignore_peers)


def get_speedtest_last_result(conn: sqlite3.Connection) -> dict[str, Any] | None:
	"""Return the last successful local speedtest result stored in SQLite."""
	return _get_json_dict(conn, "speedtest_last_result")


def set_speedtest_last_result(conn: sqlite3.Connection, result: dict[str, Any] | None = None) -> None:
	"""Persist the last successful local speedtest result in SQLite."""
	_set_json_dict(conn, "speedtest_last_result", result)


def _node_speedtest_last_result_key(node_id: str) -> str:
	"""Build the settings key for a node-specific last speedtest result."""
	return f"speedtest_last_result:node:{node_id}"


def get_node_speedtest_last_result(conn: sqlite3.Connection, node_id: str) -> dict[str, Any] | None:
	"""Return the last successful speedtest result stored for a node."""
	return _get_json_dict(conn, _node_speedtest_last_result_key(node_id))


def get_node_speedtest_last_results(
	conn: sqlite3.Connection,
	node_ids: set[str],
) -> dict[str, dict[str, Any]]:
	"""Return last successful speedtest results for the requested nodes.

	Uses a single IN-query instead of O(n) individual lookups.
	"""
	if not node_ids:
		return {}

	keys = [_node_speedtest_last_result_key(nid) for nid in node_ids]
	prefix = "speedtest_last_result:node:"
	placeholders = ",".join("?" * len(keys))
	rows = conn.execute(
		f"SELECT key, value FROM settings WHERE key IN ({placeholders})",
		tuple(keys),
	).fetchall()

	results: dict[str, dict[str, Any]] = {}
	for row in rows:
		node_id = row["key"].removeprefix(prefix) if isinstance(row, sqlite3.Row) else row[0].removeprefix(prefix)
		raw_value = row["value"] if isinstance(row, sqlite3.Row) else row[1]
		if raw_value is None:
			continue
		try:
			parsed = json.loads(raw_value)
			if isinstance(parsed, dict):
				results[node_id] = parsed
		except json.JSONDecodeError:
			_log.warning("Corrupt speedtest JSON for node %s", node_id)
	return results


def set_node_speedtest_last_result(
	conn: sqlite3.Connection,
	node_id: str,
	result: dict[str, Any] | None = None,
) -> None:
	"""Persist the last successful speedtest result for a node."""
	_set_json_dict(conn, _node_speedtest_last_result_key(node_id), result)


def get_speedtest_last_run_at(conn: sqlite3.Connection) -> datetime | None:
	"""Return the last completed local speedtest run timestamp in UTC."""
	raw = get_setting(conn, "speedtest_last_run_at", None)
	return parse_utc(raw) if raw else None


def set_speedtest_last_run_at(conn: sqlite3.Connection, when: datetime | None = None) -> None:
	"""Persist the last completed local speedtest run timestamp in UTC."""
	value = ensure_utc(when) if when is not None else utcnow()
	set_setting(conn, "speedtest_last_run_at", value.isoformat())



