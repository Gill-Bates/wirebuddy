#!/usr/bin/env python3
#
# app/utils/config.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Configuration loading and app-level defaults."""

from __future__ import annotations

import ipaddress
import logging
import os
import stat
import threading
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Fixed constants (not configurable - Docker is a closed system)
# ---------------------------------------------------------------------------
WG_CONFIG_PATH = Path("/etc/wireguard")
WG_DEFAULT_DNS = "1.1.1.1,9.9.9.9"  # Cloudflare + Quad9 with DoT support
_MAX_DOTENV_SIZE = 1024 * 1024
_MIN_SECRET_KEY_BYTES = 32

# Default trusted-proxy CIDRs when WIREBUDDY_TRUSTED_PROXIES is unset. This
# only covers loopback so that a bare install (no reverse proxy in front)
# still gets correct client-IP/HTTPS detection without any configuration.
_DEFAULT_TRUSTED_PROXY_CIDRS = "127.0.0.0/8,::1/128"

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_proxy_cidrs(raw: str, source: str = "trusted-proxy") -> tuple[IPNetwork, ...]:
	"""Parse a comma-separated CIDR list, skipping and logging invalid entries."""
	networks: list[IPNetwork] = []
	for item in (part.strip() for part in raw.split(",")):
		if not item:
			continue
		try:
			networks.append(ipaddress.ip_network(item, strict=False))
		except ValueError:
			_log.warning("Ignoring invalid %s CIDR entry: %r", source, item)
	return tuple(networks)


TRUSTED_PROXIES_ENV = "WIREBUDDY_TRUSTED_PROXIES"
_explicit_proxy_networks: tuple[IPNetwork, ...] | None = None


def get_explicit_trusted_proxy_networks() -> tuple[IPNetwork, ...]:
	"""Return the CIDRs listed in WIREBUDDY_TRUSTED_PROXIES; empty when unset.

	Unlike ``Config.trusted_proxies`` there is no loopback default, so callers
	that must never trust loopback implicitly (the /status check) can use it. Resolved
	lazily and cached: ``get_config()`` runs first so settings.env is loaded
	regardless of module import order.
	"""
	global _explicit_proxy_networks
	if _explicit_proxy_networks is None:
		get_config()
		raw = os.environ.get(TRUSTED_PROXIES_ENV, "").strip()
		_explicit_proxy_networks = parse_proxy_cidrs(raw, TRUSTED_PROXIES_ENV) if raw else ()
	return _explicit_proxy_networks


MTLS_PROXIES_ENV = "WIREBUDDY_MTLS_PROXIES"
_mtls_proxy_networks: tuple[IPNetwork, ...] | None = None


def get_mtls_proxy_networks() -> tuple[IPNetwork, ...]:
	"""Return the CIDRs allowed to deliver the client-cert fingerprint header.

	Deliberately independent of WIREBUDDY_TRUSTED_PROXIES: a proxy trusted for
	X-Forwarded-* is not thereby trusted for mTLS. Empty when unset (trust
	nothing); invalid entries are logged and skipped, which only narrows trust.
	"""
	global _mtls_proxy_networks
	if _mtls_proxy_networks is None:
		get_config()
		raw = os.environ.get(MTLS_PROXIES_ENV, "").strip()
		_mtls_proxy_networks = parse_proxy_cidrs(raw, MTLS_PROXIES_ENV) if raw else ()
	return _mtls_proxy_networks


@dataclass(frozen=True)
class Config:
	"""Resolved runtime configuration derived from env and defaults."""

	base_dir: Path
	db_path: Path
	tsdb_dir: Path
	dns_dir: Path
	data_dir: Path
	log_level: str = "INFO"
	secret_key: str | None = None
	# Canonical public origin, e.g. "https://vpn.example.com". Drives CSRF
	# allowed origins, the passkey RP ID/origin, the Host-header allowlist,
	# and the secure-cookie default (not HSTS). Empty when not configured.
	public_origin: str = ""
	# CIDRs of reverse proxies whose forwarded headers (X-Forwarded-*,
	# client-cert fingerprint) are trusted. Empty tuple = trust nothing.
	trusted_proxies: tuple[IPNetwork, ...] = field(default_factory=tuple)
	# Opt-in: reject plaintext-HTTP authentication (user login and node
	# bearer/enrollment auth) outright instead of only warning. Loopback stays
	# exempt so local development over HTTP keeps working.
	require_https_auth: bool = False
	# Enrollment-token migration (I-016): master accepts legacy v1 (HMAC) tokens
	# at /api/nodes/enroll, and the protocol version of newly issued tokens.
	enrollment_accept_v1: bool = True
	enrollment_token_version: int = 2

	@property
	def public_origin_hostname(self) -> str | None:
		"""Hostname component of ``public_origin``, or ``None`` if unset/invalid."""
		if not self.public_origin:
			return None
		hostname = (urlparse(self.public_origin).hostname or "").strip()
		return hostname or None

	@property
	def force_https(self) -> bool:
		"""Whether the public origin is HTTPS (forces secure cookies; HSTS is decided per request)."""
		return urlparse(self.public_origin).scheme.lower() == "https" if self.public_origin else False

	def is_trusted_proxy_ip(self, ip_text: str) -> bool:
		"""Return True when the given IP belongs to a configured trusted-proxy CIDR."""
		try:
			ip_obj = ipaddress.ip_address(ip_text)
		except ValueError:
			return False
		return any(ip_obj in network for network in self.trusted_proxies)


def _parse_value(raw: str) -> str:
	"""Extract value, respecting quotes and stripping inline comments.

	Handles quoted values correctly (e.g., DATABASE_URL="postgres://...#5")
	and only strips comments from unquoted values.
	"""
	raw = raw.strip()
	if raw and raw[0] in ('"', "'"):
		quote = raw[0]
		end = raw.find(quote, 1)
		if end != -1:
			return raw[1:end]
		# Unterminated quote - fall through to unquoted handling
	# Unquoted: strip inline comments
	if " #" in raw:
		raw = raw.split(" #", 1)[0]
	return raw.strip()


def parse_strict_bool(name: str, default: bool) -> bool:
	"""Read a boolean env var; an unrecognized value is an error, never a silent default."""
	raw = os.getenv(name, "").strip().lower()
	if not raw:
		return default
	if raw in ("1", "true", "yes", "on"):
		return True
	if raw in ("0", "false", "no", "off"):
		return False
	raise ValueError(f"{name} must be one of 1/0/true/false/yes/no/on/off")


def _validate_secret_key(secret_key: str) -> str:
	"""Validate the master secret key for minimum strength."""
	secret = secret_key.strip()
	if len(secret.encode("utf-8")) < _MIN_SECRET_KEY_BYTES:
		raise ValueError(f"WIREBUDDY_SECRET_KEY must be at least {_MIN_SECRET_KEY_BYTES} bytes")
	return secret


def load_dotenv(dotenv_path: Path | None = None) -> None:
	"""Load simple KEY=VALUE pairs from .env.

	Behavior:
	- Ignores blank lines and comments (# ...)
	- Handles `export KEY=VALUE` syntax (common in shell-sourced files)
	- Respects quoted values (doesn't strip # inside quotes)
	- Does not override already-set environment variables
	"""
	project_root = Path(__file__).resolve().parents[2]
	dotenv_path = dotenv_path or (project_root / "settings.env")
	if not dotenv_path.exists():
		return
	if dotenv_path.stat().st_size > _MAX_DOTENV_SIZE:
		raise RuntimeError(f"settings.env exceeds {_MAX_DOTENV_SIZE} bytes")
	for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
		line = raw_line.strip()
		if not line or line.startswith("#"):
			continue
		if "=" not in line:
			continue
		key, value = line.split("=", 1)
		key = key.strip()

		# Handle shell export syntax
		if key.startswith("export "):
			key = key[7:].strip()

		value = _parse_value(value)
		if not key:
			continue
		os.environ.setdefault(key, value)


def _unresolved_dir(path: Path) -> Path:
	"""Make *path* absolute and resolve only its parent.

	The final component is kept as given so that a symlink there is still
	visible to the later safety check instead of being replaced by its target.
	"""
	absolute = Path(os.path.abspath(path))  # noqa: PTH100 - lexical only, resolve() would follow a final symlink
	if absolute == absolute.parent:
		return absolute
	return absolute.parent.resolve() / absolute.name


def _ensure_private_dir(path: Path) -> None:
	"""Create *path* (0700) and exit unless it is a real, non-writable-by-others directory.

	The directory is opened with O_NOFOLLOW and validated and chmodded through
	that descriptor, so a symlink (or a swap between check and use) can never
	redirect the chmod to a foreign directory. A failing chmod is tolerated
	only when the directory is not group/other writable (same rule as
	``app.db.sqlite_runtime.connect``).
	"""
	try:
		path.mkdir(mode=0o700, parents=True, exist_ok=True)
		fd = os.open(
			path,
			os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
		)
	except OSError as exc:
		_log.critical(
			"Path is not a safe directory (missing, symlink or not a directory): %s (%s)",
			path,
			exc,
		)
		raise SystemExit(1) from exc
	try:
		try:
			os.fchmod(fd, 0o700)
		except OSError as exc:
			_log.warning("Failed to enforce restrictive permissions on %s: %s", path, exc)
		mode = stat.S_IMODE(os.fstat(fd).st_mode)
	except OSError as exc:
		_log.critical("Cannot inspect data directory %s: %s", path, exc)
		raise SystemExit(1) from exc
	finally:
		os.close(fd)
	if mode & (stat.S_IWGRP | stat.S_IWOTH):
		_log.critical(
			"Data directory %s is group/other writable (%s) and could not be restricted to 0700",
			path,
			oct(mode),
		)
		raise SystemExit(1)


def load_config() -> Config:
	"""Load configuration from environment variables (optionally via settings.env)."""
	load_dotenv()
	project_root = Path(__file__).resolve().parents[2]
	base_dir = project_root

	# Data path (overrideable for containers/deployments)
	raw_data_dir = os.getenv("WIREBUDDY_DATA_DIR", "").strip()
	data_dir = _unresolved_dir(Path(raw_data_dir).expanduser() if raw_data_dir else project_root / "data")
	db_path = data_dir / "wirebuddy.db"
	tsdb_dir = data_dir / "tsdb"
	dns_dir = data_dir / "dns"
	# Self-healing: Ensure core directories exist
	# Note: dns_dir is created on-demand only when Unbound is installed
	for d in (data_dir, tsdb_dir):
		_ensure_private_dir(d)
	allowed_levels = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
	log_level = os.getenv("LOG_LEVEL", "INFO").upper()
	if log_level not in allowed_levels:
		_log.warning("Invalid LOG_LEVEL=%r; using INFO", log_level)
		log_level = "INFO"

	# Secret key (required for master mode, not for node mode)
	secret_key = os.getenv("WIREBUDDY_SECRET_KEY", "")
	server_mode = os.getenv("SERVER_MODE", "master").lower()
	if not secret_key:
		import sys

		if server_mode == "node":
			# Nodes don't need secret_key - they use enrollment token
			secret_key = None
			_log.debug("Node mode: secret key not required")
		elif "pytest" not in sys.modules and "PYTEST_CURRENT_TEST" not in os.environ:
			_log.critical(
				"WIREBUDDY_SECRET_KEY is not set. "
				"Refusing to start without a secret key. "
				"Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
			)
			raise SystemExit(1)
		else:
			# Allow tests to run with a default
			secret_key = "test-only-secret-do-not-use-in-production"  # noqa: S105 - not a real secret
			_log.debug("Using test-only secret key")
	elif server_mode != "node":
		try:
			secret_key = _validate_secret_key(secret_key)
		except ValueError as exc:
			_log.critical(str(exc))
			raise SystemExit(1) from exc

	public_origin = os.getenv("WIREBUDDY_PUBLIC_ORIGIN", "").strip()
	trusted_proxies_raw = os.getenv("WIREBUDDY_TRUSTED_PROXIES", "").strip()
	trusted_proxies = parse_proxy_cidrs(trusted_proxies_raw) if trusted_proxies_raw else parse_proxy_cidrs(_DEFAULT_TRUSTED_PROXY_CIDRS)

	require_https_auth = os.getenv("WIREBUDDY_REQUIRE_HTTPS_AUTH", "").strip().lower() in ("true", "1", "yes")

	try:
		enrollment_accept_v1 = parse_strict_bool("WIREBUDDY_ENROLLMENT_ACCEPT_V1", True)
		enrollment_token_version = int(os.getenv("WIREBUDDY_ENROLLMENT_TOKEN_VERSION", "").strip() or "2")
		if enrollment_token_version not in (1, 2):
			raise ValueError("WIREBUDDY_ENROLLMENT_TOKEN_VERSION must be 1 or 2")
	except ValueError as exc:
		_log.critical(str(exc))
		raise SystemExit(1) from exc

	return Config(
		base_dir=base_dir,
		data_dir=data_dir,
		db_path=db_path,
		tsdb_dir=tsdb_dir,
		dns_dir=dns_dir,
		log_level=log_level,
		secret_key=secret_key,
		public_origin=public_origin,
		trusted_proxies=trusted_proxies,
		require_https_auth=require_https_auth,
		enrollment_accept_v1=enrollment_accept_v1,
		enrollment_token_version=enrollment_token_version,
	)


# Global config singleton with thread-safe lazy initialization
_config: Config | None = None
_config_lock = threading.Lock()


def get_config() -> Config:
	"""Get the global config singleton (thread-safe)."""
	global _config
	if _config is None:
		with _config_lock:
			if _config is None:  # Double-checked locking
				_config = load_config()
	return _config
