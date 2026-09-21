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


def _parse_proxy_cidrs(raw: str) -> tuple[IPNetwork, ...]:
	"""Parse a comma-separated CIDR list, skipping and logging invalid entries."""
	networks: list[IPNetwork] = []
	for item in (part.strip() for part in raw.split(",")):
		if not item:
			continue
		try:
			networks.append(ipaddress.ip_network(item, strict=False))
		except ValueError:
			_log.warning("Ignoring invalid trusted-proxy CIDR entry: %r", item)
	return tuple(networks)


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
	# and secure-cookie/HSTS defaults. Empty when not configured.
	public_origin: str = ""
	# CIDRs of reverse proxies whose forwarded headers (X-Forwarded-*,
	# client-cert fingerprint) are trusted. Empty tuple = trust nothing.
	trusted_proxies: tuple[IPNetwork, ...] = field(default_factory=tuple)

	@property
	def public_origin_hostname(self) -> str | None:
		"""Hostname component of ``public_origin``, or ``None`` if unset/invalid."""
		if not self.public_origin:
			return None
		hostname = (urlparse(self.public_origin).hostname or "").strip()
		return hostname or None

	@property
	def force_https(self) -> bool:
		"""Whether the public origin is HTTPS (drives secure cookies/HSTS defaults)."""
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


def _validate_secret_key(secret_key: str) -> str:
	"""Validate the master secret key for minimum strength."""
	secret = secret_key.strip()
	if len(secret.encode("utf-8")) < _MIN_SECRET_KEY_BYTES:
		raise ValueError(
			f"WIREBUDDY_SECRET_KEY must be at least {_MIN_SECRET_KEY_BYTES} bytes"
		)
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


def load_config() -> Config:
	"""Load configuration from environment variables (optionally via settings.env)."""
	load_dotenv()
	project_root = Path(__file__).resolve().parents[2]
	base_dir = project_root

	# Data path (overrideable for containers/deployments)
	raw_data_dir = os.getenv("WIREBUDDY_DATA_DIR", "").strip()
	data_dir = Path(raw_data_dir).expanduser().resolve() if raw_data_dir else (project_root / "data").resolve()
	db_path = (data_dir / "wirebuddy.db").resolve()
	tsdb_dir = (data_dir / "tsdb").resolve()
	dns_dir = (data_dir / "dns").resolve()

	# Self-healing: Ensure core directories exist
	# Note: dns_dir is created on-demand only when Unbound is installed
	try:
		for d in (data_dir, tsdb_dir):
			d.mkdir(mode=0o700, parents=True, exist_ok=True)
			d.lstat()
			if d.is_symlink() or not d.is_dir():
				_log.critical("Path exists but is not a safe directory: %s", d)
				raise SystemExit(1)
			d.chmod(0o700)
	except OSError as exc:
		_log.critical("Cannot create data directories: %s", exc)
		raise SystemExit(1) from exc

	# Validate log level
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
	trusted_proxies = _parse_proxy_cidrs(trusted_proxies_raw) if trusted_proxies_raw else _parse_proxy_cidrs(
		_DEFAULT_TRUSTED_PROXY_CIDRS
	)

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


def reset_config() -> None:
	"""Reset the cached config. Intended for tests only."""
	global _config
	with _config_lock:
		_config = None
