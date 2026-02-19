#!/usr/bin/env python3
#
# app/utils/config.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Configuration loading and app-level defaults."""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger(__name__)


class ConfigValidationError(Exception):
	"""Raised when critical configuration is missing or invalid."""


# ---------------------------------------------------------------------------
# Fixed constants (not configurable - Docker is a closed system)
# ---------------------------------------------------------------------------
WG_CONFIG_PATH = Path("/etc/wireguard")
WG_DEFAULT_DNS = "1.1.1.1,9.9.9.9"  # Cloudflare + Quad9 with DoT support


@dataclass(frozen=True)
class Config:
	"""Resolved runtime configuration derived from env and defaults."""
	base_dir: Path
	db_path: Path
	tsdb_dir: Path
	dns_dir: Path
	data_dir: Path
	log_level: str = "INFO"
	secret_key: str = ""


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
		# Unterminated quote – fall through to unquoted handling
	# Unquoted: strip inline comments
	if " #" in raw:
		raw = raw.split(" #", 1)[0]
	return raw.strip()


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
	
	# Data path
	data_dir = Path(os.getenv("WIREBUDDY_DATA_DIR", str(project_root / "data"))).resolve()
	db_path = (data_dir / "wirebuddy.db").resolve()
	tsdb_dir = (data_dir / "tsdb").resolve()
	dns_dir = (data_dir / "dns").resolve()

	# Self-healing: Ensure directories exist
	try:
		for d in (data_dir, tsdb_dir, dns_dir):
			if d.exists() and not d.is_dir():
				raise ConfigValidationError(f"Path exists but is not a directory: {d}")
			d.mkdir(parents=True, exist_ok=True)
	except OSError as exc:
		raise ConfigValidationError(f"Cannot create data directories: {exc}") from exc

	# Validate log level
	allowed_levels = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
	log_level = os.getenv("LOG_LEVEL", "INFO").upper()
	if log_level not in allowed_levels:
		log_level = "INFO"

	# Secret key (required for production)
	secret_key = os.getenv("WIREBUDDY_SECRET_KEY", "")
	if not secret_key:
		import sys
		if "pytest" not in sys.modules and "PYTEST_CURRENT_TEST" not in os.environ:
			raise ConfigValidationError(
				"WIREBUDDY_SECRET_KEY is not set. "
				"Refusing to start without a secret key. "
				"Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
			)
		# Allow tests to run with a default
		secret_key = "test-only-secret-do-not-use-in-production"
		_log.debug("Using test-only secret key")

	return Config(
		base_dir=base_dir,
		data_dir=data_dir,
		db_path=db_path,
		tsdb_dir=tsdb_dir,
		dns_dir=dns_dir,
		log_level=log_level,
		secret_key=secret_key,
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
