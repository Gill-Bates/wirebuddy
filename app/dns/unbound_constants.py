#!/usr/bin/env python3
#
# app/dns/unbound_constants.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Unbound DNS constants and shared utilities."""

from __future__ import annotations

import contextlib
import logging
import os
import re
import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import IO, TypedDict

from ..utils.config import get_config
from ..utils.subprocess import run_command

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class BlocklistMeta(TypedDict):
	"""Metadata for a blocklist source."""
	name: str
	description: str
	url: str
	level: str  # UI badge label

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

UNBOUND_CONF_DIR = Path("/etc/unbound")
UNBOUND_CONF = UNBOUND_CONF_DIR / "unbound.conf"
QUERY_LOG = Path("/var/log/unbound/queries.log")
UNBOUND_PID_FILE = Path("/var/run/unbound.pid")
DNSSEC_ROOT_KEY = Path("/var/lib/unbound/root.key")

# Blocklist definitions with stable IDs for per-peer tagging
BLOCKLIST_REGISTRY: dict[str, BlocklistMeta] = {
	"ads": {
		"name": "StevenBlack",
		"description": "Unified hosts (ads, malware, trackers)",
		"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		"level": "Moderat",
	},
	"adguard": {
		"name": "AdGuard DNS filter",
		"description": "AdGuard's curated filter list",
		"url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
		"level": "Ausgewogen",
	},
	"porn": {
		"name": "StevenBlack Adult",
		"description": "StevenBlack porn-only hosts",
		"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
		"level": "18+",
	},
	"hagezi": {
		"name": "HaGeZi Pro",
		"description": "HaGeZi's Pro DNS Blocklist",
		"url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/pro-compressed.txt",
		"level": "Extrem",
	},
}

_BLOCKLIST_ID_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
_ALLOWED_BLOCKLIST_LEVELS: frozenset[str] = frozenset({"Moderat", "Ausgewogen", "Extrem", "18+"})


def _validate_blocklist_registry() -> None:
	"""Validate static blocklist metadata at import time."""
	for blocklist_id, meta in BLOCKLIST_REGISTRY.items():
		if not _BLOCKLIST_ID_RE.fullmatch(blocklist_id):
			raise ValueError(f"Invalid blocklist id: {blocklist_id!r}")

		if not str(meta["name"]).strip():
			raise ValueError(f"Blocklist {blocklist_id!r} has empty name")

		url = str(meta["url"]).strip()
		if not url.startswith(("https://", "http://")):
			raise ValueError(f"Blocklist {blocklist_id!r} has invalid URL")

		level = str(meta["level"]).strip()
		if level not in _ALLOWED_BLOCKLIST_LEVELS:
			raise ValueError(f"Blocklist {blocklist_id!r} has invalid level {level!r}")


_validate_blocklist_registry()

# Default blocklists for new installations
# Adult content list ("porn") is available, but disabled by default.
# HaGeZi Pro ("hagezi") is available, but disabled by default (large list).
DEFAULT_BLOCKLIST_IDS = ["ads"]

# Computed once at import; BLOCKLIST_REGISTRY must not change at runtime.
_unknown_default_blocklists = set(DEFAULT_BLOCKLIST_IDS) - set(BLOCKLIST_REGISTRY)
if _unknown_default_blocklists:
	raise ValueError(f"DEFAULT_BLOCKLIST_IDS references unknown IDs: {_unknown_default_blocklists!r}")
DEFAULT_BLOCKLISTS = [BLOCKLIST_REGISTRY[bid]["url"] for bid in DEFAULT_BLOCKLIST_IDS]

BLOCKLIST_MAX_BYTES = 25 * 1024 * 1024
BLOCKLIST_MAX_LINES = 2_000_000
BLOCKLIST_MAX_DOMAINS = 1_000_000
CUSTOM_RULES_TAG = "custom"

# Allowed content types for blocklist downloads
ALLOWED_BLOCKLIST_CONTENT_TYPES: frozenset[str] = frozenset({
	"text/plain",
	"text/x-hosts",  # Vendor-prefixed hosts file MIME type
	"application/octet-stream",
})

# Regex patterns
# Input is normalized to lowercase before matching.
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")  # Allow underscores (_dmarc, _acme-challenge)
HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
UPSTREAM_ADDR_RE = re.compile(r"^([^@#\s]+)(?:@(\d{1,5}))?#([^\s#]+)$")

# Exec timeout for subprocess calls (prevents event loop blocking)
EXEC_TIMEOUT = 5  # seconds


def get_blocklist_file() -> Path:
	"""Return the path to the blocklist file in data/dns directory."""
	return get_config().dns_dir / "blocklist.conf"


def get_custom_client_rules_file() -> Path:
	"""Return the path to generated client-specific custom DNS overrides."""
	return get_config().dns_dir / "custom-client-rules.conf"


def get_local_data_file() -> Path:
	"""Return the path to local-data overrides (split-DNS for WG interfaces)."""
	return get_config().dns_dir / "local-data.conf"


def normalize_content_type(value: str | None) -> str:
	"""Normalize an HTTP Content-Type to media type only."""
	return (value or "").split(";", 1)[0].strip().lower()


def is_allowed_blocklist_content_type(value: str | None) -> bool:
	"""Return True if Content-Type media type is accepted for blocklist downloads."""
	return normalize_content_type(value) in ALLOWED_BLOCKLIST_CONTENT_TYPES


# ---------------------------------------------------------------------------
# Shared Utility Functions
# ---------------------------------------------------------------------------

async def run_exec(*cmd: str, timeout: float = EXEC_TIMEOUT) -> tuple[int, str, str]:
	"""Run a command and return (code, stdout, stderr). Uses exec, not shell.

	Never raises: a timeout or launch failure comes back as ``(-1, "", reason)``,
	which is the contract the Unbound supervisor relies on. The process handling
	itself (process-group kill, output limit, cancellation cleanup) is
	``app.utils.subprocess.run_command``.
	"""
	try:
		result = await run_command(*cmd, timeout=timeout)
	except TimeoutError:
		_log.warning("DNS_EXEC_TIMEOUT command timed out after %.1fs: %s", timeout, cmd)
		return -1, "", f"Command timed out after {timeout}s"
	except Exception as exc:
		_log.warning("DNS_EXEC_ERROR command failed: %s – %s", cmd, exc)
		return -1, "", str(exc)
	return result.returncode, result.stdout, result.stderr


@contextlib.contextmanager
def atomic_write(
	path: Path,
	encoding: str = "utf-8",
	*,
	mode: int = 0o644,
) -> Generator[IO[str]]:
	r"""Context manager for atomic file writes with fsync.

	Yields a file handle for writing. On successful exit, the file is
	fsync'd and atomically moved to the target path.

	Example:
		with atomic_write(path) as f:
			f.write("line 1\n")
			f.write("line 2\n")
	"""
	path.parent.mkdir(parents=True, exist_ok=True)
	fd, tmp_path = tempfile.mkstemp(
		dir=str(path.parent),
		prefix=f".{path.name}.",
		suffix=".tmp",
	)
	fd_owned_by_fileobj = False
	try:
		with os.fdopen(fd, "w", encoding=encoding) as f:
			fd_owned_by_fileobj = True
			yield f
			f.flush()
			os.fsync(f.fileno())
		Path(tmp_path).chmod(mode)
		Path(tmp_path).replace(path)
		# Sync parent directory to ensure the rename is durable
		try:
			dir_fd = os.open(str(path.parent), os.O_RDONLY)
			try:
				os.fsync(dir_fd)
			finally:
				os.close(dir_fd)
		except OSError:
			_log.debug("Could not fsync parent directory %s", path.parent)
	except BaseException:
		if not fd_owned_by_fileobj:
			with contextlib.suppress(OSError):
				os.close(fd)
		raise
	finally:
		with contextlib.suppress(OSError):
			if Path(tmp_path).exists():
				Path(tmp_path).unlink()


def atomic_write_text(path: Path, content: str, *, mode: int = 0o644) -> None:
	"""Atomically write UTF-8 text to a file (convenience wrapper)."""
	with atomic_write(path, mode=mode) as f:
		f.write(content)


__all__ = [
	"ALLOWED_BLOCKLIST_CONTENT_TYPES",
	"BLOCKLIST_MAX_BYTES",
	"BLOCKLIST_MAX_DOMAINS",
	"BLOCKLIST_MAX_LINES",
	"BLOCKLIST_REGISTRY",
	"CUSTOM_RULES_TAG",
	"DEFAULT_BLOCKLISTS",
	"DEFAULT_BLOCKLIST_IDS",
	"DNSSEC_ROOT_KEY",
	"DOMAIN_LABEL_RE",
	"EXEC_TIMEOUT",
	"HOST_LABEL_RE",
	"QUERY_LOG",
	"UNBOUND_CONF",
	"UNBOUND_CONF_DIR",
	"UNBOUND_PID_FILE",
	"UPSTREAM_ADDR_RE",
	"BlocklistMeta",
	"atomic_write",
	"atomic_write_text",
	"get_blocklist_file",
	"get_custom_client_rules_file",
	"get_local_data_file",
	"is_allowed_blocklist_content_type",
	"normalize_content_type",
	"run_exec",
]
