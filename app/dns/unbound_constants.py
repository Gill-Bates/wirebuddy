#!/usr/bin/env python3
#
# app/dns/unbound_constants.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Unbound DNS constants and shared utilities."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import tempfile
from collections.abc import Generator
from functools import lru_cache
from pathlib import Path
from typing import IO, TypedDict

from ..utils.config import get_config

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class BlocklistMeta(TypedDict):
	"""Metadata for a blocklist source."""
	name: str
	description: str
	url: str

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
		"name": "Ads & Trackers",
		"description": "StevenBlack unified hosts (ads, malware, trackers)",
		"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
	},
	"porn": {
		"name": "Adult Content",
		"description": "StevenBlack porn-only hosts",
		"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
	},
	"hagezi": {
		"name": "HaGeZi Pro",
		"description": "HaGeZi's Pro DNS Blocklist (ads, trackers, malware)",
		"url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/pro-compressed.txt",
	},
}

# Default blocklists for new installations
# Adult content list ("porn") is available, but disabled by default.
DEFAULT_BLOCKLIST_IDS = ["ads", "hagezi"]

# Computed once at import; BLOCKLIST_REGISTRY must not change at runtime.
for _bid in DEFAULT_BLOCKLIST_IDS:
	if _bid not in BLOCKLIST_REGISTRY:
		raise ValueError(f"DEFAULT_BLOCKLIST_IDS references unknown ID: {_bid!r}")
DEFAULT_BLOCKLISTS = [BLOCKLIST_REGISTRY[bid]["url"] for bid in DEFAULT_BLOCKLIST_IDS]

BLOCKLIST_MAX_BYTES = 25 * 1024 * 1024
BLOCKLIST_MAX_LINES = 2_000_000
BLOCKLIST_MAX_DOMAINS = 1_000_000

# Allowed content types for blocklist downloads
ALLOWED_BLOCKLIST_CONTENT_TYPES: frozenset[str] = frozenset({
	"text/plain",
	"text/x-hosts",  # Vendor-prefixed hosts file MIME type
	"application/octet-stream",
})

# Regex patterns
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")  # Allow underscores (_dmarc, _acme-challenge)
HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
UPSTREAM_ADDR_RE = re.compile(r"^([^@#\s]+)(?:@(\d{1,5}))?#([^\s#]+)$")

# Exec timeout for subprocess calls (prevents event loop blocking)
EXEC_TIMEOUT = 5  # seconds


@lru_cache(maxsize=1)
def get_blocklist_file() -> Path:
	"""Return the path to the blocklist file in data/dns directory."""
	return get_config().dns_dir / "blocklist.conf"


@lru_cache(maxsize=1)
def get_custom_client_rules_file() -> Path:
	"""Return the path to generated client-specific custom DNS overrides."""
	return get_config().dns_dir / "custom-client-rules.conf"


@lru_cache(maxsize=1)
def get_local_data_file() -> Path:
	"""Return the path to local-data overrides (split-DNS for WG interfaces)."""
	return get_config().dns_dir / "local-data.conf"


# ---------------------------------------------------------------------------
# Shared Utility Functions
# ---------------------------------------------------------------------------

async def run_exec(*cmd: str, timeout: float = EXEC_TIMEOUT) -> tuple[int, str, str]:
	"""Run a command and return (code, stdout, stderr). Uses exec, not shell.

	A timeout (default 5 s) prevents hung subprocesses from blocking the
	FastAPI event loop – which was the root cause of UI freezes.
	"""
	proc: asyncio.subprocess.Process | None = None
	timed_out = False
	try:
		proc = await asyncio.create_subprocess_exec(
			*cmd,
			stdout=asyncio.subprocess.PIPE,
			stderr=asyncio.subprocess.PIPE,
		)
		stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
		code = proc.returncode
		assert code is not None, "returncode should be set after communicate()"
		return code, stdout.decode(), stderr.decode()
	except asyncio.TimeoutError:
		timed_out = True
		_log.warning("DNS_EXEC_TIMEOUT command timed out after %.1fs: %s", timeout, cmd)
		return -1, "", f"Command timed out after {timeout}s"
	except Exception as exc:
		_log.warning("DNS_EXEC_ERROR command failed: %s – %s", cmd, exc)
		return -1, "", str(exc)
	finally:
		# Cleanup: kill leftover process regardless of exception type
		if proc is not None and proc.returncode is None:
			with contextlib.suppress(Exception):
				proc.kill()
			if timed_out:
				with contextlib.suppress(Exception):
					await asyncio.wait_for(proc.communicate(), timeout=2.0)
			with contextlib.suppress(Exception):
				await proc.wait()


@contextlib.contextmanager
def atomic_write(path: Path, encoding: str = "utf-8") -> Generator[IO[str], None, None]:
	"""Context manager for atomic file writes with fsync.
	
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
		os.replace(tmp_path, path)
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
			if os.path.exists(tmp_path):
				os.unlink(tmp_path)


def atomic_write_text(path: Path, content: str) -> None:
	"""Atomically write UTF-8 text to a file (convenience wrapper)."""
	with atomic_write(path) as f:
		f.write(content)


__all__ = [
	"BlocklistMeta",
	"UNBOUND_CONF_DIR",
	"UNBOUND_CONF",
	"QUERY_LOG",
	"UNBOUND_PID_FILE",
	"DNSSEC_ROOT_KEY",
	"BLOCKLIST_REGISTRY",
	"DEFAULT_BLOCKLIST_IDS",
	"DEFAULT_BLOCKLISTS",
	"BLOCKLIST_MAX_BYTES",
	"BLOCKLIST_MAX_LINES",
	"BLOCKLIST_MAX_DOMAINS",
	"ALLOWED_BLOCKLIST_CONTENT_TYPES",
	"DOMAIN_LABEL_RE",
	"HOST_LABEL_RE",
	"UPSTREAM_ADDR_RE",
	"EXEC_TIMEOUT",
	"get_blocklist_file",
	"get_custom_client_rules_file",
	"get_local_data_file",
	"run_exec",
	"atomic_write",
	"atomic_write_text",
]
