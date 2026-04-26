#!/usr/bin/env python3
#
# app/api/wireguard_utils.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard utility functions."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from ..db.sqlite_settings import (
	get_enabled_blocklists,
)
from ..models.peers import PeerPublic

__all__ = [
	"validate_interface_name",
	"select_display_unit",
	"bytes_to_unit",
	"safe_int",
	"get_enabled_blocklist_ids",
	"filter_peer_blocklist_ids",
	"effective_peer_blocklist_ids",
	"validate_post_script",
	"row_to_public",
	"run_wg_command",
	"run_wg_command_stdin",
	"wg_set_peer_with_psk",
	"generate_keypair",
	"generate_preshared_key",
	"derive_public_key",
	"validate_keypair",
	"parse_blocklist_ids",
	"safe_row_get",
	"is_valid_wg_key",
	"WgPeerDump",
	"parse_wg_show_dump",
]

# Interface name validation regex.
# NOTE: More restrictive than Linux IFNAMSIZ (which allows almost anything up to 15 chars).
# This is intentional for security: only alphanumeric, underscore, hyphen, starting with letter.
_IFACE_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,14}$")

# WireGuard key validation regex (base64 with exact 32-byte decoded length).
# WireGuard keys are always 44 base64 chars with '=' padding.
_WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")

_KB = 1024
_MB = _KB ** 2
_GB = _KB ** 3

_log = logging.getLogger(__name__)

# Timeout for wg commands (seconds)
WG_COMMAND_TIMEOUT = 30

# Secondary timeout for process cleanup after kill (seconds)
_KILL_WAIT_TIMEOUT = 5


def _resolve_command_args(*args: str) -> tuple[str, ...]:
	"""Resolve command arguments for subprocess execution.

	Supported call styles:
	- ``run_wg_command("show", "all")`` -> executes ``wg show all``
	- ``run_wg_command("wg", "show", "all")`` -> executes as provided
	- ``run_wg_command("wg-quick", "up", "wg0")`` -> executes as provided
	- ``run_wg_command("iptables", ...)`` -> executes as provided
	"""
	if not args:
		raise ValueError("No command arguments provided")

	first = str(args[0]).strip()
	if not first:
		raise ValueError("Command must not be empty")

	# Explicit executable passed by caller (common in this codebase).
	explicit_bins = frozenset({"wg", "wg-quick", "iptables", "ip6tables", "ip", "nft"})
	if first in explicit_bins:
		return tuple(args)
	if "/" in first:
		candidate = Path(first)
		if candidate.name in explicit_bins and candidate.is_absolute():
			return tuple(args)
		raise ValueError(f"Unsupported command path: {first!r}")

	# Backward-compatible shorthand: assume WireGuard subcommand.
	return ("wg", *args)


def validate_interface_name(name: str) -> str:
	"""Validate interface name follows Linux naming rules and security constraints.
	
	Raises:
		HTTPException: If name is invalid.
	"""
	if not _IFACE_NAME_RE.fullmatch(name):
		raise HTTPException(
			status_code=400,
			detail="Invalid interface name. Must start with letter, max 15 chars, alphanumeric with - or _"
		)
	return name


def select_display_unit(max_bytes: float) -> str:
	"""Choose a readable byte unit for chart payloads."""
	if max_bytes >= _GB:
		return "GB"
	if max_bytes >= _MB:
		return "MB"
	if max_bytes >= _KB:
		return "KB"
	return "B"


def bytes_to_unit(value: float, unit: str) -> float:
	"""Convert bytes to selected display unit."""
	if unit == "GB":
		return value / _GB
	if unit == "MB":
		return value / _MB
	if unit == "KB":
		return value / _KB
	return value


def safe_int(value: str, default: int = 0) -> int:
	"""Safely convert string to int, returning default on failure."""
	try:
		return int(value) if value else default
	except (ValueError, TypeError):
		return default


@dataclass
class WgPeerDump:
	"""Structured representation of a peer line from `wg show all dump`."""
	interface: str | None
	public_key: str
	endpoint_raw: str | None
	client_ip: str | None
	handshake_ts: int
	rx: int
	tx: int


def _extract_client_ip(endpoint_raw: str | None) -> str | None:
	"""Extract client IP from WireGuard endpoint string (handles IPv4/IPv6)."""
	if not endpoint_raw or endpoint_raw == "(none)":
		return None
	if endpoint_raw.startswith("["):
		# IPv6 format: [addr]:port
		return endpoint_raw.split("]")[0].lstrip("[")
	# IPv4 format: addr:port
	return endpoint_raw.rsplit(":", 1)[0]


def parse_wg_show_dump(stdout: str) -> list[WgPeerDump]:
	"""Parse `wg show all dump` output into structured peer records.
	
	Handles both output formats:
	- Format A (9 cols): iface, pubkey, psk, endpoint, allowed-ips, handshake, rx, tx, keepalive
	- Format B (8 cols): pubkey, psk, endpoint, allowed-ips, handshake, rx, tx, keepalive
	
	Interface header lines (5 cols) are tracked to provide context for format B.
	"""
	results: list[WgPeerDump] = []
	last_iface: str | None = None

	for line in stdout.splitlines():
		if not line:
			continue
		parts = line.split("\t")

		# Interface header (5 cols): iface, privkey, pubkey, listen_port, fwmark
		if 5 <= len(parts) < 8:
			last_iface = parts[0]
			continue

		# Determine format based on column count
		if len(parts) >= 9:
			# Format A: interface column present
			offset = 1
			iface = parts[0] or last_iface
		elif len(parts) >= 8:
			# Format B: no interface column (use last header)
			offset = 0
			iface = last_iface
		else:
			continue

		if iface:
			last_iface = iface

		pubkey = parts[offset]
		if not _WG_KEY_RE.fullmatch(pubkey):
			_log.warning("WG_DUMP_UNEXPECTED_FORMAT invalid pubkey in line: %r", line)
			continue

		endpoint_raw = parts[offset + 2]
		if endpoint_raw == "(none)":
			endpoint_raw = None

		results.append(WgPeerDump(
			interface=iface,
			public_key=pubkey,
			endpoint_raw=endpoint_raw,
			client_ip=_extract_client_ip(endpoint_raw),
			handshake_ts=safe_int(parts[offset + 4]),
			rx=safe_int(parts[offset + 5]),
			tx=safe_int(parts[offset + 6]),
		))

	return results


def get_enabled_blocklist_ids(conn: sqlite3.Connection) -> list[str]:
	"""Return globally enabled blocklist IDs in registry order."""
	# Lazy import avoids module-level import cycle with DNS constants in some startup paths.
	from ..dns import constants as _dns_constants
	enabled_urls = {u for u in get_enabled_blocklists(conn) if u}
	return [
		bid
		for bid, meta in _dns_constants.BLOCKLIST_REGISTRY.items()
		if meta.get("url") in enabled_urls
	]


def filter_peer_blocklist_ids(
	blocklist_ids: list[str] | None,
	enabled_blocklist_ids: list[str],
) -> list[str] | None:
	"""Filter peer blocklist IDs to globally enabled IDs (preserve user order)."""
	if blocklist_ids is None:
		return None
	enabled_set = set(enabled_blocklist_ids)
	filtered: list[str] = []
	seen: set[str] = set()
	for bid in blocklist_ids:
		if bid in enabled_set and bid not in seen:
			filtered.append(bid)
			seen.add(bid)
	return filtered


def effective_peer_blocklist_ids(
	peer_blocklist_ids: list[str] | None,
	enabled_global_ids: list[str],
) -> list[str]:
	"""Compute effective blocklist IDs for a peer.

	Semantics:
	- peer_blocklist_ids=None → inherit all globally enabled blocklists
	- peer_blocklist_ids=[]   → explicitly disable all blocklists for this peer
	- peer_blocklist_ids=[...] → use specified subset (filtered to globally enabled)
	"""
	if peer_blocklist_ids is None:
		return enabled_global_ids
	return filter_peer_blocklist_ids(peer_blocklist_ids, enabled_global_ids) or []


def validate_post_script(value: str | None, field: str) -> str | None:
	"""Validate post-up/post-down script (max 2KB, printable ASCII only).

	SECURITY: Only printable ASCII + newline/tab is allowed. This is intentionally
	restricted to prevent encoding-based injection attacks. These scripts are passed
	to wg-quick which executes them via shell. UTF-8 could enable homoglyph attacks
	or exploit locale-dependent shell behavior.
	"""
	if not value:
		return None
	if len(value.encode("ascii", errors="ignore")) > 2048:
		raise HTTPException(status_code=400, detail=f"{field} script too long (max 2048 bytes)")
	if not all(32 <= ord(c) <= 126 or c in "\n\t" for c in value):
		raise HTTPException(status_code=400, detail=f"{field} script must be printable ASCII")
	return value.strip()


def row_to_public(row: sqlite3.Row, enabled_blocklist_ids: list[str] | None = None) -> PeerPublic:
	"""Convert DB row to PeerPublic model."""
	blocklist_ids = None
	raw_blocklist_ids = safe_row_get(row, "blocklist_ids")
	if raw_blocklist_ids:
		try:
			blocklist_ids = json.loads(raw_blocklist_ids)
		except (json.JSONDecodeError, TypeError):
			blocklist_ids = None
	
	if enabled_blocklist_ids is not None:
		blocklist_ids = filter_peer_blocklist_ids(blocklist_ids, enabled_blocklist_ids)
	
	return PeerPublic(
		id=safe_row_get(row, "id"),
		name=safe_row_get(row, "name", ""),
		interface_name=safe_row_get(row, "interface_name", ""),
		public_key=safe_row_get(row, "public_key", ""),
		peer_address=safe_row_get(row, "peer_address"),
		allowed_ips=safe_row_get(row, "allowed_ips", ""),
		persistent_keepalive=safe_row_get(row, "persistent_keepalive") or None,
		use_adblocker=bool(safe_row_get(row, "use_adblocker", 0)),
		blocklist_ids=blocklist_ids,
		client_isolation=bool(safe_row_get(row, "client_isolation", 0)),
		created_at=safe_row_get(row, "created_at"),
		updated_at=safe_row_get(row, "updated_at"),
	)


async def _run_subprocess(
	cmd: tuple[str, ...],
	*,
	stdin_data: bytes | None = None,
	timeout: int = WG_COMMAND_TIMEOUT,
) -> tuple[int, str, str]:
	"""Shared subprocess runner with timeout and cleanup."""
	try:
		proc = await asyncio.create_subprocess_exec(
			*cmd,
			stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
			stdout=asyncio.subprocess.PIPE,
			stderr=asyncio.subprocess.PIPE,
		)
		try:
			stdout_bytes, stderr_bytes = await asyncio.wait_for(
				proc.communicate(input=stdin_data),
				timeout=timeout,
			)
			return (
				proc.returncode if proc.returncode is not None else 1,
				stdout_bytes.decode("utf-8", errors="replace"),
				stderr_bytes.decode("utf-8", errors="replace"),
			)
		except asyncio.TimeoutError:
			proc.kill()
			try:
				await asyncio.wait_for(proc.wait(), timeout=_KILL_WAIT_TIMEOUT)
			except asyncio.TimeoutError:
				pass
			return 1, "", f"Command timed out after {timeout}s"
	except FileNotFoundError:
		_log.error("WG_BINARY_NOT_FOUND cmd=%s", cmd[0])
		return 1, "", f"Command not found: {cmd[0]}"
	except OSError as exc:
		_log.exception("WG_COMMAND_OS_ERROR cmd=%s", cmd)
		return 1, "", str(exc)


async def run_wg_command(
	*args: str,
	stdin_data: str | None = None,
	timeout: int = WG_COMMAND_TIMEOUT,
) -> tuple[int, str, str]:
	"""Run a WireGuard (or related) command with optional stdin input.

	Accepts the same shorthand as ``_resolve_command_args``.
	"""
	cmd = _resolve_command_args(*args)
	return await _run_subprocess(
		cmd,
		stdin_data=stdin_data.encode("utf-8") if stdin_data is not None else None,
		timeout=timeout,
	)


async def run_wg_command_stdin(stdin_data: str, *args: str, timeout: int = WG_COMMAND_TIMEOUT) -> tuple[int, str, str]:
	"""Backward-compatible wrapper — prefer ``run_wg_command(..., stdin_data=...)``."""
	return await run_wg_command(*args, stdin_data=stdin_data, timeout=timeout)


async def _run_wg_or_raise(
	*args: str,
	stdin_data: str | None = None,
	detail: str,
	log_tag: str = "WG_CMD_FAILED",
	timeout: int = WG_COMMAND_TIMEOUT,
) -> str:
	"""Run a WireGuard command and raise HTTPException(500) if it fails."""
	code, out, err = await run_wg_command(*args, stdin_data=stdin_data, timeout=timeout)
	if code != 0 or not out:
		_log.error("%s cmd=%s stderr=%s", log_tag, args, err.strip())
		raise HTTPException(status_code=500, detail=detail)
	return out.strip()


async def wg_set_peer_with_psk(
	interface: str,
	public_key: str,
	allowed_ips: str,
	preshared_key: str,
	timeout: int = WG_COMMAND_TIMEOUT,
) -> tuple[int, str, str]:
	"""Add a WireGuard peer with a preshared key using a secure temp file.

	WireGuard's `wg set ... preshared-key /dev/stdin` does not work reliably
	in container environments because it tries to fopen("/dev/stdin") rather
	than reading from the actual stdin pipe. This function uses a secure
	temporary file with restrictive permissions instead.
	"""
	def _write_psk_temp(key: str) -> str:
		fd, path = tempfile.mkstemp(prefix="wg_psk_", suffix=".key")
		try:
			os.chmod(path, 0o600)
			os.write(fd, key.encode("utf-8"))
			os.close(fd)
			return path
		except Exception:
			try:
				os.close(fd)
			except OSError:
				pass
			raise

	tmp_path: str | None = None
	try:
		tmp_path = await asyncio.to_thread(_write_psk_temp, preshared_key)
		return await run_wg_command(
			"wg", "set", interface,
			"peer", public_key,
			"allowed-ips", allowed_ips,
			"preshared-key", tmp_path,
		)
	finally:
		if tmp_path is not None:
			await asyncio.to_thread(
				lambda p: os.unlink(p) if os.path.exists(p) else None,
				tmp_path,
			)


async def generate_keypair() -> tuple[str, str]:
	"""Generate WireGuard private/public key pair."""
	privkey = await _run_wg_or_raise(
		"genkey",
		detail="Failed to generate private key",
		log_tag="WG_GENKEY_FAILED",
	)
	pubkey = await _run_wg_or_raise(
		"pubkey",
		stdin_data=privkey,
		detail="Failed to derive public key",
		log_tag="WG_PUBKEY_FAILED",
	)
	return privkey, pubkey


async def generate_preshared_key() -> str:
	"""Generate WireGuard preshared key."""
	return await _run_wg_or_raise(
		"genpsk",
		detail="Failed to generate PSK",
		log_tag="WG_GENPSK_FAILED",
	)


async def derive_public_key(private_key: str) -> str:
	"""Derive public key from a private key using WireGuard's pubkey command.
	
	Raises:
		HTTPException: If derivation fails.
	"""
	return await _run_wg_or_raise(
		"pubkey",
		stdin_data=private_key.strip(),
		detail="Failed to derive public key",
		log_tag="WG_DERIVE_PUBKEY_FAILED",
	)


def is_valid_wg_key(key: str) -> bool:
	"""Validate WireGuard key format: base64-encoded 32-byte key.

	WireGuard keys must be exactly 32 bytes, which encodes to 44 base64 chars
	with mandatory '=' padding.
	"""
	key = key.strip()
	# Quick regex check first (faster than base64 decode for invalid input)
	if not _WG_KEY_RE.fullmatch(key):
		return False
	# Actually decode and verify length
	try:
		return len(base64.b64decode(key, validate=True)) == 32
	except Exception:
		return False


async def validate_keypair(private_key: str, public_key: str) -> None:
	"""Validate WireGuard keypair format and derivation.

	Raises:
		HTTPException: If keys are invalid or don't match.
	"""
	if not is_valid_wg_key(private_key):
		raise HTTPException(status_code=422, detail="Invalid private key format")
	if not is_valid_wg_key(public_key):
		raise HTTPException(status_code=422, detail="Invalid public key format")

	# Verify public key derives from private key
	derived_pub = await derive_public_key(private_key)
	if derived_pub != public_key.strip():
		raise HTTPException(status_code=422, detail="Public key does not match private key")


def parse_blocklist_ids(raw: str | None) -> list[str] | None:
	"""Parse blocklist_ids JSON column, returning None on missing/invalid data."""
	if not raw:
		return None
	try:
		parsed = json.loads(raw)
		return parsed if isinstance(parsed, list) else None
	except (json.JSONDecodeError, TypeError):
		return None


def safe_row_get(row: sqlite3.Row, key: str, default: Any = None) -> Any:
	"""Safely get a column from a Row, returning default if missing."""
	try:
		return row[key]
	except (KeyError, IndexError):
		return default
