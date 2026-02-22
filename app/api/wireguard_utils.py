#!/usr/bin/env python3
#
# app/api/wireguard_utils.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard utility functions."""

from __future__ import annotations

from ..db.sqlite_settings import (
	get_enabled_blocklists,
)

import asyncio
import base64
import json
import os
import re
import sqlite3
import tempfile
from dataclasses import dataclass
from typing import Any, Optional

from fastapi import HTTPException

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
	if first in explicit_bins or "/" in first:
		return tuple(args)

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
	if max_bytes >= 1024 ** 3:
		return "GB"
	if max_bytes >= 1024 ** 2:
		return "MB"
	if max_bytes >= 1024:
		return "KB"
	return "B"


def bytes_to_unit(value: float, unit: str) -> float:
	"""Convert bytes to selected display unit."""
	if unit == "GB":
		return value / (1024 ** 3)
	if unit == "MB":
		return value / (1024 ** 2)
	if unit == "KB":
		return value / 1024
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

	for line in stdout.strip().split("\n"):
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

		endpoint_raw = parts[offset + 2]
		if endpoint_raw == "(none)":
			endpoint_raw = None

		results.append(WgPeerDump(
			interface=iface,
			public_key=parts[offset],
			endpoint_raw=endpoint_raw,
			client_ip=_extract_client_ip(endpoint_raw),
			handshake_ts=safe_int(parts[offset + 4]),
			rx=safe_int(parts[offset + 5]),
			tx=safe_int(parts[offset + 6]),
		))

	return results


def get_enabled_blocklist_ids(conn: sqlite3.Connection) -> list[str]:
	"""Return globally enabled blocklist IDs in registry order."""
	from ..dns import constants as _dns_constants
	enabled_urls = {u for u in get_enabled_blocklists(conn) if u}
	return [
		bid
		for bid, meta in _dns_constants.BLOCKLIST_REGISTRY.items()
		if meta.get("url") in enabled_urls
	]


def filter_peer_blocklist_ids(
	blocklist_ids: Optional[list[str]],
	enabled_blocklist_ids: list[str],
) -> Optional[list[str]]:
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
	peer_blocklist_ids: Optional[list[str]],
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
	if len(value) > 2048:
		raise HTTPException(status_code=400, detail=f"{field} script too long (max 2048 bytes)")
	if not all(32 <= ord(c) <= 126 or c in "\n\t" for c in value):
		raise HTTPException(status_code=400, detail=f"{field} script must be printable ASCII")
	return value.strip()


def row_to_public(row: sqlite3.Row, enabled_blocklist_ids: Optional[list[str]] = None) -> PeerPublic:
	"""Convert DB row to PeerPublic model."""
	blocklist_ids = None
	if row["blocklist_ids"]:
		try:
			blocklist_ids = json.loads(row["blocklist_ids"])
		except (json.JSONDecodeError, TypeError):
			blocklist_ids = None
	
	if enabled_blocklist_ids is not None:
		blocklist_ids = filter_peer_blocklist_ids(blocklist_ids, enabled_blocklist_ids)
	
	return PeerPublic(
		id=row["id"],
		name=row["name"],
		interface_name=row["interface_name"],
		public_key=row["public_key"],
		peer_address=row["peer_address"],
		allowed_ips=row["allowed_ips"],
		persistent_keepalive=row["persistent_keepalive"] if row["persistent_keepalive"] else None,
		use_adblocker=bool(row["use_adblocker"]),
		blocklist_ids=blocklist_ids,
		client_isolation=bool(row["client_isolation"]),
		created_at=row["created_at"],
		updated_at=row["updated_at"],
	)


async def run_wg_command(*args: str, timeout: int = WG_COMMAND_TIMEOUT) -> tuple[int, str, str]:
	"""Run command with timeout (WireGuard shorthand supported)."""
	try:
		cmd = _resolve_command_args(*args)
		proc = await asyncio.create_subprocess_exec(
			*cmd,
			stdout=asyncio.subprocess.PIPE,
			stderr=asyncio.subprocess.PIPE,
		)
		try:
			stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
			# returncode is always set after communicate() completes
			return (
				proc.returncode if proc.returncode is not None else 1,
				stdout_bytes.decode("utf-8", errors="replace"),
				stderr_bytes.decode("utf-8", errors="replace"),
			)
		except asyncio.TimeoutError:
			proc.kill()
			# Wait with secondary timeout to avoid zombie processes
			try:
				await asyncio.wait_for(proc.wait(), timeout=_KILL_WAIT_TIMEOUT)
			except asyncio.TimeoutError:
				pass  # Process stuck; will become zombie but we can't do more
			return 1, "", f"Command timed out after {timeout}s"
	except Exception as e:
		return 1, "", str(e)


async def run_wg_command_stdin(stdin_data: str, *args: str, timeout: int = WG_COMMAND_TIMEOUT) -> tuple[int, str, str]:
	"""Run command with stdin data (WireGuard shorthand supported).

	Uses communicate() with input parameter for reliable stdin handling.
	"""
	try:
		cmd = _resolve_command_args(*args)
		proc = await asyncio.create_subprocess_exec(
			*cmd,
			stdin=asyncio.subprocess.PIPE,
			stdout=asyncio.subprocess.PIPE,
			stderr=asyncio.subprocess.PIPE,
		)
		try:
			stdout_bytes, stderr_bytes = await asyncio.wait_for(
				proc.communicate(input=stdin_data.encode("utf-8")),
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
	except Exception as e:
		return 1, "", str(e)


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
	fd = None
	tmp_path = None
	try:
		# Create temp file with restrictive permissions (readable only by owner)
		fd, tmp_path = tempfile.mkstemp(prefix="wg_psk_", suffix=".key")
		os.chmod(tmp_path, 0o600)
		os.write(fd, preshared_key.encode("utf-8"))
		os.close(fd)
		fd = None  # Mark as closed

		return await run_wg_command(
			"wg", "set", interface,
			"peer", public_key,
			"allowed-ips", allowed_ips,
			"preshared-key", tmp_path,
		)
	finally:
		# Clean up: close fd if still open, remove temp file
		if fd is not None:
			try:
				os.close(fd)
			except OSError:
				pass
		if tmp_path and os.path.exists(tmp_path):
			try:
				os.unlink(tmp_path)
			except OSError:
				pass


async def generate_keypair() -> tuple[str, str]:
	"""Generate WireGuard private/public key pair."""
	exit_code, privkey, stderr = await run_wg_command("genkey")
	if exit_code != 0 or not privkey:
		raise HTTPException(status_code=500, detail=f"Failed to generate private key: {stderr}")
	
	privkey = privkey.strip()
	exit_code, pubkey, stderr = await run_wg_command_stdin(privkey, "pubkey")
	if exit_code != 0 or not pubkey:
		raise HTTPException(status_code=500, detail=f"Failed to derive public key: {stderr}")
	
	return privkey, pubkey.strip()


async def generate_preshared_key() -> str:
	"""Generate WireGuard preshared key."""
	exit_code, psk, stderr = await run_wg_command("genpsk")
	if exit_code != 0 or not psk:
		raise HTTPException(status_code=500, detail=f"Failed to generate PSK: {stderr}")
	return psk.strip()


async def derive_public_key(private_key: str) -> str:
	"""Derive public key from a private key using WireGuard's pubkey command.
	
	Raises:
		HTTPException: If derivation fails.
	"""
	exit_code, pubkey, stderr = await run_wg_command_stdin(private_key.strip(), "pubkey")
	if exit_code != 0 or not pubkey:
		raise HTTPException(status_code=500, detail=f"Failed to derive public key: {stderr}")
	return pubkey.strip()


def _is_valid_wg_key(key: str) -> bool:
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


# Public alias for external use
is_valid_wg_key = _is_valid_wg_key


async def validate_keypair(private_key: str, public_key: str) -> None:
	"""Validate WireGuard keypair format and derivation.

	Raises:
		HTTPException: If keys are invalid or don't match.
	"""
	if not _is_valid_wg_key(private_key):
		raise HTTPException(status_code=422, detail="Invalid private key format")
	if not _is_valid_wg_key(public_key):
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
