#!/usr/bin/env python3
#
# app/api/wireguard.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard management API routes."""

from __future__ import annotations

import asyncio
import io
import ipaddress
import logging
import os
import re
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response

from ..db import sqlite as sqlite_db
from ..db import tsdb
from ..models.peers import PeerCreate, PeerPublic, PeerUpdate, PeerConfig, PeerStats
from ..utils.deps import get_conn, get_tsdb_dir, get_config
from ..utils.config import WG_CONFIG_PATH, WG_DEFAULT_DNS
from ..utils.vault import encrypt as vault_encrypt, decrypt as vault_decrypt

from .auth import get_current_user, require_admin
from .response import ok_response
from ..utils.geoip import lookup_ip
from pydantic import BaseModel, Field
import json

_log = logging.getLogger(__name__)

router = APIRouter(tags=["wireguard"])

# Interface name validation regex
_IFACE_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,14}$")

# Timeout for wg commands (seconds)
WG_COMMAND_TIMEOUT = 30
TRAFFIC_RANGE_TO_HOURS = {
	"6h": 6,
	"24h": 24,
	"3d": 72,
	"7d": 168,
}


def _validate_interface_name(name: str) -> str:
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


def _select_display_unit(max_bytes: float) -> str:
	"""Choose a readable byte unit for chart payloads."""
	if max_bytes >= 1024 ** 3:
		return "GB"
	if max_bytes >= 1024 ** 2:
		return "MB"
	if max_bytes >= 1024:
		return "KB"
	return "B"


def _bytes_to_unit(value: float, unit: str) -> float:
	"""Convert bytes to selected display unit."""
	if unit == "GB":
		return value / (1024 ** 3)
	if unit == "MB":
		return value / (1024 ** 2)
	if unit == "KB":
		return value / 1024
	return value


def _safe_int(value: str, default: int = 0) -> int:
	"""Safely convert string to int, returning default on failure."""
	try:
		return int(value) if value else default
	except (ValueError, TypeError):
		return default


# Regex for detecting dangerous shell characters in PostUp/PostDown
_DANGEROUS_SHELL_RE = re.compile(r'[;&|`$]')


def _validate_post_script(value: str | None, field: str) -> str | None:
	"""Validate PostUp/PostDown scripts to prevent shell injection.
	
	Raises:
		HTTPException: If script contains dangerous shell characters.
	"""
	if value is None:
		return None
	# Reject obvious injection patterns; full sandboxing requires AppArmor/seccomp
	if _DANGEROUS_SHELL_RE.search(value):
		raise HTTPException(400, f"{field} contains disallowed shell characters (;&|`$)")
	return value


def _regenerate_peer_tags(conn: sqlite3.Connection) -> None:
	"""Regenerate Unbound peer-tags.conf for per-peer blocklist filtering.
	
	Reads all peers from DB and generates access-control-tag entries
	based on each peer's blocklist_ids setting.
	"""
	try:
		from ..dns import unbound as _unbound
		peers = sqlite_db.get_all_peers(conn)
		peer_list = []
		for row in peers:
			blocklist_ids = None
			if row["blocklist_ids"]:
				try:
					blocklist_ids = json.loads(row["blocklist_ids"])
				except (json.JSONDecodeError, TypeError):
					pass
			peer_list.append({
				"peer_address": row["peer_address"],
				"use_adblocker": bool(row["use_adblocker"]),
				"blocklist_ids": blocklist_ids,
			})
		_unbound.write_peer_tags(peer_list)
	except Exception as exc:
		_log.warning("Failed to regenerate peer tags: %s", exc)


def _row_to_public(row: sqlite3.Row) -> PeerPublic:
	"""Convert a SQLite peer row into the public response model."""
	# Parse blocklist_ids from JSON string
	blocklist_ids_raw = row["blocklist_ids"]
	blocklist_ids = None
	if blocklist_ids_raw:
		try:
			blocklist_ids = json.loads(blocklist_ids_raw)
		except (json.JSONDecodeError, TypeError):
			blocklist_ids = None
	
	return PeerPublic(
		id=row["id"],
		public_key=row["public_key"],
		name=row["name"],
		description=row["description"],
		allowed_ips=row["allowed_ips"],
		allowed_ips_mode=row["allowed_ips_mode"] or "full",
		peer_address=row["peer_address"],
		endpoint=row["endpoint"],
		interface=row["interface"],
		is_enabled=bool(row["is_enabled"]),
		use_adblocker=bool(row["use_adblocker"]),
		blocklist_ids=blocklist_ids,
		client_isolation=bool(row["client_isolation"]) if "client_isolation" in row.keys() else False,
		created_at=row["created_at"],
		updated_at=row["updated_at"],
	)


async def _run_wg_command(*args: str, timeout: int = WG_COMMAND_TIMEOUT) -> tuple[int, str, str]:
	"""Run a WireGuard command and return (returncode, stdout, stderr)."""
	proc: asyncio.subprocess.Process | None = None
	try:
		proc = await asyncio.create_subprocess_exec(
			*args,
			stdout=asyncio.subprocess.PIPE,
			stderr=asyncio.subprocess.PIPE,
		)
		stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
		return proc.returncode, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")
	except asyncio.TimeoutError:
		if proc and proc.returncode is None:
			proc.kill()
			await proc.wait()
		return -1, "", f"Command timed out after {timeout}s"


async def _run_wg_command_stdin(stdin_data: str, *args: str, timeout: int = WG_COMMAND_TIMEOUT) -> tuple[int, str, str]:
	"""Run a WireGuard command with stdin input and return (returncode, stdout, stderr).
	
	If args contains '/dev/stdin', it will be replaced with a temp file path.
	Otherwise, stdin_data is piped to the process stdin.
	"""
	args_list = list(args)
	has_stdin_arg = "/dev/stdin" in args_list
	proc: asyncio.subprocess.Process | None = None
	
	try:
		if has_stdin_arg:
			# Use temp file for commands that take /dev/stdin as argument (e.g., wg set ... preshared-key /dev/stdin)
			# Create with restrictive permissions to prevent local privilege escalation
			fd, temp_path = tempfile.mkstemp(suffix='.key')
			try:
				# Use fdopen to ensure fd is properly closed even if write fails
				with os.fdopen(fd, 'wb') as f:
					f.write(stdin_data.encode('utf-8'))
				# fd is now guaranteed closed
				
				for i, arg in enumerate(args_list):
					if arg == "/dev/stdin":
						args_list[i] = temp_path
				
				proc = await asyncio.create_subprocess_exec(
					*args_list,
					stdout=asyncio.subprocess.PIPE,
					stderr=asyncio.subprocess.PIPE,
				)
				stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
				return proc.returncode, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")
			finally:
				try:
					os.unlink(temp_path)
				except OSError:
					pass
		else:
			proc = await asyncio.create_subprocess_exec(
				*args_list,
				stdin=asyncio.subprocess.PIPE,
				stdout=asyncio.subprocess.PIPE,
				stderr=asyncio.subprocess.PIPE,
			)
			if proc.stdin:
				proc.stdin.write(stdin_data.encode("utf-8"))
				await proc.stdin.drain()
				proc.stdin.close()
			stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
			return proc.returncode, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")
	except asyncio.TimeoutError:
		if proc and proc.returncode is None:
			proc.kill()
			await proc.wait()
		return -1, "", f"Command timed out after {timeout}s"
	except Exception as e:
		return -1, "", f"Command failed: {e}"


async def _generate_keypair() -> tuple[str, str]:
	"""Generate a WireGuard keypair (private_key, public_key)."""
	# Generate private key
	code, privkey, err = await _run_wg_command("wg", "genkey")
	if code != 0:
		raise HTTPException(status_code=500, detail=f"Failed to generate private key: {err}")
	privkey = privkey.strip()
	
	# Derive public key via stdin
	code, pubkey, err = await _run_wg_command_stdin(privkey, "wg", "pubkey")
	if code != 0:
		raise HTTPException(status_code=500, detail=f"Failed to derive public key: {err}")
	pubkey = pubkey.strip()
	
	return privkey, pubkey


async def _generate_preshared_key() -> str:
	"""Generate a WireGuard preshared key."""
	code, psk, err = await _run_wg_command("wg", "genpsk")
	if code != 0:
		raise HTTPException(status_code=500, detail=f"Failed to generate preshared key: {err}")
	return psk.strip()


def _client_iso_chain_name(interface_name: str, *, ipv6: bool = False) -> str:
	"""Return deterministic firewall chain name for client-isolation rules."""
	base = re.sub(r"[^A-Za-z0-9_]", "_", interface_name)
	prefix = "WBISO6_" if ipv6 else "WBISO4_"
	return f"{prefix}{base}"[:28]


def _extract_peer_ips(peer_address: str | None) -> tuple[str | None, str | None]:
	"""Extract IPv4/IPv6 host addresses from a stored peer_address string."""
	if not peer_address:
		return None, None
	v4: str | None = None
	v6: str | None = None
	for part in str(peer_address).split(","):
		item = part.strip()
		if not item:
			continue
		try:
			addr = ipaddress.ip_interface(item)
		except ValueError:
			continue
		if isinstance(addr.ip, ipaddress.IPv4Address):
			v4 = str(addr.ip)
		else:
			v6 = str(addr.ip)
	return v4, v6


def _build_client_isolation_post_rules(
	interface_name: str,
	*,
	v4_subnet: str | None,
	v6_subnet: str | None,
	isolated_v4_ips: list[str],
	isolated_v6_ips: list[str],
) -> tuple[list[str], list[str]]:
	"""Build PostUp/PostDown shell commands for peer-to-peer isolation."""
	up_rules: list[str] = []
	down_rules: list[str] = []

	# IPv4 chain
	if v4_subnet:
		chain4 = _client_iso_chain_name(interface_name, ipv6=False)
		up_rules.extend([
			f"iptables -N {chain4} 2>/dev/null || true",
			f"iptables -F {chain4}",
			f"iptables -D FORWARD -i %i -o %i -j {chain4} 2>/dev/null || true",
		])
		if isolated_v4_ips:
			up_rules.append(f"iptables -I FORWARD 1 -i %i -o %i -j {chain4}")
			for ip in sorted(set(isolated_v4_ips)):
				up_rules.append(f"iptables -A {chain4} -s {ip}/32 -d {v4_subnet} -j DROP")
				up_rules.append(f"iptables -A {chain4} -s {v4_subnet} -d {ip}/32 -j DROP")
		else:
			up_rules.append(f"iptables -X {chain4} 2>/dev/null || true")

		down_rules.extend([
			f"iptables -D FORWARD -i %i -o %i -j {chain4} 2>/dev/null || true",
			f"iptables -F {chain4} 2>/dev/null || true",
			f"iptables -X {chain4} 2>/dev/null || true",
		])

	# IPv6 chain
	if v6_subnet:
		chain6 = _client_iso_chain_name(interface_name, ipv6=True)
		up_rules.extend([
			f"ip6tables -N {chain6} 2>/dev/null || true",
			f"ip6tables -F {chain6}",
			f"ip6tables -D FORWARD -i %i -o %i -j {chain6} 2>/dev/null || true",
		])
		if isolated_v6_ips:
			up_rules.append(f"ip6tables -I FORWARD 1 -i %i -o %i -j {chain6}")
			for ip in sorted(set(isolated_v6_ips)):
				up_rules.append(f"ip6tables -A {chain6} -s {ip}/128 -d {v6_subnet} -j DROP")
				up_rules.append(f"ip6tables -A {chain6} -s {v6_subnet} -d {ip}/128 -j DROP")
		else:
			up_rules.append(f"ip6tables -X {chain6} 2>/dev/null || true")

		down_rules.extend([
			f"ip6tables -D FORWARD -i %i -o %i -j {chain6} 2>/dev/null || true",
			f"ip6tables -F {chain6} 2>/dev/null || true",
			f"ip6tables -X {chain6} 2>/dev/null || true",
		])

	return up_rules, down_rules


async def _apply_client_isolation_runtime(interface_name: str, conn: sqlite3.Connection) -> None:
	"""Apply per-peer client-isolation rules to a running interface (best effort)."""
	iface = sqlite_db.get_interface(conn, interface_name)
	if not iface:
		return

	# Skip when interface is down.
	code, _, _ = await _run_wg_command("wg", "show", interface_name)
	if code != 0:
		return

	def _parse_subnet(addr: str | None) -> str | None:
		if not addr:
			return None
		try:
			return str(ipaddress.ip_interface(addr).network)
		except ValueError:
			return None

	v4_subnet = _parse_subnet(iface["address"])
	v6_subnet = _parse_subnet(iface["address6"])

	cur = conn.execute(
		"""
		SELECT peer_address
		FROM peers
		WHERE interface = ? AND is_enabled = 1 AND client_isolation = 1
		""",
		(interface_name,),
	)
	isolated_v4: set[str] = set()
	isolated_v6: set[str] = set()
	for row in cur.fetchall():
		ipv4, ipv6 = _extract_peer_ips(row["peer_address"])
		if ipv4:
			isolated_v4.add(ipv4)
		if ipv6:
			isolated_v6.add(ipv6)

	async def _run_ignore(*args: str) -> int:
		cmd_name = args[0] if args else ""
		code_inner, _, stderr_inner = await _run_wg_command(*args)
		if code_inner != 0 and stderr_inner and "No chain/target/match" not in stderr_inner:
			_log.debug("CLIENT_ISO runtime cmd failed (%s): %s", cmd_name, stderr_inner.strip())
		return code_inner

	# IPv4 runtime chain
	if v4_subnet:
		chain4 = _client_iso_chain_name(interface_name, ipv6=False)
		await _run_ignore("iptables", "-N", chain4)
		await _run_ignore("iptables", "-F", chain4)
		while await _run_ignore("iptables", "-D", "FORWARD", "-i", interface_name, "-o", interface_name, "-j", chain4) == 0:
			pass
		if isolated_v4:
			await _run_ignore("iptables", "-I", "FORWARD", "1", "-i", interface_name, "-o", interface_name, "-j", chain4)
			for ip in sorted(isolated_v4):
				await _run_ignore("iptables", "-A", chain4, "-s", f"{ip}/32", "-d", v4_subnet, "-j", "DROP")
				await _run_ignore("iptables", "-A", chain4, "-s", v4_subnet, "-d", f"{ip}/32", "-j", "DROP")
		else:
			await _run_ignore("iptables", "-X", chain4)

	# IPv6 runtime chain
	if v6_subnet:
		chain6 = _client_iso_chain_name(interface_name, ipv6=True)
		await _run_ignore("ip6tables", "-N", chain6)
		await _run_ignore("ip6tables", "-F", chain6)
		while await _run_ignore("ip6tables", "-D", "FORWARD", "-i", interface_name, "-o", interface_name, "-j", chain6) == 0:
			pass
		if isolated_v6:
			await _run_ignore("ip6tables", "-I", "FORWARD", "1", "-i", interface_name, "-o", interface_name, "-j", chain6)
			for ip in sorted(isolated_v6):
				await _run_ignore("ip6tables", "-A", chain6, "-s", f"{ip}/128", "-d", v6_subnet, "-j", "DROP")
				await _run_ignore("ip6tables", "-A", chain6, "-s", v6_subnet, "-d", f"{ip}/128", "-j", "DROP")
		else:
			await _run_ignore("ip6tables", "-X", chain6)


def _write_interface_config(
	config_path: Path,
	name: str,
	private_key: str,
	address: str,
	listen_port: int,
	dns: str | None,
	post_up: str | None,
	post_down: str | None,
	conn: sqlite3.Connection,
	address6: str | None = None,
	pepper: str = "",
) -> None:
	"""Write a WireGuard interface config file including all peers."""
	# Decrypt interface private key
	private_key_plain = vault_decrypt(private_key, pepper)
	
	# Build Address line (IPv4 + optional IPv6)
	addr_parts = [address]
	if address6:
		addr_parts.append(address6)
	
	config_lines = [
		"[Interface]",
		f"PrivateKey = {private_key_plain}",
		f"Address = {', '.join(addr_parts)}",
		f"ListenPort = {listen_port}",
	]
	
	# NOTE: DNS is intentionally omitted from the server-side config.
	# wg-quick rewrites /etc/resolv.conf when DNS is set, which breaks
	# container-internal DNS resolution.  DNS belongs only in the CLIENT
	# config (PeerConfig) that peers download.
	# Add peers for this interface and collect isolated peers.
	cur = conn.execute(
		"""
		SELECT public_key, preshared_key, peer_address, allowed_ips_mode, client_isolation
		FROM peers
		WHERE interface = ? AND is_enabled = 1
		""",
		(name,),
	)
	peer_rows = cur.fetchall()
	isolated_v4_ips: list[str] = []
	isolated_v6_ips: list[str] = []
	for peer_row in peer_rows:
		if not peer_row["peer_address"]:
			continue  # Skip peers without assigned address
		# Check client_isolation flag for server-side firewall rules
		if peer_row["client_isolation"]:
			ipv4, ipv6 = _extract_peer_ips(peer_row["peer_address"])
			if ipv4:
				isolated_v4_ips.append(ipv4)
			if ipv6:
				isolated_v6_ips.append(ipv6)
		config_lines.append("")
		config_lines.append("[Peer]")
		config_lines.append(f"PublicKey = {peer_row['public_key']}")
		if peer_row["preshared_key"]:
			psk_plain = vault_decrypt(peer_row["preshared_key"], pepper)
			config_lines.append(f"PresharedKey = {psk_plain}")
		config_lines.append(f"AllowedIPs = {peer_row['peer_address']}")

	# Append dynamic client-isolation firewall rules.
	v4_subnet = None
	try:
		v4_subnet = str(ipaddress.ip_interface(address).network)
	except ValueError:
		pass

	v6_subnet = None
	if address6:
		try:
			v6_subnet = str(ipaddress.ip_interface(address6).network)
		except ValueError:
			pass

	isolation_up, isolation_down = _build_client_isolation_post_rules(
		name,
		v4_subnet=v4_subnet,
		v6_subnet=v6_subnet,
		isolated_v4_ips=isolated_v4_ips,
		isolated_v6_ips=isolated_v6_ips,
	)

	post_up_parts: list[str] = []
	post_down_parts: list[str] = []
	if post_up:
		post_up_parts.append(post_up)
	if post_down:
		post_down_parts.append(post_down)
	post_up_parts.extend(isolation_up)
	post_down_parts.extend(isolation_down)

	# Insert PostUp/PostDown before first [Peer] section (or at end of [Interface] block)
	peer_start = next(
		(i for i, line in enumerate(config_lines) if line == "[Peer]"),
		len(config_lines),
	)
	if post_down_parts:
		config_lines.insert(peer_start, f"PostDown = {'; '.join(post_down_parts)}")
	if post_up_parts:
		config_lines.insert(peer_start, f"PostUp = {'; '.join(post_up_parts)}")
	
	config_content = "\n".join(config_lines) + "\n"
	
	config_path.mkdir(parents=True, exist_ok=True)
	conf_file = config_path / f"{name}.conf"
	
	# Atomic write: write to temp file, chmod, then rename
	# This prevents partially-written configs if interrupted
	fd, temp_path = tempfile.mkstemp(dir=str(config_path), suffix=".tmp")
	fd_closed = False
	try:
		os.write(fd, config_content.encode('utf-8'))
		os.fchmod(fd, 0o600)
		os.close(fd)
		fd_closed = True
		os.rename(temp_path, str(conf_file))
	except Exception:
		if not fd_closed:
			os.close(fd)
		try:
			os.unlink(temp_path)
		except OSError:
			pass
		raise


def regenerate_all_configs(config_path: Path, conn: sqlite3.Connection, pepper: str = "") -> int:
	"""Regenerate all WireGuard configs from database. Returns count of interfaces written."""
	interfaces = sqlite_db.list_interfaces(conn)
	count = 0
	for iface in interfaces:
		if not iface["is_enabled"]:
			continue
		try:
			_write_interface_config(
				config_path,
				iface["name"],
				iface["private_key"],
				iface["address"],
				iface["listen_port"],
				iface["dns"],
				iface["post_up"],
				iface["post_down"],
				conn,
				address6=iface["address6"],
				pepper=pepper,
			)
			count += 1
			_log.info("CONFIG_REGENERATED interface=%s", iface["name"])
		except Exception as e:
			_log.error("CONFIG_REGENERATE_FAILED interface=%s error=%s", iface["name"], e)
	return count


def _sync_interface_config(config_path: Path, interface_name: str, conn: sqlite3.Connection, pepper: str = "") -> bool:
	"""Sync a single interface config file with DB state. Returns True if successful."""
	iface = sqlite_db.get_interface(conn, interface_name)
	if not iface:
		return False
	try:
		_write_interface_config(
			config_path,
			iface["name"],
			iface["private_key"],
			iface["address"],
			iface["listen_port"],
			iface["dns"],
			iface["post_up"],
			iface["post_down"],
			conn,
			address6=iface["address6"],
			pepper=pepper,
		)
		return True
	except Exception as e:
		_log.warning("CONFIG_SYNC_FAILED interface=%s error=%s", interface_name, e)
		return False


# ---------------------------------------------------------------------------
# WireGuard Settings
# ---------------------------------------------------------------------------

class WgSettingsPayload(BaseModel):
	"""Payload for WireGuard global settings."""
	wg_fqdn: Optional[str] = Field(None, max_length=256, description="Server FQDN / public hostname")
	wg_port: Optional[int] = Field(None, ge=1, le=65535, description="WireGuard listen port")
	wg_mtu: Optional[int] = Field(None, ge=1280, le=9000, description="Global MTU value (1280-9000)")
	wg_persistent_keepalive: Optional[int] = Field(None, ge=0, le=600, description="Persistent keepalive in seconds")
	wg_use_psk: Optional[str] = Field(None, pattern=r"^[01]$", description="Enable PresharedKey (0/1)")
	gui_port: Optional[int] = Field(None, ge=1, le=65535, description="HTTP port for the web UI")
	gui_localhost_only: Optional[str] = Field(None, pattern=r"^[01]$", description="Only listen on localhost (0/1)")


WG_SETTING_KEYS = ["wg_fqdn", "wg_port", "wg_mtu", "wg_persistent_keepalive", "wg_use_psk", "gui_port", "gui_localhost_only"]


def _get_server_endpoint(conn: sqlite3.Connection) -> str:
	"""Build the WireGuard server endpoint from DB settings.

	Returns ``fqdn:port`` (e.g. ``vpn.example.com:51820``).
	Falls back to sensible defaults if not configured.
	"""
	fqdn = sqlite_db.get_setting(conn, "wg_fqdn") or "vpn.example.com"
	port = sqlite_db.get_setting(conn, "wg_port") or "51820"
	# IPv6 addresses need brackets
	if ":" in fqdn:
		return f"[{fqdn}]:{port}"
	return f"{fqdn}:{port}"


async def _get_dns_for_peer(
	conn: sqlite3.Connection,
	interface_name: str,
	use_adblocker: bool,
	default_dns: str,
) -> str:
	"""Get the DNS server(s) for a peer based on adblocker setting.

	If ``use_adblocker`` is True, returns the interface IPv4 address
	(internal WireBuddy DNS). This path is strict by design: it never
	falls back to public resolvers to avoid DNS leaks in generated client
	configurations.

	If ``use_adblocker`` is False, returns the configured default DNS servers.
	"""
	if not use_adblocker:
		return default_dns

	# Get interface to extract gateway IP
	iface = sqlite_db.get_interface(conn, interface_name)
	if not iface:
		raise HTTPException(
			status_code=500,
			detail=f"Interface '{interface_name}' not found while resolving peer DNS",
		)
	if not iface["address"]:
		raise HTTPException(
			status_code=422,
			detail=f"Interface '{interface_name}' has no IPv4 address for WireBuddy DNS",
		)

	# Extract gateway IP from interface address (e.g., "10.13.13.1/24" -> "10.13.13.1")
	try:
		ipv4_iface = ipaddress.ip_interface(iface["address"].strip())
	except ValueError as exc:
		raise HTTPException(
			status_code=422,
			detail=f"Invalid interface IPv4 address for '{interface_name}': {iface['address']!r}",
		) from exc

	# Intentionally return IPv4 only.
	# Some clients prefer IPv6 DNS first; if Unbound is not listening on IPv6,
	# DNS can appear fully broken even though IPv4 DNS works.
	return str(ipv4_iface.ip)


def _allowed_ips_with_dns_routes(
	allowed_ips: str,
	dns_servers: str,
	use_adblocker: bool,
) -> str:
	"""Ensure internal DNS server IPs are routed via tunnel (leak protection).

	When WireBuddy DNS is enabled and client routing is split/custom, DNS IPs may
	not be included in client AllowedIPs. In that case queries can time out or
	fall back outside the tunnel. We enforce host routes for DNS IPs unless they
	are already covered by existing AllowedIPs.
	"""
	if not use_adblocker:
		return allowed_ips

	items = [x.strip() for x in (allowed_ips or "").split(",") if x.strip()]
	if not items:
		items = []

	# Parse existing networks once; ignore malformed entries but keep them as-is.
	existing_networks: list[ipaddress._BaseNetwork] = []
	for entry in items:
		try:
			existing_networks.append(ipaddress.ip_network(entry, strict=False))
		except ValueError:
			continue

	def _covered(ip_obj: ipaddress._BaseAddress) -> bool:
		for net in existing_networks:
			if net.version == ip_obj.version and ip_obj in net:
				return True
		return False

	for dns in [x.strip() for x in (dns_servers or "").split(",") if x.strip()]:
		try:
			ip_obj = ipaddress.ip_address(dns)
		except ValueError:
			continue
		if _covered(ip_obj):
			continue

		host_route = f"{ip_obj}/32" if ip_obj.version == 4 else f"{ip_obj}/128"
		items.append(host_route)
		existing_networks.append(ipaddress.ip_network(host_route, strict=False))

	# De-duplicate while preserving order.
	seen: set[str] = set()
	result: list[str] = []
	for entry in items:
		if entry in seen:
			continue
		seen.add(entry)
		result.append(entry)
	return ", ".join(result)


@router.get("/settings")
async def get_wg_settings(
	_: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get WireGuard global settings."""
	result = {}
	for key in WG_SETTING_KEYS:
		result[key] = sqlite_db.get_setting(conn, key)
	return ok_response(data=result)


@router.put("/settings")
async def update_wg_settings(
	payload: WgSettingsPayload,
	_: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Update WireGuard global settings (admin only).
	
	Only explicitly provided fields will be updated (PATCH semantics).
	"""
	updated = []
	for key in WG_SETTING_KEYS:
		# Only update fields that were explicitly set in the request
		if key in payload.model_fields_set:
			value = getattr(payload, key)
			sqlite_db.set_setting(conn, key, str(value) if value is not None else "")
			updated.append(key)
	
	settings = {k: sqlite_db.get_setting(conn, k) for k in WG_SETTING_KEYS}
	return ok_response(updated=updated, settings=settings, data={"updated": updated, "settings": settings})


@router.get("/settings/psk")
async def get_global_psk(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get the current global PresharedKey (masked for security)."""
	cfg = get_config(request)
	enc_psk = sqlite_db.get_setting(conn, "wg_global_psk")
	if not enc_psk:
		return ok_response(data={"masked": None})
	try:
		plain = vault_decrypt(enc_psk, cfg.secret_key)
		masked = plain[:6] + "*" * (len(plain) - 10) + plain[-4:] if len(plain) > 10 else "*" * len(plain)
		return ok_response(data={"masked": masked}, masked=masked)
	except Exception:
		return ok_response(data={"masked": None})


@router.post("/settings/generate-psk")
async def generate_global_psk(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Generate a new global PresharedKey."""
	cfg = get_config(request)
	psk = await _generate_preshared_key()
	enc_psk = vault_encrypt(psk, cfg.secret_key)
	sqlite_db.set_setting(conn, "wg_global_psk", enc_psk)
	masked = psk[:6] + "*" * (len(psk) - 10) + psk[-4:] if len(psk) > 10 else "*" * len(psk)
	return ok_response(data={"masked": masked}, masked=masked)


# ---------------------------------------------------------------------------
# Interface Management
# ---------------------------------------------------------------------------

@router.get("/interfaces")
async def list_interfaces(
	request: Request,
	_: sqlite3.Row = Depends(get_current_user),
):
	"""List all WireGuard interfaces (both configured and active)."""
	cfg = get_config(request)
	config_path = WG_CONFIG_PATH
	
	# Get active interfaces from wg
	active_interfaces: set[str] = set()
	code, stdout, stderr = await _run_wg_command("wg", "show", "interfaces")
	if code == 0 and stdout.strip():
		active_interfaces = set(stdout.strip().split())
	
	# Get configured interfaces from config files
	configured: set[str] = set()
	if config_path.is_dir():
		for conf in config_path.glob("*.conf"):
			configured.add(conf.stem)
	
	# Build combined list with status
	all_interfaces = sorted(configured | active_interfaces)
	result = []
	for name in all_interfaces:
		result.append({
			"name": name,
			"is_active": name in active_interfaces,
			"is_configured": name in configured,
		})
	
	return ok_response(data={"interfaces": result}, interfaces=result)


@router.get("/interfaces/{name}")
async def get_interface(name: str, _: sqlite3.Row = Depends(get_current_user)):
	"""Get details of a specific WireGuard interface."""
	# Validate interface name
	_validate_interface_name(name)
	
	code, stdout, stderr = await _run_wg_command("wg", "show", name)
	if code != 0:
		raise HTTPException(status_code=404, detail=f"Interface not found: {stderr}")
	
	# Parse wg show output
	lines = stdout.strip().split("\n")
	result = {"name": name, "public_key": None, "listen_port": None, "peers": []}
	
	current_peer = None
	for line in lines:
		line = line.strip()
		if line.startswith("public key:"):
			result["public_key"] = line.split(":", 1)[1].strip()
		elif line.startswith("listening port:"):
			result["listen_port"] = int(line.split(":", 1)[1].strip())
		elif line.startswith("peer:"):
			if current_peer:
				result["peers"].append(current_peer)
			current_peer = {"public_key": line.split(":", 1)[1].strip()}
		elif current_peer:
			if line.startswith("endpoint:"):
				current_peer["endpoint"] = line.split(":", 1)[1].strip()
			elif line.startswith("allowed ips:"):
				current_peer["allowed_ips"] = line.split(":", 1)[1].strip()
			elif line.startswith("latest handshake:"):
				current_peer["latest_handshake"] = line.split(":", 1)[1].strip()
			elif line.startswith("transfer:"):
				transfer = line.split(":", 1)[1].strip()
				current_peer["transfer"] = transfer
	
	if current_peer:
		result["peers"].append(current_peer)
	
	return ok_response(data=result)


@router.post("/interfaces/{name}/up")
async def interface_up(
	name: str,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Bring up a WireGuard interface."""
	_validate_interface_name(name)
	
	code, stdout, stderr = await _run_wg_command("wg-quick", "up", name)
	if code != 0:
		raise HTTPException(status_code=500, detail=f"Failed to bring up interface: {stderr}")

	# Ensure client-isolation firewall rules are applied immediately.
	await _apply_client_isolation_runtime(name, conn)
	
	_log.info("INTERFACE_UP name=%s", name)
	return ok_response(message=f"Interface {name} is up")


@router.post("/interfaces/{name}/down")
async def interface_down(name: str, _: sqlite3.Row = Depends(require_admin)):
	"""Bring down a WireGuard interface."""
	_validate_interface_name(name)
	
	code, stdout, stderr = await _run_wg_command("wg-quick", "down", name)
	if code != 0:
		raise HTTPException(status_code=500, detail=f"Failed to bring down interface: {stderr}")
	
	_log.info("INTERFACE_DOWN name=%s", name)
	return ok_response(message=f"Interface {name} is down")


class InterfaceCreate(BaseModel):
	"""Schema for creating a new WireGuard interface."""
	name: str = Field(..., min_length=1, max_length=15, pattern=r"^[a-zA-Z][a-zA-Z0-9_-]*$")
	address: str = Field(
		default="10.13.13.1/24",
		min_length=7,
		description="IPv4 interface address with subnet (e.g., 10.13.13.1/24)",
	)
	address6: Optional[str] = Field(
		default="fd13:13:13::1/64",
		description="IPv6 interface address with prefix (e.g., fd13:13:13::1/64). Set to empty string to disable.",
	)
	listen_port: int = Field(default=51820, ge=1, le=65535)
	dns: Optional[str] = Field(default=None, description="DNS servers for clients")
	post_up: Optional[str] = Field(default=None, description="PostUp script")
	post_down: Optional[str] = Field(default=None, description="PostDown script")


class InterfaceUpdate(BaseModel):
	"""Schema for updating an existing WireGuard interface."""
	address: str = Field(
		...,
		min_length=7,
		description="IPv4 interface address with subnet (e.g., 10.13.13.1/24)",
	)
	address6: Optional[str] = Field(
		default=None,
		description="IPv6 interface address with prefix (optional)",
	)
	listen_port: int = Field(default=51820, ge=1, le=65535)
	dns: Optional[str] = Field(default=None, description="DNS servers for clients")
	post_up: Optional[str] = Field(default=None, description="PostUp script")
	post_down: Optional[str] = Field(default=None, description="PostDown script")


@router.post("/interfaces", status_code=201)
async def create_interface(
	request: Request,
	payload: InterfaceCreate,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Create a new WireGuard interface configuration."""
	
	cfg = get_config(request)
	config_path = WG_CONFIG_PATH
	conf_file = config_path / f"{payload.name}.conf"
	
	# Check if this will be the first interface (before creating)
	is_first_interface = False
	if config_path.is_dir():
		existing_count = len(list(config_path.glob("*.conf")))
		is_first_interface = (existing_count == 0)
	
	# Check if interface already exists (in DB or filesystem)
	if conf_file.exists():
		raise HTTPException(status_code=409, detail=f"Interface '{payload.name}' already exists")
	if sqlite_db.get_interface(conn, payload.name):
		raise HTTPException(status_code=409, detail=f"Interface '{payload.name}' already exists in database")
	
	# Validate addresses
	try:
		v4 = ipaddress.ip_interface(payload.address)
	except ValueError:
		raise HTTPException(status_code=422, detail=f"Invalid IPv4 address: {payload.address}")
	
	v6_str = payload.address6 or None
	if v6_str:
		try:
			ipaddress.ip_interface(v6_str)
		except ValueError:
			raise HTTPException(status_code=422, detail=f"Invalid IPv6 address: {v6_str}")
	
	# Generate server keypair
	private_key, public_key = await _generate_keypair()
	
	# Build PostUp/PostDown with IPv4 + IPv6 NAT rules
	post_up = payload.post_up
	post_down = payload.post_down
	
	v4_subnet = str(v4.network)
	
	if not post_up:
		rules = [
			f"iptables -t nat -A POSTROUTING -s {v4_subnet} -o eth0 -j MASQUERADE",
			"iptables -A FORWARD -i %i -j ACCEPT",
			"iptables -A FORWARD -o %i -j ACCEPT",
			# Allow DNS queries from WireGuard clients to reach Unbound
			"iptables -A INPUT -i %i -p udp --dport 53 -j ACCEPT",
			"iptables -A INPUT -i %i -p tcp --dport 53 -j ACCEPT",
			# Allow DNS responses back to WireGuard clients on hardened OUTPUT policies
			"iptables -A OUTPUT -o %i -p udp --sport 53 -j ACCEPT",
			"iptables -A OUTPUT -o %i -p tcp --sport 53 -j ACCEPT",
			# Allow Unbound upstream DNS egress (DoT + classic DNS)
			"iptables -A OUTPUT -o eth0 -p tcp --dport 853 -j ACCEPT",
			"iptables -A OUTPUT -o eth0 -p udp --dport 53 -j ACCEPT",
			"iptables -A OUTPUT -o eth0 -p tcp --dport 53 -j ACCEPT",
		]
		if v6_str:
			v6_subnet = str(ipaddress.ip_interface(v6_str).network)
			rules += [
				f"ip6tables -t nat -A POSTROUTING -s {v6_subnet} -o eth0 -j MASQUERADE",
				"ip6tables -A FORWARD -i %i -j ACCEPT",
				"ip6tables -A FORWARD -o %i -j ACCEPT",
				"ip6tables -A INPUT -i %i -p udp --dport 53 -j ACCEPT",
				"ip6tables -A INPUT -i %i -p tcp --dport 53 -j ACCEPT",
				"ip6tables -A OUTPUT -o %i -p udp --sport 53 -j ACCEPT",
				"ip6tables -A OUTPUT -o %i -p tcp --sport 53 -j ACCEPT",
				"ip6tables -A OUTPUT -o eth0 -p tcp --dport 853 -j ACCEPT",
				"ip6tables -A OUTPUT -o eth0 -p udp --dport 53 -j ACCEPT",
				"ip6tables -A OUTPUT -o eth0 -p tcp --dport 53 -j ACCEPT",
			]
		post_up = "; ".join(rules)

	if not post_down:
		rules = [
			f"iptables -t nat -D POSTROUTING -s {v4_subnet} -o eth0 -j MASQUERADE",
			"iptables -D FORWARD -i %i -j ACCEPT",
			"iptables -D FORWARD -o %i -j ACCEPT",
			"iptables -D INPUT -i %i -p udp --dport 53 -j ACCEPT",
			"iptables -D INPUT -i %i -p tcp --dport 53 -j ACCEPT",
			"iptables -D OUTPUT -o %i -p udp --sport 53 -j ACCEPT",
			"iptables -D OUTPUT -o %i -p tcp --sport 53 -j ACCEPT",
			"iptables -D OUTPUT -o eth0 -p tcp --dport 853 -j ACCEPT",
			"iptables -D OUTPUT -o eth0 -p udp --dport 53 -j ACCEPT",
			"iptables -D OUTPUT -o eth0 -p tcp --dport 53 -j ACCEPT",
		]
		if v6_str:
			v6_subnet = str(ipaddress.ip_interface(v6_str).network)
			rules += [
				f"ip6tables -t nat -D POSTROUTING -s {v6_subnet} -o eth0 -j MASQUERADE",
				"ip6tables -D FORWARD -i %i -j ACCEPT",
				"ip6tables -D FORWARD -o %i -j ACCEPT",
				"ip6tables -D INPUT -i %i -p udp --dport 53 -j ACCEPT",
				"ip6tables -D INPUT -i %i -p tcp --dport 53 -j ACCEPT",
				"ip6tables -D OUTPUT -o %i -p udp --sport 53 -j ACCEPT",
				"ip6tables -D OUTPUT -o %i -p tcp --sport 53 -j ACCEPT",
				"ip6tables -D OUTPUT -o eth0 -p tcp --dport 853 -j ACCEPT",
				"ip6tables -D OUTPUT -o eth0 -p udp --dport 53 -j ACCEPT",
				"ip6tables -D OUTPUT -o eth0 -p tcp --dport 53 -j ACCEPT",
			]
		post_down = "; ".join(rules)
	
	# Save to database first (source of truth)
	# Encrypt private key before storage
	private_key_encrypted = vault_encrypt(private_key, cfg.secret_key)
	try:
		sqlite_db.create_interface(
			conn,
			name=payload.name,
			private_key=private_key_encrypted,
			public_key=public_key,
			address=payload.address,
			address6=v6_str,
			listen_port=payload.listen_port,
			dns=payload.dns,
			post_up=post_up,
			post_down=post_down,
		)
	except Exception as e:
		raise HTTPException(status_code=500, detail=f"Failed to save interface to database: {e}")
	
	# Write config file to /etc/wireguard
	try:
		_write_interface_config(
			config_path,
			payload.name,
			private_key_encrypted,
			payload.address,
			payload.listen_port,
			payload.dns,
			post_up,
			post_down,
			conn,
			address6=v6_str,
			pepper=cfg.secret_key,
		)
	except OSError as e:
		# Rollback: remove from DB
		sqlite_db.delete_interface(conn, payload.name)
		raise HTTPException(status_code=500, detail=f"Failed to write config: {e}")
	
	_log.info("INTERFACE_CREATED name=%s address=%s address6=%s", payload.name, payload.address, v6_str)
	
	# Auto-start the interface if it's the first one
	if is_first_interface:
		try:
			code, stdout, stderr = await _run_wg_command("wg-quick", "up", payload.name)
			if code == 0:
				_log.info("INTERFACE_AUTO_STARTED name=%s (first interface)", payload.name)
			else:
				_log.warning("Failed to auto-start first interface %s: %s", payload.name, stderr)
		except Exception as e:
			_log.warning("Exception during auto-start of first interface %s: %s", payload.name, e)

	data = {
		"name": payload.name,
		"public_key": public_key,
		"address": payload.address,
		"address6": v6_str,
		"listen_port": payload.listen_port,
	}
	return ok_response(data=data, **data)


@router.get("/interfaces/{name}/config")
async def get_interface_config(
	name: str,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Get stored configuration fields for an interface (for UI editing)."""
	_validate_interface_name(name)

	iface = sqlite_db.get_interface(conn, name)
	if not iface:
		raise HTTPException(status_code=404, detail=f"Interface '{name}' not found in database")

	data = {
		"name": iface["name"],
		"address": iface["address"],
		"address6": iface["address6"],
		"listen_port": iface["listen_port"],
		"dns": iface["dns"],
		"post_up": iface["post_up"],
		"post_down": iface["post_down"],
		"is_enabled": bool(iface["is_enabled"]),
	}
	return ok_response(data=data, **data)


@router.put("/interfaces/{name}", status_code=200)
async def update_interface(
	request: Request,
	name: str,
	payload: InterfaceUpdate,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Update a WireGuard interface config in DB and on disk."""

	_validate_interface_name(name)

	iface = sqlite_db.get_interface(conn, name)
	if not iface:
		raise HTTPException(status_code=404, detail=f"Interface '{name}' not found")

	# Validate addresses
	try:
		ipaddress.ip_interface(payload.address)
	except ValueError:
		raise HTTPException(status_code=422, detail=f"Invalid IPv4 address: {payload.address}")

	fields_set = payload.model_fields_set

	v6_str = payload.address6 or None
	if "address6" not in fields_set:
		v6_str = iface["address6"]
	if v6_str:
		try:
			ipaddress.ip_interface(v6_str)
		except ValueError:
			raise HTTPException(status_code=422, detail=f"Invalid IPv6 address: {v6_str}")

	new_dns = payload.dns if "dns" in fields_set else iface["dns"]
	new_post_up = payload.post_up if "post_up" in fields_set else iface["post_up"]
	new_post_down = payload.post_down if "post_down" in fields_set else iface["post_down"]

	cfg = get_config(request)
	config_path = WG_CONFIG_PATH

	# Keep rollback snapshot in case file write fails
	old = {
		"address": iface["address"],
		"address6": iface["address6"],
		"listen_port": iface["listen_port"],
		"dns": iface["dns"],
		"post_up": iface["post_up"],
		"post_down": iface["post_down"],
	}

	try:
		sqlite_db.update_interface(
			conn,
			name=name,
			address=payload.address,
			address6=v6_str,
			listen_port=payload.listen_port,
			dns=new_dns,
			post_up=new_post_up,
			post_down=new_post_down,
		)

		_write_interface_config(
			config_path=config_path,
			name=name,
			private_key=iface["private_key"],
			address=payload.address,
			address6=v6_str,
			listen_port=payload.listen_port,
			dns=new_dns,
			post_up=new_post_up,
			post_down=new_post_down,
			conn=conn,
			pepper=cfg.secret_key,
		)
	except Exception as exc:
		# Best-effort rollback to previous DB values when write failed
		try:
			sqlite_db.update_interface(
				conn,
				name=name,
				address=old["address"],
				address6=old["address6"],
				listen_port=old["listen_port"],
				dns=old["dns"],
				post_up=old["post_up"],
				post_down=old["post_down"],
			)
		except Exception:
			_log.exception("Failed to rollback interface update for %s", name)
		raise HTTPException(status_code=500, detail=f"Failed to update interface config: {exc}")

	# If interface is currently active, note restart requirement for full apply.
	code, _, _ = await _run_wg_command("wg", "show", name)
	restart_required = (code == 0)

	data = {
		"name": name,
		"address": payload.address,
		"address6": v6_str,
		"listen_port": payload.listen_port,
		"dns": new_dns,
		"restart_required": restart_required,
	}
	return ok_response(data=data, **data)


@router.delete("/interfaces/{name}", status_code=200)
async def delete_interface(
	request: Request,
	name: str,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Delete a WireGuard interface configuration."""
	_validate_interface_name(name)
	
	cfg = get_config(request)
	config_path = WG_CONFIG_PATH
	conf_file = config_path / f"{name}.conf"
	
	# Check DB first
	db_exists = sqlite_db.get_interface(conn, name) is not None
	file_exists = conf_file.exists()
	
	if not db_exists and not file_exists:
		raise HTTPException(status_code=404, detail=f"Interface '{name}' not found")
	
	# Bring down interface if active
	code, _, _ = await _run_wg_command("wg", "show", name)
	if code == 0:
		await _run_wg_command("wg-quick", "down", name)
	
	# Delete from database
	if db_exists:
		sqlite_db.delete_interface(conn, name)
	
	# Delete config file
	if file_exists:
		try:
			conf_file.unlink()
		except OSError as e:
			raise HTTPException(status_code=500, detail=f"Failed to delete config: {e}")
	
	_log.info("INTERFACE_DELETED name=%s", name)
	
	return ok_response(message=f"Interface '{name}' deleted")


# ---------------------------------------------------------------------------
# Peer Management
# ---------------------------------------------------------------------------

@router.get("/peers")
def list_peers(
	interface: Optional[str] = None,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""List all peers."""
	rows = sqlite_db.get_all_peers(conn, interface)
	data = [_row_to_public(row) for row in rows]
	return ok_response(data=data)


@router.post("/peers", status_code=201)
async def create_peer(
	request: Request,
	payload: PeerCreate,
	conn: sqlite3.Connection = Depends(get_conn),
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Create a new peer.
	
	WG-first approach: Add peer to WireGuard interface first, then store in DB.
	This ensures consistency - if WG fails, we don't have orphaned DB entries.
	"""
	cfg = get_config(request)
	
	# 1. Verify interface exists and is active
	code, _, stderr = await _run_wg_command("wg", "show", payload.interface)
	if code != 0:
		raise HTTPException(
			status_code=400,
			detail=f"Interface '{payload.interface}' is not active. Bring it up first.",
		)
	
	# 2. Generate keypair if not provided
	private_key = payload.private_key
	public_key = payload.public_key
	
	if not private_key or not public_key:
		private_key, public_key = await _generate_keypair()
	
	# 3. Generate preshared key if not provided
	preshared_key = payload.preshared_key
	if not preshared_key:
		preshared_key = await _generate_preshared_key()
	
	# 4. Check if peer already exists in DB
	existing = sqlite_db.get_peer_by_public_key(conn, public_key)
	if existing:
		raise HTTPException(status_code=409, detail="Peer with this public key already exists")

	# 5. Store peer in WireGuard + DB (with retry on concurrent IP allocation conflict)
	# Encrypt private_key and preshared_key before storage
	private_key_encrypted = vault_encrypt(private_key, cfg.secret_key)
	preshared_key_encrypted = vault_encrypt(preshared_key, cfg.secret_key)
	
	# allowed_ips = client-side routing (what client routes through VPN)
	# peer_address = peer's VPN IP (used in server config and QR code)
	peer_address: str | None = None
	for attempt in range(3):
		peer_address = sqlite_db.allocate_peer_ip(conn, payload.interface)
		if not peer_address:
			raise HTTPException(
				status_code=500,
				detail=f"No available IP addresses in interface '{payload.interface}' subnet",
			)

		code, _, stderr = await _run_wg_command_stdin(
			preshared_key,
			"wg", "set", payload.interface,
			"peer", public_key,
			"allowed-ips", peer_address,
			"preshared-key", "/dev/stdin",
		)
		if code != 0:
			raise HTTPException(
				status_code=500,
				detail=f"Failed to add peer to WireGuard: {stderr}",
			)

		try:
			sqlite_db.create_peer(
				conn,
				public_key=public_key,
				private_key=private_key_encrypted,
				preshared_key=preshared_key_encrypted,
				allowed_ips=payload.allowed_ips,
				allowed_ips_mode=payload.allowed_ips_mode,
				peer_address=peer_address,
				name=payload.name,
				description=payload.description,
				endpoint=payload.endpoint,
				interface=payload.interface,
				use_adblocker=payload.use_adblocker,
				blocklist_ids=payload.blocklist_ids,
				client_isolation=payload.client_isolation,
			)
			break
		except sqlite3.IntegrityError as e:
			# Rollback: remove peer from WireGuard
			_log.error("DB integrity error, rolling back WG peer: %s", e)
			await _run_wg_command("wg", "set", payload.interface, "peer", public_key, "remove")
			ip_conflict = "idx_peers_address_interface_unique" in str(e) or "peer_address" in str(e).lower()
			if ip_conflict and attempt < 2:
				continue
			if ip_conflict:
				raise HTTPException(status_code=409, detail="Peer IP address conflict. Please retry.")
			raise HTTPException(status_code=409, detail="Peer already exists or conflicts with existing data")
		except Exception as e:
			# Rollback: remove peer from WireGuard
			_log.error("DB insert failed, rolling back WG peer: %s", e)
			await _run_wg_command("wg", "set", payload.interface, "peer", public_key, "remove")
			raise HTTPException(status_code=500, detail="Failed to store peer in database")
	
	# 8. Sync config file so wg-quick down/up preserves new peer
	_sync_interface_config(WG_CONFIG_PATH, payload.interface, conn, pepper=cfg.secret_key)
	await _apply_client_isolation_runtime(payload.interface, conn)

	# 9. Seed TSDB series so peer directories exist immediately after creation.
	try:
		tsdb.append_point(tsdb_dir, peer_key=public_key, metric="rx_bytes", value=0)
		tsdb.append_point(tsdb_dir, peer_key=public_key, metric="tx_bytes", value=0)
	except Exception as exc:
		_log.warning("Failed to seed TSDB for peer %s...: %s", public_key[:8], exc)
	
	peer = sqlite_db.get_peer_by_public_key(conn, public_key)
	_log.info("PEER_CREATED public_key=%s... interface=%s peer_address=%s", public_key[:8], payload.interface, peer_address)
	
	# Regenerate Unbound peer tags for per-peer blocklist filtering
	_regenerate_peer_tags(conn)
	
	peer_data = _row_to_public(peer).model_dump(mode="json")
	return ok_response(data=peer_data, **peer_data)


@router.get("/peers/{peer_id}")
def get_peer(
	peer_id: int,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get a peer by ID."""
	peer = sqlite_db.get_peer_by_id(conn, peer_id)
	if not peer:
		raise HTTPException(status_code=404, detail="Peer not found")
	return ok_response(data=_row_to_public(peer))


@router.patch("/peers/{peer_id}")
async def update_peer(
	request: Request,
	peer_id: int,
	payload: PeerUpdate,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Update a peer."""
	cfg = get_config(request)
	peer = sqlite_db.get_peer_by_id(conn, peer_id)
	if not peer:
		raise HTTPException(status_code=404, detail="Peer not found")
	
	public_key = peer["public_key"]
	interface_name = peer["interface"]
	fields_set = payload.model_fields_set

	def _val_or_unset(field: str):
		return getattr(payload, field) if field in fields_set else sqlite_db.UNSET

	sqlite_db.update_peer(
		conn,
		peer_id,
		name=_val_or_unset("name"),
		description=_val_or_unset("description"),
		allowed_ips=_val_or_unset("allowed_ips"),
		allowed_ips_mode=_val_or_unset("allowed_ips_mode"),
		endpoint=_val_or_unset("endpoint"),
		is_enabled=_val_or_unset("is_enabled"),
		use_adblocker=_val_or_unset("use_adblocker"),
		blocklist_ids=_val_or_unset("blocklist_ids"),
		client_isolation=_val_or_unset("client_isolation"),
	)
	
	# Keep server-side cryptokey routing strict: always peer_address on server.
	# payload.allowed_ips is client-side policy and must not be pushed to server.
	if "allowed_ips" in fields_set and payload.allowed_ips is not None:
		peer_address = peer["peer_address"]
		if not peer_address:
			_log.warning("Peer %s has no peer_address; skipped runtime allowed-ips repair", public_key[:8])
		else:
			code, _, stderr = await _run_wg_command(
				"wg", "set", interface_name,
				"peer", public_key,
				"allowed-ips", peer_address,
			)
			if code != 0:
				_log.warning("Failed to update peer allowed-ips in WireGuard: %s", stderr)
	
	# Sync config file if peer routing/enabled state changed.
	if any(k in fields_set for k in ("allowed_ips", "allowed_ips_mode", "is_enabled", "client_isolation")):
		_sync_interface_config(WG_CONFIG_PATH, interface_name, conn, pepper=cfg.secret_key)
		await _apply_client_isolation_runtime(interface_name, conn)
	
	# Regenerate Unbound peer tags if blocklist settings changed
	if "blocklist_ids" in fields_set or "use_adblocker" in fields_set:
		_regenerate_peer_tags(conn)
	
	updated = sqlite_db.get_peer_by_id(conn, peer_id)
	_log.info("PEER_UPDATED id=%d public_key=%s...", peer_id, public_key[:8])
	updated_data = _row_to_public(updated).model_dump(mode="json")
	return ok_response(data=updated_data, **updated_data)


@router.delete("/peers/{peer_id}", status_code=204)
async def delete_peer(
	request: Request,
	peer_id: int,
	conn: sqlite3.Connection = Depends(get_conn),
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Delete a peer."""
	cfg = get_config(request)
	peer = sqlite_db.get_peer_by_id(conn, peer_id)
	if not peer:
		raise HTTPException(status_code=404, detail="Peer not found")
	
	public_key = peer["public_key"]
	interface_name = peer["interface"]
	
	# Remove from WireGuard
	try:
		await _run_wg_command(
			"wg", "set", interface_name,
			"peer", public_key,
			"remove",
		)
	except Exception as e:
		_log.warning("Failed to remove peer from WireGuard: %s", e)
	
	# Delete from database
	sqlite_db.delete_peer(conn, peer_id)
	
	# Sync config file
	_sync_interface_config(WG_CONFIG_PATH, interface_name, conn, pepper=cfg.secret_key)
	await _apply_client_isolation_runtime(interface_name, conn)
	
	# Delete TSDB data
	tsdb.delete_peer_data(tsdb_dir, public_key)
	
	# Regenerate Unbound peer tags
	_regenerate_peer_tags(conn)
	
	_log.info("PEER_DELETED id=%d public_key=%s...", peer_id, public_key[:8])


@router.get("/peers/{peer_id}/stats")
async def get_peer_stats(
	peer_id: int,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get live statistics for a peer from WireGuard."""
	peer = sqlite_db.get_peer_by_id(conn, peer_id)
	if not peer:
		raise HTTPException(status_code=404, detail="Peer not found")
	
	public_key = peer["public_key"]
	interface_name = peer["interface"]
	
	# Get stats from wg show dump
	code, stdout, stderr = await _run_wg_command("wg", "show", interface_name, "dump")
	if code != 0:
		raise HTTPException(status_code=500, detail=f"Failed to get stats: {stderr}")
	
	# Parse dump output (tab-separated)
	# Format: interface private-key public-key listen-port fwmark
	# Then for each peer: public-key preshared-key endpoint allowed-ips latest-handshake transfer-rx transfer-tx persistent-keepalive
	stats = PeerStats(public_key=public_key)

	# Endpoint can vary by wg output format; resolve it from the dedicated endpoint view first.
	code_ep, stdout_ep, _ = await _run_wg_command("wg", "show", interface_name, "endpoints")
	if code_ep == 0:
		for line in stdout_ep.strip().split("\n"):
			if not line:
				continue
			parts = line.split("\t")
			if len(parts) >= 2 and parts[0] == public_key:
				stats.endpoint = parts[1] if parts[1] != "(none)" else None
				break
	
	lines = stdout.strip().split("\n")
	for line in lines[1:]:  # Skip interface line
		parts = line.split("\t")
		if len(parts) >= 7 and parts[0] == public_key:
			# Fallback endpoint from dump for environments where "wg show ... endpoints" is unavailable.
			if stats.endpoint is None:
				stats.endpoint = parts[2] if parts[2] != "(none)" else None
			stats.allowed_ips = parts[3] if parts[3] != "(none)" else None
			
			# Latest handshake (Unix timestamp)
			if parts[4] != "0":
				stats.latest_handshake = datetime.fromtimestamp(int(parts[4]), timezone.utc)
			
			stats.transfer_rx = int(parts[5])
			stats.transfer_tx = int(parts[6])
			break
	
	return ok_response(data=stats)


@router.get("/peers/{peer_id}/qrcode")
async def get_peer_qrcode(
	request: Request,
	peer_id: int,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Generate a QR code for peer configuration (admin only)."""
	peer = sqlite_db.get_peer_by_id(conn, peer_id)
	if not peer:
		raise HTTPException(status_code=404, detail="Peer not found")
	
	# Verify we have the stored private key
	private_key = peer["private_key"]
	if not private_key:
		raise HTTPException(
			status_code=400,
			detail="No private key stored for this peer. Peer was created without key storage.",
		)
	
	# Verify we have a peer address
	peer_address = peer["peer_address"]
	if not peer_address:
		raise HTTPException(
			status_code=400,
			detail="No address assigned to this peer. Peer may have been created before IP allocation was implemented.",
		)
	
	cfg = get_config(request)
	
	# Decrypt stored keys
	private_key_plain = vault_decrypt(private_key, cfg.secret_key)
	preshared_key_plain = vault_decrypt(peer["preshared_key"] or "", cfg.secret_key) if peer["preshared_key"] else None
	
	# Get server public key from WireGuard
	code, stdout, stderr = await _run_wg_command("wg", "show", peer["interface"], "public-key")
	if code != 0 or not stdout.strip():
		_log.warning("QR_CODE wg show public-key failed: %s", stderr.strip() if stderr else "no output")
		raise HTTPException(
			status_code=503,
			detail=f"WireGuard interface '{peer['interface']}' is not running. Bring it up first.",
		)
	server_public_key = stdout.strip()
	
	# Determine DNS based on adblocker setting
	use_adblocker = True if peer["use_adblocker"] is None else bool(peer["use_adblocker"])
	dns_servers = await _get_dns_for_peer(
		conn,
		peer["interface"],
		use_adblocker,
		WG_DEFAULT_DNS,
	)
	client_allowed_ips = _allowed_ips_with_dns_routes(
		peer["allowed_ips"],
		dns_servers,
		use_adblocker,
	)
	
	# Build config using stored private key and peer address
	# allowed_ips from DB is the client-side routing (what traffic goes through VPN)
	config = PeerConfig(
		interface_name=peer["interface"],
		private_key=private_key_plain,
		address=peer_address,
		dns=dns_servers,
		server_public_key=server_public_key,
		server_endpoint=_get_server_endpoint(conn),
		allowed_ips=client_allowed_ips,
		preshared_key=preshared_key_plain,
	)
	
	config_text = config.to_wg_config()
	
	# Generate QR code
	try:
		import qrcode
		qr = qrcode.QRCode(version=1, box_size=10, border=4)
		qr.add_data(config_text)
		qr.make(fit=True)
		
		img = qr.make_image(fill_color="black", back_color="white")
		
		buffer = io.BytesIO()
		img.save(buffer, format="PNG")
		buffer.seek(0)
		
		# Sanitize filename to prevent header injection
		safe_name = re.sub(r'[^\w.-]', '_', peer['name'] or 'peer')
		
		return Response(
			content=buffer.getvalue(),
			media_type="image/png",
			headers={"Content-Disposition": f'inline; filename="{safe_name}.png"'},
		)
	except ImportError:
		raise HTTPException(status_code=500, detail="QR code generation not available (qrcode package missing)")
	except Exception as exc:
		_log.exception("QR_CODE generation error")
		raise HTTPException(status_code=500, detail=f"QR code generation failed: {exc}")


@router.get("/peers/{peer_id}/config")
async def get_peer_config(
	request: Request,
	peer_id: int,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Get the WireGuard configuration file for a peer (admin only)."""
	peer = sqlite_db.get_peer_by_id(conn, peer_id)
	if not peer:
		raise HTTPException(status_code=404, detail="Peer not found")
	
	# Verify we have the stored private key
	private_key = peer["private_key"]
	if not private_key:
		raise HTTPException(
			status_code=400,
			detail="No private key stored for this peer. Peer was created without key storage.",
		)
	
	# Verify peer address
	peer_address = peer["peer_address"]
	if not peer_address:
		raise HTTPException(
			status_code=400,
			detail="No address assigned to this peer.",
		)
	
	cfg = get_config(request)
	
	# Decrypt stored keys
	private_key_plain = vault_decrypt(private_key, cfg.secret_key)
	preshared_key_plain = vault_decrypt(peer["preshared_key"] or "", cfg.secret_key) if peer["preshared_key"] else None
	
	# Get server public key
	code, stdout, stderr = await _run_wg_command("wg", "show", peer["interface"], "public-key")
	if code != 0:
		raise HTTPException(
			status_code=503,
			detail=f"WireGuard interface '{peer['interface']}' is not running. Bring it up first.",
		)
	server_public_key = stdout.strip()
	
	# Determine DNS based on adblocker setting
	use_adblocker = True if peer["use_adblocker"] is None else bool(peer["use_adblocker"])
	dns_servers = await _get_dns_for_peer(
		conn,
		peer["interface"],
		use_adblocker,
		WG_DEFAULT_DNS,
	)
	client_allowed_ips = _allowed_ips_with_dns_routes(
		peer["allowed_ips"],
		dns_servers,
		use_adblocker,
	)
	
	config = PeerConfig(
		interface_name=peer["interface"],
		private_key=private_key_plain,
		address=peer_address,
		dns=dns_servers,
		server_public_key=server_public_key,
		server_endpoint=_get_server_endpoint(conn),
		allowed_ips=client_allowed_ips,
		preshared_key=preshared_key_plain,
	)
	
	# Sanitize filename to prevent header injection
	safe_name = re.sub(r'[^\w.-]', '_', peer['name'] or 'wg0')
	
	return Response(
		content=config.to_wg_config(),
		media_type="text/plain",
		headers={"Content-Disposition": f'attachment; filename="{safe_name}.conf"'},
	)


# ---------------------------------------------------------------------------
# Dashboard Statistics
# ---------------------------------------------------------------------------

@router.get("/stats/traffic")
async def get_traffic_stats(
	hours: int = 24,
	range_key: str | None = None,
	conn: sqlite3.Connection = Depends(get_conn),
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get per-peer RX/TX traffic over time.

	Returns bucketed data suitable for charting, with each peer as a separate dataset.
	"""
	from ..utils.time import utcnow

	if range_key:
		mapped = TRAFFIC_RANGE_TO_HOURS.get(range_key.lower())
		if mapped is not None:
			hours = mapped
	hours = min(max(hours, 1), 168)  # 1h .. 7d
	since = utcnow() - timedelta(hours=hours)
	query_since = since - timedelta(hours=1)
	resolved_range = next((k for k, v in TRAFFIC_RANGE_TO_HOURS.items() if v == hours), f"{hours}h")

	# Determine bucket size (aim for ~60 data points)
	bucket_seconds = max((hours * 3600) // 60, 60)

	all_peers = sqlite_db.get_all_peers(conn)
	peer_keys = [peer["public_key"] for peer in all_peers if peer["public_key"]]
	peer_name_map: dict[str, str] = {
		peer["public_key"]: (peer["name"] or peer["public_key"][:8])
		for peer in all_peers
		if peer["public_key"]
	}

	def _bucket_counter_delta(points: list[tsdb.MetricPoint]) -> dict[str, float]:
		"""Aggregate counter deltas into time buckets (consumption per bucket)."""
		from datetime import datetime as dt, timezone as tz
		buckets: dict[str, float] = {}
		prev: float | None = None
		for pt in points:
			if not isinstance(pt.value, (int, float)):
				continue
			value = float(pt.value)
			if prev is None:
				prev = value
				continue

			delta = value - prev
			prev = value
			# Counter reset/restart: ignore negative deltas.
			if delta < 0:
				continue
			if pt.ts < since:
				continue

			ts_epoch = pt.ts.timestamp()
			bucket_ts = int(ts_epoch // bucket_seconds) * bucket_seconds
			label = dt.fromtimestamp(bucket_ts, tz.utc).isoformat()
			buckets[label] = buckets.get(label, 0) + delta
		return dict(sorted(buckets.items()))

	# Collect per-peer traffic data
	peer_data: list[dict] = []
	all_labels: set[str] = set()

	for key in peer_keys:
		rx_points = tsdb.query(tsdb_dir, peer_key=key, metric="rx_bytes", since=query_since, limit=10000)
		tx_points = tsdb.query(tsdb_dir, peer_key=key, metric="tx_bytes", since=query_since, limit=10000)

		rx_buckets = _bucket_counter_delta(rx_points)
		tx_buckets = _bucket_counter_delta(tx_points)

		# Only include peers with actual data
		if rx_buckets or tx_buckets:
			peer_name = peer_name_map.get(key, key[:8])
			peer_data.append({
				"key": key[:8],
				"name": peer_name,
				"rx": rx_buckets,
				"tx": tx_buckets,
			})
			all_labels.update(rx_buckets.keys())
			all_labels.update(tx_buckets.keys())

	labels = sorted(all_labels)

	# Build datasets for each peer
	peers: list[dict] = []
	for entry in peer_data:
		peers.append({
			"key": entry["key"],
			"name": entry["name"],
			"rx": [entry["rx"].get(label, 0) for label in labels],
			"tx": [entry["tx"].get(label, 0) for label in labels],
		})

	# Add server-side unit metadata + normalized series for consistent UI rendering.
	max_bytes = 0.0
	for peer in peers:
		max_bytes = max(max_bytes, max(peer["rx"], default=0), max(peer["tx"], default=0))
	display_unit = _select_display_unit(max_bytes)
	peers_display = [
		{
			"key": peer["key"],
			"name": peer["name"],
			"rx": [round(_bytes_to_unit(float(v), display_unit), 4) for v in peer["rx"]],
			"tx": [round(_bytes_to_unit(float(v), display_unit), 4) for v in peer["tx"]],
		}
		for peer in peers
	]

	data = {
		"range": resolved_range,
		"hours": hours,
		"labels": labels,
		"peers": peers,
		"peers_display": peers_display,
		"value_unit": "bytes_per_bucket",
		"display_unit": display_unit,
		"bucket_seconds": bucket_seconds,
	}

	return ok_response(
		data=data,
		**data,
	)


@router.get("/stats/connections")
async def get_connection_stats(
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get the current number of connected peers per interface (latest handshake < 3 min)."""
	import time as _time

	try:
		code, stdout, stderr = await _run_wg_command("wg", "show", "all", "dump")
		if code != 0:
			data = {"interfaces": {}, "total_connected": 0, "total_peers": 0}
			return ok_response(data=data, **data)

		now = _time.time()
		threshold = 180  # 3 minutes

		interfaces: dict[str, dict] = {}
		last_iface: str | None = None
		
		for line in stdout.strip().split("\n"):
			if not line:
				continue
			parts = line.split("\t")
			
			# Peer line has 9 fields: iface, pubkey, psk, endpoint, allowed-ips, handshake, rx, tx, keepalive
			if len(parts) >= 9:
				iface = parts[0] if parts[0] else last_iface
				if not iface:
					continue  # Skip if we still don't know the interface
				
				last_handshake = _safe_int(parts[5])
				connected = (now - last_handshake) < threshold if last_handshake else False
				rx = _safe_int(parts[6])
				tx = _safe_int(parts[7])

				if iface:
					last_iface = iface

				if iface not in interfaces:
					interfaces[iface] = {"connected": 0, "total": 0, "rx": 0, "tx": 0}
				interfaces[iface]["total"] += 1
				interfaces[iface]["rx"] += rx
				interfaces[iface]["tx"] += tx
				if connected:
					interfaces[iface]["connected"] += 1
			elif len(parts) >= 5:
				# Interface header line: iface, privkey, pubkey, listen_port, fwmark
				last_iface = parts[0]

		total_connected = sum(v["connected"] for v in interfaces.values())
		total_peers = sum(v["total"] for v in interfaces.values())

		data = {
			"interfaces": interfaces,
			"total_connected": total_connected,
			"total_peers": total_peers,
		}
		return ok_response(data=data, **data)
	except Exception:
		# Return empty data on any parsing error
		data = {"interfaces": {}, "total_connected": 0, "total_peers": 0}
		return ok_response(data=data, **data)


@router.get("/stats/peer-locations")
async def get_peer_locations(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Return geolocated positions of all WireGuard peers with known endpoints.

	Parses ``wg show all dump`` for peer endpoints, resolves each public IP
	via GeoLite2-City + GeoLite2-ASN and returns a list suitable for a
	Leaflet heatmap.  Includes both currently-connected and recently-seen
	peers (any peer with a non-``(none)`` endpoint and a handshake timestamp).
	"""
	import time as _time

	try:
		code, stdout, stderr = await _run_wg_command("wg", "show", "all", "dump")
		if code != 0:
			return ok_response(data={"locations": []}, locations=[])

		now = _time.time()
		connected_threshold = 180  # 3 minutes – still "online"

		# Build peer name lookup from DB
		all_db_peers = sqlite_db.get_all_peers(conn)
		name_by_key: dict[str, str] = {
			p["public_key"]: (p["name"] or p["public_key"][:8])
			for p in all_db_peers if p["public_key"]
		}

		seen_ips: dict[str, dict] = {}  # deduplicate by IP
		last_iface: str | None = None

		for line in stdout.strip().split("\n"):
			if not line:
				continue
			parts = line.split("\t")

			pub_key: str | None = None
			endpoint_raw: str | None = None
			handshake_ts = 0
			iface: str | None = None

			# Interface header: iface, privkey, pubkey, listen_port, fwmark
			if len(parts) >= 5 and len(parts) < 8:
				last_iface = parts[0]
				continue

			# Peer line format A (9-col): iface, pubkey, psk, endpoint, allowed-ips, hs, rx, tx, keepalive
			if len(parts) >= 9:
				iface = parts[0] if parts[0] else last_iface
				if iface:
					last_iface = iface
				pub_key = parts[1]
				endpoint_raw = parts[3]
				handshake_ts = _safe_int(parts[5])
			# Peer line format B (8-col): pubkey, psk, endpoint, allowed-ips, hs, rx, tx, keepalive
			elif len(parts) >= 8:
				pub_key = parts[0]
				endpoint_raw = parts[2]
				handshake_ts = _safe_int(parts[4])
				iface = last_iface

			if not pub_key or not endpoint_raw or endpoint_raw == "(none)":
				continue
			# Include any peer that has ever had a handshake (endpoint known)
			if handshake_ts == 0:
				continue

			# Strip port from endpoint (handle IPv6 [addr]:port)
			if endpoint_raw.startswith("["):
				ip_str = endpoint_raw.split("]")[0].lstrip("[")
			else:
				ip_str = endpoint_raw.rsplit(":", 1)[0]

			connected = (now - handshake_ts) < connected_threshold

			if ip_str in seen_ips:
				seen_ips[ip_str]["count"] += 1
				# Upgrade to connected if any peer from this IP is connected
				if connected:
					seen_ips[ip_str]["connected"] = True
				continue

			info = lookup_ip(ip_str)
			if info:
				peer_name = name_by_key.get(pub_key, pub_key[:8] if pub_key else "")
				seen_ips[ip_str] = {
					"lat": info["lat"],
					"lon": info["lon"],
					"city": info["city"],
					"country": info["country"],
					"asn": info["asn"],
					"as_org": info["as_org"],
					"ip": ip_str,
					"name": peer_name,
					"interface": iface,
					"connected": connected,
					"count": 1,
				}

		locations = list(seen_ips.values())
		return ok_response(data={"locations": locations}, locations=locations)
	except Exception:
		_log.exception("Failed to get peer locations")
		return ok_response(data={"locations": []}, locations=[])


@router.get("/stats/peers-enriched")
async def get_peers_enriched(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Return all peers with live WireGuard stats and GeoIP / ASN data.

	Merges DB peer records with ``wg show all dump`` output and enriches
	each peer's endpoint IP via GeoLite2-City + GeoLite2-ASN.

	Client IP and last-handshake timestamp are **persisted** to the DB so
	they survive container restarts and are always available, even when
	``wg show`` has no live data for a peer.
	"""
	import time as _time

	# 1. Load all peers from DB
	rows = sqlite_db.get_all_peers(conn)
	peers_by_key: dict[str, dict] = {}
	for row in rows:
		peers_by_key[row["public_key"]] = {
			"id": row["id"],
			"name": row["name"],
			"public_key": row["public_key"],
			"allowed_ips": row["allowed_ips"],
			"peer_address": row["peer_address"],
			"interface": row["interface"],
			"is_enabled": bool(row["is_enabled"]),
			# Live stats (filled below, fall back to DB)
			"endpoint_ip": row["last_client_ip"],
			"endpoint": None,
			"latest_handshake": row["last_handshake_at"],
			"_db_handshake_at": row["last_handshake_at"] or 0,  # For comparison in update check
			"connected": False,
			"transfer_rx": 0,
			"transfer_tx": 0,
			# Geo / ASN (filled below)
			"country": None,
			"city": None,
			"asn": None,
			"as_org": None,
		}

	# 2. Parse wg show all dump for live stats
	now = _time.time()
	threshold = 180  # 3 min – consider "connected"
	db_updates: list[tuple[str, int, str]] = []  # (client_ip, handshake_at, pub_key)

	try:
		code, stdout, stderr = await _run_wg_command("wg", "show", "all", "dump")
		if code != 0:
			_log.debug("wg show all dump failed (code=%d): %s", code, stderr.strip() if stderr else "no output")
		elif code == 0:
			last_iface: str | None = None
			for line in stdout.strip().split("\n"):
				if not line:
					continue
				parts = line.split("\t")
				pub_key: str | None = None
				endpoint_raw: str | None = None
				handshake_ts = 0
				rx = 0
				tx = 0

				# Interface header: iface, privkey, pubkey, listen_port, fwmark
				if len(parts) >= 5 and len(parts) < 8:
					last_iface = parts[0]
					continue

				# Peer line (format A): iface, pubkey, psk, endpoint, …
				if len(parts) >= 9:
					iface = parts[0] if parts[0] else last_iface
					if iface:
						last_iface = iface
					pub_key = parts[1]
					endpoint_raw = parts[3]
					handshake_ts = _safe_int(parts[5])
					rx = _safe_int(parts[6])
					tx = _safe_int(parts[7])
				# Peer line (format B): pubkey, psk, endpoint, …
				elif len(parts) >= 8:
					pub_key = parts[0]
					endpoint_raw = parts[2]
					handshake_ts = _safe_int(parts[4])
					rx = _safe_int(parts[5])
					tx = _safe_int(parts[6])

				if not pub_key or pub_key not in peers_by_key:
					continue

				peer = peers_by_key[pub_key]
				peer["endpoint"] = endpoint_raw if endpoint_raw and endpoint_raw != "(none)" else None
				peer["transfer_rx"] = rx
				peer["transfer_tx"] = tx

				# Extract client IP from endpoint (ip:port or [ipv6]:port)
				client_ip: str | None = None
				if endpoint_raw and endpoint_raw != "(none)":
					if endpoint_raw.startswith("["):
						client_ip = endpoint_raw.split("]")[0].lstrip("[")
					else:
						client_ip = endpoint_raw.rsplit(":", 1)[0]

				# Keep last-seen/client-ip sticky and update only on newer handshakes.
				stored_hs = int(peer.get("_db_handshake_at") or 0)
				stored_ip = str(peer.get("endpoint_ip") or "").strip()
				if handshake_ts:
					# Never regress to an older timestamp from a transient wg state.
					current_hs = int(peer.get("latest_handshake") or 0)
					effective_hs = handshake_ts if handshake_ts >= current_hs else current_hs
					peer["latest_handshake"] = effective_hs
					peer["connected"] = (now - effective_hs) < threshold
					if client_ip:
						peer["endpoint_ip"] = client_ip

					# Persist only when handshake is newer; keep last known IP if endpoint is missing.
					if handshake_ts > stored_hs:
						persist_ip = client_ip or stored_ip
						if persist_ip:
							db_updates.append((persist_ip, handshake_ts, pub_key))
							peer["_db_handshake_at"] = handshake_ts
							if not peer.get("endpoint_ip"):
								peer["endpoint_ip"] = persist_ip
							_log.debug("PEER_SEEN %s ip=%s handshake=%d (stored=%d)", pub_key[:8], persist_ip, handshake_ts, stored_hs)
				elif client_ip:
					# Endpoint present but no handshake – still use live IP
					peer["endpoint_ip"] = client_ip
	except Exception:
		_log.warning("Failed to parse wg dump for enriched peers", exc_info=True)

	# Batch-persist updated last-seen data to DB
	if db_updates:
		try:
			sqlite_db.update_peers_last_seen_batch(conn, db_updates)
			_log.info("PEERS_LAST_SEEN persisted %d peer(s)", len(db_updates))
		except Exception:
			_log.warning("Failed to persist last-seen data", exc_info=True)

	# 3. GeoIP + ASN enrichment for peers with known client IPs
	for peer in peers_by_key.values():
		ip_str = peer.get("endpoint_ip")
		if not ip_str:
			continue
		info = lookup_ip(ip_str)
		if info:
			peer["country"] = info["country"]
			peer["city"] = info["city"]
			peer["asn"] = info["asn"]
			peer["as_org"] = info["as_org"]

	# 4. Clean up internal fields before returning
	for peer in peers_by_key.values():
		peer.pop("_db_handshake_at", None)

	# 5. Sort: connected first, then by latest handshake (most recent first)
	result = sorted(
		peers_by_key.values(),
		key=lambda p: (not p["connected"], -(p["latest_handshake"] or 0)),
	)

	return ok_response(data={"peers": result}, peers=result)


# ---------------------------------------------------------------------------
# TSDB Stats & Management
# ---------------------------------------------------------------------------

@router.get("/stats/tsdb")
async def get_tsdb_stats(
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get TSDB storage statistics."""
	data = tsdb.get_db_stats(tsdb_dir)
	return ok_response(data=data, **data)


@router.delete("/stats/tsdb")
async def reset_tsdb(
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Reset/delete all TSDB data (admin only)."""
	deleted = tsdb.reset_all(tsdb_dir)
	return ok_response(
		message=f"TSDB reset: {deleted} peer directories deleted",
		deleted=deleted,
		data={"deleted": deleted},
	)


@router.post("/stats/tsdb/maintenance")
async def run_tsdb_maintenance(
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Run TSDB retention/rotation/compression maintenance immediately."""
	stats = tsdb.run_maintenance(tsdb_dir)
	return ok_response(
		message="TSDB maintenance completed",
		data=stats,
		series=stats.get("series", 0),
		rotated=stats.get("rotated", 0),
		pruned=stats.get("pruned", 0),
	)
