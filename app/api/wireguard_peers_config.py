#!/usr/bin/env python3
#
# app/api/wireguard_peers_config.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard peer configuration and QR code API routes."""

from __future__ import annotations

from ..db.sqlite_peers import (
	get_peer_by_id,
)

import asyncio
import logging
import re
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import SecretStr

from ..models.peers import PeerConfig, PeerStats
from ..utils.config import WG_DEFAULT_DNS
from ..utils.deps import get_conn, get_config
from ..utils.network import allowed_ips_with_dns_routes
from ..utils.vault import decrypt as vault_decrypt
from .auth import require_admin
from .response import ok_response
from .wireguard_utils import run_wg_command
from .wireguard_settings import get_server_endpoint, get_dns_for_peer, InterfaceConfigError

_log = logging.getLogger(__name__)

router = APIRouter(tags=["wireguard"])

__all__ = ["router"]

# WireGuard dump format column indices
DUMP_PEER_PUBKEY = 0
DUMP_PEER_PSK = 1
DUMP_PEER_ENDPOINT = 2
DUMP_PEER_ALLOWED = 3
DUMP_PEER_HANDSHAKE = 4
DUMP_PEER_RX = 5
DUMP_PEER_TX = 6
DUMP_PEER_KEEPALIVE = 7   # defined for documentation; not currently read
DUMP_PEER_MIN_FIELDS = 7  # columns 0..6 are required; keepalive (7) is optional

# Security limits
_MAX_FILENAME_LENGTH = 64


def _validate_port(port: int) -> None:
	"""Validate port is in valid range."""
	if not (1 <= port <= 65535):
		raise ValueError(f"Port out of valid range: {port}")


def _validate_hostname(hostname: str) -> None:
	"""Validate hostname/FQDN format.
	
	Rejects:
	- Empty strings
	- Whitespace
	- Control characters
	- Invalid length
	"""
	if not hostname or not hostname.strip():
		raise ValueError("Hostname cannot be empty")
	if hostname != hostname.strip():
		raise ValueError("Hostname contains leading/trailing whitespace")
	if any(ord(ch) < 32 or ord(ch) == 127 for ch in hostname):
		raise ValueError("Hostname contains control characters")
	if len(hostname) > 253:
		raise ValueError("Hostname exceeds maximum length (253)")
	# Basic format check: should be alphanumeric with dots, hyphens
	if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$', hostname):
		raise ValueError(f"Invalid hostname format: {hostname}")


async def _build_peer_config(
	request: Request,
	peer_id: int,
	conn: sqlite3.Connection,
) -> tuple[PeerConfig, sqlite3.Row, SecretStr, Optional[SecretStr]]:
	"""Fetch peer, decrypt keys, resolve DNS, build PeerConfig.
	
	Returns:
		tuple of (config, peer row, private_key SecretStr, preshared_key SecretStr or None)
	"""
	peer = get_peer_by_id(conn, peer_id)
	if not peer:
		raise HTTPException(status_code=404, detail="Peer not found")
	
	# Verify we have the stored private key
	private_key = peer["private_key"]
	if not private_key:
		raise HTTPException(
			status_code=400,
			detail="No private key stored for this peer.",
		)
	
	# Verify peer address
	peer_address = peer["peer_address"]
	if not peer_address:
		raise HTTPException(
			status_code=400,
			detail="No address assigned to this peer.",
		)
	
	cfg = get_config(request)
	
	# Decrypt stored keys - wrap in SecretStr for memory safety
	try:
		private_key_plain = SecretStr(vault_decrypt(private_key, cfg.secret_key))
	except ValueError as e:
		_log.error("KEY_MISMATCH: Cannot decrypt peer private key for peer_id=%d: %s", peer_id, e)
		raise HTTPException(
			status_code=503,
			detail="Cannot decrypt peer configuration. WIREBUDDY_SECRET_KEY does not match the database encryption key.",
		)
	preshared_key_plain = None
	if peer["preshared_key"]:
		try:
			preshared_key_plain = SecretStr(vault_decrypt(peer["preshared_key"], cfg.secret_key))
		except ValueError as e:
			_log.error("KEY_MISMATCH: Cannot decrypt peer PSK for peer_id=%d: %s", peer_id, e)
			raise HTTPException(
				status_code=503,
				detail="Cannot decrypt peer configuration. WIREBUDDY_SECRET_KEY does not match the database encryption key.",
			)
	
	# Get server public key and endpoint — differs for node-assigned peers
	node_id = peer["node_id"]
	if node_id:
		# Peer runs on a remote node: use node's keypair and endpoint
		from ..db.sqlite_nodes import get_node as db_get_node, get_node_interface_public_key
		node = db_get_node(conn, node_id)
		if not node:
			raise HTTPException(status_code=404, detail="Assigned node not found")
		
		# Validate node endpoint components for security
		try:
			_validate_hostname(node['fqdn'])
			_validate_port(int(node['wg_port']))
		except ValueError as e:
			_log.error("Invalid node endpoint for node_id=%s: %s", node_id, e)
			raise HTTPException(
				status_code=503,
				detail="Node configuration error: invalid endpoint"
			)
		
		node_pubkey = get_node_interface_public_key(conn, node_id, peer["interface"])
		if not node_pubkey:
			raise HTTPException(
				status_code=503,
				detail=f"Node '{node['name']}' has no keypair for interface '{peer['interface']}'",
			)
		server_public_key = node_pubkey
		server_endpoint = f"{node['fqdn']}:{node['wg_port']}"
	else:
		# Local peer: get public key from running WireGuard interface
		code, stdout, stderr = await run_wg_command("wg", "show", peer["interface"], "public-key")
		if code != 0 or not stdout.strip():
			_log.warning(
				"public-key retrieval failed for interface=%s: %s",
				peer["interface"],
				stderr.strip() if stderr else "no output",
			)
			raise HTTPException(
				status_code=503,
				detail=f"WireGuard interface '{peer['interface']}' is not running. Bring it up first.",
			)
		server_public_key = stdout.strip()
		server_endpoint = get_server_endpoint(conn, peer["interface"])
	
	# Determine DNS based on adblocker setting.
	# NULL (never explicitly set by user) defaults to True — ad-blocking is
	# opt-out, matching the server-wide default when the feature is enabled.
	use_adblocker = True if peer["use_adblocker"] is None else bool(peer["use_adblocker"])
	try:
		dns_servers = get_dns_for_peer(
			conn,
			peer["interface"],
			use_adblocker,
			WG_DEFAULT_DNS,
			peer_address=peer_address,
		)
	except InterfaceConfigError:
		# Don't leak internal config details to client
		raise HTTPException(status_code=422, detail="Invalid interface configuration")
	
		client_allowed_ips = allowed_ips_with_dns_routes(
		peer["allowed_ips"],
		dns_servers,
		use_adblocker,
	)

	config = PeerConfig(
		interface_name=peer["interface"],
		private_key=private_key_plain.get_secret_value(),
		address=peer_address,
		dns=dns_servers,
		server_public_key=server_public_key,
		server_endpoint=server_endpoint,
		allowed_ips=client_allowed_ips,
		preshared_key=preshared_key_plain.get_secret_value() if preshared_key_plain else None,
	)
	
	return config, peer, private_key_plain, preshared_key_plain


@router.get("/peers/{peer_id}/stats")
async def get_peer_stats(
	peer_id: int,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Get live statistics for a peer from WireGuard (admin only)."""
	# Use threadpool for blocking DB call
	peer = await asyncio.to_thread(get_peer_by_id, conn, peer_id)
	if not peer:
		raise HTTPException(status_code=404, detail="Peer not found")
	
	public_key = peer["public_key"]
	interface_name = peer["interface"]
	
	# Get stats from wg show dump
	code, stdout, stderr = await run_wg_command("wg", "show", interface_name, "dump")
	if code != 0:
		_log.error("wg show dump failed for %s: %s", interface_name, stderr)
		raise HTTPException(status_code=500, detail="Failed to retrieve peer stats.")
	
	# Parse dump output (tab-separated)
	# Format: interface private-key public-key listen-port fwmark
	# Then for each peer: public-key preshared-key endpoint allowed-ips latest-handshake transfer-rx transfer-tx persistent-keepalive
	stats = PeerStats(public_key=public_key)
	
	lines = stdout.strip().split("\n")
	for line in lines[1:]:  # Skip interface line
		parts = line.split("\t")
		if len(parts) < DUMP_PEER_MIN_FIELDS:
			continue
		if parts[DUMP_PEER_PUBKEY] != public_key:
			continue
		
		# Parse endpoint
		stats.endpoint = parts[DUMP_PEER_ENDPOINT] if parts[DUMP_PEER_ENDPOINT] != "(none)" else None
		stats.allowed_ips = parts[DUMP_PEER_ALLOWED] if parts[DUMP_PEER_ALLOWED] != "(none)" else None
		
		# Latest handshake (Unix timestamp) - validate before parsing
		try:
			handshake_ts = int(parts[DUMP_PEER_HANDSHAKE])
			if handshake_ts > 0:
				stats.latest_handshake = datetime.fromtimestamp(handshake_ts, timezone.utc)
		except (ValueError, OSError) as e:
			_log.warning("Invalid handshake timestamp for peer %s: %s", public_key[:8], e)
		
		# Transfer stats - validate before parsing
		try:
			stats.transfer_rx = int(parts[DUMP_PEER_RX])
			stats.transfer_tx = int(parts[DUMP_PEER_TX])
		except ValueError as e:
			_log.warning("Invalid transfer stats for peer %s: %s", public_key[:8], e)
			stats.transfer_rx = 0
			stats.transfer_tx = 0
		
		break
	
	return ok_response(data=stats)


# TODO: Add rate limiting to config/QR endpoints to prevent bulk key exfiltration
# e.g., @limiter.limit("10/minute") or similar
@router.get("/peers/{peer_id}/qrcode")
async def get_peer_qrcode(
	request: Request,
	peer_id: int,
	conn: sqlite3.Connection = Depends(get_conn),
	current_user: sqlite3.Row = Depends(require_admin),
):
	"""Generate a QR code for peer configuration (admin only).
	
	Note: Requires 'qrcode' and 'Pillow' packages.
	"""
	config, peer, private_key_plain, preshared_key_plain = await _build_peer_config(request, peer_id, conn)
	
	try:
		from ..utils.qrimage import generate_qr_png

		# Serialize inside try – avoid decrypting for nothing when deps are missing
		config_text = config.to_wg_config()
		peer_name = peer["name"] or "Peer"

		# Resolve node name for badge (remote peers only)
		node_name = None
		node_id = peer["node_id"] if "node_id" in peer.keys() else None
		if node_id:
			from ..db.sqlite_nodes import get_node as db_get_node
			node = db_get_node(conn, node_id)
			if node:
				node_name = node["name"]

		png_bytes = generate_qr_png(config_text, peer_name, node_name=node_name)

		# Sanitize filename — restrict to ASCII-safe characters (\w is
		# unicode-aware in Python 3 and would let through non-ASCII)
		safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', peer['name'] or 'peer').lstrip('.')
		if not safe_name:
			safe_name = 'peer'
		# Enforce maximum length to prevent header abuse
		safe_name = safe_name[:_MAX_FILENAME_LENGTH]

		result = Response(
			content=png_bytes,
			media_type="image/png",
			headers={"Content-Disposition": f'inline; filename="{safe_name}.png"'},
		)

		# NOTE: best-effort only; Python cannot guarantee scrubbing of immutable strings
		del config_text, private_key_plain, preshared_key_plain

		return result
	except ImportError:
		raise HTTPException(status_code=500, detail="QR code generation not available (qrcode/Pillow package missing)")
	except Exception:
		_log.exception("QR code generation error for peer_id=%s", peer_id)
		raise HTTPException(status_code=500, detail="QR code generation failed")


# TODO: Add rate limiting to config/QR endpoints to prevent bulk key exfiltration
@router.get("/peers/{peer_id}/config")
async def get_peer_config(
	request: Request,
	peer_id: int,
	conn: sqlite3.Connection = Depends(get_conn),
	current_user: sqlite3.Row = Depends(require_admin),
):
	"""Get the WireGuard configuration file for a peer (admin only)."""
	config, peer, private_key_plain, preshared_key_plain = await _build_peer_config(request, peer_id, conn)
	
	# Sanitize filename — restrict to ASCII-safe characters
	safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', peer['name'] or 'wg0').lstrip('.')
	if not safe_name:
		safe_name = 'wg0'
	# Enforce maximum length to prevent header abuse
	safe_name = safe_name[:_MAX_FILENAME_LENGTH]
	
	_log.info(
		"CONFIG_DOWNLOADED peer_id=%s peer_name=%s interface=%s user=%s",
		peer_id, peer['name'], peer['interface'], current_user['username'],
	)
	
	config_text = config.to_wg_config()
	
	result = Response(
		content=config_text,
		media_type="text/plain",
		headers={"Content-Disposition": f'attachment; filename="{safe_name}.conf"'},
	)
	
	# NOTE: best-effort only; Python cannot guarantee scrubbing of immutable strings
	del config_text, private_key_plain, preshared_key_plain
	
	return result
