#!/usr/bin/env python3
#
# app/api/wireguard_peers_config.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard peer configuration and QR code API routes."""

from __future__ import annotations

from ..db.sqlite_peers import (
	get_peer_by_id,
)

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
from .auth import get_current_user, require_admin
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
DUMP_PEER_KEEPALIVE = 7
DUMP_PEER_MIN_FIELDS = 7


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
	private_key_plain = SecretStr(vault_decrypt(private_key, cfg.secret_key))
	preshared_key_plain = None
	if peer["preshared_key"]:
		preshared_key_plain = SecretStr(vault_decrypt(peer["preshared_key"], cfg.secret_key))
	
	# Get server public key
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
	
	# Determine DNS based on adblocker setting
	use_adblocker = True if peer["use_adblocker"] is None else bool(peer["use_adblocker"])
	try:
		dns_servers = get_dns_for_peer(
			conn,
			peer["interface"],
			use_adblocker,
			WG_DEFAULT_DNS,
			peer_address=peer_address,
		)
	except InterfaceConfigError as exc:
		raise HTTPException(status_code=422, detail=str(exc))
	
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
		server_endpoint=get_server_endpoint(conn),
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
	peer = get_peer_by_id(conn, peer_id)
	if not peer:
		raise HTTPException(status_code=404, detail="Peer not found")
	
	public_key = peer["public_key"]
	interface_name = peer["interface"]
	
	# Get stats from wg show dump
	code, stdout, stderr = await run_wg_command("wg", "show", interface_name, "dump")
	if code != 0:
		raise HTTPException(status_code=500, detail=f"Failed to get stats: {stderr}")
	
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
	
	Note: Requires 'qrcode' package (optional dependency).
	"""
	config, peer, private_key_plain, preshared_key_plain = await _build_peer_config(request, peer_id, conn)
	
	# Serialize config to text (contains plaintext private key)
	config_text = config.to_wg_config()
	
	# Generate QR code
	try:
		import qrcode
		qr = qrcode.QRCode(version=1, box_size=10, border=4)
		qr.add_data(config_text)
		qr.make(fit=True)
		
		img = qr.make_image(fill_color="black", back_color="white")
		
		import io
		buffer = io.BytesIO()
		img.save(buffer, format="PNG")
		buffer.seek(0)
		
		# Sanitize filename to prevent header injection and path traversal
		safe_name = re.sub(r'[^\w.-]', '_', peer['name'] or 'peer').lstrip('.')
		if not safe_name:
			safe_name = 'peer'
		
		_log.info(
			"QR_CODE_DISPLAYED peer_id=%s peer_name=%s interface=%s user=%s",
			peer_id, peer['name'], peer['interface'], current_user['username'],
		)
		
		result = Response(
			content=buffer.getvalue(),
			media_type="image/png",
			headers={"Content-Disposition": f'inline; filename="{safe_name}.png"'},
		)
		
		# Clear sensitive data from memory
		del config_text, private_key_plain, preshared_key_plain
		
		return result
	except ImportError:
		raise HTTPException(status_code=500, detail="QR code generation not available (qrcode package missing)")
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
	
	# Sanitize filename to prevent header injection and path traversal
	safe_name = re.sub(r'[^\w.-]', '_', peer['name'] or 'wg0').lstrip('.')
	if not safe_name:
		safe_name = 'wg0'
	
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
	
	# Clear sensitive data from memory
	del config_text, private_key_plain, preshared_key_plain
	
	return result
