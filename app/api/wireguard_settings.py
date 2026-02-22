#!/usr/bin/env python3
#
# app/api/wireguard_settings.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard global settings endpoints."""

from __future__ import annotations

from ..db.sqlite_interfaces import (
	get_interface,
)
from ..db.sqlite_settings import (
	get_setting,
	set_setting,
)

import ipaddress
import logging
import sqlite3
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .response import ok_response
from ..utils.deps import get_conn, get_config
from .auth import get_current_user, require_admin
from ..utils.vault import decrypt as vault_decrypt, encrypt as vault_encrypt
from .wireguard_utils import generate_preshared_key

_log = logging.getLogger(__name__)

router = APIRouter()

__all__ = [
	"router",
	"WgSettingsPayload",
	"WG_SETTING_KEYS",
	"get_server_endpoint",
	"get_dns_for_peer",
	"InterfaceConfigError",
]


class InterfaceConfigError(Exception):
	"""Raised when interface configuration is invalid or missing."""
	pass


def _mask_secret(value: str, *, reveal: int = 4) -> str:
	"""Mask a secret string, revealing only first/last `reveal` characters.
	
	Requires at least (reveal * 2 + 4) characters to reveal any part of the secret.
	This ensures at least 4 characters are always masked in the middle.
	"""
	min_length = reveal * 2 + 4  # Ensure at least 4 masked chars
	if len(value) >= min_length:
		mask_count = len(value) - reveal * 2
		return value[:reveal] + "*" * mask_count + value[-reveal:]
	return "*" * len(value)


class WgSettingsPayload(BaseModel):
	"""Payload for WireGuard global settings."""
	wg_fqdn: Optional[str] = Field(
		None,
		max_length=256,
		pattern=r"^[a-zA-Z0-9.\-:\[\]]+$",
		description="Server FQDN or IP address",
	)
	wg_port: Optional[int] = Field(None, ge=1, le=65535, description="WireGuard listen port")
	wg_mtu: Optional[int] = Field(None, ge=1280, le=9000, description="Global MTU value (1280-9000)")
	wg_persistent_keepalive: Optional[int] = Field(None, ge=0, le=600, description="Persistent keepalive in seconds")
	wg_use_psk: Optional[str] = Field(None, pattern=r"^[01]$", description="Enable PresharedKey (0/1)")
	gui_port: Optional[int] = Field(None, ge=1, le=65535, description="HTTP port for the web UI")
	gui_localhost_only: Optional[str] = Field(None, pattern=r"^[01]$", description="Only listen on localhost (0/1)")


WG_SETTING_KEYS = [
	"wg_fqdn",
	"wg_port",
	"wg_mtu",
	"wg_persistent_keepalive",
	"wg_use_psk",
	"gui_port",
	"gui_localhost_only",
]


def get_server_endpoint(conn: sqlite3.Connection) -> str:
	"""Build the WireGuard server endpoint from DB settings.

	Returns ``fqdn:port`` (e.g. ``vpn.example.com:51820``).
	Falls back to sensible defaults if not configured.
	"""
	fqdn = get_setting(conn, "wg_fqdn") or "vpn.example.com"
	port = get_setting(conn, "wg_port") or "51820"
	
	# Strip existing brackets if present (users may store bracketed IPv6)
	fqdn_clean = fqdn.strip("[]")
	
	# IPv6 addresses need brackets
	try:
		addr = ipaddress.ip_address(fqdn_clean)
		if addr.version == 6:
			return f"[{fqdn_clean}]:{port}"
	except ValueError:
		pass  # It's a hostname, use as-is
	return f"{fqdn_clean}:{port}"


def get_dns_for_peer(
	conn: sqlite3.Connection,
	interface_name: str,
	use_adblocker: bool,
	default_dns: str,
	peer_address: str | None = None,
) -> str:
	"""Get the DNS server(s) for a peer based on adblocker setting.

	If ``use_adblocker`` is True, returns the interface IPv4 address
	(internal WireBuddy DNS). This path is strict by design: it never
	falls back to public resolvers to avoid DNS leaks in generated client
	configurations.
	
	If ``peer_address`` contains an IPv6 address and the interface has IPv6,
	both IPv4 and IPv6 DNS servers are returned (comma-separated).

	If ``use_adblocker`` is False, returns the configured default DNS servers.
	
	Raises:
		InterfaceConfigError: If interface is not found or has invalid address.
	"""
	if not use_adblocker:
		return default_dns

	# Get interface to extract gateway IP
	iface = get_interface(conn, interface_name)
	if not iface:
		raise InterfaceConfigError(
			f"Interface '{interface_name}' not found while resolving peer DNS"
		)
	if not iface["address"]:
		raise InterfaceConfigError(
			f"Interface '{interface_name}' has no IPv4 address for WireBuddy DNS"
		)

	# Extract gateway IP from interface address (e.g., "10.13.13.1/24" -> "10.13.13.1")
	try:
		ipv4_iface = ipaddress.ip_interface(iface["address"].strip())
	except ValueError as exc:
		raise InterfaceConfigError(
			f"Invalid interface IPv4 address for '{interface_name}': {iface['address']!r}"
		) from exc

	dns_servers = [str(ipv4_iface.ip)]

	# Check if peer has IPv6 and interface has IPv6 → add IPv6 DNS server
	iface_address6 = iface["address6"] if "address6" in iface.keys() else None
	if peer_address and iface_address6:
		# Check if peer has an IPv6 address
		peer_has_v6 = False
		for part in str(peer_address).split(","):
			item = part.strip()
			if not item:
				continue
			try:
				addr = ipaddress.ip_interface(item)
				if addr.ip.version == 6:
					peer_has_v6 = True
					break
			except ValueError:
				continue
		
		if peer_has_v6:
			try:
				# Use the already-validated iface_address6 variable consistently
				ipv6_iface = ipaddress.ip_interface(iface_address6.strip())
				dns_servers.append(str(ipv6_iface.ip))
			except ValueError:
				pass  # Invalid IPv6 on interface, skip

	return ", ".join(dns_servers)


@router.get("/settings")
async def get_wg_settings(
	_: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get WireGuard global settings."""
	result = {}
	for key in WG_SETTING_KEYS:
		result[key] = get_setting(conn, key)
	return ok_response(data=result)


@router.patch("/settings")
async def update_wg_settings(
	payload: WgSettingsPayload,
	_: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Update WireGuard global settings (admin only).
	
	Only explicitly provided fields will be updated.
	Note: Empty strings are stored for None values, which cause get_setting() 
	to return empty string. Callers use 'or' fallback for defaults.
	"""
	updated = []
	for key in WG_SETTING_KEYS:
		# Only update fields that were explicitly set in the request
		if key in payload.model_fields_set:
			value = getattr(payload, key)
			if value is not None:
				set_setting(conn, key, str(value))
			else:
				# Clear the setting by storing empty string (allows 'or' fallback)
				set_setting(conn, key, "")
			updated.append(key)
	
	settings = {k: get_setting(conn, k) for k in WG_SETTING_KEYS}
	return ok_response(data={"updated": updated, "settings": settings})


@router.get("/settings/psk")
async def get_global_psk(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get the current global PresharedKey (masked for security)."""
	cfg = get_config(request)
	enc_psk = get_setting(conn, "wg_global_psk")
	if not enc_psk:
		return ok_response(data={"masked": None})
	try:
		plain = vault_decrypt(enc_psk, cfg.secret_key)
		masked = _mask_secret(plain)
		return ok_response(data={"masked": masked})
	except Exception:
		_log.exception("Failed to decrypt global PSK")
		return ok_response(data={"masked": None})


@router.post("/settings/generate-psk")
async def generate_global_psk(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Generate a new global PresharedKey."""
	cfg = get_config(request)
	psk = await generate_preshared_key()
	enc_psk = vault_encrypt(psk, cfg.secret_key)
	set_setting(conn, "wg_global_psk", enc_psk)
	masked = _mask_secret(psk)
	return ok_response(data={"masked": masked})


@router.get("/settings/check-updates")
async def check_updates(
	_: sqlite3.Row = Depends(get_current_user),
	force: bool = False,
):
	"""Check for available WireBuddy updates from GitHub."""
	from starlette.concurrency import run_in_threadpool
	from ..utils.version import check_for_updates
	
	result = await run_in_threadpool(check_for_updates, force)
	return ok_response(data=result, **result)
