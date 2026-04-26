#!/usr/bin/env python3
#
# app/api/wireguard_settings.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard global settings endpoints."""

from __future__ import annotations

import ipaddress
import logging
import sqlite3
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from starlette.concurrency import run_in_threadpool

from ..db.sqlite_interfaces import get_interface, list_interfaces
from ..db.sqlite_runtime import transaction
from ..db.sqlite_settings import delete_setting, get_setting, set_setting
from ..dns.unbound_config import write_local_data_overrides
from ..dns import unbound_process as unbound
from ..utils.conntrack import init_conntrack_accounting
from ..utils.deps import get_conn, get_config
from ..utils.rate_limit import limiter, RATE_LIMIT_CRITICAL
from ..utils.vault import decrypt as vault_decrypt, encrypt as vault_encrypt
from ..utils.version import check_for_updates
from .auth import get_current_user, require_admin
from .response import ok_response
from .wireguard_utils import generate_preshared_key, is_valid_wg_key

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


class _FieldAction(Enum):
	"""Internal signal for how a settings field should be handled."""
	SKIP = "skip"
	CLEAR = "clear"
	UPDATE = "update"


_REQUIRED_SETTINGS: frozenset[str] = frozenset({"wg_fqdn", "wg_port"})


def _mask_secret(value: str, *, reveal: int = 4) -> str:
	"""Mask a secret string, revealing only first/last ``reveal`` characters.

	Requires at least (reveal * 2 + 4) characters to reveal any part;
	short values are fully masked.

	Example::

		>>> _mask_secret("ABCDEFGHIJKLMNOP")
		'ABCD********MNOP'
		>>> _mask_secret("short")
		'*****'
	"""
	if not isinstance(value, str):
		raise TypeError(f"Expected str, got {type(value).__name__!r}")
	if not value:
		return ""
	reveal = max(0, int(reveal))
	min_length = reveal * 2 + 4  # Ensure at least 4 chars are masked
	if len(value) >= min_length:
		mask_count = len(value) - reveal * 2
		return value[:reveal] + "*" * mask_count + value[-reveal:]
	return "*" * len(value)


class WgSettingsPayload(BaseModel):
	"""Payload for WireGuard global settings."""
	wg_fqdn: str | None = Field(
		None,
		max_length=256,
		pattern=r"^[a-zA-Z0-9.\-:]+$",
		description="Server FQDN or IP address",
	)
	wg_port: int | None = Field(None, ge=1, le=65535, description="WireGuard listen port")
	wg_mtu: int | None = Field(None, ge=1280, le=9000, description="Global MTU value (1280-9000)")
	wg_persistent_keepalive: int | None = Field(None, ge=0, le=600, description="Persistent keepalive in seconds")
	# Issue #7: real booleans instead of '0'/'1' strings — get_db_value() handles
	# the conversion to the '0'/'1' format required by SQLite.
	wg_use_psk: bool | None = Field(None, description="Enable PresharedKey")
	gui_port: int | None = Field(None, ge=1, le=65535, description="HTTP port for the web UI")
	gui_external_port: int | None = Field(None, ge=1, le=65535, description="External port for node enrollment (reverse proxy)")
	gui_localhost_only: bool | None = Field(None, description="Only listen on localhost")
	enable_status_page: bool | None = Field(None, description="Enable public internal status page")
	enable_swagger: bool | None = Field(None, description="Enable Swagger API documentation")
	traffic_analysis_enabled: bool | None = Field(None, description="Enable traffic country analysis")

	def get_db_value(self, field: str) -> str | None:
		"""Return the DB-storable string for ``field`` (converts bool → '0'/'1')."""
		value = getattr(self, field)
		if value is None:
			return None
		if isinstance(value, bool):
			return "1" if value else "0"
		return str(value)

	def field_action(self, field: str) -> _FieldAction:
		"""Determine whether field is skipped, cleared (null), or updated."""
		if field not in self.model_fields_set:
			return _FieldAction.SKIP
		if getattr(self, field) is None:
			return _FieldAction.CLEAR
		return _FieldAction.UPDATE

	@field_validator("wg_fqdn")
	@classmethod
	def validate_fqdn(cls, v: str | None) -> str | None:
		"""Reject obviously malformed FQDNs (double dots, leading/trailing dots)."""
		if v is None:
			return v
		v = v.strip()
		# Allow bare IP addresses
		try:
			ipaddress.ip_address(v.strip("[]"))
			return v
		except ValueError:
			pass
		# Reject colons in hostnames (only IPv6 addresses may contain colons)
		if ":" in v:
			raise ValueError("Colons are only allowed in IPv6 addresses; do not include a port")
		if not v or ".." in v or v.startswith(".") or v.endswith("."):
			raise ValueError("Invalid FQDN format")
		return v


class GlobalPskPayload(BaseModel):
	"""Payload to set global WireGuard PresharedKey."""
	psk: str = Field(..., min_length=44, max_length=44, description="WireGuard PSK (44-char base64)")

	@field_validator("psk")
	@classmethod
	def strip_psk(cls, v: str) -> str:
		"""Strip whitespace before length validation."""
		return v.strip()


# Issue #8: derive from model_fields so this list never drifts out-of-sync
# with WgSettingsPayload.
WG_SETTING_KEYS: list[str] = list(WgSettingsPayload.model_fields.keys())


def _build_endpoint(fqdn_clean: str, port: str) -> str:
	"""Build an ``fqdn:port`` string, wrapping IPv6 addresses in brackets."""
	if not fqdn_clean:
		raise ValueError("Empty FQDN after cleaning")
	try:
		addr = ipaddress.ip_address(fqdn_clean)
		if addr.version == 6:
			return f"[{fqdn_clean}]:{port}"
	except ValueError:
		pass  # hostname — use as-is
	return f"{fqdn_clean}:{port}"


def _peer_has_ipv6(peer_address: str) -> bool:
	"""Return True if ``peer_address`` contains at least one IPv6 address."""
	for part in peer_address.split(","):
		item = part.strip()
		if not item:
			continue
		try:
			if ipaddress.ip_interface(item).ip.version == 6:
				return True
		except ValueError:
			continue
	return False


async def _regenerate_split_dns(conn: sqlite3.Connection, fqdn: str | None = None) -> bool:
	"""Regenerate split-DNS local-data after an FQDN or interface change.

	Logs but does not propagate exceptions so a DNS hiccup never rolls back
	an otherwise-successful settings update.
	"""
	try:
		interfaces = list_interfaces(conn)
		if fqdn is None:
			fqdn = get_setting(conn, "wg_fqdn")
		count = write_local_data_overrides(interfaces, fqdn)
		if count > 0:
			ok, msg = await unbound.reload_config()
			if ok:
				_log.info("SPLIT_DNS_UPDATED records=%d fqdn=%s", count, fqdn)
				return True
			else:
				_log.warning("SPLIT_DNS_RELOAD_FAILED records=%d msg=%s", count, msg)
				return False
		return True
	except Exception:
		_log.exception("SPLIT_DNS_REGENERATE_FAILED")
		return False


def get_server_endpoint(conn: sqlite3.Connection, interface_name: str | None = None) -> str:
	"""Build the WireGuard server endpoint from DB settings.

	Returns ``fqdn:port`` (e.g. ``vpn.example.com:51820``). When an
	interface name is provided, the listen port from that interface is
	used. Falls back to global settings if not configured.

	Note: This is a synchronous function. Call it from a thread pool
	(e.g. ``run_in_threadpool``) when used from async request handlers.
	"""
	fqdn_setting = get_setting(conn, "wg_fqdn")
	if not fqdn_setting:
		_log.warning("WG settings: 'wg_fqdn' is not configured, falling back to placeholder")
	fqdn = fqdn_setting or "vpn.example.com"

	port: str | None = None
	if interface_name:
		iface = get_interface(conn, interface_name)
		if iface:
			port = str(iface["listen_port"] or "") or None

	if not port:
		wg_port_setting = get_setting(conn, "wg_port")
		if not wg_port_setting:
			_log.warning("WG settings: 'wg_port' is not configured, falling back to default 51820")
		port = str(wg_port_setting or "51820")

	return _build_endpoint(fqdn.strip("[]"), port)


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
		msg = f"Interface '{interface_name}' not found while resolving peer DNS"
		_log.error(msg)
		raise InterfaceConfigError(msg)
	if not iface["address"]:
		msg = f"Interface '{interface_name}' has no IPv4 address for WireBuddy DNS"
		_log.error(msg)
		raise InterfaceConfigError(msg)

	# Extract gateway IP from interface address (e.g. "10.13.13.1/24" → "10.13.13.1")
	try:
		ipv4_iface = ipaddress.ip_interface(iface["address"].strip())
	except ValueError as exc:
		msg = f"Invalid interface IPv4 address for '{interface_name}': {iface['address']!r}"
		_log.error(msg)
		raise InterfaceConfigError(msg) from exc

	dns_servers = [str(ipv4_iface.ip)]

	# sqlite3.Row support dictionary-like access; keys() is available.
	iface_address6: str | None = iface["address6"] if "address6" in iface.keys() else None
	if peer_address and iface_address6:
		if _peer_has_ipv6(peer_address):
			try:
				ipv6_iface = ipaddress.ip_interface(iface_address6.strip())
				dns_servers.append(str(ipv6_iface.ip))
			except ValueError:
				_log.warning(
					"Invalid interface IPv6 address for '%s': %r (skipping IPv6 DNS)",
					interface_name,
					iface_address6,
				)

	return ", ".join(dns_servers)


@router.get("/settings")
async def get_wg_settings(
	_: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get WireGuard global settings (read: any user, write: admin only)."""
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

	- Absent fields are skipped.
	- Fields explicitly set to null are cleared (deleted).
	- Fields with concrete values are updated.

	Required settings (wg_fqdn, wg_port) cannot be cleared.
	"""
	updates: list[tuple[str, _FieldAction, str | None]] = []
	for key in WG_SETTING_KEYS:
		action = payload.field_action(key)
		if action is _FieldAction.SKIP:
			continue
		if action is _FieldAction.CLEAR and key in _REQUIRED_SETTINGS:
			raise HTTPException(status_code=422, detail=f"Setting '{key}' is required and cannot be cleared")
		updates.append((key, action, payload.get_db_value(key)))

	committed_fqdn: str | None = None
	try:
		with transaction(conn, immediate=True):
			for key, action, value in updates:
				if action is _FieldAction.CLEAR:
					delete_setting(conn, key)
					_log.info("SETTING_CLEARED key=%s", key)
				else:
					assert value is not None, f"BUG: UPDATE action with None value for {key}"
					set_setting(conn, key, value)
					if key == "wg_fqdn":
						committed_fqdn = value
	except Exception:
		_log.exception("SETTINGS_UPDATE_FAILED")
		raise HTTPException(status_code=500, detail="Failed to persist settings")

	updated = [key for key, _, _ in updates]
	warnings: list[str] = []

	if "wg_fqdn" in updated:
		if not await _regenerate_split_dns(conn, committed_fqdn):
			warnings.append("Settings saved but split-DNS regeneration failed")

	settings = {k: get_setting(conn, k) for k in WG_SETTING_KEYS}
	data: dict[str, object] = {"updated": updated, "settings": settings}
	if warnings:
		data["warnings"] = warnings
	return ok_response(data=data)


@router.get("/settings/psk")
@limiter.limit(RATE_LIMIT_CRITICAL)
async def get_global_psk(
	request: Request,
	reveal: bool = Query(False),
	current_user: sqlite3.Row = Depends(require_admin),  # named for audit log
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get the current global PresharedKey (masked or full).
	
	Rate limited to prevent abuse of PSK reveal.
	"""
	cfg = get_config(request)
	enc_psk = get_setting(conn, "wg_global_psk")
	if not enc_psk:
		return ok_response(data={"masked": None, "key": None})
	try:
		plain = vault_decrypt(enc_psk, cfg.secret_key)
	except ValueError as exc:
		# Key mismatch/corrupted payload should not break the settings page UX.
		_log.warning("PSK_DECRYPT_INVALID_DATA: %s", exc)
		return ok_response(data={
			"masked": None,
			"key": None,
			"invalid": True,
			"message": "Stored PSK cannot be decrypted with current WIREBUDDY_SECRET_KEY",
		})
	except Exception:
		_log.exception("PSK_DECRYPT_UNEXPECTED_FAILURE")
		raise HTTPException(status_code=500, detail="Failed to decrypt global PSK")

	if reveal:
		# Issue #1: audit log whenever the PSK is revealed in plaintext
		_log.warning(
			"PSK_REVEALED user=%s ip=%s",
			current_user["username"],
			request.client.host if request.client else "unknown",
		)
		return ok_response(data={"key": plain, "masked": _mask_secret(plain)})
	return ok_response(data={"masked": _mask_secret(plain)})


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
	try:
		with transaction(conn, immediate=True):
			set_setting(conn, "wg_global_psk", enc_psk)
	except Exception:
		_log.exception("PSK_PERSIST_FAILED")
		raise HTTPException(status_code=500, detail="Failed to persist global PSK")
	masked = _mask_secret(psk)
	return ok_response(data={"masked": masked})


@router.put("/settings/psk")
async def set_global_psk(
	request: Request,
	payload: GlobalPskPayload,
	_: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Set a custom global PresharedKey (admin only)."""
	cfg = get_config(request)
	psk = payload.psk  # Already stripped by field_validator
	if not is_valid_wg_key(psk):
		raise HTTPException(
			status_code=422,
			detail="Invalid WireGuard PSK format (must be 44-char base64 for 32 bytes)",
		)
	enc_psk = vault_encrypt(psk, cfg.secret_key)
	try:
		with transaction(conn, immediate=True):
			set_setting(conn, "wg_global_psk", enc_psk)
	except Exception:
		_log.exception("PSK_PERSIST_FAILED")
		raise HTTPException(status_code=500, detail="Failed to persist global PSK")
	return ok_response(data={"masked": _mask_secret(psk)})


@router.get("/settings/check-updates")
async def check_updates(
	current_user: sqlite3.Row = Depends(get_current_user),
	force: bool = Query(False, description="Bypass cache and check immediately"),
):
	"""Check for available WireBuddy updates from GitHub."""
	if force and not bool(current_user["is_admin"]):
		raise HTTPException(status_code=403, detail="Only admins can force update checks")
	result = await run_in_threadpool(check_for_updates, force)
	return ok_response(data=result)


@router.get("/settings/traffic")
async def get_traffic_status(
	_: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get traffic analysis status and host requirements."""
	# Check if conntrack accounting is available
	requirements_met = await run_in_threadpool(init_conntrack_accounting)
	# Get enabled setting (factory default: disabled)
	enabled_str = get_setting(conn, "traffic_analysis_enabled")
	enabled = enabled_str == "1"
	return ok_response(data={
		"enabled": enabled,
		"requirements_met": requirements_met,
	})
