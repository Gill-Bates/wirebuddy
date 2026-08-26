#!/usr/bin/env python3
#
# app/api/wireguard_settings.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard global settings endpoints."""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
import sqlite3
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, field_validator
from starlette.concurrency import run_in_threadpool

from ..db.sqlite_interfaces import get_interface, list_interfaces
from ..db.sqlite_runtime import transaction
from ..db.sqlite_settings import delete_setting, get_setting, set_setting
from ..dns.unbound_config import write_local_data_overrides
from ..dns import unbound_process as unbound
from ..utils.deps import get_conn, get_config
from ..utils.rate_limit import limiter, RATE_LIMIT_CRITICAL, RATE_LIMIT_UI_HEAVY
from ..utils.vault import decrypt as vault_decrypt
from ..utils.version import check_for_updates
from .auth import get_current_user, require_admin
from .response import OkResponse, ok_response
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


class _FieldAction(Enum):
	"""Internal signal for how a settings field should be handled."""
	SKIP = "skip"
	CLEAR = "clear"
	UPDATE = "update"


_REQUIRED_SETTINGS: frozenset[str] = frozenset({"wg_fqdn", "wg_port"})
_SECRET_RESPONSE_HEADERS = {
	"Cache-Control": "no-store",
	"Pragma": "no-cache",
	"X-Content-Type-Options": "nosniff",
}
_CONNTRACK_ACCT_PATH = Path("/proc/sys/net/netfilter/nf_conntrack_acct")


def _mask_secret(value: str, *, reveal: int = 4) -> str:
	"""Mask a secret string, revealing only first/last ``reveal`` characters.

	Requires at least (reveal * 2 + 4) characters to reveal any part;
	short values are fully masked.

	Example::

		>>> _mask_secret("ABCDEFGHIJKLMNOP")
		'ABCD********MNOP'
		>>> _mask_secret("short")
		'********'
	"""
	if not isinstance(value, str):
		raise TypeError(f"Expected str, got {type(value).__name__!r}")
	if not value:
		return ""
	reveal = max(0, int(reveal))
	min_length = reveal * 2 + 4  # Ensure at least 4 chars are masked
	if len(value) >= min_length and reveal > 0:
		return value[:reveal] + "*" * 8 + value[-reveal:]
	return "*" * 8


def _conntrack_accounting_requirements_met() -> bool:
	"""Check conntrack accounting availability without mutating host state."""
	try:
		return _CONNTRACK_ACCT_PATH.read_text(encoding="ascii").strip() == "1"
	except (OSError, ValueError):
		return False


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

	@field_validator("wg_fqdn", mode="before")
	@classmethod
	def validate_fqdn(cls, v: object) -> object:
		"""Normalize and reject obviously malformed FQDNs."""
		if v is None:
			return v
		if not isinstance(v, str):
			return v
		v = v.strip()
		# Allow bare IP addresses
		try:
			return str(ipaddress.ip_address(v.strip("[]")))
		except ValueError:
			pass
		# Reject colons in hostnames (only IPv6 addresses may contain colons)
		if ":" in v:
			raise ValueError("Colons are only allowed in IPv6 addresses; do not include a port")
		if not v or ".." in v or v.startswith(".") or v.endswith("."):
			raise ValueError("Invalid FQDN format")
		for label in v.split("."):
			if (
				not label
				or len(label) > 63
				or label.startswith("-")
				or label.endswith("-")
			):
				raise ValueError("Invalid FQDN label")
		return v


class GlobalPskPayload(BaseModel):
	"""Payload to set global WireGuard PresharedKey."""
	psk: str = Field(..., min_length=44, max_length=44, description="WireGuard PSK (44-char base64)")

	@field_validator("psk", mode="before")
	@classmethod
	def strip_psk(cls, v: object) -> object:
		"""Strip whitespace before length validation."""
		return v.strip() if isinstance(v, str) else v


# Issue #8: derive from model_fields so this list never drifts out-of-sync
# with WgSettingsPayload. Secrets have dedicated endpoints and must remain
# excluded even if a future payload field is added accidentally.
_NEVER_EXPOSED_SETTINGS: frozenset[str] = frozenset({"wg_global_psk"})
WG_SETTING_KEYS: list[str] = [
	key for key in WgSettingsPayload.model_fields if key not in _NEVER_EXPOSED_SETTINGS
]


class PskResponseData(BaseModel):
	"""Masked global PSK payload returned by non-reveal endpoints."""
	masked: str | None
	invalid: bool | None = None
	message: str | None = None


class PskRevealResponseData(PskResponseData):
	"""Global PSK payload for the explicit reveal endpoint."""
	key: str | None = None


class WgSettingsUpdateResult(BaseModel):
	"""Result of a global WireGuard settings update."""
	updated: list[str]
	settings: dict[str, str | None]
	warnings: list[str] = Field(default_factory=list)


class UpdateInfoResponse(BaseModel):
	"""Public update-check result."""
	update_available: bool
	current_version: str
	latest_version: str | None
	release_url: str | None
	release_notes: str | None
	published_at: str | None
	error: str | None


class TrafficStatusResponse(BaseModel):
	"""Traffic analysis state and host capability."""
	enabled: bool
	requirements_met: bool


def _load_global_psk(
	conn: sqlite3.Connection,
	secret_key: str,
) -> tuple[str | None, dict[str, object] | None]:
	"""Load and decrypt the global PSK in one synchronous operation.

	Returns the plaintext and no error payload on success. For an absent or
	invalid stored key, returns no plaintext and the response payload to use.
	Unexpected decryption failures become a generic server error.
	"""
	enc_psk = get_setting(conn, "wg_global_psk")
	if not enc_psk:
		return None, {"masked": None, "key": None}
	try:
		return vault_decrypt(enc_psk, secret_key), None
	except ValueError as exc:
		# Key mismatch/corrupted payload should not break the settings page UX.
		_log.warning("PSK_DECRYPT_INVALID_DATA: %s", exc)
		return None, {
			"masked": None,
			"key": None,
			"invalid": True,
			"message": "Stored PSK cannot be decrypted with current WIREBUDDY_SECRET_KEY",
		}
	except Exception:
		_log.exception("PSK_DECRYPT_UNEXPECTED_FAILURE")
		raise HTTPException(status_code=500, detail="Failed to decrypt global PSK") from None


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

	The database and file work is completed before awaiting the Unbound reload,
	so the request connection is never held across an await point. Expected DNS
	and file-system failures are logged and returned as a warning; database
	errors are allowed to propagate.
	"""
	def _prepare() -> tuple[int, str | None]:
		interfaces = list_interfaces(conn)
		resolved_fqdn = fqdn if fqdn is not None else get_setting(conn, "wg_fqdn")
		count = write_local_data_overrides(interfaces, resolved_fqdn)
		return count, resolved_fqdn

	try:
		count, resolved_fqdn = await run_in_threadpool(_prepare)
	except (OSError, RuntimeError, ValueError):
		_log.exception("SPLIT_DNS_REGENERATE_FAILED")
		return False

	if count == 0:
		return True

	try:
		ok, msg = await unbound.reload_config()
	except (OSError, RuntimeError, ValueError):
		_log.exception("SPLIT_DNS_REGENERATE_FAILED")
		return False
	if ok:
		_log.info("SPLIT_DNS_UPDATED records=%d fqdn=%s", count, resolved_fqdn)
		return True
	_log.warning("SPLIT_DNS_RELOAD_FAILED records=%d msg=%s", count, msg)
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

	Note: This is a synchronous function performing database I/O. Call it via
	``run_in_threadpool`` from async request handlers.

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

	# sqlite3.Row has no __contains__; keys() is the membership check.
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


@router.get("/settings", response_model=OkResponse[dict[str, str | None]])
async def get_wg_settings(
	_: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get WireGuard global settings (read: any user, write: admin only)."""
	result = await run_in_threadpool(
		lambda: {key: get_setting(conn, key) for key in WG_SETTING_KEYS}
	)
	return ok_response(data=result)


@router.patch("/settings", response_model=OkResponse[WgSettingsUpdateResult])
@limiter.limit(RATE_LIMIT_CRITICAL)
async def update_wg_settings(
	request: Request,
	payload: WgSettingsPayload,
	_: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Update WireGuard global settings (admin only).

	- Absent fields are skipped.
	- Fields explicitly set to null are cleared (deleted).
	- Fields with concrete values are updated.

	Required settings (wg_fqdn, wg_port) cannot be cleared.

	Returns 200 even if split-DNS regeneration fails; inspect ``data.warnings``
	for partial failures.
	"""
	updates: list[tuple[str, _FieldAction, str | None]] = []
	for key in WG_SETTING_KEYS:
		action = payload.field_action(key)
		if action is _FieldAction.SKIP:
			continue
		if action is _FieldAction.CLEAR and key in _REQUIRED_SETTINGS:
			raise HTTPException(status_code=422, detail=f"Setting '{key}' is required and cannot be cleared")
		updates.append((key, action, payload.get_db_value(key)))

	# Enabling "Use PresharedKey" must guarantee a global PSK exists, since
	# peer creation silently skips the PSK when wg_use_psk is on but
	# wg_global_psk is unset. Toggling must never replace an existing key —
	# only the explicit "Regenerate PSK" endpoint may do that — so only
	# generate one here if none is configured yet. Generated outside the
	# transaction (it shells out to `wg genpsk`); the existence check is
	# repeated inside the immediate transaction below to close the race
	# against a concurrent request doing the same.
	new_psk: str | None = None
	if payload.field_action("wg_use_psk") is _FieldAction.UPDATE and payload.wg_use_psk:
		current_psk = await run_in_threadpool(get_setting, conn, "wg_global_psk")
		if not current_psk:
			new_psk = await generate_preshared_key()

	def _persist() -> tuple[str | None, dict[str, str | None]]:
		committed_fqdn: str | None = None
		with transaction(conn, immediate=True):
			for key, action, value in updates:
				if action is _FieldAction.CLEAR:
					delete_setting(conn, key)
					_log.info("SETTING_CLEARED key=%s", key)
				else:
					if value is None:
						raise RuntimeError(f"UPDATE action with None value for {key}")
					set_setting(conn, key, value)
					if key == "wg_fqdn":
						committed_fqdn = value
			if new_psk and not get_setting(conn, "wg_global_psk"):
				set_setting(conn, "wg_global_psk", new_psk)
				_log.info("PSK_AUTO_GENERATED reason=wg_use_psk_enabled")
		return committed_fqdn, {k: get_setting(conn, k) for k in WG_SETTING_KEYS}

	try:
		committed_fqdn, settings = await run_in_threadpool(_persist)
	except Exception:
		_log.exception("SETTINGS_UPDATE_FAILED")
		raise HTTPException(status_code=500, detail="Failed to persist settings")

	updated = [key for key, _, _ in updates]
	warnings: list[str] = []

	if "wg_fqdn" in updated:
		if not await _regenerate_split_dns(conn, committed_fqdn):
			warnings.append("Settings saved but split-DNS regeneration failed")

	data = {"updated": updated, "settings": settings, "warnings": warnings}
	return ok_response(data=data)


@router.get("/settings/psk", response_model=OkResponse[PskResponseData])
@limiter.limit(RATE_LIMIT_UI_HEAVY)
async def get_global_psk(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get the current global PresharedKey in masked form.
	
	Uses UI-heavy rate limit because this read endpoint is polled by admin views.
	"""
	cfg = get_config(request)
	plain, error_data = await run_in_threadpool(_load_global_psk, conn, cfg.secret_key)
	if error_data is not None:
		return ok_response(data=error_data)
	if plain is None:
		raise HTTPException(status_code=500, detail="Failed to load global PSK")
	return ok_response(data={"masked": _mask_secret(plain)})


@router.post("/settings/psk/reveal", response_model=OkResponse[PskRevealResponseData])
@limiter.limit(RATE_LIMIT_CRITICAL)
async def reveal_global_psk(
	request: Request,
	response: Response,
	current_user: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Reveal the current global PresharedKey in plaintext.

	POST avoids secret-bearing GET URLs that may leak through logs, caches, or history.
	"""
	for header, value in _SECRET_RESPONSE_HEADERS.items():
		response.headers[header] = value
	cfg = get_config(request)
	plain, error_data = await run_in_threadpool(_load_global_psk, conn, cfg.secret_key)
	if error_data is not None:
		return ok_response(data=error_data)
	if plain is None:
		raise HTTPException(status_code=500, detail="Failed to load global PSK")
	_log.warning(
		"PSK_REVEALED user=%s ip=%s",
		current_user["username"],
		request.client.host if request.client else "unknown",
	)
	return ok_response(data={"key": plain, "masked": _mask_secret(plain)})


@router.post("/settings/generate-psk", response_model=OkResponse[PskResponseData])
@limiter.limit(RATE_LIMIT_CRITICAL)
async def generate_global_psk(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Generate a new global PresharedKey."""
	psk = await generate_preshared_key()

	def _persist() -> None:
		# set_setting() auto-encrypts "wg_global_psk".
		with transaction(conn, immediate=True):
			set_setting(conn, "wg_global_psk", psk)

	try:
		await run_in_threadpool(_persist)
	except Exception:
		_log.exception("PSK_PERSIST_FAILED")
		raise HTTPException(status_code=500, detail="Failed to persist global PSK")
	masked = _mask_secret(psk)
	return ok_response(data={"masked": masked})


@router.put("/settings/psk", response_model=OkResponse[PskResponseData])
@limiter.limit(RATE_LIMIT_CRITICAL)
async def set_global_psk(
	request: Request,
	payload: GlobalPskPayload,
	_: sqlite3.Row = Depends(require_admin),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Set a custom global PresharedKey (admin only)."""
	psk = payload.psk  # Already stripped by field_validator
	if not is_valid_wg_key(psk):
		raise HTTPException(
			status_code=422,
			detail="Invalid WireGuard PSK format (must be 44-char base64 for 32 bytes)",
		)
	try:
		def _persist() -> None:
			# set_setting() auto-encrypts "wg_global_psk".
			with transaction(conn, immediate=True):
				set_setting(conn, "wg_global_psk", psk)

		await run_in_threadpool(_persist)
	except Exception:
		_log.exception("PSK_PERSIST_FAILED")
		raise HTTPException(status_code=500, detail="Failed to persist global PSK")
	return ok_response(data={"masked": _mask_secret(psk)})


@router.get("/settings/check-updates", response_model=OkResponse[UpdateInfoResponse])
@limiter.limit(RATE_LIMIT_UI_HEAVY)
async def check_updates(
	request: Request,
	response: Response,
	current_user: sqlite3.Row = Depends(get_current_user),
	force: bool = Query(False, description="Bypass cache and check immediately"),
):
	"""Check for available WireBuddy updates from GitHub."""
	if force and not bool(current_user["is_admin"]):
		raise HTTPException(status_code=403, detail="Only admins can force update checks")
	response.headers["Cache-Control"] = "no-store" if force else "private, max-age=300"
	result = await run_in_threadpool(check_for_updates, force)
	return ok_response(data=result)


@router.get("/settings/traffic", response_model=OkResponse[TrafficStatusResponse])
async def get_traffic_status(
	_: sqlite3.Row = Depends(get_current_user),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Get traffic analysis status and host requirements."""
	requirements_met = await run_in_threadpool(_conntrack_accounting_requirements_met)
	# Get enabled setting (factory default: disabled)
	enabled_str = await run_in_threadpool(get_setting, conn, "traffic_analysis_enabled")
	enabled = enabled_str == "1"
	return ok_response(data={
		"enabled": enabled,
		"requirements_met": requirements_met,
	})
