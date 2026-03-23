#!/usr/bin/env python3
#
# app/api/wireguard_interfaces_crud.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard interface create/update/delete endpoints."""

from __future__ import annotations

import ipaddress
import hashlib
import logging
import re
import sqlite3
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .response import ok_response
from ..db import tsdb
from ..db.sqlite_interfaces import (
	create_interface as db_create_interface,
	delete_interface as db_delete_interface,
	delete_peers_by_interface,
	get_interface,
	list_interfaces,
	update_interface as db_update_interface,
)
from ..db.sqlite_peers import get_all_peers
from ..db.sqlite_settings import (
	get_dns_blocklist_enabled,
	get_dns_query_logging_enabled,
	get_dns_upstream_servers,
	get_dnssec_enabled,
	get_setting,
	set_dns_service_enabled,
)
from ..dns.unbound_config import write_config as write_unbound_config, write_local_data_overrides
from ..dns import unbound_process as unbound
from ..db.sqlite_runtime import transaction
from ..utils.config import WG_CONFIG_PATH
from ..utils.deps import get_conn, get_config, get_tsdb_dir
from .auth import require_admin
from ..utils.vault import encrypt as vault_encrypt
from .wireguard_utils import run_wg_command, generate_keypair, validate_interface_name
from .wireguard_config import write_interface_config, _validate_hook

_log = logging.getLogger(__name__)

router = APIRouter()

__all__ = ["router", "InterfaceCreate", "InterfaceUpdate"]

# Issue #16: Renamed from _IFACE_NAME_RE for clarity — only used for outbound iface validation
_OUTBOUND_IFACE_RE = re.compile(r"^[a-zA-Z0-9._-]+$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _regenerate_split_dns(conn: sqlite3.Connection) -> str | None:
	"""Regenerate split-DNS local-data and reload Unbound.

	Called after interface create/update/delete to ensure DNS overrides
	for wg_fqdn point to the correct internal addresses.

	Returns a warning string on failure so callers can surface it in the
	response payload without failing the overall operation.
	"""
	try:
		interfaces = list_interfaces(conn)
		fqdn = get_setting(conn, "wg_fqdn")
		count = write_local_data_overrides(interfaces, fqdn)
		if count > 0:
			ok, msg = await unbound.reload_config()
			if ok:
				_log.info("SPLIT_DNS_UPDATED records=%d fqdn=%s", count, fqdn)
			else:
				_log.warning("SPLIT_DNS_RELOAD_FAILED records=%d msg=%s", count, msg)
				return f"Split-DNS reload failed: {msg}"
	# Catch only expected errors; let programming errors propagate
	except (OSError, sqlite3.Error) as exc:
		_log.exception("SPLIT_DNS_REGENERATE_FAILED")
		return f"Split-DNS regeneration failed: {exc}"
	return None


def _get_default_route_iface() -> str:
	"""Detect the system's default outbound network interface.

	Reads /proc/net/route for the entry with Destination=0.0.0.0 and
	Mask=0.0.0.0 (all values in hex). Falls back to 'eth0' if detection
	fails.
	"""
	try:
		with open("/proc/net/route") as fh:
			next(fh)  # skip header line
			for line in fh:
				parts = line.split()
				# Columns: Iface Dest Gateway Flags RefCnt Use Metric Mask ...
				if len(parts) >= 8 and parts[1] == "00000000" and parts[7] == "00000000":
					detected = parts[0]
					_log.debug("AUTO_DETECTED_DEFAULT_ROUTE_IFACE iface=%s", detected)
					return detected
	except (OSError, StopIteration, IndexError):
		pass
	_log.warning("Could not detect default route interface, falling back to eth0")
	return "eth0"


def _script_fingerprint(script: str | None) -> str:
	"""Return a short stable fingerprint for script audit logging."""
	if not script:
		return "none"
	digest = hashlib.sha256(script.encode("utf-8", errors="replace")).hexdigest()[:12]
	return f"sha256:{digest} len:{len(script)}"

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
	"""Schema for updating an existing WireGuard interface.

	Note: This endpoint uses PATCH semantics – only explicitly provided
	fields are updated; omitted fields retain their current values.
	"""
	address: Optional[str] = Field(
		default=None,
		min_length=7,
		description="IPv4 interface address with subnet (e.g., 10.13.13.1/24)",
	)
	address6: Optional[str] = Field(
		default=None,
		description="IPv6 interface address with prefix (optional)",
	)
	listen_port: Optional[int] = Field(default=None, ge=1, le=65535)
	dns: Optional[str] = Field(default=None, description="DNS servers for clients")
	post_up: Optional[str] = Field(default=None, description="PostUp script")
	post_down: Optional[str] = Field(default=None, description="PostDown script")
	show_on_dashboard: Optional[bool] = Field(
		default=None,
		description="Show this interface on dashboard network gauges",
	)


def _build_default_firewall_rules(
	v4_subnet: str,
	v6_subnet: str | None,
	outbound_iface: str = "eth0",
) -> tuple[str, str]:
	"""Build default PostUp/PostDown iptables rules for NAT and DNS."""
	if not _OUTBOUND_IFACE_RE.fullmatch(outbound_iface):
		raise ValueError(f"Suspicious outbound interface name: {outbound_iface!r}")
	try:
		v4_net = ipaddress.ip_network(v4_subnet, strict=False)
		if v4_net.version != 4:
			raise ValueError("v4_subnet must be IPv4")
	except ValueError as exc:
		raise ValueError(f"Invalid IPv4 subnet for firewall rules: {v4_subnet!r}") from exc

	v6_net_str: str | None = None
	if v6_subnet:
		try:
			v6_net = ipaddress.ip_network(v6_subnet, strict=False)
			if v6_net.version != 6:
				raise ValueError("v6_subnet must be IPv6")
			v6_net_str = str(v6_net)
		except ValueError as exc:
			raise ValueError(f"Invalid IPv6 subnet for firewall rules: {v6_subnet!r}") from exc

	oi = outbound_iface
	v4_subnet_safe = str(v4_net)
	up_rules = [
		f"iptables -t nat -A POSTROUTING -s {v4_subnet_safe} -o {oi} -j MASQUERADE",
		"iptables -A FORWARD -i %i -j ACCEPT",
		"iptables -A FORWARD -o %i -j ACCEPT",
		"iptables -A INPUT -i %i -p udp --dport 53 -j ACCEPT",
		"iptables -A INPUT -i %i -p tcp --dport 53 -j ACCEPT",
		"iptables -A OUTPUT -o %i -p udp --sport 53 -j ACCEPT",
		"iptables -A OUTPUT -o %i -p tcp --sport 53 -j ACCEPT",
		f"iptables -A OUTPUT -o {oi} -p tcp --dport 853 -j ACCEPT",
		f"iptables -A OUTPUT -o {oi} -p udp --dport 53 -j ACCEPT",
		f"iptables -A OUTPUT -o {oi} -p tcp --dport 53 -j ACCEPT",
	]
	down_rules = [
		f"iptables -t nat -D POSTROUTING -s {v4_subnet_safe} -o {oi} -j MASQUERADE",
		"iptables -D FORWARD -i %i -j ACCEPT",
		"iptables -D FORWARD -o %i -j ACCEPT",
		"iptables -D INPUT -i %i -p udp --dport 53 -j ACCEPT",
		"iptables -D INPUT -i %i -p tcp --dport 53 -j ACCEPT",
		"iptables -D OUTPUT -o %i -p udp --sport 53 -j ACCEPT",
		"iptables -D OUTPUT -o %i -p tcp --sport 53 -j ACCEPT",
		f"iptables -D OUTPUT -o {oi} -p tcp --dport 853 -j ACCEPT",
		f"iptables -D OUTPUT -o {oi} -p udp --dport 53 -j ACCEPT",
		f"iptables -D OUTPUT -o {oi} -p tcp --dport 53 -j ACCEPT",
	]

	if v6_net_str:
		up_rules += [
			f"ip6tables -t nat -A POSTROUTING -s {v6_net_str} -o {oi} -j MASQUERADE",
			"ip6tables -A FORWARD -i %i -j ACCEPT",
			"ip6tables -A FORWARD -o %i -j ACCEPT",
			"ip6tables -A INPUT -i %i -p udp --dport 53 -j ACCEPT",
			"ip6tables -A INPUT -i %i -p tcp --dport 53 -j ACCEPT",
			"ip6tables -A OUTPUT -o %i -p udp --sport 53 -j ACCEPT",
			"ip6tables -A OUTPUT -o %i -p tcp --sport 53 -j ACCEPT",
			f"ip6tables -A OUTPUT -o {oi} -p tcp --dport 853 -j ACCEPT",
			f"ip6tables -A OUTPUT -o {oi} -p udp --dport 53 -j ACCEPT",
			f"ip6tables -A OUTPUT -o {oi} -p tcp --dport 53 -j ACCEPT",
		]
		down_rules += [
			f"ip6tables -t nat -D POSTROUTING -s {v6_net_str} -o {oi} -j MASQUERADE",
			"ip6tables -D FORWARD -i %i -j ACCEPT",
			"ip6tables -D FORWARD -o %i -j ACCEPT",
			"ip6tables -D INPUT -i %i -p udp --dport 53 -j ACCEPT",
			"ip6tables -D INPUT -i %i -p tcp --dport 53 -j ACCEPT",
			"ip6tables -D OUTPUT -o %i -p udp --sport 53 -j ACCEPT",
			"ip6tables -D OUTPUT -o %i -p tcp --sport 53 -j ACCEPT",
			f"ip6tables -D OUTPUT -o {oi} -p tcp --dport 853 -j ACCEPT",
			f"ip6tables -D OUTPUT -o {oi} -p udp --dport 53 -j ACCEPT",
			f"ip6tables -D OUTPUT -o {oi} -p tcp --dport 53 -j ACCEPT",
		]

	return "; ".join(up_rules), "; ".join(down_rules)


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


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

	if conf_file.exists():
		raise HTTPException(status_code=409, detail=f"Interface '{payload.name}' already exists")
	if get_interface(conn, payload.name):
		raise HTTPException(status_code=409, detail=f"Interface '{payload.name}' already exists in database")

	# Issue #4: strict IP family validation
	try:
		v4 = ipaddress.ip_interface(payload.address)
	except ValueError:
		raise HTTPException(status_code=422, detail=f"Invalid address: {payload.address}")
	if v4.version != 4:
		raise HTTPException(status_code=422, detail="address must be an IPv4 CIDR (e.g. 10.0.0.1/24)")
	# Issue #4 (Security): Enforce subnet prefix — /32 host address is useless for VPN
	if v4.network.prefixlen == 32:
		raise HTTPException(
			status_code=422,
			detail="address must include a subnet prefix (e.g. /24), not a /32 host address",
		)

	v6_str = payload.address6 or None
	if v6_str:
		try:
			v6_obj = ipaddress.ip_interface(v6_str)
		except ValueError:
			raise HTTPException(status_code=422, detail=f"Invalid IPv6 address: {v6_str}")
		if v6_obj.version != 6:
			raise HTTPException(status_code=422, detail="address6 must be an IPv6 CIDR (e.g. fd00::1/64)")
		# Issue #4 (Security): Enforce subnet prefix — /128 host address is useless
		if v6_obj.network.prefixlen == 128:
			raise HTTPException(
				status_code=422,
				detail="address6 must include a subnet prefix (e.g. /64), not a /128 host address",
			)

	# Check for subnet overlap with existing interfaces
	existing_interfaces = list_interfaces(conn)
	new_v4_net = v4.network
	new_v6_net = ipaddress.ip_interface(v6_str).network if v6_str else None

	for iface in existing_interfaces:
		# Check IPv4 overlap
		if iface["address"]:
			try:
				existing_v4 = ipaddress.ip_interface(iface["address"]).network
				if new_v4_net.overlaps(existing_v4):
					raise HTTPException(
						status_code=409,
						detail=f"IPv4 subnet {new_v4_net} overlaps with interface '{iface['name']}' ({existing_v4})"
					)
			except ValueError as exc:
				# Issue #19: Log invalid DB entries at DEBUG level for diagnostic visibility
				_log.debug("Skipping invalid IPv4 address in DB for interface %s: %s", iface["name"], exc)
				pass
		if new_v6_net and iface["address6"]:
			try:
				existing_v6 = ipaddress.ip_interface(iface["address6"]).network
				if new_v6_net.overlaps(existing_v6):
					raise HTTPException(
						status_code=409,
						detail=f"IPv6 subnet {new_v6_net} overlaps with interface '{iface['name']}' ({existing_v6})"
					)
			except ValueError as exc:
				# Issue #19: Log invalid DB entries at DEBUG level for diagnostic visibility
				_log.debug("Skipping invalid IPv6 address in DB for interface %s: %s", iface["name"], exc)
				pass
	for iface in existing_interfaces:
		if iface["listen_port"] == payload.listen_port:
			raise HTTPException(
				status_code=409,
				detail=f"Listen port {payload.listen_port} is already used by interface '{iface['name']}'"
			)

	# Issue #2: validate hook scripts before touching DB or disk
	try:
		if payload.post_up:
			_validate_hook(payload.post_up, "PostUp")
		if payload.post_down:
			_validate_hook(payload.post_down, "PostDown")
	except ValueError as exc:
		raise HTTPException(status_code=422, detail=str(exc))

	private_key, public_key = await generate_keypair()

	# Issue #10: detect real outbound interface instead of hardcoding eth0
	post_up = payload.post_up
	post_down = payload.post_down
	if not post_up or not post_down:
		v4_subnet = str(v4.network)
		v6_subnet = str(ipaddress.ip_interface(v6_str).network) if v6_str else None
		outbound_iface = _get_default_route_iface()
		_log.info("AUTO_DETECTED_OUTBOUND_IFACE iface=%s for interface=%s", outbound_iface, payload.name)
		default_up, default_down = _build_default_firewall_rules(v4_subnet, v6_subnet, outbound_iface)
		if not post_up:
			post_up = default_up
		if not post_down:
			post_down = default_down

	private_key_encrypted = vault_encrypt(private_key, cfg.secret_key)

	# Issue #7: catch IntegrityError from unique-name constraint
	try:
		db_create_interface(
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
	except sqlite3.IntegrityError:
		raise HTTPException(status_code=409, detail=f"Interface '{payload.name}' already exists")
	except Exception:
		# Issue #9: log full error server-side, return generic message
		_log.exception("INTERFACE_DB_CREATE_FAILED name=%s", payload.name)
		raise HTTPException(status_code=500, detail="Failed to save interface; please check server logs")

	# Issue #1: use keyword arguments to eliminate positional-order ambiguity
	# Issue #6: catch all exceptions (not just OSError) and clean up partial file
	try:
		write_interface_config(
			config_path=config_path,
			name=payload.name,
			private_key=private_key_encrypted,
			address=payload.address,
			address6=v6_str,
			listen_port=payload.listen_port,
			dns=payload.dns,
			post_up=post_up,
			post_down=post_down,
			conn=conn,
			pepper=cfg.secret_key,
		)
	except Exception:
		_log.exception("INTERFACE_CONFIG_WRITE_FAILED name=%s", payload.name)
		cleanup_ok = True
		try:
			db_delete_interface(conn, payload.name)
		except Exception:
			cleanup_ok = False
			_log.exception("INTERFACE_CREATE_CLEANUP_DB_FAILED name=%s", payload.name)
		try:
			conf_file.unlink(missing_ok=True)
		except Exception:
			cleanup_ok = False
			_log.exception("INTERFACE_CREATE_CLEANUP_FILE_FAILED name=%s", payload.name)
		detail = "Failed to write interface config; the interface was not created"
		if not cleanup_ok:
			detail = "Failed to write interface config; cleanup may be incomplete"
		raise HTTPException(status_code=500, detail=detail)

	_log.info("INTERFACE_CREATED name=%s address=%s address6=%s", payload.name, payload.address, v6_str)
	if post_up:
		_log.info(
			"INTERFACE_SCRIPT_CREATED name=%s type=PostUp fingerprint=%s",
			payload.name,
			_script_fingerprint(post_up),
		)
	if post_down:
		_log.info(
			"INTERFACE_SCRIPT_CREATED name=%s type=PostDown fingerprint=%s",
			payload.name,
			_script_fingerprint(post_down),
		)

	# Auto-start if this is the first interface
	if config_path.is_dir():
		existing_count = len(list(config_path.glob("*.conf")))
		if existing_count == 1:
			try:
				code, _, stderr = await run_wg_command("wg-quick", "up", payload.name)
				if code == 0:
					_log.info("INTERFACE_AUTO_STARTED name=%s (first interface)", payload.name)
				else:
					_log.warning("Failed to auto-start first interface %s: %s", payload.name, stderr)
			except Exception as exc:
				_log.warning("Exception during auto-start of first interface %s: %s", payload.name, exc)

			# Auto-start Unbound DNS when first interface is created
			try:
				if unbound.is_unbound_installed():
					# Extract IP from interface address (strip CIDR)
					listen_ipv4 = [payload.address.split("/")[0]]
					listen_ipv6 = [v6_str.split("/")[0]] if v6_str else None
					# Write Unbound config with interface IPs
					await run_in_threadpool(
						write_unbound_config,
						enable_logging=get_dns_query_logging_enabled(conn),
						enable_blocklist=get_dns_blocklist_enabled(conn),
						upstream_dns=get_dns_upstream_servers(conn),
						enable_dnssec=get_dnssec_enabled(conn),
						listen_addrs_ipv4=listen_ipv4,
						listen_addrs_ipv6=listen_ipv6,
					)
					ok, msg = await unbound.start()
					if ok:
						set_dns_service_enabled(conn, True)
						_log.info("UNBOUND_AUTO_STARTED (first interface created)")
					else:
						_log.warning("Failed to auto-start Unbound: %s", msg)
			except Exception as exc:
				_log.warning("Exception during Unbound auto-start: %s", exc)

	data = {
		"name": payload.name,
		"public_key": public_key,
		"address": payload.address,
		"address6": v6_str,
		"listen_port": payload.listen_port,
	}

	# Issue #12: surface DNS regeneration warnings in response
	dns_warning = await _regenerate_split_dns(conn)
	if dns_warning:
		data["warning"] = dns_warning

	return ok_response(data=data)


# Issue #3 (Bug): PUT requires full resource replacement, conflicts with PATCH semantics.
# Current implementation uses PATCH semantics (partial update via model_fields_set).
# Removing @router.put decorator to avoid semantic confusion.
@router.patch("/interfaces/{name}", status_code=200)
async def update_interface(
	request: Request,
	name: str,
	payload: InterfaceUpdate,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Update (patch) a WireGuard interface config in DB and on disk."""
	validate_interface_name(name)

	iface = get_interface(conn, name)
	if not iface:
		raise HTTPException(status_code=404, detail=f"Interface '{name}' not found")

	fields_set = payload.model_fields_set
	if not fields_set:
		raise HTTPException(status_code=422, detail="No fields provided for update")

	new_address = payload.address if "address" in fields_set else iface["address"]
	new_listen_port = payload.listen_port if "listen_port" in fields_set else iface["listen_port"]
	if new_address is None:
		raise HTTPException(status_code=422, detail="address cannot be null")
	if new_listen_port is None:
		raise HTTPException(status_code=422, detail="listen_port cannot be null")

	# Issue #4: strict IP family validation
	try:
		v4 = ipaddress.ip_interface(new_address)
	except ValueError:
		raise HTTPException(status_code=422, detail=f"Invalid address: {new_address}")
	if v4.network.prefixlen == 32:
		raise HTTPException(
			status_code=422,
			detail="address must include a subnet prefix (e.g. /24), not a /32 host address",
		)
	if v4.version != 4:
		raise HTTPException(status_code=422, detail="address must be an IPv4 CIDR")

	v6_str = payload.address6 if "address6" in fields_set else iface["address6"]
	if v6_str:
		try:
			v6_obj = ipaddress.ip_interface(v6_str)
		except ValueError:
			raise HTTPException(status_code=422, detail=f"Invalid IPv6 address: {v6_str}")
		if v6_obj.version != 6:
			raise HTTPException(status_code=422, detail="address6 must be an IPv6 CIDR")
		if v6_obj.network.prefixlen == 128:
			raise HTTPException(
				status_code=422,
				detail="address6 must include a subnet prefix (e.g. /64), not a /128 host address",
			)

	new_dns = payload.dns if "dns" in fields_set else iface["dns"]
	new_post_up = payload.post_up if "post_up" in fields_set else iface["post_up"]
	new_post_down = payload.post_down if "post_down" in fields_set else iface["post_down"]

	# Check for subnet overlap / port conflict with other interfaces
	new_v4_net = v4.network
	new_v6_net = ipaddress.ip_interface(v6_str).network if v6_str else None
	for other in list_interfaces(conn):
		if other["name"] == name:
			continue
		if other["address"]:
			try:
				other_v4 = ipaddress.ip_interface(other["address"]).network
				if new_v4_net.overlaps(other_v4):
					raise HTTPException(
						status_code=409,
						detail=f"IPv4 subnet {new_v4_net} overlaps with interface '{other['name']}' ({other_v4})",
					)
			except ValueError as exc:
				# Issue #19: Log invalid DB entries at DEBUG level for diagnostic visibility
				_log.debug("Skipping invalid IPv4 address in DB for interface %s: %s", other["name"], exc)
				pass
		if new_v6_net and other["address6"]:
			try:
				other_v6 = ipaddress.ip_interface(other["address6"]).network
				if new_v6_net.overlaps(other_v6):
					raise HTTPException(
						status_code=409,
						detail=f"IPv6 subnet {new_v6_net} overlaps with interface '{other['name']}' ({other_v6})",
					)
			except ValueError as exc:
				# Issue #19: Log invalid DB entries at DEBUG level for diagnostic visibility
				_log.debug("Skipping invalid IPv6 address in DB for interface %s: %s", other["name"], exc)
				pass
		if other["listen_port"] == new_listen_port:
			raise HTTPException(
				status_code=409,
				detail=f"Listen port {new_listen_port} is already used by interface '{other['name']}'",
			)

	# Issue #2: validate hook scripts before writing
	try:
		if new_post_up:
			_validate_hook(new_post_up, "PostUp")
		if new_post_down:
			_validate_hook(new_post_down, "PostDown")
	except ValueError as exc:
		raise HTTPException(status_code=422, detail=str(exc))

	# AUDIT: log PostUp/PostDown script changes
	if "post_up" in fields_set and new_post_up != iface["post_up"]:
		_log.warning(
			"INTERFACE_SCRIPT_CHANGED name=%s type=PostUp old=%s new=%s",
			name,
			_script_fingerprint(iface["post_up"]),
			_script_fingerprint(new_post_up),
		)
	if "post_down" in fields_set and new_post_down != iface["post_down"]:
		_log.warning(
			"INTERFACE_SCRIPT_CHANGED name=%s type=PostDown old=%s new=%s",
			name,
			_script_fingerprint(iface["post_down"]),
			_script_fingerprint(new_post_down),
		)

	cfg = get_config(request)
	config_path = WG_CONFIG_PATH
	conf_file = config_path / f"{name}.conf"

	# Handle show_on_dashboard field (DB-only, not in config file)
	# Issue #7 (Bug): Use sentinel to distinguish "not provided" from "explicitly False"
	_UNSET = object()
	new_show_on_dashboard = _UNSET
	if "show_on_dashboard" in fields_set:
		new_show_on_dashboard = payload.show_on_dashboard
	# Only pass to DB if explicitly set, otherwise db_update_interface keeps existing value
	new_show_on_dashboard_db = new_show_on_dashboard if new_show_on_dashboard is not _UNSET else None

	old = {
		"address": iface["address"],
		"address6": iface["address6"],
		"listen_port": iface["listen_port"],
		"dns": iface["dns"],
		"post_up": iface["post_up"],
		"post_down": iface["post_down"],
	}

	old_config_content = None
	if conf_file.exists():
		try:
			old_config_content = conf_file.read_text()
		except OSError:
			pass  # Continue without backup; rollback will be DB-only

	try:
		with transaction(conn, immediate=True):
			db_update_interface(
				conn,
				name=name,
				address=new_address,
				address6=v6_str,
				listen_port=new_listen_port,
				dns=new_dns,
				post_up=new_post_up,
				post_down=new_post_down,
				show_on_dashboard=new_show_on_dashboard_db,
			)
			write_interface_config(
				config_path=config_path,
				name=name,
				private_key=iface["private_key"],
				address=new_address,
				address6=v6_str,
				listen_port=new_listen_port,
				dns=new_dns,
				post_up=new_post_up,
				post_down=new_post_down,
				conn=conn,
				pepper=cfg.secret_key,
			)
	except Exception:
		_log.exception("INTERFACE_UPDATE_FAILED name=%s", name)
		if old_config_content and conf_file.exists():
			try:
				conf_file.write_text(old_config_content)
			except OSError:
				_log.exception("Failed to restore config file during rollback for %s", name)
		# Issue #9: generic message to client
		raise HTTPException(status_code=500, detail="Failed to update interface config; changes were rolled back")

	code, _, _ = await run_wg_command("wg", "show", name)
	
	# Check if only show_on_dashboard was changed (no config-relevant changes)
	config_relevant_fields = {"address", "address6", "listen_port", "dns", "post_up", "post_down"}
	config_changed = bool(fields_set & config_relevant_fields)
	
	# Only require restart if interface is active AND config was actually changed
	restart_required = (code == 0) and config_changed

	data = {
		"name": name,
		"address": new_address,
		"address6": v6_str,
		"listen_port": new_listen_port,
		"dns": new_dns,
		"restart_required": restart_required,
	}

	# Issue #12: surface DNS regeneration warnings in response
	dns_warning = await _regenerate_split_dns(conn)
	if dns_warning:
		data["warning"] = dns_warning

	return ok_response(data=data)


@router.delete("/interfaces/{name}", status_code=200)
async def delete_interface(
	name: str,  # Issue #11: removed unused `request: Request`
	conn: sqlite3.Connection = Depends(get_conn),
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Delete a WireGuard interface configuration."""
	validate_interface_name(name)

	config_path = WG_CONFIG_PATH
	conf_file = config_path / f"{name}.conf"

	db_exists = get_interface(conn, name) is not None
	file_exists = conf_file.exists()

	# Check if interface is active in kernel
	code, _, _ = await run_wg_command("wg", "show", name)
	is_active = code == 0

	if not db_exists and not file_exists and not is_active:
		raise HTTPException(status_code=404, detail=f"Interface '{name}' not found")

	# Bring down active interface
	if is_active:
		if file_exists:
			# Normal case: config file exists, use wg-quick
			code, _, stderr = await run_wg_command("wg-quick", "down", name)
			if code != 0:
				_log.warning("Failed to bring down interface %s via wg-quick: %s", name, stderr)
		else:
			# Orphaned interface: config file missing, use ip link commands directly
			_log.warning("INTERFACE_DELETE_ORPHANED name=%s (no config file, using ip link)", name)
			code, _, stderr = await run_wg_command("ip", "link", "set", name, "down")
			if code != 0:
				_log.warning("Failed to set interface %s down: %s", name, stderr)
			code, _, stderr = await run_wg_command("ip", "link", "delete", name)
			if code != 0:
				_log.warning("Failed to delete interface %s: %s", name, stderr)

	# Delete file before DB rows to avoid half-deleted DB state on file unlink errors.
	if file_exists:
		try:
			conf_file.unlink()
		except OSError:
			_log.exception("INTERFACE_FILE_DELETE_FAILED name=%s", name)
			raise HTTPException(status_code=500, detail="Failed to delete interface config file")

	# Issue #8: use DB-layer function instead of raw SQL
	if db_exists:
		# Issue #1 (Critical): Wrap DB operations in transaction for atomicity
		# Issue #5 (Security): Get peers before deletion but delete TSDB data AFTER successful DB delete
		try:
			peers = await run_in_threadpool(get_all_peers, conn, name)
		except Exception:
			_log.exception("Failed to fetch peers for interface %s", name)
			peers = []  # Continue with DB delete even if peer fetch fails

		try:
			with transaction(conn, immediate=True):
				deleted = delete_peers_by_interface(conn, name)
				_log.info("INTERFACE_PEERS_DELETED name=%s count=%d", name, deleted)
				db_delete_interface(conn, name)
		except Exception:
			_log.exception("INTERFACE_DB_DELETE_FAILED name=%s", name)
			raise HTTPException(status_code=500, detail="Failed to delete interface from database")

		# Issue #5: Clean up TSDB data only after successful DB deletion
		for peer in peers:
			public_key = peer["public_key"]
			try:
				await run_in_threadpool(tsdb.delete_peer_data, tsdb_dir, public_key)
			except Exception:
				_log.exception("Failed to delete TSDB data for peer %s...", public_key[:8])

	_log.info("INTERFACE_DELETED name=%s", name)

	# Auto-stop Unbound if no interfaces remain
	remaining_interfaces = list_interfaces(conn)
	if not remaining_interfaces:
		try:
			if unbound.is_unbound_installed():
				is_running = await unbound.is_running()
				if is_running:
					ok, msg = await unbound.stop()
					if ok:
						set_dns_service_enabled(conn, False)
						_log.info("UNBOUND_AUTO_STOPPED (no interfaces remaining)")
					else:
						_log.warning("Failed to auto-stop Unbound: %s", msg)
		except Exception as exc:
			_log.warning("Exception during Unbound auto-stop: %s", exc)

	# Issue #12: surface DNS regeneration warnings in response
	dns_warning = await _regenerate_split_dns(conn)
	msg = f"Interface '{name}' deleted"
	if dns_warning:
		return ok_response(message=msg, data={"warning": dns_warning})
	return ok_response(message=msg)


# ---------------------------------------------------------------------------
# Next available subnet endpoint
# ---------------------------------------------------------------------------


@router.get("/interfaces/_next-subnet")
@router.get("/interfaces/next-subnet")
async def get_next_subnet(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Calculate the next available IPv4/IPv6 subnet and port for a new interface.

	Scans existing interfaces and finds unused subnets in the 10.13.X.0/24 range
	and fd13:13:X::/64 range.
	"""
	interfaces = list_interfaces(conn)

	# Collect used third octets (for 10.13.X.0/24 pattern)
	used_v4_octets: set[int] = set()
	# Collect used fourth hex group (for fd13:13:X::/64 pattern)
	used_v6_groups: set[int] = set()
	# Collect used ports
	used_ports: set[int] = set()

	for iface in interfaces:
		# Parse IPv4 address
		addr_v4 = iface["address"]
		if addr_v4:
			try:
				net = ipaddress.ip_interface(addr_v4)
				octets = net.ip.packed
				# Check if it matches 10.13.X.Y pattern
				if octets[0] == 10 and octets[1] == 13:
					used_v4_octets.add(octets[2])
			except (ValueError, TypeError):
				pass

		# Parse IPv6 address
		addr_v6 = iface["address6"]
		if addr_v6:
			try:
				net6 = ipaddress.ip_interface(addr_v6)
				# Check if it matches fd13:13:X:: pattern
				parts = net6.ip.exploded.split(":")
				if parts[0] == "fd13" and parts[1] == "0013":
					# Third group is the variable part
					used_v6_groups.add(int(parts[2], 16))
			except (ValueError, TypeError):
				pass

		# Collect used port
		port = iface["listen_port"]
		if port:
			used_ports.add(int(port))

	# Find next available IPv4 octet (10.13.13.0/24 ... 10.13.254.0/24)
	next_v4_octet = 13
	while next_v4_octet in used_v4_octets and next_v4_octet <= 254:
		next_v4_octet += 1
	if next_v4_octet > 254:
		raise HTTPException(status_code=409, detail="No available IPv4 subnets in 10.13.x.0/24 range")

	# Find next available IPv6 group
	next_v6_group = 13
	while next_v6_group in used_v6_groups and next_v6_group <= 0xFFFF:
		next_v6_group += 1
	if next_v6_group > 0xFFFF:
		raise HTTPException(status_code=409, detail="No available IPv6 subnets in fd13:13:x::/64 range")

	# Find next available port (start at 51820)
	next_port = 51820
	while next_port in used_ports and next_port <= 65535:
		next_port += 1
	if next_port > 65535:
		raise HTTPException(status_code=409, detail="No available listen ports in range 51820-65535")

	# Construct suggested addresses
	suggested_v4 = f"10.13.{next_v4_octet}.1/24"
	suggested_v6 = f"fd13:13:{next_v6_group:x}::1/64"

	return ok_response(data={
		"address": suggested_v4,
		"address6": suggested_v6,
		"listen_port": next_port,
	})
