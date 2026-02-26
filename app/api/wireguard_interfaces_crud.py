#!/usr/bin/env python3
#
# app/api/wireguard_interfaces_crud.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard interface create/update/delete endpoints."""

from __future__ import annotations

import ipaddress
import logging
import sqlite3
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .response import ok_response
from ..db.sqlite_interfaces import (
	create_interface as db_create_interface,
	delete_interface as db_delete_interface,
	delete_peers_by_interface,
	get_interface,
	list_interfaces,
	update_interface as db_update_interface,
)
from ..db.sqlite_settings import get_setting
from ..dns.unbound_config import write_local_data_overrides
from ..dns import unbound_process as unbound
from ..utils.config import WG_CONFIG_PATH
from ..utils.deps import get_conn, get_config
from .auth import require_admin
from ..utils.vault import encrypt as vault_encrypt
from .wireguard_utils import run_wg_command, generate_keypair, validate_interface_name
from .wireguard_config import write_interface_config, _validate_hook

_log = logging.getLogger(__name__)

router = APIRouter()

__all__ = ["router", "InterfaceCreate", "InterfaceUpdate"]


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
	except Exception:
		_log.exception("SPLIT_DNS_REGENERATE_FAILED")
		return "Split-DNS regeneration failed; DNS override may be stale"
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
					return parts[0]
	except (OSError, StopIteration, IndexError):
		pass
	_log.warning("Could not detect default route interface, falling back to eth0")
	return "eth0"

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
	client_endpoint_port: Optional[int] = Field(
		default=None,
		ge=1,
		le=65535,
		description="Optional port override for client Endpoint in generated configs",
	)
	dns: Optional[str] = Field(default=None, description="DNS servers for clients")
	post_up: Optional[str] = Field(default=None, description="PostUp script")
	post_down: Optional[str] = Field(default=None, description="PostDown script")


class InterfaceUpdate(BaseModel):
	"""Schema for updating an existing WireGuard interface.

	Note: This endpoint uses PATCH semantics – only explicitly provided
	fields are updated; omitted fields retain their current values.
	"""
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
	client_endpoint_port: Optional[int] = Field(
		default=None,
		ge=1,
		le=65535,
		description="Optional port override for client Endpoint in generated configs",
	)
	dns: Optional[str] = Field(default=None, description="DNS servers for clients")
	post_up: Optional[str] = Field(default=None, description="PostUp script")
	post_down: Optional[str] = Field(default=None, description="PostDown script")


def _build_default_firewall_rules(
	v4_subnet: str,
	v6_subnet: str | None,
	outbound_iface: str = "eth0",
) -> tuple[str, str]:
	"""Build default PostUp/PostDown iptables rules for NAT and DNS."""
	oi = outbound_iface
	up_rules = [
		f"iptables -t nat -A POSTROUTING -s {v4_subnet} -o {oi} -j MASQUERADE",
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
		f"iptables -t nat -D POSTROUTING -s {v4_subnet} -o {oi} -j MASQUERADE",
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

	if v6_subnet:
		up_rules += [
			f"ip6tables -t nat -A POSTROUTING -s {v6_subnet} -o {oi} -j MASQUERADE",
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
			f"ip6tables -t nat -D POSTROUTING -s {v6_subnet} -o {oi} -j MASQUERADE",
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
# Pydantic models
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

	v6_str = payload.address6 or None
	if v6_str:
		try:
			v6_obj = ipaddress.ip_interface(v6_str)
		except ValueError:
			raise HTTPException(status_code=422, detail=f"Invalid IPv6 address: {v6_str}")
		if v6_obj.version != 6:
			raise HTTPException(status_code=422, detail="address6 must be an IPv6 CIDR (e.g. fd00::1/64)")

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
			client_endpoint_port=payload.client_endpoint_port,
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
		db_delete_interface(conn, payload.name)
		conf_file.unlink(missing_ok=True)
		raise HTTPException(status_code=500, detail="Failed to write interface config; the interface was not created")

	_log.info("INTERFACE_CREATED name=%s address=%s address6=%s", payload.name, payload.address, v6_str)
	if post_up:
		_log.info("INTERFACE_SCRIPT_CREATED name=%s type=PostUp script=%s", payload.name, post_up[:100])
	if post_down:
		_log.info("INTERFACE_SCRIPT_CREATED name=%s type=PostDown script=%s", payload.name, post_down[:100])

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

	data = {
		"name": payload.name,
		"public_key": public_key,
		"address": payload.address,
		"address6": v6_str,
		"listen_port": payload.listen_port,
		"client_endpoint_port": payload.client_endpoint_port,
	}

	# Issue #12: surface DNS regeneration warnings in response
	dns_warning = await _regenerate_split_dns(conn)
	if dns_warning:
		data["warning"] = dns_warning

	return ok_response(data=data)


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

	# Issue #4: strict IP family validation
	try:
		v4 = ipaddress.ip_interface(payload.address)
	except ValueError:
		raise HTTPException(status_code=422, detail=f"Invalid address: {payload.address}")
	if v4.version != 4:
		raise HTTPException(status_code=422, detail="address must be an IPv4 CIDR")

	fields_set = payload.model_fields_set
	v6_str = payload.address6 if "address6" in fields_set else iface["address6"]
	if v6_str:
		try:
			v6_obj = ipaddress.ip_interface(v6_str)
		except ValueError:
			raise HTTPException(status_code=422, detail=f"Invalid IPv6 address: {v6_str}")
		if v6_obj.version != 6:
			raise HTTPException(status_code=422, detail="address6 must be an IPv6 CIDR")

	new_dns = payload.dns if "dns" in fields_set else iface["dns"]
	new_post_up = payload.post_up if "post_up" in fields_set else iface["post_up"]
	new_post_down = payload.post_down if "post_down" in fields_set else iface["post_down"]
	new_client_endpoint_port = (
		payload.client_endpoint_port
		if "client_endpoint_port" in fields_set
		else iface["client_endpoint_port"]
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
			(iface["post_up"] or "")[:100],
			(new_post_up or "")[:100],
		)
	if "post_down" in fields_set and new_post_down != iface["post_down"]:
		_log.warning(
			"INTERFACE_SCRIPT_CHANGED name=%s type=PostDown old=%s new=%s",
			name,
			(iface["post_down"] or "")[:100],
			(new_post_down or "")[:100],
		)

	cfg = get_config(request)
	config_path = WG_CONFIG_PATH
	conf_file = config_path / f"{name}.conf"

	old = {
		"address": iface["address"],
		"address6": iface["address6"],
		"listen_port": iface["listen_port"],
		"client_endpoint_port": iface["client_endpoint_port"],
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
		# Issue #3: fixed client_endpoint_port indentation
		db_update_interface(
			conn,
			name=name,
			address=payload.address,
			address6=v6_str,
			listen_port=payload.listen_port,
			client_endpoint_port=new_client_endpoint_port,
			dns=new_dns,
			post_up=new_post_up,
			post_down=new_post_down,
		)
		write_interface_config(
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
		_log.exception("INTERFACE_UPDATE_FAILED name=%s", name)
		# Best-effort rollback
		try:
			# Issue #3: fixed client_endpoint_port indentation
			db_update_interface(
				conn,
				name=name,
				address=old["address"],
				address6=old["address6"],
				listen_port=old["listen_port"],
				client_endpoint_port=old["client_endpoint_port"],
				dns=old["dns"],
				post_up=old["post_up"],
				post_down=old["post_down"],
			)
			if old_config_content and conf_file.exists():
				try:
					conf_file.write_text(old_config_content)
				except OSError:
					_log.exception("Failed to restore config file during rollback for %s", name)
		except Exception:
			_log.exception("Failed to rollback interface update for %s", name)
		# Issue #9: generic message to client
		raise HTTPException(status_code=500, detail="Failed to update interface config; changes were rolled back")

	code, _, _ = await run_wg_command("wg", "show", name)
	restart_required = (code == 0)

	data = {
		"name": name,
		"address": payload.address,
		"address6": v6_str,
		"listen_port": payload.listen_port,
		"client_endpoint_port": new_client_endpoint_port,
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
	_: sqlite3.Row = Depends(require_admin),
):
	"""Delete a WireGuard interface configuration."""
	validate_interface_name(name)

	config_path = WG_CONFIG_PATH
	conf_file = config_path / f"{name}.conf"

	db_exists = get_interface(conn, name) is not None
	file_exists = conf_file.exists()

	if not db_exists and not file_exists:
		raise HTTPException(status_code=404, detail=f"Interface '{name}' not found")

	code, _, _ = await run_wg_command("wg", "show", name)
	if code == 0:
		await run_wg_command("wg-quick", "down", name)

	# Issue #8: use DB-layer function instead of raw SQL
	if db_exists:
		try:
			deleted = delete_peers_by_interface(conn, name)
			_log.info("INTERFACE_PEERS_DELETED name=%s count=%d", name, deleted)
		except Exception as exc:
			_log.warning("Failed to delete peers for interface %s: %s", name, exc)

		db_delete_interface(conn, name)

	if file_exists:
		try:
			conf_file.unlink()
		except OSError:
			# Issue #9: log full error, return generic message
			_log.exception("INTERFACE_FILE_DELETE_FAILED name=%s", name)
			raise HTTPException(status_code=500, detail="Failed to delete interface config file")

	_log.info("INTERFACE_DELETED name=%s", name)

	# Issue #12: surface DNS regeneration warnings in response
	dns_warning = await _regenerate_split_dns(conn)
	msg = f"Interface '{name}' deleted"
	if dns_warning:
		return ok_response(message=msg, data={"warning": dns_warning})
	return ok_response(message=msg)
