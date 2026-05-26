#!/usr/bin/env python3
#
# app/api/wireguard_interfaces.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard interface management endpoints (list/get/up/down)."""

from __future__ import annotations

import asyncio
import logging
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from .auth import get_current_user, require_admin
from .response import OkResponse
from .wireguard_isolation import apply_client_isolation_runtime, cleanup_client_isolation
from .wireguard_utils import run_wg_command, validate_interface_name
from ..db.sqlite_interfaces import (
	get_interface as db_get_interface,
	list_interfaces as db_list_interfaces,
)
from ..utils.config import WG_CONFIG_PATH
from ..utils.deps import get_conn
from ..utils.rate_limit import RATE_LIMIT_HEAVY, limiter

_log = logging.getLogger(__name__)
_WG_COMMAND_TIMEOUT_SECONDS = 30.0

router = APIRouter()

__all__ = ["router"]


class InterfaceSummary(BaseModel):
	name: str
	in_database: bool
	has_config_file: bool
	is_configured: bool
	is_active: bool


class InterfaceListPayload(BaseModel):
	interfaces: list[InterfaceSummary]


class InterfacePeer(BaseModel):
	public_key: str
	endpoint: str | None = None
	allowed_ips: str | None = None
	latest_handshake: str | None = None
	transfer: str | None = None


class InterfaceDetailPayload(BaseModel):
	name: str
	is_active: bool
	in_database: bool
	has_config_file: bool
	public_key: str | None = None
	listen_port: int | None = None
	address: str | None = None
	address6: str | None = None
	peers: list[InterfacePeer]


class InterfaceConfigPayload(BaseModel):
	name: str
	address: str
	address6: str | None = None
	listen_port: int
	dns: str | None = None
	post_up: str | None = None
	post_down: str | None = None
	is_enabled: bool
	show_on_dashboard: bool


async def _run_wg_command_with_timeout(*args: str) -> tuple[int, str, str]:
	command = " ".join(args)
	try:
		return await asyncio.wait_for(run_wg_command(*args), timeout=_WG_COMMAND_TIMEOUT_SECONDS)
	except TimeoutError as exc:
		_log.error("WG_COMMAND_TIMEOUT command=%s timeout=%ss", command, _WG_COMMAND_TIMEOUT_SECONDS)
		raise HTTPException(status_code=504, detail=f"Command timed out: {command}") from exc


@router.get("/interfaces", response_model=OkResponse[InterfaceListPayload])
async def list_interfaces(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""List all WireGuard interfaces from database, config files, and active state."""
	config_path = WG_CONFIG_PATH
	
	db_interfaces: set[str] = set()
	for row in await asyncio.to_thread(db_list_interfaces, conn):
		db_interfaces.add(row["name"])
	
	active_interfaces: set[str] = set()
	code, stdout, _ = await _run_wg_command_with_timeout("wg", "show", "interfaces")
	if code == 0 and stdout.strip():
		active_interfaces = set(stdout.strip().split())
	
	config_files: set[str] = set()
	if config_path.is_dir():
		for conf in config_path.glob("*.conf"):
			config_files.add(conf.stem)
	
	all_interfaces = sorted(db_interfaces | config_files | active_interfaces)
	result = []
	for name in all_interfaces:
		in_db = name in db_interfaces
		has_config = name in config_files
		result.append({
			"name": name,
			"in_database": in_db,
			"has_config_file": has_config,
			"is_configured": in_db or has_config,
			"is_active": name in active_interfaces,
		})
	
	return OkResponse[InterfaceListPayload](data=InterfaceListPayload(interfaces=result))


@router.get("/interfaces/{name}", response_model=OkResponse[InterfaceDetailPayload])
async def get_interface(
	name: str,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get details of a specific WireGuard interface."""
	validate_interface_name(name)
	
	db_iface = await asyncio.to_thread(db_get_interface, conn, name)
	config_file = WG_CONFIG_PATH / f"{name}.conf"
	has_config = config_file.is_file()
	
	code, stdout, _ = await _run_wg_command_with_timeout("wg", "show", name)
	is_active = code == 0
	
	# If interface doesn't exist anywhere, return 404
	if not is_active and not db_iface and not has_config:
		raise HTTPException(status_code=404, detail=f"Interface not found: {name}")
	
	# Build result from available sources
	result = {
		"name": name,
		"is_active": is_active,
		"in_database": db_iface is not None,
		"has_config_file": has_config,
		"public_key": None,
		"listen_port": None,
		"address": db_iface["address"] if db_iface else None,
		"address6": db_iface["address6"] if db_iface else None,
		"peers": [],
	}
	
	# If not active, populate from stored config
	if not is_active:
		if db_iface:
			result["listen_port"] = db_iface["listen_port"]
		return OkResponse[InterfaceDetailPayload](data=InterfaceDetailPayload.model_validate(result))
	
	# Parse wg show output for active interface
	lines = stdout.strip().split("\n")
	current_peer = None
	for line in lines:
		line = line.strip()
		if line.startswith("public key:"):
			result["public_key"] = line.split(":", 1)[1].strip()
		elif line.startswith("listening port:"):
			port_str = line.split(":", 1)[1].strip()
			try:
				result["listen_port"] = int(port_str)
			except ValueError:
				_log.warning("Invalid listen port value: %r", port_str)
				result["listen_port"] = None
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
	
	return OkResponse[InterfaceDetailPayload](data=InterfaceDetailPayload.model_validate(result))


@router.post("/interfaces/{name}/up", response_model=OkResponse[None])
@limiter.limit(RATE_LIMIT_HEAVY)
async def interface_up(
	request: Request,
	name: str,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Bring up a WireGuard interface."""
	validate_interface_name(name)
	
	code, _, stderr = await _run_wg_command_with_timeout("wg-quick", "up", name)
	if code != 0:
		raise HTTPException(status_code=500, detail=f"Failed to bring up interface: {stderr}")

	# Ensure client-isolation firewall rules are applied immediately.
	isolation_result = await apply_client_isolation_runtime(name, conn)
	
	_log.info("INTERFACE_UP name=%s", name)
	
	if isolation_result.rules_failed > 0 or isolation_result.errors:
		_log.error(
			"INTERFACE_UP isolation failure: name=%s failed=%d errors=%s",
			name, isolation_result.rules_failed, isolation_result.errors,
		)
		raise HTTPException(
			status_code=500,
			detail=f"Interface up but client isolation failed: {isolation_result.errors}",
		)
	
	return OkResponse[None](message=f"Interface {name} is up")


@router.post("/interfaces/{name}/down", response_model=OkResponse[None])
@limiter.limit(RATE_LIMIT_HEAVY)
async def interface_down(
	request: Request,
	name: str,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Bring down a WireGuard interface."""
	validate_interface_name(name)
	
	# Check if interface exists at all (active or configured)
	config_file = WG_CONFIG_PATH / f"{name}.conf"
	has_config = config_file.is_file()
	
	code, _, _ = await _run_wg_command_with_timeout("wg", "show", name)
	is_active = code == 0
	
	if not is_active:
		raise HTTPException(status_code=400, detail=f"Interface {name} is not active")
	
	# Clean up isolation chains before bringing interface down
	# (uses database as source of truth, not PostDown scripts)
	await cleanup_client_isolation(name)
	
	if has_config:
		# Normal case: config file exists, use wg-quick
		code, _, stderr = await _run_wg_command_with_timeout("wg-quick", "down", name)
		if code != 0:
			raise HTTPException(status_code=500, detail=f"Failed to bring down interface: {stderr}")
	else:
		# Orphaned interface: config file missing (e.g. data dir was deleted)
		# Use ip link commands directly since wg-quick needs the config
		_log.warning("INTERFACE_DOWN_ORPHANED name=%s (no config file, using ip link)", name)
		code, _, stderr = await _run_wg_command_with_timeout("ip", "link", "set", name, "down")
		if code != 0:
			raise HTTPException(status_code=500, detail=f"Failed to set interface down: {stderr}")
		code, _, stderr = await _run_wg_command_with_timeout("ip", "link", "delete", name)
		if code != 0:
			raise HTTPException(status_code=500, detail=f"Failed to delete interface: {stderr}")
	
	_log.info("INTERFACE_DOWN name=%s", name)
	return OkResponse[None](message=f"Interface {name} is down")


@router.post("/interfaces/{name}/restart", response_model=OkResponse[None])
@limiter.limit(RATE_LIMIT_HEAVY)
async def interface_restart(
	request: Request,
	name: str,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Restart a WireGuard interface."""
	validate_interface_name(name)
	
	await cleanup_client_isolation(name)
	down_code, _, down_stderr = await _run_wg_command_with_timeout("wg-quick", "down", name)
	if down_code != 0:
		_log.error("INTERFACE_RESTART down failed: name=%s stderr=%s", name, down_stderr)
		raise HTTPException(status_code=500, detail=f"Failed to stop interface: {down_stderr}")
	
	code, _, stderr = await _run_wg_command_with_timeout("wg-quick", "up", name)
	if code != 0:
		raise HTTPException(status_code=500, detail=f"Failed to restart interface: {stderr}")

	isolation_result = await apply_client_isolation_runtime(name, conn)
	_log.info("INTERFACE_RESTART name=%s", name)
	
	if isolation_result.rules_failed > 0 or isolation_result.errors:
		_log.error(
			"INTERFACE_RESTART isolation failure: name=%s failed=%d errors=%s",
			name, isolation_result.rules_failed, isolation_result.errors,
		)
		raise HTTPException(
			status_code=500,
			detail=f"Interface restart but client isolation failed: {isolation_result.errors}",
		)
	
	return OkResponse[None](message=f"Interface {name} restarted")


@router.get("/interfaces/{name}/config", response_model=OkResponse[InterfaceConfigPayload])
async def get_interface_config(
	name: str,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Get stored configuration fields for an interface (for UI editing)."""
	validate_interface_name(name)

	iface = await asyncio.to_thread(db_get_interface, conn, name)
	if not iface:
		raise HTTPException(status_code=404, detail=f"Interface '{name}' not found in database")
	iface_data = dict(iface)

	payload = InterfaceConfigPayload(
		name=iface_data["name"],
		address=iface_data["address"],
		address6=iface_data["address6"],
		listen_port=iface_data["listen_port"],
		dns=iface_data["dns"],
		post_up=iface_data["post_up"],
		post_down=iface_data["post_down"],
		is_enabled=bool(iface_data["is_enabled"]),
		show_on_dashboard=bool(iface_data.get("show_on_dashboard", True)),
	)
	return OkResponse[InterfaceConfigPayload](data=payload)
