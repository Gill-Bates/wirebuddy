#!/usr/bin/env python3
#
# app/api/wireguard_interfaces.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard interface management endpoints (list/get/up/down)."""

from __future__ import annotations

from ..db.sqlite_interfaces import (
	get_interface as db_get_interface,
	list_interfaces as db_list_interfaces,
)

import logging
import sqlite3

from fastapi import APIRouter, Depends, HTTPException

from .response import ok_response
from ..utils.deps import get_conn
from ..utils.config import WG_CONFIG_PATH
from .auth import get_current_user, require_admin
from .wireguard_utils import validate_interface_name, run_wg_command
from .wireguard_isolation import apply_client_isolation_runtime, cleanup_client_isolation

_log = logging.getLogger(__name__)

router = APIRouter()

__all__ = ["router"]


@router.get("/interfaces")
async def list_interfaces(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""List all WireGuard interfaces from database, config files, and active state."""
	config_path = WG_CONFIG_PATH
	
	db_interfaces: set[str] = set()
	for row in db_list_interfaces(conn):
		db_interfaces.add(row["name"])
	
	active_interfaces: set[str] = set()
	code, stdout, stderr = await run_wg_command("wg", "show", "interfaces")
	if code == 0 and stdout.strip():
		active_interfaces = set(stdout.strip().split())
	
	config_files: set[str] = set()
	if config_path.is_dir():
		for conf in config_path.glob("*.conf"):
			config_files.add(conf.stem)
	
	all_interfaces = sorted(db_interfaces | config_files | active_interfaces)
	result = []
	for name in all_interfaces:
		result.append({
			"name": name,
			"in_database": name in db_interfaces,
			"has_config_file": name in config_files,
			"is_active": name in active_interfaces,
		})
	
	return ok_response(data={"interfaces": result}, interfaces=result)


@router.get("/interfaces/{name}")
async def get_interface(
	name: str,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get details of a specific WireGuard interface."""
	validate_interface_name(name)
	

	db_iface = db_get_interface(conn, name)
	config_file = WG_CONFIG_PATH / f"{name}.conf"
	has_config = config_file.is_file()
	
	code, stdout, stderr = await run_wg_command("wg", "show", name)
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
		"peers": [],
	}
	
	# If not active, populate from stored config
	if not is_active:
		if db_iface:
			result["listen_port"] = db_iface["listen_port"]
			result["address"] = db_iface["address"]
			result["address6"] = db_iface["address6"]
		return ok_response(data=result)
	
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
	
	return ok_response(data=result)


@router.post("/interfaces/{name}/up")
async def interface_up(
	name: str,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Bring up a WireGuard interface."""
	validate_interface_name(name)
	
	code, stdout, stderr = await run_wg_command("wg-quick", "up", name)
	if code != 0:
		raise HTTPException(status_code=500, detail=f"Failed to bring up interface: {stderr}")

	# Ensure client-isolation firewall rules are applied immediately.
	isolation_result = await apply_client_isolation_runtime(name, conn)
	
	_log.info("INTERFACE_UP name=%s", name)
	
	# Warn if isolation rules failed (security concern)
	if isolation_result.rules_failed > 0 or isolation_result.errors:
		_log.warning(
			"INTERFACE_UP isolation partial failure: name=%s failed=%d errors=%s",
			name, isolation_result.rules_failed, isolation_result.errors,
		)
		return ok_response(
			message=f"Interface {name} is up",
			isolation_warnings={
				"rules_failed": isolation_result.rules_failed,
				"errors": isolation_result.errors,
			},
		)
	
	return ok_response(message=f"Interface {name} is up")


@router.post("/interfaces/{name}/down")
async def interface_down(
	name: str,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Bring down a WireGuard interface."""
	validate_interface_name(name)
	
	# Clean up isolation chains before bringing interface down
	# (uses database as source of truth, not PostDown scripts)
	await cleanup_client_isolation(name)
	
	code, stdout, stderr = await run_wg_command("wg-quick", "down", name)
	if code != 0:
		raise HTTPException(status_code=500, detail=f"Failed to bring down interface: {stderr}")
	
	_log.info("INTERFACE_DOWN name=%s", name)
	return ok_response(message=f"Interface {name} is down")


@router.get("/interfaces/{name}/config")
async def get_interface_config(
	name: str,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Get stored configuration fields for an interface (for UI editing)."""
	validate_interface_name(name)

	iface = db_get_interface(conn, name)
	if not iface:
		raise HTTPException(status_code=404, detail=f"Interface '{name}' not found in database")

	# Only expose safe fields at top level (not post_up/post_down shell commands)
	return ok_response(
		data={
			"name": iface["name"],
			"address": iface["address"],
			"address6": iface["address6"],
			"listen_port": iface["listen_port"],
			"dns": iface["dns"],
			"post_up": iface["post_up"],
			"post_down": iface["post_down"],
			"is_enabled": bool(iface["is_enabled"]),
		},
		name=iface["name"],
		address=iface["address"],
		address6=iface["address6"],
		listen_port=iface["listen_port"],
		dns=iface["dns"],
		is_enabled=bool(iface["is_enabled"]),
	)
