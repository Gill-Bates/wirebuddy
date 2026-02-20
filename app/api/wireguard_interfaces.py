#!/usr/bin/env python3
#
# app/api/wireguard_interfaces.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard interface management endpoints (list/get/up/down)."""

from __future__ import annotations

from ..db.sqlite_interfaces import (
	get_interface as db_get_interface,
)

import logging
import sqlite3

from fastapi import APIRouter, Depends, HTTPException

from .response import ok_response
from ..utils.deps import get_conn
from ..utils.config import WG_CONFIG_PATH
from .auth import get_current_user, require_admin
from .wireguard_utils import validate_interface_name, run_wg_command
from .wireguard_isolation import apply_client_isolation_runtime

_log = logging.getLogger(__name__)

router = APIRouter()

__all__ = ["router"]


@router.get("/interfaces")
async def list_interfaces(
	_: sqlite3.Row = Depends(get_current_user),
):
	"""List all WireGuard interfaces (both configured and active)."""
	config_path = WG_CONFIG_PATH
	
	# Get active interfaces from wg
	active_interfaces: set[str] = set()
	code, stdout, stderr = await run_wg_command("wg", "show", "interfaces")
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
async def get_interface(
	name: str,
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get details of a specific WireGuard interface."""
	# Validate interface name
	validate_interface_name(name)
	
	code, stdout, stderr = await run_wg_command("wg", "show", name)
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
	validate_interface_name(name)
	
	code, stdout, stderr = await run_wg_command("wg-quick", "up", name)
	if code != 0:
		raise HTTPException(status_code=500, detail=f"Failed to bring up interface: {stderr}")

	# Ensure client-isolation firewall rules are applied immediately.
	await apply_client_isolation_runtime(name, conn)
	
	_log.info("INTERFACE_UP name=%s", name)
	return ok_response(message=f"Interface {name} is up")


@router.post("/interfaces/{name}/down")
async def interface_down(
	name: str,
	_: sqlite3.Row = Depends(require_admin),
):
	"""Bring down a WireGuard interface."""
	validate_interface_name(name)
	
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
