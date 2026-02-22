#!/usr/bin/env python3
#
# app/api/wireguard_interfaces_crud.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard interface create/update/delete endpoints."""

from __future__ import annotations

from ..db.sqlite_interfaces import (
	create_interface as db_create_interface,
	delete_interface as db_delete_interface,
	get_interface,
	update_interface as db_update_interface,
)

import ipaddress
import logging
import sqlite3
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .response import ok_response
from ..utils.config import WG_CONFIG_PATH
from ..utils.deps import get_conn, get_config
from .auth import require_admin
from ..utils.vault import encrypt as vault_encrypt
from .wireguard_utils import run_wg_command, generate_keypair, validate_interface_name
from .wireguard_config import write_interface_config

_log = logging.getLogger(__name__)

router = APIRouter()

__all__ = ["router", "InterfaceCreate", "InterfaceUpdate"]


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
	"""Schema for updating an existing WireGuard interface."""
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
	dns: Optional[str] = Field(default=None, description="DNS servers for clients")
	post_up: Optional[str] = Field(default=None, description="PostUp script")
	post_down: Optional[str] = Field(default=None, description="PostDown script")


def _build_default_firewall_rules(v4_subnet: str, v6_subnet: str | None) -> tuple[str, str]:
	"""Build default PostUp/PostDown iptables rules for NAT and DNS."""
	up_rules = [
		f"iptables -t nat -A POSTROUTING -s {v4_subnet} -o eth0 -j MASQUERADE",
		"iptables -A FORWARD -i %i -j ACCEPT",
		"iptables -A FORWARD -o %i -j ACCEPT",
		"iptables -A INPUT -i %i -p udp --dport 53 -j ACCEPT",
		"iptables -A INPUT -i %i -p tcp --dport 53 -j ACCEPT",
		"iptables -A OUTPUT -o %i -p udp --sport 53 -j ACCEPT",
		"iptables -A OUTPUT -o %i -p tcp --sport 53 -j ACCEPT",
		"iptables -A OUTPUT -o eth0 -p tcp --dport 853 -j ACCEPT",
		"iptables -A OUTPUT -o eth0 -p udp --dport 53 -j ACCEPT",
		"iptables -A OUTPUT -o eth0 -p tcp --dport 53 -j ACCEPT",
	]
	down_rules = [
		f"iptables -t nat -D POSTROUTING -s {v4_subnet} -o eth0 -j MASQUERADE",
		"iptables -D FORWARD -i %i -j ACCEPT",
		"iptables -D FORWARD -o %i -j ACCEPT",
		"iptables -D INPUT -i %i -p udp --dport 53 -j ACCEPT",
		"iptables -D INPUT -i %i -p tcp --dport 53 -j ACCEPT",
		"iptables -D OUTPUT -o %i -p udp --sport 53 -j ACCEPT",
		"iptables -D OUTPUT -o %i -p tcp --sport 53 -j ACCEPT",
		"iptables -D OUTPUT -o eth0 -p tcp --dport 853 -j ACCEPT",
		"iptables -D OUTPUT -o eth0 -p udp --dport 53 -j ACCEPT",
		"iptables -D OUTPUT -o eth0 -p tcp --dport 53 -j ACCEPT",
	]

	if v6_subnet:
		up_rules += [
			f"ip6tables -t nat -A POSTROUTING -s {v6_subnet} -o eth0 -j MASQUERADE",
			"ip6tables -A FORWARD -i %i -j ACCEPT",
			"ip6tables -A FORWARD -o %i -j ACCEPT",
			"ip6tables -A INPUT -i %i -p udp --dport 53 -j ACCEPT",
			"ip6tables -A INPUT -i %i -p tcp --dport 53 -j ACCEPT",
			"ip6tables -A OUTPUT -o %i -p udp --sport 53 -j ACCEPT",
			"ip6tables -A OUTPUT -o %i -p tcp --sport 53 -j ACCEPT",
			"ip6tables -A OUTPUT -o eth0 -p tcp --dport 853 -j ACCEPT",
			"ip6tables -A OUTPUT -o eth0 -p udp --dport 53 -j ACCEPT",
			"ip6tables -A OUTPUT -o eth0 -p tcp --dport 53 -j ACCEPT",
		]
		down_rules += [
			f"ip6tables -t nat -D POSTROUTING -s {v6_subnet} -o eth0 -j MASQUERADE",
			"ip6tables -D FORWARD -i %i -j ACCEPT",
			"ip6tables -D FORWARD -o %i -j ACCEPT",
			"ip6tables -D INPUT -i %i -p udp --dport 53 -j ACCEPT",
			"ip6tables -D INPUT -i %i -p tcp --dport 53 -j ACCEPT",
			"ip6tables -D OUTPUT -o %i -p udp --sport 53 -j ACCEPT",
			"ip6tables -D OUTPUT -o %i -p tcp --sport 53 -j ACCEPT",
			"ip6tables -D OUTPUT -o eth0 -p tcp --dport 853 -j ACCEPT",
			"ip6tables -D OUTPUT -o eth0 -p udp --dport 53 -j ACCEPT",
			"ip6tables -D OUTPUT -o eth0 -p tcp --dport 53 -j ACCEPT",
		]

	return "; ".join(up_rules), "; ".join(down_rules)


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
	try:
		v4 = ipaddress.ip_interface(payload.address)
	except ValueError:
		raise HTTPException(status_code=422, detail=f"Invalid IPv4 address: {payload.address}")
	
	v6_str = payload.address6 or None
	if v6_str:
		try:
			ipaddress.ip_interface(v6_str)
		except ValueError:
			raise HTTPException(status_code=422, detail=f"Invalid IPv6 address: {v6_str}")
	
	private_key, public_key = await generate_keypair()
	
	# Build PostUp/PostDown with IPv4 + IPv6 NAT rules
	post_up = payload.post_up
	post_down = payload.post_down
	
	if not post_up or not post_down:
		v4_subnet = str(v4.network)
		v6_subnet = str(ipaddress.ip_interface(v6_str).network) if v6_str else None
		default_up, default_down = _build_default_firewall_rules(v4_subnet, v6_subnet)
		if not post_up:
			post_up = default_up
		if not post_down:
			post_down = default_down
	
	# Save to database first (source of truth)
	private_key_encrypted = vault_encrypt(private_key, cfg.secret_key)
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
	except Exception as e:
		raise HTTPException(status_code=500, detail=f"Failed to save interface to database: {e}")
	
	# Write config file to /etc/wireguard
	try:
		write_interface_config(
			config_path,
			payload.name,
			private_key_encrypted,
			payload.address,
			payload.listen_port,
			payload.dns,
			post_up,
			post_down,
			conn,
			address6=v6_str,
			pepper=cfg.secret_key,
		)
	except OSError as e:
		# Rollback: remove from DB
		db_delete_interface(conn, payload.name)
		raise HTTPException(status_code=500, detail=f"Failed to write config: {e}")
	
	_log.info("INTERFACE_CREATED name=%s address=%s address6=%s", payload.name, payload.address, v6_str)
	
	# AUDIT: Log PostUp/PostDown scripts (executed as root)
	if post_up:
		_log.info("INTERFACE_SCRIPT_CREATED name=%s type=PostUp script=%s", payload.name, post_up[:100])
	if post_down:
		_log.info("INTERFACE_SCRIPT_CREATED name=%s type=PostDown script=%s", payload.name, post_down[:100])
	
	# Auto-start if this is the first interface (check after successful write)
	if config_path.is_dir():
		existing_count = len(list(config_path.glob("*.conf")))
		if existing_count == 1:  # Just created this one
			try:
				code, stdout, stderr = await run_wg_command("wg-quick", "up", payload.name)
				if code == 0:
					_log.info("INTERFACE_AUTO_STARTED name=%s (first interface)", payload.name)
				else:
					_log.warning("Failed to auto-start first interface %s: %s", payload.name, stderr)
			except Exception as e:
				_log.warning("Exception during auto-start of first interface %s: %s", payload.name, e)

	data = {
		"name": payload.name,
		"public_key": public_key,
		"address": payload.address,
		"address6": v6_str,
		"listen_port": payload.listen_port,
	}
	return ok_response(data=data, **data)


@router.put("/interfaces/{name}", status_code=200)
async def update_interface(
	request: Request,
	name: str,
	payload: InterfaceUpdate,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Update a WireGuard interface config in DB and on disk."""
	validate_interface_name(name)

	iface = get_interface(conn, name)
	if not iface:
		raise HTTPException(status_code=404, detail=f"Interface '{name}' not found")


	try:
		ipaddress.ip_interface(payload.address)
	except ValueError:
		raise HTTPException(status_code=422, detail=f"Invalid IPv4 address: {payload.address}")

	fields_set = payload.model_fields_set
	v6_str = payload.address6 if "address6" in fields_set else iface["address6"]
	if v6_str:
		try:
			ipaddress.ip_interface(v6_str)
		except ValueError:
			raise HTTPException(status_code=422, detail=f"Invalid IPv6 address: {v6_str}")

	new_dns = payload.dns if "dns" in fields_set else iface["dns"]
	new_post_up = payload.post_up if "post_up" in fields_set else iface["post_up"]
	new_post_down = payload.post_down if "post_down" in fields_set else iface["post_down"]

	# AUDIT: Log PostUp/PostDown script changes (executed as root)
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
		"dns": iface["dns"],
		"post_up": iface["post_up"],
		"post_down": iface["post_down"],
	}
	

	old_config_content = None
	if conf_file.exists():
		try:
			old_config_content = conf_file.read_text()
		except OSError:
			pass  # Continue without backup, rollback will be DB-only

	try:
		db_update_interface(
			conn,
			name=name,
			address=payload.address,
			address6=v6_str,
			listen_port=payload.listen_port,
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
		# Best-effort rollback: restore DB and config file
		try:
			db_update_interface(
				conn,
				name=name,
				address=old["address"],
				address6=old["address6"],
				listen_port=old["listen_port"],
				dns=old["dns"],
				post_up=old["post_up"],
				post_down=old["post_down"],
			)
			# Restore config file if we have a backup
			if old_config_content and conf_file.exists():
				try:
					conf_file.write_text(old_config_content)
				except OSError:
					_log.exception("Failed to restore config file during rollback for %s", name)
		except Exception:
			_log.exception("Failed to rollback interface update for %s", name)
		raise HTTPException(status_code=500, detail=f"Failed to update interface config: {exc}")

	# Check if restart is required
	code, _, _ = await run_wg_command("wg", "show", name)
	restart_required = (code == 0)

	data = {
		"name": name,
		"address": payload.address,
		"address6": v6_str,
		"listen_port": payload.listen_port,
		"dns": new_dns,
		"restart_required": restart_required,
	}
	return ok_response(data=data, **data)


@router.delete("/interfaces/{name}", status_code=200)
async def delete_interface(
	request: Request,
	name: str,
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
	
	# Delete associated peers first (no CASCADE in schema)
	if db_exists:
		try:
			conn.execute("DELETE FROM peers WHERE interface = ?", (name,))
			conn.commit()
			_log.info("INTERFACE_PEERS_DELETED name=%s", name)
		except Exception as e:
			_log.warning("Failed to delete peers for interface %s: %s", name, e)
	

	if db_exists:
		db_delete_interface(conn, name)
	

	if file_exists:
		try:
			conf_file.unlink()
		except OSError as e:
			raise HTTPException(status_code=500, detail=f"Failed to delete config: {e}")
	
	_log.info("INTERFACE_DELETED name=%s", name)
	
	return ok_response(message=f"Interface '{name}' deleted")
