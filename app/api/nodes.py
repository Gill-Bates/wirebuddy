#!/usr/bin/env python3
#
# app/api/nodes.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Node management API — admin-only CRUD for remote VPN nodes."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import sqlite3
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from ..api.auth import require_admin
from ..api.response import ok_response
from ..node.notifier import notify_node_removed
from ..db.sqlite_nodes import (
	create_node,
	delete_node,
	get_all_nodes,
	get_node,
	get_node_by_name,
	get_peer_count_for_node,
	get_peers_count_by_node,
	update_node,
	update_node_api_secret,
)
from ..db.sqlite_settings import get_setting
from ..utils.config import get_config
from ..utils.crypto import hash_token
from ..utils.deps import get_conn
from ..utils.node_token import generate_enrollment_token

_log = logging.getLogger(__name__)
_NODE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")
_HOSTNAME_RE = re.compile(
	r"^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)*"
	r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)$"
)

router = APIRouter(tags=["nodes"])


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response Models
# ─────────────────────────────────────────────────────────────────────────────


class _NodePayloadBase(BaseModel):
	"""Shared validation for node create/update payloads."""

	@field_validator("name", "fqdn", mode="before", check_fields=False)
	@classmethod
	def _strip_text_fields(cls, value: Any) -> Any:
		if isinstance(value, str):
			return value.strip()
		return value

	@field_validator("name", check_fields=False)
	@classmethod
	def _validate_name(cls, value: str | None) -> str | None:
		if value is None:
			return value
		if _NODE_NAME_RE.fullmatch(value) is None:
			raise ValueError("Name may only contain letters, numbers, spaces, dots, underscores, and hyphens")
		return value

	@field_validator("fqdn", check_fields=False)
	@classmethod
	def _validate_fqdn(cls, value: str | None) -> str | None:
		if value is None:
			return value

		raw = value.strip()
		if not raw:
			raise ValueError("FQDN / IP address is required")

		try:
			addr = ipaddress.ip_address(raw.strip("[]"))
		except ValueError:
			if ":" in raw:
				raise ValueError("Colons are only allowed in IPv6 addresses; do not include a port")
			if ".." in raw or raw.startswith(".") or raw.endswith("."):
				raise ValueError("Invalid FQDN format")
			if _HOSTNAME_RE.fullmatch(raw) is None:
				raise ValueError("Invalid FQDN / IP address")
			return raw

		return f"[{addr.compressed}]" if addr.version == 6 else str(addr)


class NodeCreate(_NodePayloadBase):
	"""Payload for creating a new remote node."""
	name: str = Field(..., min_length=1, max_length=64, description="Display name (e.g. 'Frankfurt')")
	fqdn: str = Field(..., min_length=1, max_length=253, description="Public FQDN or IP address")
	wg_port: int = Field(default=51820, ge=1, le=65535, description="WireGuard listen port")


class NodeUpdate(_NodePayloadBase):
	"""Payload for updating a node."""
	name: str | None = Field(None, min_length=1, max_length=64)
	fqdn: str | None = Field(None, min_length=1, max_length=253)
	wg_port: int | None = Field(None, ge=1, le=65535)


# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────


def _parse_node_metadata(value: Any, *, node_id: str) -> Any:
	"""Return parsed node metadata when stored as JSON text."""
	if value is None or value == "":
		return None
	if not isinstance(value, str):
		return value
	try:
		return json.loads(value)
	except json.JSONDecodeError:
		_log.warning("Node %s has invalid metadata JSON; returning raw value", node_id)
		return value


def _format_host_for_url(host: str) -> str:
	"""Normalize a host for URL usage, adding IPv6 brackets when needed."""
	clean = host.strip().strip("[]")
	if not clean:
		raise ValueError("Host is empty")
	try:
		addr = ipaddress.ip_address(clean)
	except ValueError:
		return clean
	return f"[{addr.compressed}]" if addr.version == 6 else str(addr)


def _get_master_url(conn: sqlite3.Connection) -> str:
	"""Build the externally reachable master URL for node enrollment tokens.

	Uses gui_external_port if set (for reverse proxy setups), otherwise gui_port.
	Omits port from URL if it's the HTTPS default (443).
	"""
	host = str(get_setting(conn, "wg_fqdn", "") or "").strip()
	if not host or host == "vpn.example.com":
		raise HTTPException(
			status_code=409,
			detail="Server FQDN/IP not configured. Please set 'Server FQDN / IP' in Settings → WireGuard before creating node tokens.",
		)

	# Prefer external port (reverse proxy), fall back to internal GUI port
	external_port = str(get_setting(conn, "gui_external_port", "") or "").strip()
	if external_port and external_port.isdigit() and 1 <= int(external_port) <= 65535:
		port = int(external_port)
	else:
		port_raw = str(get_setting(conn, "gui_port", "8000") or "8000").strip()
		if not port_raw.isdigit() or not (1 <= int(port_raw) <= 65535):
			_log.error("Invalid gui_port setting for node enrollment URL: %r", port_raw)
			raise HTTPException(status_code=500, detail="Server GUI port setting is invalid")
		port = int(port_raw)

	# Omit port for HTTPS default
	if port == 443:
		return f"https://{_format_host_for_url(host)}"
	return f"https://{_format_host_for_url(host)}:{port}"


def _node_to_dict(row: sqlite3.Row, peer_count: int = 0) -> dict[str, Any]:
	"""Convert a node Row to a serialisable dict (strip secret hash)."""
	from datetime import datetime
	from .frontend_pages import _resolve_node_geo_ip
	from .frontend_shared import extract_geo_fields, format_last_seen_label, lookup_ip_cached
	from ..node import notifier as node_notifier
	
	resolved_geo_ip = _resolve_node_geo_ip(row["fqdn"])
	geo_fields = extract_geo_fields(lookup_ip_cached(resolved_geo_ip)) if resolved_geo_ip else {
		"country_code": None,
		"city": None,
		"as_org": None,
	}
	
	# Extract version from metadata
	node_version = None
	metadata = _parse_node_metadata(row["metadata"], node_id=row["id"])
	if isinstance(metadata, dict):
		node_version = metadata.get("version")
	
	# Convert last_seen datetime to formatted label
	last_seen_epoch = 0
	if row["last_seen"]:
		try:
			if isinstance(row["last_seen"], datetime):
				last_seen_epoch = int(row["last_seen"].timestamp())
			elif isinstance(row["last_seen"], str):
				dt = datetime.fromisoformat(row["last_seen"].replace("Z", "+00:00"))
				last_seen_epoch = int(dt.timestamp())
		except (ValueError, TypeError, AttributeError):
			pass
	last_seen_label = format_last_seen_label(last_seen_epoch)
	
	return {
		"id": row["id"],
		"name": row["name"],
		"fqdn": row["fqdn"],
		"wg_port": row["wg_port"],
		"status": row["status"],
		"last_seen": row["last_seen"],
		"last_seen_text": last_seen_label.text,
		"last_seen_class": last_seen_label.css_class,
		"enrolled_at": row["enrolled_at"],
		"created_at": row["created_at"],
		"config_version": row["config_version"],
		"metadata": metadata,
		"peer_count": peer_count,
		"geo_country_code": geo_fields["country_code"],
		"geo_city": geo_fields["city"],
		"geo_as_org": geo_fields["as_org"],
		"node_version": node_version,
		"sse_connected": node_notifier.is_node_connected_sync(row["id"]),
	}


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────


@router.post("")
def create_node_endpoint(
	body: NodeCreate,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_admin),
) -> dict[str, Any]:
	"""Create a new remote node and return the one-time enrollment token."""
	# Validate unique name
	if get_node_by_name(conn, body.name):
		raise HTTPException(status_code=409, detail=f"Node name '{body.name}' already exists")

	cfg = get_config()
	node_id = uuid.uuid4().hex
	master_url = _get_master_url(conn)

	token, api_secret = generate_enrollment_token(
		master_url=master_url,
		node_id=node_id,
		node_name=body.name,
		secret_key=cfg.secret_key,
	)
	secret_hash = hash_token(api_secret)

	create_node(conn, node_id, body.name, body.fqdn, body.wg_port, secret_hash)
	_log.info("Node created: name=%s, id=%s (by user=%s)", body.name, node_id, user["username"])

	return ok_response(
		data={
			"node_id": node_id,
			"enrollment_token": token,
		},
		message="Node created. Copy the enrollment token — it will not be shown again.",
	)


@router.get("")
def list_nodes(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
) -> dict[str, Any]:
	"""List all registered nodes with their status and peer counts."""
	nodes = get_all_nodes(conn)
	counts = get_peers_count_by_node(conn)
	return ok_response(
		data=[_node_to_dict(n, counts.get(n["id"], 0)) for n in nodes],
	)


@router.get("/{node_id}")
def get_node_endpoint(
	node_id: str,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
) -> dict[str, Any]:
	"""Get details for a single node."""
	node = get_node(conn, node_id)
	if not node:
		raise HTTPException(status_code=404, detail="Node not found")
	return ok_response(data=_node_to_dict(node, get_peer_count_for_node(conn, node_id)))


@router.patch("/{node_id}")
def update_node_endpoint(
	node_id: str,
	body: NodeUpdate,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_admin),
) -> dict[str, Any]:
	"""Update a node's name, FQDN, or port."""
	if not get_node(conn, node_id):
		raise HTTPException(status_code=404, detail="Node not found")

	updates = body.model_dump(exclude_none=True)
	if not updates:
		raise HTTPException(status_code=422, detail="No fields to update")

	# Validate unique name if changing
	if body.name is not None:
		existing = get_node_by_name(conn, body.name)
		if existing and existing["id"] != node_id:
			raise HTTPException(status_code=409, detail=f"Node name '{body.name}' already exists")

	update_node(conn, node_id, **updates)
	_log.info("Node updated: id=%s (by user=%s)", node_id, user["username"])
	return ok_response(message="Node updated")


@router.delete("/{node_id}")
async def delete_node_endpoint(
	node_id: str,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_admin),
) -> dict[str, Any]:
	"""Delete a node. Assigned peers are unassigned (node_id set to NULL)."""
	node = get_node(conn, node_id)
	if not node:
		raise HTTPException(status_code=404, detail="Node not found")

	assigned_peer_count = get_peer_count_for_node(conn, node_id)

	# Send removal signal to node before deleting (must happen while SSE auth still works)
	notified = await notify_node_removed(node_id)
	if notified > 0:
		_log.info("Sent removal signal to %d SSE client(s) for node %s", notified, node_id)

	if not delete_node(conn, node_id):
		raise HTTPException(status_code=404, detail="Node not found")
	_log.info("Node deleted: id=%s (by user=%s)", node_id, user["username"])
	message = "Node deleted."
	if assigned_peer_count:
		message = f"Node deleted. {assigned_peer_count} assigned peer(s) have been unassigned."
	return ok_response(
		message=message,
		data={"unassigned_peer_count": assigned_peer_count},
	)


@router.post("/{node_id}/token")
def regenerate_token(
	node_id: str,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_admin),
) -> dict[str, Any]:
	"""Regenerate enrollment token for re-enrollment. Invalidates old token."""
	node = get_node(conn, node_id)
	if not node:
		raise HTTPException(status_code=404, detail="Node not found")

	cfg = get_config()
	master_url = _get_master_url(conn)

	token, api_secret = generate_enrollment_token(
		master_url=master_url,
		node_id=node_id,
		node_name=node["name"],
		secret_key=cfg.secret_key,
	)
	secret_hash = hash_token(api_secret)
	update_node_api_secret(conn, node_id, secret_hash)
	_log.info("Node token regenerated: id=%s (by user=%s)", node_id, user["username"])

	return ok_response(
		data={"enrollment_token": token},
		message="New enrollment token generated. The node must re-enroll.",
	)


@router.post("/{node_id}/restart")
async def restart_node(
	node_id: str,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_admin),
) -> dict[str, Any]:
	"""Request a remote node to restart gracefully.
	
	Sends a restart signal via SSE. The node daemon will shut down
	gracefully and Docker/systemd will restart it.
	"""
	from ..node import notifier as node_notifier
	
	node = get_node(conn, node_id)
	if not node:
		raise HTTPException(status_code=404, detail="Node not found")
	
	if node["status"] != "online":
		raise HTTPException(
			status_code=400,
			detail=f"Cannot restart node in '{node['status']}' status. Node must be online."
		)
	
	notified = await node_notifier.notify_restart(node_id)
	
	if notified == 0:
		raise HTTPException(
			status_code=503,
			detail="Node is not connected via SSE. Restart signal could not be delivered."
		)
	
	_log.info("Restart signal sent to node: id=%s, name=%s (by user=%s)", 
			 node_id, node["name"], user["username"])
	
	return ok_response(
		message=f"Restart signal sent to node '{node['name']}'. The node will restart shortly.",
		data={"notified_clients": notified},
	)
