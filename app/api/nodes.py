#!/usr/bin/env python3
#
# app/api/nodes.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Node management API — admin-only CRUD for remote VPN nodes."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import logging
import re
import sqlite3
import unicodedata
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator

from ..api.auth import require_admin
from ..api.response import ok_response
from ..api.speedtest import SPEEDTEST_TSDB_KEY, SPEEDTEST_TSDB_METRIC
from ..api.sse import format_sse_event, format_sse_keepalive
from ..api.frontend_shared import (
	extract_geo_fields,
	format_last_seen_label,
	lookup_ip_cached,
	parse_last_seen_epoch,
	parse_node_metadata as _parse_node_metadata,
	resolve_node_geo_ip,
)
from ..api import nodes_sync
from ..db import tsdb
from ..node import notifier as node_notifier
from ..db.sqlite_nodes import (
	create_node,
	delete_node,
	get_all_nodes,
	get_node,
	get_node_by_fqdn,
	get_node_by_name,
	get_peer_count_for_node,
	get_peers_count_by_node,
	set_node_pending_command,
	update_node,
	update_node_api_secret,
)
from ..db.sqlite_peers import get_peer_by_id
from ..db.sqlite_settings import get_setting
from ..db.sqlite_settings import get_node_speedtest_last_results
from ..utils.config import get_config, WG_CONFIG_PATH
from ..utils.crypto import hash_token
from ..utils.deps import get_conn
from ..utils.node_token import generate_enrollment_token
from ..utils.tsdb_helpers import build_latest_by_node
from .wireguard_config import sync_interface_config
from .wireguard_utils import run_wg_command

_log = logging.getLogger(__name__)
_NODE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")
_HOSTNAME_RE = re.compile(
	r"^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)*"
	r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)$"
)
_NODE_STATUS_ONLINE = "online"
_PENDING_COMMAND_RESTART = "restart"
_PENDING_COMMAND_SPEEDTEST = "speedtest"
_NODE_NAME_MAX_LEN = 64
_FQDN_MAX_LEN = 253
_PORT_MIN = 1
_PORT_MAX = 65535
_SPEEDTEST_STREAM_TIMEOUT_S = 150
_SPEEDTEST_QUEUE_MAXSIZE = 32
_SPEEDTEST_KEEPALIVE_INTERVAL_S = 15

router = APIRouter(tags=["nodes"])


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response Models
# ─────────────────────────────────────────────────────────────────────────────


class _NodePayloadBase(BaseModel):
	"""Shared validation for node create/update payloads."""

	@field_validator("name", "fqdn", mode="before", check_fields=False)
	@classmethod
	def _strip_text_fields(cls, value: Any) -> Any:
		# check_fields=False is intentional in this base class because fields
		# are declared by subclasses (NodeCreate/NodeUpdate).
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
			if len(raw) > _FQDN_MAX_LEN:
				raise ValueError(f"FQDN must not exceed {_FQDN_MAX_LEN} characters")
			if ".." in raw or raw.startswith(".") or raw.endswith("."):
				raise ValueError("Invalid FQDN format")
			if _HOSTNAME_RE.fullmatch(raw) is None:
				raise ValueError("Invalid FQDN / IP address")
			return raw

		return f"[{addr.compressed}]" if addr.version == 6 else str(addr)


class NodeCreate(_NodePayloadBase):
	"""Payload for creating a new remote node."""
	name: str = Field(..., min_length=1, max_length=_NODE_NAME_MAX_LEN, description="Display name (e.g. 'Frankfurt')")
	fqdn: str = Field(..., min_length=1, max_length=_FQDN_MAX_LEN, description="Public FQDN or IP address")
	wg_port: int = Field(default=51820, ge=_PORT_MIN, le=_PORT_MAX, description="WireGuard listen port")


class NodeUpdate(_NodePayloadBase):
	"""Payload for updating a node."""
	name: str | None = Field(None, min_length=1, max_length=_NODE_NAME_MAX_LEN)
	fqdn: str | None = Field(None, min_length=1, max_length=_FQDN_MAX_LEN)
	wg_port: int | None = Field(None, ge=_PORT_MIN, le=_PORT_MAX)


# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────


def _get_node_or_404(conn: sqlite3.Connection, node_id: str) -> sqlite3.Row:
	"""Fetch a node row or raise HTTP 404."""
	node = get_node(conn, node_id)
	if not node:
		raise HTTPException(status_code=404, detail="Node not found")
	return node


def _sanitize_host_chars(host: str) -> str:
	"""Reject control characters in host string to prevent header injection."""
	for ch in host:
		cat = unicodedata.category(ch)
		if cat.startswith("C") or ch in "\r\n\t":
			raise ValueError(f"Invalid character in host: {ch!r}")
	return host


def _is_private_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
	"""Return True if addr is private/loopback/link-local/ULA (Python-version-safe)."""
	if addr.is_private or addr.is_loopback or addr.is_link_local:
		return True
	# ULA (fc00::/7) — not marked as private in Python < 3.11
	if isinstance(addr, ipaddress.IPv6Address):
		return addr in ipaddress.ip_network("fc00::/7")
	return False


def _format_host_for_url(host: str) -> str:
	"""Normalize a host for URL usage, adding IPv6 brackets when needed."""
	clean = _sanitize_host_chars(host.strip())
	clean = re.sub(r"^https?://", "", clean, flags=re.IGNORECASE)
	clean = clean.rstrip("/")
	if any(ch in clean for ch in ("/", "?", "#", "@")):
		raise ValueError("Host must not contain URL path, query, fragment, or credentials")

	# Bracketed IPv6 with optional port: [::1] or [::1]:8443
	if clean.startswith("["):
		end = clean.find("]")
		if end > 0:
			inner = clean[1:end]
			rest = clean[end + 1 :].strip()
			if rest and re.fullmatch(r":\d{1,5}", rest):
				raise ValueError("Do not include a port in host settings")
			if rest:
				raise ValueError("Invalid bracketed IPv6 host")
			clean = inner

	# Unbracketed host: strip optional :port only for hostnames/IPv4
	if clean.count(":") <= 1 and ":" in clean:
		_host_part, port_part = clean.rsplit(":", 1)
		if port_part.isdigit():
			raise ValueError("Do not include a port in host settings")

	clean = clean.strip().strip("[]")
	if not clean:
		raise ValueError("Host is empty")
	try:
		addr = ipaddress.ip_address(clean)
	except ValueError:
		return clean
	# Unwrap IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) before SSRF check
	if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
		addr = addr.ipv4_mapped
	if _is_private_ip(addr):
		raise ValueError("Private/loopback addresses are not allowed as server FQDN")
	return f"[{addr.compressed}]" if isinstance(addr, ipaddress.IPv6Address) else str(addr)


def _is_valid_hostname_or_ip(value: str) -> bool:
	"""Validate host token as RFC-like hostname or IPv4/IPv6 literal."""
	clean = str(value or "").strip().strip("[]")
	if not clean:
		return False
	try:
		ipaddress.ip_address(clean)
		return True
	except ValueError:
		return _HOSTNAME_RE.fullmatch(clean) is not None


async def _send_node_command(
	*,
	node_id: str,
	command: str,
	notify_func: Callable[[str], Coroutine[Any, Any, int]],
	conn: sqlite3.Connection,
	user: sqlite3.Row,
	action_label: str,
	success_message: str,
) -> dict[str, Any]:
	"""Send a node command via in-memory SSE or DB pending-command fallback."""
	node = get_node(conn, node_id)
	if not node:
		raise HTTPException(status_code=404, detail="Node not found")

	if node["status"] != _NODE_STATUS_ONLINE:
		raise HTTPException(
			status_code=400,
			detail=f"Cannot {action_label.lower()} node in '{node['status']}' status. Node must be online.",
		)

	notified = await notify_func(node_id)

	if notified == 0:
		_log.info(
			"notify_%s: no in-memory queue for node=%s, falling back to DB pending command",
			command,
			node_id,
		)
		try:
			stored = set_node_pending_command(conn, node_id, command)
		except Exception as exc:
			_log.error("Failed to queue pending command '%s' for node=%s: %s", command, node_id, exc)
			raise HTTPException(status_code=500, detail=f"Failed to queue {action_label.lower()} command") from None

		if not stored:
			_log.error("set_node_pending_command returned false for node=%s command=%s", node_id, command)
			raise HTTPException(status_code=500, detail=f"Failed to queue {action_label.lower()} command")

	_log.info("%s signal sent to node: id=%s, name=%s (by user=%s)", action_label, node_id, node["name"], user["username"])
	return ok_response(
		message=success_message.format(node_name=node["name"]),
		data={"notified_clients": notified},
	)


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
	try:
		normalized_host = _format_host_for_url(host)
	except ValueError as exc:
		raise HTTPException(status_code=409, detail=str(exc)) from None
	if not _is_valid_hostname_or_ip(normalized_host):
		raise HTTPException(
			status_code=409,
			detail="Server FQDN/IP in settings is invalid. Please update it in Settings.",
		)

	if port == 443:
		return f"https://{normalized_host}"
	return f"https://{normalized_host}:{port}"


def _generate_node_token(
	conn: sqlite3.Connection,
	node_id: str,
	node_name: str,
) -> tuple[str, str]:
	"""Generate an enrollment token and secret hash for a node.

	Returns:
		(enrollment_token, secret_hash)
	"""
	cfg = get_config()
	master_url = _get_master_url(conn)
	token, api_secret = generate_enrollment_token(
		master_url=master_url,
		node_id=node_id,
		node_name=node_name,
		secret_key=cfg.secret_key,
	)
	return token, hash_token(api_secret)


def _get_latest_speedtests_by_node(
	tsdb_dir: Path,
	conn: sqlite3.Connection,
	node_ids: set[str] | None = None,
) -> dict[str, dict[str, Any]]:
	"""Return the latest recorded speedtest result for each requested node."""
	requested_ids = {str(nid) for nid in node_ids} if node_ids is not None else None
	latest_by_node: dict[str, dict[str, Any]] = {}

	since = datetime.now(timezone.utc) - timedelta(days=90)
	try:
		points = tsdb.query(
			tsdb_dir,
			peer_key=SPEEDTEST_TSDB_KEY,
			metric=SPEEDTEST_TSDB_METRIC,
			since=since,
			limit=2000,
			latest=True,
		)
	except Exception:
		_log.warning("Failed to load speedtest data from TSDB", exc_info=True)
	else:
		all_latest = build_latest_by_node(points)
		latest_by_node.update({
			str(k): v
			for k, v in all_latest.items()
			if k is not None and (requested_ids is None or str(k) in requested_ids)
		})

	if requested_ids:
		latest_by_node.update(get_node_speedtest_last_results(conn, requested_ids))
	return latest_by_node


def _node_to_dict(
	row: sqlite3.Row,
	peer_count: int = 0,
	*,
	last_speedtest: dict[str, Any] | None = None,
) -> dict[str, Any]:
	"""Convert a node Row to a serialisable dict (strip secret hash)."""

	resolved_geo_ip = resolve_node_geo_ip(row["fqdn"])
	geo_fields = extract_geo_fields(lookup_ip_cached(resolved_geo_ip) if resolved_geo_ip else None)
	
	# Extract version from metadata
	node_version = None
	metadata = _parse_node_metadata(row["metadata"], node_id=row["id"])
	if isinstance(metadata, dict):
		node_version = metadata.get("version")
	
	# Convert last_seen datetime to formatted label
	# Bug fix: naive datetimes (no tz suffix) are assumed to be UTC to avoid
	# local-time misinterpretation on servers not running UTC.
	last_seen_epoch = parse_last_seen_epoch(row["last_seen"])
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
		"last_speedtest": last_speedtest,
		"sse_connected": (
			node_notifier.is_node_connected_sync(row["id"])
			if row["status"] == _NODE_STATUS_ONLINE
			else False
		),
	}


# ─────────────────────────────────────────────────────────────────────────────
# Uniqueness Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _assert_node_name_unique(
	conn: sqlite3.Connection,
	name: str,
	*,
	exclude_id: str | None = None,
) -> None:
	"""Raise HTTP 409 if a node with *name* already exists (excluding *exclude_id*)."""
	_assert_node_unique(conn, "name", name, get_node_by_name, exclude_id=exclude_id)


def _assert_node_fqdn_unique(
	conn: sqlite3.Connection,
	fqdn: str,
	*,
	exclude_id: str | None = None,
) -> None:
	"""Raise HTTP 409 if a node with *fqdn* already exists (excluding *exclude_id*)."""
	_assert_node_unique(conn, "FQDN", fqdn, get_node_by_fqdn, exclude_id=exclude_id)


def _assert_node_unique(
	conn: sqlite3.Connection,
	label: str,
	value: str,
	getter: Callable[[sqlite3.Connection, str], sqlite3.Row | None],
	*,
	exclude_id: str | None = None,
) -> None:
	"""Raise HTTP 409 if a node with the given value already exists."""
	existing = getter(conn, value)
	if existing and existing["id"] != exclude_id:
		raise HTTPException(status_code=409, detail=f"Node {label} '{value}' already exists")


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
	# Validate unique name and FQDN before doing any work
	_assert_node_name_unique(conn, body.name)
	_assert_node_fqdn_unique(conn, body.fqdn)

	node_id = uuid.uuid4().hex
	token, secret_hash = _generate_node_token(conn, node_id, body.name)

	try:
		create_node(conn, node_id, body.name, body.fqdn, body.wg_port, secret_hash)
	except sqlite3.IntegrityError:
		# DB-level UNIQUE constraint: catches races that slip past the app-level checks above
		raise HTTPException(status_code=409, detail="A node with that name or FQDN already exists")
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
	"""List all registered nodes with their status and peer counts.

	NOTE: sync – FastAPI threadpools this handler. Contains TSDB file reads
	(_get_latest_speedtests_by_node) and per-node GeoIP lookups (_node_to_dict).
	If node count grows large, convert to async def + asyncio.to_thread.
	"""
	cfg = get_config()
	nodes = get_all_nodes(conn)
	counts = get_peers_count_by_node(conn)
	latest_speedtests = _get_latest_speedtests_by_node(cfg.tsdb_dir, conn, {str(n["id"]) for n in nodes})
	return ok_response(
		data=[
			_node_to_dict(
				n,
				counts.get(n["id"], 0),
				last_speedtest=latest_speedtests.get(str(n["id"])),
			)
			for n in nodes
		],
	)


@router.get("/{node_id}")
def get_node_endpoint(
	node_id: str,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
) -> dict[str, Any]:
	"""Get details for a single node."""
	node = _get_node_or_404(conn, node_id)
	return ok_response(data=_node_to_dict(node, get_peer_count_for_node(conn, node_id)))


@router.patch("/{node_id}")
def update_node_endpoint(
	node_id: str,
	body: NodeUpdate,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_admin),
) -> dict[str, Any]:
	"""Update a node's name, FQDN, or port."""
	# exclude_unset distinguishes "not sent" from "sent as null"
	updates = body.model_dump(exclude_unset=True)
	if not updates:
		raise HTTPException(status_code=422, detail="No fields to update")

	# Validate unique name if changing
	if body.name is not None:
		_assert_node_name_unique(conn, body.name, exclude_id=node_id)

	# Validate unique FQDN if changing
	if body.fqdn is not None:
		_assert_node_fqdn_unique(conn, body.fqdn, exclude_id=node_id)

	try:
		updated = update_node(conn, node_id, **updates)
	except sqlite3.IntegrityError:
		# DB-level UNIQUE constraint: catches races that slip past the app-level checks above
		raise HTTPException(status_code=409, detail="A node with that name or FQDN already exists")
	if not updated:
		raise HTTPException(status_code=404, detail="Node not found")
	_log.info("Node updated: id=%s (by user=%s)", node_id, user["username"])
	return ok_response(message="Node updated")


@router.delete("/{node_id}")
async def delete_node_endpoint(
	node_id: str,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_admin),
) -> dict[str, Any]:
	"""Delete a node. Assigned peers are unassigned (node_id set to NULL)."""
	node = _get_node_or_404(conn, node_id)

	# Pre-read tunnel peer info for WG runtime removal after DB delete
	tunnel_peer_info: tuple[str, str] | None = None
	if node["tunnel_peer_id"]:
		tunnel_peer = get_peer_by_id(conn, node["tunnel_peer_id"])
		if tunnel_peer:
			tunnel_peer_info = (tunnel_peer["public_key"], tunnel_peer["interface"])

	# Send removal signal to node before deleting (must happen while SSE auth still works)
	notified = await node_notifier.notify_node_removed(node_id)
	if notified > 0:
		_log.info("Sent removal signal to %d SSE client(s) for node %s", notified, node_id)

	unassigned_peer_count = delete_node(conn, node_id)
	if unassigned_peer_count is None:
		raise HTTPException(status_code=404, detail="Node not found")

	# Remove tunnel peer from live WireGuard interface (best-effort, don't fail the delete)
	if tunnel_peer_info:
		public_key, interface_name = tunnel_peer_info
		code, _, stderr = await run_wg_command(
			"wg", "set", interface_name,
			"peer", public_key,
			"remove",
		)
		if code == 0:
			_log.info("Removed tunnel peer from WG: node=%s iface=%s", node_id, interface_name)
		else:
			_log.warning(
				"Failed to remove tunnel peer from WG (may not exist): node=%s iface=%s err=%s",
				node_id, interface_name, stderr.strip(),
			)

		# Sync config file to reflect tunnel peer removal
		cfg = get_config()
		try:
			sync_interface_config(
				WG_CONFIG_PATH,
				interface_name,
				conn,
				pepper=cfg.secret_key,
			)
		except Exception as exc:
			_log.warning("Failed to sync config after tunnel peer removal: %s", exc)

	_log.info("Node deleted: id=%s (by user=%s)", node_id, user["username"])
	message = "Node deleted."
	if unassigned_peer_count:
		message = f"Node deleted. {unassigned_peer_count} assigned peer(s) have been unassigned."
	return ok_response(
		message=message,
		data={"unassigned_peer_count": unassigned_peer_count},
	)


@router.post("/{node_id}/token")
def regenerate_token(
	node_id: str,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_admin),
) -> dict[str, Any]:
	"""Regenerate enrollment token for re-enrollment. Invalidates old token."""
	node = _get_node_or_404(conn, node_id)
	token, secret_hash = _generate_node_token(conn, node_id, node["name"])
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
	return await _send_node_command(
		node_id=node_id,
		command=_PENDING_COMMAND_RESTART,
		notify_func=node_notifier.notify_restart,
		conn=conn,
		user=user,
		action_label="Restart",
		success_message="Restart signal sent to node '{node_name}'. The node will restart shortly.",
	)


@router.post("/{node_id}/speedtest")
async def trigger_node_speedtest(
	node_id: str,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_admin),
) -> dict[str, Any]:
	"""Request a remote node to run an immediate speedtest.
	
	Sends a speedtest signal via SSE. The node daemon will run a speedtest
	and submit the results to the master.
	"""
	return await _send_node_command(
		node_id=node_id,
		command=_PENDING_COMMAND_SPEEDTEST,
		notify_func=node_notifier.notify_run_speedtest,
		conn=conn,
		user=user,
		action_label="Speedtest",
		success_message="Speedtest signal sent to node '{node_name}'. Results will appear shortly.",
	)


@router.get("/{node_id}/speedtest/stream")
async def stream_node_speedtest_progress(
	node_id: str,
	request: Request,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_admin),
) -> StreamingResponse:
	"""Stream speedtest progress updates from a remote node via SSE.
	
	This endpoint allows the frontend to receive real-time progress updates
	while a speedtest is running on the node.
	
	Events:
	- event: progress (phase, progress 0-1, message, detail)
	- event: complete (when test finishes)
	- event: timeout (if no updates received for 150s)
	"""
	node = _get_node_or_404(conn, node_id)
	if node["status"] != _NODE_STATUS_ONLINE:
		raise HTTPException(
			status_code=400,
			detail=f"Node is '{node['status']}', cannot stream speedtest progress",
		)
	
	async def event_generator():
		"""Generate SSE events for node speedtest progress."""
		progress_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=_SPEEDTEST_QUEUE_MAXSIZE)
		latest_progress = await nodes_sync.register_speedtest_progress_queue(node_id, progress_queue)
		
		try:
			# Send initial progress if available
			if latest_progress:
				yield format_sse_event("progress", latest_progress)
			
			# Stream progress updates with keepalive to survive proxy idle timeouts.
			remaining_timeout = _SPEEDTEST_STREAM_TIMEOUT_S
			while True:
				if await request.is_disconnected():
					break
				
				try:
					wait_for = min(_SPEEDTEST_KEEPALIVE_INTERVAL_S, remaining_timeout)
					progress = await asyncio.wait_for(progress_queue.get(), timeout=wait_for)
					try:
						serialized = json.dumps(progress)
					except (TypeError, ValueError) as exc:
						_log.warning("Non-serializable speedtest progress dropped: %s", exc)
						serialized = json.dumps({"error": "non-serializable data"})
					yield format_sse_event("progress", json.loads(serialized))
					remaining_timeout = _SPEEDTEST_STREAM_TIMEOUT_S

					# If progress is 100%, send complete event
					if progress.get("progress", 0) >= 1.0:
						yield format_sse_event("complete", {})
						break
				except asyncio.TimeoutError:
					remaining_timeout -= wait_for
					if remaining_timeout <= 0:
						# No updates received within timeout
						yield format_sse_event("timeout", {"message": "No progress updates received"})
						break
					yield format_sse_keepalive()
		finally:
			await nodes_sync.unregister_speedtest_progress_queue(node_id, progress_queue)
	
	return StreamingResponse(
		event_generator(),
		media_type="text/event-stream",
		headers={
			"Cache-Control": "no-cache",
			"X-Accel-Buffering": "no",
		},
	)
