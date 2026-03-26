#!/usr/bin/env python3
#
# app/api/nodes.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Node management API — admin-only CRUD for remote VPN nodes."""

from __future__ import annotations

import logging
import sqlite3
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..api.auth import require_admin
from ..api.response import ok_response
from ..db.sqlite_nodes import (
	create_node,
	delete_node,
	get_all_nodes,
	get_node,
	get_node_by_name,
	get_peers_count_by_node,
	update_node,
	update_node_api_secret,
)
from ..utils.config import get_config
from ..utils.crypto import hash_token
from ..utils.deps import get_conn
from ..utils.node_token import generate_enrollment_token

_log = logging.getLogger(__name__)

router = APIRouter(tags=["nodes"])


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response Models
# ─────────────────────────────────────────────────────────────────────────────


class NodeCreate(BaseModel):
	"""Payload for creating a new remote node."""
	name: str = Field(..., min_length=1, max_length=64, description="Display name (e.g. 'Frankfurt')")
	fqdn: str = Field(..., min_length=1, max_length=253, description="Public FQDN or IP address")
	wg_port: int = Field(default=51820, ge=1, le=65535, description="WireGuard listen port")


class NodeUpdate(BaseModel):
	"""Payload for updating a node."""
	name: str | None = Field(None, min_length=1, max_length=64)
	fqdn: str | None = Field(None, min_length=1, max_length=253)
	wg_port: int | None = Field(None, ge=1, le=65535)


# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────


def _node_to_dict(row: sqlite3.Row, peer_count: int = 0) -> dict:
	"""Convert a node Row to a serialisable dict (strip secret hash)."""
	return {
		"id": row["id"],
		"name": row["name"],
		"fqdn": row["fqdn"],
		"wg_port": row["wg_port"],
		"status": row["status"],
		"last_seen": row["last_seen"],
		"enrolled_at": row["enrolled_at"],
		"created_at": row["created_at"],
		"config_version": row["config_version"],
		"metadata": row["metadata"],
		"peer_count": peer_count,
	}


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────


@router.post("")
def create_node_endpoint(
	body: NodeCreate,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_admin),
):
	"""Create a new remote node and return the one-time enrollment token."""
	# Validate unique name
	if get_node_by_name(conn, body.name):
		raise HTTPException(status_code=409, detail=f"Node name '{body.name}' already exists")

	cfg = get_config()
	node_id = uuid.uuid4().hex

	# Determine master URL from config
	master_url = f"https://{cfg.wg_fqdn}:{cfg.gui_port}" if hasattr(cfg, "gui_port") else f"https://{cfg.wg_fqdn}"

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
):
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
):
	"""Get details for a single node."""
	node = get_node(conn, node_id)
	if not node:
		raise HTTPException(status_code=404, detail="Node not found")
	counts = get_peers_count_by_node(conn)
	return ok_response(data=_node_to_dict(node, counts.get(node_id, 0)))


@router.patch("/{node_id}")
def update_node_endpoint(
	node_id: str,
	body: NodeUpdate,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_admin),
):
	"""Update a node's name, FQDN, or port."""
	if not get_node(conn, node_id):
		raise HTTPException(status_code=404, detail="Node not found")

	# Validate unique name if changing
	if body.name:
		existing = get_node_by_name(conn, body.name)
		if existing and existing["id"] != node_id:
			raise HTTPException(status_code=409, detail=f"Node name '{body.name}' already exists")

	update_node(conn, node_id, name=body.name, fqdn=body.fqdn, wg_port=body.wg_port)
	_log.info("Node updated: id=%s (by user=%s)", node_id, user["username"])
	return ok_response(message="Node updated")


@router.delete("/{node_id}")
def delete_node_endpoint(
	node_id: str,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_admin),
):
	"""Delete a node. Assigned peers are unassigned (node_id set to NULL)."""
	if not delete_node(conn, node_id):
		raise HTTPException(status_code=404, detail="Node not found")
	_log.info("Node deleted: id=%s (by user=%s)", node_id, user["username"])
	return ok_response(message="Node deleted. Assigned peers have been unassigned.")


@router.post("/{node_id}/token")
def regenerate_token(
	node_id: str,
	conn: sqlite3.Connection = Depends(get_conn),
	user: sqlite3.Row = Depends(require_admin),
):
	"""Regenerate enrollment token for re-enrollment. Invalidates old token."""
	node = get_node(conn, node_id)
	if not node:
		raise HTTPException(status_code=404, detail="Node not found")

	cfg = get_config()
	master_url = f"https://{cfg.wg_fqdn}:{cfg.gui_port}" if hasattr(cfg, "gui_port") else f"https://{cfg.wg_fqdn}"

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
