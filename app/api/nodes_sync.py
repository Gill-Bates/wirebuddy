#!/usr/bin/env python3
#
# app/api/nodes_sync.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Node synchronisation API — endpoints called by remote nodes.

Authentication:  Bearer token (api_secret) + certificate fingerprint
verification.  These endpoints are NOT protected by user/admin auth;
they have their own ``get_current_node`` dependency.
"""

from __future__ import annotations

import logging
import sqlite3

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from ..api.response import ok_response
from ..db.sqlite_nodes import (
	bump_node_config_version,
	create_node_interface,
	enroll_node,
	get_node,
	get_node_by_api_secret,
	get_node_config,
	update_node_heartbeat,
)
from ..utils.config import get_config
from ..utils.crypto import hash_token
from ..utils.deps import get_conn
from ..utils.node_token import get_cert_fingerprint, verify_enrollment_token
from ..api.wireguard_utils import generate_keypair

_log = logging.getLogger(__name__)

router = APIRouter(tags=["nodes-sync"])


# ─────────────────────────────────────────────────────────────────────────────
# Node Authentication Dependency
# ─────────────────────────────────────────────────────────────────────────────


def get_current_node(
	request: Request,
	authorization: str = Header(..., alias="Authorization"),
	conn: sqlite3.Connection = Depends(get_conn),
) -> sqlite3.Row:
	"""Authenticate a node via Bearer api_secret + cert fingerprint.

	Raises 401/403 on failure.
	"""
	if not authorization.startswith("Bearer "):
		raise HTTPException(status_code=401, detail="Invalid authorization header")

	api_secret = authorization[7:]
	secret_hash = hash_token(api_secret)
	node = get_node_by_api_secret(conn, secret_hash)

	if node is None:
		raise HTTPException(status_code=401, detail="Invalid API secret")

	if node["status"] == "pending":
		# Pending nodes can only call /enroll — skip cert check
		return node

	# For enrolled nodes: verify certificate fingerprint
	client_cert_fp = request.headers.get("X-Client-Cert-Fingerprint")
	if not client_cert_fp:
		raise HTTPException(status_code=403, detail="Missing client certificate fingerprint")

	if node["cert_fingerprint"] and client_cert_fp.lower() != node["cert_fingerprint"].lower():
		_log.warning("Cert fingerprint mismatch for node=%s", node["id"])
		raise HTTPException(status_code=403, detail="Certificate fingerprint mismatch")

	return node


# ─────────────────────────────────────────────────────────────────────────────
# Request Models
# ─────────────────────────────────────────────────────────────────────────────


class EnrollRequest(BaseModel):
	"""Node enrollment payload."""
	enrollment_token: str = Field(..., description="The base64url enrollment token from master")
	cert_pem: str = Field(..., description="PEM-encoded self-signed node certificate")


class HeartbeatRequest(BaseModel):
	"""Node heartbeat payload."""
	wg_dump: dict | None = Field(None, description="Parsed wg show dump data")
	uptime: float | None = Field(None, description="System uptime in seconds")
	interfaces_status: dict | None = Field(None, description="WG interface up/down status")


# ─────────────────────────────────────────────────────────────────────────────
# Enrollment
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/enroll")
async def enroll_node_endpoint(
	body: EnrollRequest,
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Enroll a node using its enrollment token + self-signed certificate.

	Called once by the node daemon during first startup.
	"""
	cfg = get_config()

	# Verify token
	try:
		payload = verify_enrollment_token(body.enrollment_token, cfg.secret_key)
	except ValueError as exc:
		raise HTTPException(status_code=401, detail=str(exc))

	node_id = payload["node_id"]
	api_secret = payload["api_secret"]

	# Verify node exists and is pending
	node = get_node(conn, node_id)
	if node is None:
		raise HTTPException(status_code=404, detail="Node not found")
	if node["status"] != "pending":
		raise HTTPException(status_code=409, detail="Node already enrolled")

	# Verify api_secret matches stored hash
	if hash_token(api_secret) != node["api_secret_hash"]:
		raise HTTPException(status_code=401, detail="API secret mismatch")

	# Extract cert fingerprint
	try:
		cert_pem_bytes = body.cert_pem.encode("utf-8")
		fingerprint = get_cert_fingerprint(cert_pem_bytes)
	except Exception as exc:
		raise HTTPException(status_code=422, detail=f"Invalid certificate: {exc}")

	# Enroll
	enroll_node(conn, node_id, fingerprint)

	# Generate WG keypairs for each existing interface
	from ..db.sqlite_interfaces import list_interfaces

	interfaces = list_interfaces(conn)
	for iface in interfaces:
		privkey, pubkey = await generate_keypair()
		create_node_interface(conn, node_id, iface["name"], privkey, pubkey)

	# Build initial config
	bump_node_config_version(conn, node_id)
	config = get_node_config(conn, node_id)

	_log.info("Node enrolled: id=%s, name=%s, fingerprint=%s...", node_id, node["name"], fingerprint[:16])

	return ok_response(
		data=config,
		message="Enrollment successful",
	)


# ─────────────────────────────────────────────────────────────────────────────
# Heartbeat
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/{node_id}/heartbeat")
def heartbeat(
	node_id: str,
	body: HeartbeatRequest,
	node: sqlite3.Row = Depends(get_current_node),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Receive heartbeat with metrics from a remote node."""
	if node["id"] != node_id:
		raise HTTPException(status_code=403, detail="Node ID mismatch")

	metadata = {}
	if body.uptime is not None:
		metadata["uptime"] = body.uptime
	if body.interfaces_status is not None:
		metadata["interfaces_status"] = body.interfaces_status

	update_node_heartbeat(conn, node_id, metadata=metadata or None)

	# TODO: Store wg_dump peer stats in TSDB (future enhancement)

	return ok_response(message="Heartbeat received")


# ─────────────────────────────────────────────────────────────────────────────
# Config Pull
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/{node_id}/config")
def get_config_endpoint(
	node_id: str,
	version: str | None = None,
	node: sqlite3.Row = Depends(get_current_node),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Return the current WireGuard configuration for a node.

	If ``version`` matches the current config_version, returns 304.
	"""
	if node["id"] != node_id:
		raise HTTPException(status_code=403, detail="Node ID mismatch")

	db_node = get_node(conn, node_id)
	if db_node is None:
		raise HTTPException(status_code=404, detail="Node not found")

	# ETag-style: skip full payload if version matches
	if version and db_node["config_version"] and version == db_node["config_version"]:
		return ok_response(data=None, message="Config unchanged", config_version=db_node["config_version"])

	config = get_node_config(conn, node_id)
	return ok_response(data=config)
