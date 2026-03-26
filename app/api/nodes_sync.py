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

import hmac
import logging
import sqlite3

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from ..api.response import ok_response
from ..db.sqlite_interfaces import list_interfaces, get_interface
from ..db.sqlite_nodes import (
	bump_node_config_version,
	create_node_interface,
	enroll_node,
	get_node,
	get_node_by_api_secret,
	get_node_config,
	set_node_tunnel_peer,
	update_node_heartbeat,
)
from ..db.sqlite_peers import allocate_peer_ip
from ..db.sqlite_peers_mutations import create_peer
from ..utils.config import get_config
from ..utils.crypto import hash_token
from ..utils.deps import get_conn
from ..utils.network import parse_ip_str
from ..utils.node_token import get_cert_fingerprint, verify_enrollment_token
from ..api.wireguard_utils import generate_keypair, wg_set_peer_with_psk, run_wg_command
from ..db.sqlite_runtime import transaction

_log = logging.getLogger(__name__)

router = APIRouter(tags=["nodes-sync"])


def _get_socket_ip(request: Request) -> str | None:
	"""Return the normalized socket peer IP for the current request."""
	scope_client = request.scope.get("client")
	if not scope_client or not scope_client[0]:
		return None
	return parse_ip_str(scope_client[0])


# ─────────────────────────────────────────────────────────────────────────────
# Node Authentication Dependency
# ─────────────────────────────────────────────────────────────────────────────


def get_current_node(
	request: Request,
	authorization: str = Header(..., alias="Authorization"),
	conn: sqlite3.Connection = Depends(get_conn),
) -> sqlite3.Row:
	"""Authenticate a node via Bearer api_secret + cert fingerprint.

	Security model:
	- The api_secret (Bearer token) proves possession of the enrollment token
	- The cert fingerprint is compared against the value stored at enrollment
	- Both must match — an attacker needs the secret AND the original certificate
	"""
	scheme, _, token = authorization.partition(" ")
	if scheme.lower() != "bearer" or not token:
		raise HTTPException(status_code=401, detail="Invalid authorization header")

	api_secret = token
	secret_hash = hash_token(api_secret)
	node = get_node_by_api_secret(conn, secret_hash)

	if node is None:
		raise HTTPException(status_code=401, detail="Invalid API secret")

	if node["status"] == "pending":
		raise HTTPException(status_code=403, detail="Node not yet enrolled")

	# For enrolled nodes: verify certificate fingerprint
	client_cert_fp = request.headers.get("X-Client-Cert-Fingerprint")
	if not client_cert_fp:
		raise HTTPException(status_code=403, detail="Missing client certificate fingerprint")

	stored_cert_fp = (node["cert_fingerprint"] or "").strip().lower()
	if not stored_cert_fp:
		_log.error("Node %s is enrolled without a stored certificate fingerprint", node["id"])
		raise HTTPException(status_code=500, detail="Node enrollment state is invalid")

	if not hmac.compare_digest(client_cert_fp.strip().lower(), stored_cert_fp):
		_log.warning("Cert fingerprint mismatch for node=%s", node["id"])
		raise HTTPException(status_code=403, detail="Certificate fingerprint mismatch")

	return node


# ─────────────────────────────────────────────────────────────────────────────
# Request Models
# ─────────────────────────────────────────────────────────────────────────────


class EnrollRequest(BaseModel):
	"""Node enrollment payload."""
	enrollment_token: str = Field(..., max_length=2048, description="The base64url enrollment token from master")
	cert_pem: str = Field(..., max_length=16384, description="PEM-encoded self-signed node certificate")


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
	request: Request,
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
		raise HTTPException(status_code=401, detail=str(exc)) from exc

	node_id = payload["node_id"]
	api_secret = payload["api_secret"]

	# Verify node exists and is pending
	node = get_node(conn, node_id)
	if node is None:
		raise HTTPException(status_code=404, detail="Node not found")
	if node["status"] != "pending":
		raise HTTPException(status_code=409, detail="Node already enrolled")

	# Verify api_secret matches stored hash
	if not hmac.compare_digest(hash_token(api_secret), node["api_secret_hash"]):
		raise HTTPException(status_code=401, detail="API secret mismatch")

	# Extract cert fingerprint
	try:
		cert_pem_bytes = body.cert_pem.encode("utf-8")
		fingerprint = get_cert_fingerprint(cert_pem_bytes)
	except Exception as exc:
		_log.warning("Node enrollment rejected due to invalid certificate for node=%s: %s", node_id, exc)
		raise HTTPException(status_code=422, detail="Invalid certificate") from exc

	# Generate keypairs BEFORE transaction (async + SQLite = race condition risk)
	interfaces = list_interfaces(conn)
	keypairs = [(iface["name"], await generate_keypair()) for iface in interfaces]

	# Enroll atomically so partial interface/keypair creation cannot persist.
	tunnel_peer_id = None
	tunnel_info = None  # (interface, pubkey, address) for WG sync
	with transaction(conn, immediate=True):
		if not enroll_node(conn, node_id, fingerprint):
			raise HTTPException(status_code=409, detail="Node already enrolled")

		for iface_name, (privkey, pubkey) in keypairs:
			create_node_interface(conn, node_id, iface_name, privkey, pubkey)

		# Create tunnel peer on master for Node→Master DNS routing
		# Use the first interface's keypair for the tunnel
		if keypairs:
			first_iface_name, (_, first_pubkey) = keypairs[0]
			tunnel_address = allocate_peer_ip(conn, first_iface_name)
			if tunnel_address:
				tunnel_peer_id = create_peer(
					conn,
					public_key=first_pubkey,
					allowed_ips=tunnel_address,  # Node can only access its own IP on master
					name=f"[Node] {node['name']}",
					interface=first_iface_name,
					peer_address=tunnel_address,
					allowed_ips_mode="custom",
					use_adblocker=False,  # No DNS filtering for node tunnel
					dns_logging_enabled=False,  # No DNS logging for node tunnel
				)
				set_node_tunnel_peer(conn, node_id, tunnel_peer_id)
				tunnel_info = (first_iface_name, first_pubkey, tunnel_address)
				_log.info("Created tunnel peer for node=%s, peer_id=%d, address=%s", node_id, tunnel_peer_id, tunnel_address)
			else:
				_log.warning("Could not allocate tunnel address for node=%s (pool exhausted?)", node_id)

		bump_node_config_version(conn, node_id)

	# Add tunnel peer to master's WireGuard (outside transaction)
	if tunnel_info:
		iface_name, pubkey, address = tunnel_info
		code, _, stderr = await run_wg_command(
			"wg", "set", iface_name,
			"peer", pubkey,
			"allowed-ips", address,
		)
		if code != 0:
			_log.error("Failed to add tunnel peer to WireGuard: %s", stderr.strip())
		else:
			_log.info("Added tunnel peer to master WireGuard: interface=%s, pubkey=%s...", iface_name, pubkey[:8])

	config = get_node_config(conn, node_id)

	socket_ip = _get_socket_ip(request)
	_log.info(
		"Node enrolled: id=%s, name=%s, fingerprint=%s..., socket_ip=%s",
		node_id,
		node["name"],
		fingerprint[:16],
		socket_ip or "unknown",
	)

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

	If ``version`` matches the current ``config_version``, returns an
	unchanged response with ``data=None`` for node-daemon compatibility.
	"""
	if node["id"] != node_id:
		raise HTTPException(status_code=403, detail="Node ID mismatch")

	db_node = get_node(conn, node_id)
	if db_node is None:
		raise HTTPException(status_code=404, detail="Node not found")

	# ETag-style: skip full payload if version matches
	if version is not None and db_node["config_version"] and version == db_node["config_version"]:
		return ok_response(data=None, message="Config unchanged", config_version=db_node["config_version"])

	config = get_node_config(conn, node_id)
	return ok_response(data=config)
