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
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
import typing

from ..api.response import ok_response
from ..db.sqlite_interfaces import list_interfaces
from ..db.sqlite_nodes import (
	bump_node_config_version,
	create_node_interface,
	enroll_node,
	get_node,
	get_node_by_api_secret,
	get_node_config,
	rotate_node_session_secret,
	set_node_tunnel_peer,
	update_node_heartbeat,
)
from ..db.sqlite_peers import allocate_peer_ip
from ..db.sqlite_peers_mutations import create_peer
from pathlib import Path

from ..utils.config import get_config
from ..utils.crypto import hash_token, new_token
from ..utils.deps import get_conn, get_tsdb_dir
from ..utils.network import parse_ip_str
from ..db import tsdb
from ..utils.node_token import get_cert_fingerprint, verify_enrollment_token
from ..api.wireguard_utils import generate_keypair, run_wg_command
from ..db.sqlite_runtime import transaction
from ..utils.rate_limit import limiter
from ..node import notifier as node_notifier

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
		# Log first 8 chars of hash for debugging (safe: hash is not reversible)
		_log.warning("Node auth failed: no node found for secret_hash=%s...", secret_hash[:8])
		raise HTTPException(status_code=401, detail="Invalid API secret")

	if node["status"] == "pending":
		_log.warning("Node auth failed: node=%s status is still 'pending'", node["id"])
		raise HTTPException(status_code=403, detail="Node not yet enrolled")

	# For enrolled nodes: verify certificate fingerprint
	client_cert_fp = request.headers.get("X-Client-Cert-Fingerprint")
	if not client_cert_fp:
		_log.warning("Node auth failed: node=%s missing X-Client-Cert-Fingerprint header", node["id"])
		raise HTTPException(status_code=403, detail="Missing client certificate fingerprint")

	stored_cert_fp = (node["cert_fingerprint"] or "").strip().lower()
	if not stored_cert_fp:
		_log.error("Node %s is enrolled without a stored certificate fingerprint", node["id"])
		raise HTTPException(status_code=500, detail="Node enrollment state is invalid")

	if not hmac.compare_digest(client_cert_fp.strip().lower(), stored_cert_fp):
		_log.warning("Cert fingerprint mismatch for node=%s: got=%s... stored=%s...",
			node["id"], client_cert_fp[:16], stored_cert_fp[:16])
		raise HTTPException(status_code=403, detail="Certificate fingerprint mismatch")

	return node


# ─────────────────────────────────────────────────────────────────────────────
# Request Models
# ─────────────────────────────────────────────────────────────────────────────


class EnrollRequest(BaseModel):
	"""Node enrollment payload."""
	enrollment_token: str = Field(..., max_length=2048, description="The base64url enrollment token from master")
	cert_pem: str = Field(..., max_length=16384, description="PEM-encoded self-signed node certificate")


class PeerStatEntry(BaseModel):
	"""Single peer stat from a node's wg dump."""
	public_key: str = Field(..., max_length=64)
	endpoint: str | None = Field(None, max_length=256)
	latest_handshake: int | None = None
	transfer_rx: int = 0
	transfer_tx: int = 0


class MetricEntry(BaseModel):
	"""Single metric from node's queue."""
	seq: int = Field(..., ge=1, description="Sequence number")
	ts: str = Field(..., max_length=64, description="ISO 8601 timestamp")
	type: str = Field(..., max_length=32, description="Metric type: peer_traffic | peer_handshake")
	data: dict = Field(..., description="Metric payload")


class MetricsBatch(BaseModel):
	"""Batch of metrics from node's queue."""
	seq_from: int | None = Field(None, description="First sequence in batch")
	seq_to: int | None = Field(None, description="Last sequence in batch")
	metrics: list[MetricEntry] = Field(default_factory=list, max_length=500)


class HeartbeatRequest(BaseModel):
	"""Node heartbeat payload."""

	uptime: float | None = Field(None, description="System uptime in seconds")
	interfaces_status: dict | None = Field(None, description="WG interface up/down status")
	version: str | None = Field(None, max_length=32, description="WireBuddy version running on node")
	peer_stats: list[PeerStatEntry] | None = Field(None, description="WireGuard peer stats from wg dump", max_length=1000)
	metrics_batch: MetricsBatch | None = Field(None, description="Queued metrics batch for reliable delivery")


# ─────────────────────────────────────────────────────────────────────────────
# Enrollment
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/enroll")
@limiter.limit("10/minute")
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

	# Verify node exists and is pending — quick pre-check before heavier work.
	# The definitive serialised check is repeated inside the IMMEDIATE transaction.
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
	except (ValueError, UnicodeDecodeError) as exc:
		_log.warning("Node enrollment rejected due to invalid certificate for node=%s: %s", node_id, exc)
		raise HTTPException(status_code=422, detail="Invalid certificate") from exc

	# Generate keypairs BEFORE transaction (async + SQLite = race condition risk)
	interfaces = list_interfaces(conn)
	keypairs = [(iface["name"], await generate_keypair()) for iface in interfaces]

	# Enroll atomically — status check, keypairs, tunnel peer, secret rotation,
	# and config-version bump all commit together or not at all.
	session_secret = new_token()
	tunnel_peer_id = None
	tunnel_info = None  # (interface, pubkey, address) for WG sync
	with transaction(conn, immediate=True):
		# Definitive serialised pending check inside the IMMEDIATE lock
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

		# ── Secret rotation: make the enrollment token single-use ──
		# Generate a fresh session secret inside the atomic transaction
		session_secret = new_token()
		session_hash = hash_token(session_secret)
		rotate_node_session_secret(conn, node_id, session_hash)
		_log.debug("Rotated session secret for node=%s, new_hash=%s...", node_id, session_hash[:8])

	# Add tunnel peer to master's WireGuard (outside transaction)
	warning_msg = None
	if tunnel_info:
		iface_name, pubkey, address = tunnel_info
		code, _, stderr = await run_wg_command(
			"wg", "set", iface_name,
			"peer", pubkey,
			"allowed-ips", f"{address}/32" if "/" not in address else address,
		)
		if code != 0:
			_log.error("Failed to add tunnel peer to WireGuard: %s", stderr.strip())
			warning_msg = "Tunnel peer could not be activated; retry sync"
		else:
			_log.info("Added tunnel peer to master WireGuard: interface=%s, pubkey=%s...", iface_name, pubkey[:8])

	_log.info("Rotated API secret for node=%s (enrollment token invalidated)", node_id)

	config = get_node_config(conn, node_id)
	config["session_secret"] = session_secret  # One-time delivery over TLS
	if warning_msg:
		config["_warning"] = warning_msg

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


def _get_node_last_seq(conn: sqlite3.Connection, node_id: str) -> int | None:
	"""Get the last processed metric sequence for a node (idempotency)."""
	row = conn.execute(
		"SELECT last_metric_seq FROM nodes WHERE id = ?", (node_id,)
	).fetchone()
	return row["last_metric_seq"] if row and row["last_metric_seq"] else None


def _set_node_last_seq(conn: sqlite3.Connection, node_id: str, seq: int) -> None:
	"""Update the last processed metric sequence for a node."""
	conn.execute(
		"UPDATE nodes SET last_metric_seq = ? WHERE id = ?",
		(seq, node_id)
	)
	conn.commit()


@router.post("/heartbeat")
def heartbeat(
	body: HeartbeatRequest,
	node: sqlite3.Row = Depends(get_current_node),
	conn: sqlite3.Connection = Depends(get_conn),
	tsdb_dir: Path = Depends(get_tsdb_dir),
):
	"""Receive heartbeat with metrics from a remote node.
	
	Implements reliable at-least-once delivery:
	- Accepts batched metrics with sequence numbers
	- Skips already-processed sequences (idempotency)
	- Returns acked_seq to confirm receipt
	"""
	node_id = node["id"]

	metadata = {}
	if body.uptime is not None:
		metadata["uptime"] = body.uptime
	if body.interfaces_status is not None:
		metadata["interfaces_status"] = body.interfaces_status
	if body.version is not None:
		metadata["version"] = body.version

	update_node_heartbeat(conn, node_id, metadata=metadata or None)

	# Persist peer stats from node's wg dump (makes remote peers visible in UI)
	if body.peer_stats:
		from ..db.sqlite_peers import update_peers_last_seen_batch
		db_updates: list[tuple[str, int, str]] = []
		for ps in body.peer_stats:
			if not ps.latest_handshake or not ps.public_key:
				continue
			# Extract client IP from endpoint (ip:port or [ipv6]:port)
			client_ip = ""
			if ps.endpoint:
				ep = ps.endpoint
				if ep.startswith("["):
					client_ip = ep[1:ep.rfind("]")]
				elif ":" in ep:
					client_ip = ep.rsplit(":", 1)[0]
			if client_ip:
				db_updates.append((client_ip, ps.latest_handshake, ps.public_key))
		if db_updates:
			try:
				update_peers_last_seen_batch(conn, db_updates)
				_log.debug("Persisted %d peer stats from node %s", len(db_updates), node_id)
			except Exception:
				_log.warning("Failed to persist peer stats from node %s", node_id, exc_info=True)

	# Process queued metrics batch (reliable delivery with idempotency)
	acked_seq: int | None = None
	if body.metrics_batch and body.metrics_batch.metrics:
		batch = body.metrics_batch
		last_seq = _get_node_last_seq(conn, node_id)
		
		# Filter out already-processed metrics (idempotency)
		new_metrics = [
			m for m in batch.metrics
			if last_seq is None or m.seq > last_seq
		]
		
		skipped = len(batch.metrics) - len(new_metrics)
		if skipped > 0:
			_log.debug(
				"Node %s: skipped %d already-processed metrics (last_seq=%s)",
				node_id, skipped, last_seq
			)
		
		# Write new metrics to TSDB
		if new_metrics:
			try:
				points_written = 0
				for m in new_metrics:
					if m.type == "peer_traffic":
						public_key = m.data.get("public_key")
						rx_bytes = m.data.get("rx_bytes", 0)
						tx_bytes = m.data.get("tx_bytes", 0)
						if public_key and (rx_bytes > 0 or tx_bytes > 0):
							tsdb.append_point(tsdb_dir, peer_key=public_key, metric="rx_bytes", value=rx_bytes)
							tsdb.append_point(tsdb_dir, peer_key=public_key, metric="tx_bytes", value=tx_bytes)
							points_written += 2
					elif m.type == "peer_handshake":
						public_key = m.data.get("public_key")
						latest_handshake = m.data.get("latest_handshake")
						if public_key and latest_handshake:
							tsdb.append_point(tsdb_dir, peer_key=public_key, metric="latest_handshake", value=latest_handshake)
							points_written += 1
				
				_log.debug(
					"Node %s: wrote %d TSDB points from %d metrics (seq %s-%s)",
					node_id, points_written, len(new_metrics),
					new_metrics[0].seq, new_metrics[-1].seq
				)
			except Exception:
				_log.warning("Failed to write TSDB metrics from node %s", node_id, exc_info=True)
		
		# Update last processed sequence (ACK)
		if batch.seq_to is not None:
			_set_node_last_seq(conn, node_id, batch.seq_to)
			acked_seq = batch.seq_to

	return ok_response(
		data={"acked_seq": acked_seq},
		message="Heartbeat received"
	)


# ─────────────────────────────────────────────────────────────────────────────
# Config Pull
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/config")
def get_config_endpoint(
	version: str | None = None,
	node: sqlite3.Row = Depends(get_current_node),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Return the current WireGuard configuration for a node.

	If ``version`` matches the current ``config_version``, returns an
	unchanged response with ``data=None`` for node-daemon compatibility.
	"""
	node_id = node["id"]

	db_node = get_node(conn, node_id)
	if db_node is None:
		raise HTTPException(status_code=404, detail="Node not found")

	# ETag-style: skip full payload if version matches
	if version is not None and db_node["config_version"] is not None and version == str(db_node["config_version"]):
		_log.debug("NODE_CONFIG_UNCHANGED node=%s version=%s", node_id, version[:16] if version else "none")
		return ok_response(data=None, message="Config unchanged", config_version=db_node["config_version"])

	config = get_node_config(conn, node["id"])
	peer_count = len(config.get("peers", []))
	_log.info(
		"NODE_CONFIG_DELIVERED node=%s peers=%d version=%s",
		node_id, peer_count, db_node["config_version"][:16] if db_node["config_version"] else "none",
	)
	return ok_response(data=config)


@router.get("/events")
async def node_events(
	node: sqlite3.Row = Depends(get_current_node),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Server-Sent Events stream for real-time config change notifications.

	Nodes subscribe to this endpoint to receive instant push notifications
	when their configuration changes (e.g., new peer added). This eliminates
	the 30-second polling delay.

	Event format:
		event: config_changed
		data: <new_config_version>

	The node should pull the full config via GET /api/nodes/config after
	receiving an event.
	"""
	from ..db.sqlite_nodes import update_node_sse_connected, clear_node_sse_connected
	
	node_id = node["id"]
	_log.info("Node %s connected to SSE event stream", node_id)

	async def event_generator():
		try:
			# Mark node as SSE-connected in DB (multi-worker safe)
			await run_in_threadpool(update_node_sse_connected, conn, node_id)
			
			# Send initial keepalive
			yield ": keepalive\n\n"
			
			async for event in node_notifier.subscribe(node_id):
				# Update DB timestamp periodically (on keepalive events)
				if event.startswith(":"):  # Keepalive comment
					await run_in_threadpool(update_node_sse_connected, conn, node_id)
				yield event
		finally:
			# Clear SSE connection status on disconnect
			try:
				await run_in_threadpool(clear_node_sse_connected, conn, node_id)
			except Exception as exc:
				_log.debug("Failed to clear SSE status for node %s: %s", node_id, exc)

	return StreamingResponse(
		event_generator(),
		media_type="text/event-stream",
		headers={
			"Cache-Control": "no-cache",
			"Connection": "keep-alive",
			"X-Accel-Buffering": "no",  # Disable nginx buffering
		},
	)
