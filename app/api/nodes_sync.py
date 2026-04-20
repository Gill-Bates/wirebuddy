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

import asyncio
import hmac
import ipaddress
import logging
from pathlib import Path
import sqlite3
import time
from typing import Any, Callable, TypeVar

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from ..api.auth import _is_https
from ..api.response import ok_response
from ..api.speedtest import SPEEDTEST_TSDB_KEY, SPEEDTEST_TSDB_METRIC
from ..db.sqlite_interfaces import list_interfaces
from ..db.sqlite_nodes import (
	bump_node_config_version,
	clear_node_sse_connected,
	create_node_interface,
	enroll_node,
	get_and_clear_node_pending_command,
	get_node,
	get_node_by_api_secret,
	get_node_last_metric_seq,
	get_node_config,
	rotate_node_session_secret,
	set_node_last_metric_seq,
	set_node_tunnel_peer,
	update_node_sse_connected,
	update_node_heartbeat,
)
from ..db.sqlite_peers import allocate_peer_ip, get_peer_by_id, update_peers_last_seen_batch
from ..db.sqlite_peers_mutations import create_peer
from ..db.sqlite_runtime import connect, close_connection, transaction

from ..utils.config import get_config
from ..utils.crypto import hash_token, new_token
from ..utils.deps import get_conn, get_tsdb_dir
from ..utils.network import parse_ip_str
from ..db import tsdb
from ..utils.node_token import get_cert_fingerprint, verify_enrollment_token
from ..api.wireguard_utils import generate_keypair, run_wg_command
from ..utils.rate_limit import limiter
from ..node import notifier as node_notifier

_log = logging.getLogger(__name__)

router = APIRouter(tags=["nodes-sync"])

# Allowed commands for SSE command validation (prevents injection)
_ALLOWED_SSE_COMMANDS = frozenset({"config_changed", "restart", "speedtest"})
_SSE_CONNECTED_DB_UPDATE_INTERVAL_S = 60.0
T = TypeVar("T")

# ─────────────────────────────────────────────────────────────────────────────
# Node Speedtest Progress Store
# ─────────────────────────────────────────────────────────────────────────────

# In-memory store for node speedtest progress
# Structure: {node_id: {"progress": {...}, "timestamp": float, "queues": [asyncio.Queue, ...]}}
# NOTE: This state is process-local and therefore single-worker only.
# In multi-worker deployments, progress submitter and SSE client may hit
# different workers and miss updates.
_node_speedtest_progress: dict[str, dict[str, Any]] = {}


def _new_speedtest_progress_state() -> dict[str, Any]:
	"""Create default in-memory speedtest progress state for one node."""
	return {
		"progress": None,
		"timestamp": 0.0,
		"queues": [],
	}


def _get_progress_lock() -> asyncio.Lock:
	"""Get a per-event-loop lock for speedtest progress state."""
	loop = asyncio.get_running_loop()
	lock = getattr(loop, "_wirebuddy_nodes_progress_lock", None)
	if isinstance(lock, asyncio.Lock):
		return lock
	lock = asyncio.Lock()
	setattr(loop, "_wirebuddy_nodes_progress_lock", lock)
	return lock


async def register_speedtest_progress_queue(
	node_id: str,
	queue: asyncio.Queue[dict[str, Any]],
) -> dict[str, Any] | None:
	"""Register an SSE queue for node speedtest progress updates.

	Returns the latest progress event for the node, if one exists.
	"""
	async with _get_progress_lock():
		state = _node_speedtest_progress.setdefault(node_id, _new_speedtest_progress_state())
		state["queues"].append(queue)
		progress = state.get("progress")
		return progress if isinstance(progress, dict) else None


async def unregister_speedtest_progress_queue(
	node_id: str,
	queue: asyncio.Queue[dict[str, Any]],
) -> None:
	"""Unregister an SSE queue from node speedtest progress updates."""
	async with _get_progress_lock():
		state = _node_speedtest_progress.get(node_id)
		if state is None:
			return
		try:
			state["queues"].remove(queue)
		except ValueError:
			pass
		if not state["queues"] and _node_speedtest_progress.get(node_id) is state:
			del _node_speedtest_progress[node_id]

# Maps DB pending command names to the SSE event type the node daemon expects.
# Defaults to "{cmd}_requested" for any command not listed here.
_PENDING_CMD_EVENT_TYPE: dict[str, str] = {
	"config_changed": "config_changed",
	"speedtest": "run_speedtest",      # node daemon listens for "run_speedtest"
	"restart": "restart_requested",
	"removed": "node_removed",
}


def _get_socket_ip(request: Request) -> str | None:
	"""Return the normalized socket peer IP for the current request."""
	scope_client = request.scope.get("client")
	if not scope_client or not scope_client[0]:
		return None
	return parse_ip_str(scope_client[0])


def _parse_endpoint_ip(endpoint: str) -> str:
	"""Extract IP address from WireGuard endpoint string.
	
	Handles formats:
	- [ipv6]:port → ipv6
	- ipv4:port → ipv4
	- bare IP (no port) → IP
	
	Returns empty string if parsing fails.
	"""
	if not endpoint:
		return ""
	
	# IPv6 with brackets: [addr]:port
	if endpoint.startswith("["):
		bracket_end = endpoint.rfind("]")
		if bracket_end > 0:
			candidate = endpoint[1:bracket_end]
			try:
				ipaddress.ip_address(candidate)
				return candidate
			except ValueError:
				return ""
		return ""
	
	# Try to detect IPv4:port vs bare IP
	last_colon = endpoint.rfind(":")
	if last_colon > 0:
		# Check if part before colon is a valid IP
		candidate = endpoint[:last_colon]
		try:
			ipaddress.ip_address(candidate)
			return candidate
		except ValueError:
			pass

	# Validate bare value as IP (reject hostnames or malformed input)
	try:
		ipaddress.ip_address(endpoint)
		return endpoint
	except ValueError:
		return ""


async def _run_with_short_lived_conn(
	db_path: Path,
	fn: Callable[..., T],
	*args: Any,
) -> T:
	"""Run a DB operation in a thread using a short-lived connection."""
	def _exec():
		thread_conn = connect(db_path)
		try:
			return fn(thread_conn, *args)
		finally:
			close_connection(thread_conn)

	return await run_in_threadpool(_exec)


def _warn_if_not_https(request: Request, node_id: str, context: str) -> None:
	"""Log when sensitive enrollment data is delivered over non-HTTPS."""
	if not _is_https_best_effort(request):
		_log.error("%s delivered session_secret over non-HTTPS transport for node=%s", context, node_id)


def _write_peer_traffic_metric(tsdb_dir: Path, data: dict[str, Any]) -> int:
	"""Write peer traffic metrics. Returns number of written points."""
	public_key = data.get("public_key")
	rx_bytes = data.get("rx_bytes", 0)
	tx_bytes = data.get("tx_bytes", 0)
	if not public_key or (rx_bytes <= 0 and tx_bytes <= 0):
		return 0
	tsdb.append_point(tsdb_dir, peer_key=public_key, metric="rx_bytes", value=rx_bytes)
	tsdb.append_point(tsdb_dir, peer_key=public_key, metric="tx_bytes", value=tx_bytes)
	return 2


def _write_peer_handshake_metric(tsdb_dir: Path, data: dict[str, Any]) -> int:
	"""Write peer handshake metric. Returns number of written points."""
	public_key = data.get("public_key")
	latest_handshake = data.get("latest_handshake")
	if not public_key or not latest_handshake:
		return 0
	tsdb.append_point(tsdb_dir, peer_key=public_key, metric="latest_handshake", value=latest_handshake)
	return 1


_METRIC_WRITERS: dict[str, Callable[[Path, dict[str, Any]], int]] = {
	"peer_traffic": _write_peer_traffic_metric,
	"peer_handshake": _write_peer_handshake_metric,
}


def _is_https_best_effort(request: Request) -> bool:
	"""Return HTTPS status without raising transport-detection exceptions."""
	try:
		return _is_https(request)
	except HTTPException as exc:
		_log.warning("Could not determine HTTPS state for enrollment transport: %s", exc.detail)
		return False


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
		_log.warning("Node auth failed: unknown API secret")
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

	client_cert_fp_normalized = client_cert_fp.strip().lower()
	if len(client_cert_fp_normalized) != len(stored_cert_fp):
		_log.warning("Cert fingerprint length mismatch for node=%s", node["id"])
		raise HTTPException(status_code=403, detail="Certificate fingerprint mismatch")

	if not hmac.compare_digest(client_cert_fp_normalized, stored_cert_fp):
		_log.warning("Cert fingerprint mismatch for node=%s: got=%s... stored=%s...",
			node["id"], client_cert_fp_normalized[:16], stored_cert_fp[:16])
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

	# Verify node exists
	node = get_node(conn, node_id)
	if node is None:
		raise HTTPException(status_code=404, detail="Enrollment token invalid or node deleted")

	# Extract cert fingerprint from request (needed for both paths)
	try:
		cert_pem_bytes = body.cert_pem.encode("utf-8")
		fingerprint = get_cert_fingerprint(cert_pem_bytes)
	except (ValueError, UnicodeDecodeError) as exc:
		_log.warning("Node enrollment rejected due to invalid certificate for node=%s: %s", node_id, exc)
		raise HTTPException(status_code=422, detail="Invalid certificate") from exc

	# ── Recovery path: Node already enrolled but lost its state file ──
	# The enrollment token's api_secret was rotated to a session_secret after
	# first enrollment, so the token's api_secret no longer matches.
	# Instead, verify the certificate fingerprint matches what we stored.
	if node["status"] != "pending":
		session_secret = new_token()
		with transaction(conn, immediate=True):
			fresh_node = get_node(conn, node_id)
			if fresh_node is None:
				raise HTTPException(status_code=404, detail="Enrollment token invalid or node deleted")

			if fresh_node["status"] == "pending":
				raise HTTPException(status_code=409, detail="Node enrollment state changed, retry enrollment")

			stored_fingerprint = fresh_node["cert_fingerprint"]
			if not (stored_fingerprint and hmac.compare_digest(fingerprint, stored_fingerprint)):
				_log.warning(
					"Node enrollment rejected: id=%s already enrolled with different certificate "
					"(stored=%s..., request=%s...)",
					node_id,
					(stored_fingerprint or "none")[:16],
					fingerprint[:16],
				)
				raise HTTPException(status_code=409, detail="Node already enrolled")

			if not rotate_node_session_secret(conn, node_id, hash_token(session_secret)):
				raise HTTPException(status_code=409, detail="Node is pending and cannot use recovery enrollment")
			bump_node_config_version(conn, node_id)

		_log.info(
			"Node re-enrollment recovery: id=%s, name=%s — same certificate, rotating session secret",
			node_id, node["name"],
		)
		config = get_node_config(conn, node_id)
		_warn_if_not_https(request, node_id, context="Enrollment recovery")
		config["session_secret"] = session_secret
		return ok_response(data=config)

	# ── First enrollment path: Node is pending ──
	# Verify api_secret matches stored hash (only for pending nodes)
	if not hmac.compare_digest(hash_token(api_secret), node["api_secret_hash"]):
		raise HTTPException(status_code=401, detail="API secret mismatch")

	# Generate keypairs BEFORE transaction (async + SQLite = race condition risk)
	interfaces = list_interfaces(conn)
	keypairs = [(iface["name"], await generate_keypair()) for iface in interfaces]

	# Enroll atomically — status check, keypairs, tunnel peer, secret rotation,
	# and config-version bump all commit together or not at all.
	session_secret = ""
	tunnel_peer_id = None
	tunnel_info = None  # (interface, new_pubkey, allowed_ips, old_pubkey_to_remove)
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
			existing_tunnel_peer = None
			if node["tunnel_peer_id"]:
				existing_tunnel_peer = get_peer_by_id(conn, int(node["tunnel_peer_id"]))

			if existing_tunnel_peer and existing_tunnel_peer["peer_address"]:
				tunnel_peer_id = int(existing_tunnel_peer["id"])
				old_pubkey = str(existing_tunnel_peer["public_key"] or "")
				tunnel_iface = str(existing_tunnel_peer["interface"] or first_iface_name)
				tunnel_allowed_ips = str(existing_tunnel_peer["allowed_ips"] or existing_tunnel_peer["peer_address"])

				conn.execute(
					"""
					UPDATE peers
					SET public_key = ?,
					    name = ?,
					    use_adblocker = 0,
					    dns_logging_enabled = 0
					WHERE id = ?
					""",
					(first_pubkey, f"[Node] {node['name']}", tunnel_peer_id),
				)
				set_node_tunnel_peer(conn, node_id, tunnel_peer_id)
				tunnel_info = (
					tunnel_iface,
					first_pubkey,
					tunnel_allowed_ips,
					old_pubkey if old_pubkey and old_pubkey != first_pubkey else None,
				)
				_log.info(
					"Reused tunnel peer for node=%s, peer_id=%d, address=%s",
					node_id,
					tunnel_peer_id,
					existing_tunnel_peer["peer_address"],
				)
			else:
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
					tunnel_info = (first_iface_name, first_pubkey, tunnel_address, None)
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
		iface_name, pubkey, allowed_ips, old_pubkey = tunnel_info
		if old_pubkey:
			code_rm, _, stderr_rm = await run_wg_command(
				"wg", "set", iface_name,
				"peer", old_pubkey,
				"remove",
			)
			if code_rm != 0:
				_log.debug(
					"Old tunnel peer key removal skipped/failed for node=%s: %s",
					node_id,
					stderr_rm.strip(),
				)
		code, _, stderr = await run_wg_command(
			"wg", "set", iface_name,
			"peer", pubkey,
			"allowed-ips", allowed_ips,
		)
		if code != 0:
			_log.error("Failed to add tunnel peer to WireGuard: %s", stderr.strip())
			warning_msg = "Tunnel peer could not be activated; retry sync"
		else:
			_log.info("Added tunnel peer to master WireGuard: interface=%s, pubkey=%s...", iface_name, pubkey[:8])

	_log.info("Rotated API secret for node=%s (enrollment token invalidated)", node_id)

	config = get_node_config(conn, node_id)
	_warn_if_not_https(request, node_id, context="Enrollment")
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


@router.post("/heartbeat")
def heartbeat(
	body: HeartbeatRequest,
	node: sqlite3.Row = Depends(get_current_node),
	conn: sqlite3.Connection = Depends(get_conn),
	tsdb_dir: Path = Depends(get_tsdb_dir),
):
	"""Receive heartbeat with metrics from a remote node.

	NOTE: sync – FastAPI threadpools this handler. Performs TSDB file writes
	(_write_peer_traffic_metric / _write_peer_handshake_metric) and several DB
	writes per call. With many nodes at short intervals this consumes thread-pool
	slots; monitor pool saturation if the node fleet grows significantly.

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
		db_updates: list[tuple[str, int, str]] = []
		for ps in body.peer_stats:
			if not ps.latest_handshake or not ps.public_key:
				continue
			# Extract client IP from endpoint using robust parsing
			client_ip = _parse_endpoint_ip(ps.endpoint or "")
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
		last_seq = get_node_last_metric_seq(conn, node_id)
		
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
					writer = _METRIC_WRITERS.get(m.type)
					if writer is None:
						_log.debug("Node %s: unknown metric type %r (skipped)", node_id, m.type)
						continue
					points_written += writer(tsdb_dir, m.data)
				
				_log.debug(
					"Node %s: wrote %d TSDB points from %d metrics (seq %s-%s)",
					node_id, points_written, len(new_metrics),
					new_metrics[0].seq, new_metrics[-1].seq
				)
			except Exception:
				_log.warning("Failed to write TSDB metrics from node %s", node_id, exc_info=True)
				# Do NOT ack - node will retry on next heartbeat.
				# Heartbeat/peer-status DB updates are intentionally independent and idempotent.
				return ok_response(
					data={"acked_seq": acked_seq},
					message="Heartbeat received (metrics write failed)"
				)
		
		# Update last processed sequence (ACK) only after successful TSDB write
		if batch.seq_to is not None:
			set_node_last_metric_seq(conn, node_id, batch.seq_to)
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

	# ETag-style: skip full payload if version matches
	if version is not None and node["config_version"] is not None and version == str(node["config_version"]):
		_log.debug("NODE_CONFIG_UNCHANGED node=%s version=%s", node_id, version[:16] if version else "none")
		return ok_response(data=None, message="Config unchanged", config_version=node["config_version"])

	config = get_node_config(conn, node["id"])
	peer_count = len(config.get("peers", []))
	config_ver_str = str(node["config_version"]) if node["config_version"] is not None else "none"
	_log.info(
		"NODE_CONFIG_DELIVERED node=%s peers=%d version=%s",
		node_id, peer_count, config_ver_str[:16],
	)
	return ok_response(data=config)


@router.get("/events")
async def node_events(
	request: Request,
	node: sqlite3.Row = Depends(get_current_node),
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
	node_id = node["id"]
	db_path = request.app.state.db_path
	shutdown_event = getattr(request.app.state, "shutdown_signal_event", None)
	_log.info("Node %s connected to SSE event stream", node_id)

	async def check_pending_command() -> str | None:
		"""Check DB for pending command (multi-worker safe, short-lived connection)."""
		return await _run_with_short_lived_conn(db_path, get_and_clear_node_pending_command, node_id)

	async def mark_sse_connected() -> None:
		await _run_with_short_lived_conn(db_path, update_node_sse_connected, node_id)

	async def clear_sse_connected() -> None:
		await _run_with_short_lived_conn(db_path, clear_node_sse_connected, node_id)

	async def emit_pending_command() -> str | None:
		pending_cmd = await check_pending_command()
		if not pending_cmd:
			return None
		if pending_cmd not in _ALLOWED_SSE_COMMANDS:
			_log.warning("Node %s: unknown pending command %r (ignored)", node_id, pending_cmd)
			return None

		event_type = _PENDING_CMD_EVENT_TYPE.get(pending_cmd, f"{pending_cmd}_requested")
		_log.info("Node %s command from DB: %s -> event: %s", node_id, pending_cmd, event_type)
		return f"event: {event_type}\ndata: {pending_cmd}\n\n"

	async def event_generator():
		try:
			close_event = "event: close\ndata: server_shutdown\n\n"
			await mark_sse_connected()
			last_sse_connected_write = time.monotonic()
			
			# Check for any command that was queued while we were connecting
			pending_event = await emit_pending_command()
			if pending_event is not None:
				yield pending_event
			
			# Send initial keepalive
			yield ": keepalive\n\n"
			
			async for event in node_notifier.subscribe(node_id, shutdown_event=shutdown_event):
				if shutdown_event is not None and shutdown_event.is_set():
					_log.debug("SSE shutdown for node %s", node_id)
					yield close_event
					break
				if await request.is_disconnected():
					break
				# On keepalive events, also check DB for pending commands
				if event.startswith(":"):  # Keepalive comment
					now_monotonic = time.monotonic()
					if now_monotonic - last_sse_connected_write >= _SSE_CONNECTED_DB_UPDATE_INTERVAL_S:
						await mark_sse_connected()
						last_sse_connected_write = now_monotonic
					pending_event = await emit_pending_command()
					if pending_event is not None:
						yield pending_event
				if event.startswith("event: close\n"):
					yield event
					break
				yield event
		finally:
			# Clear SSE connection status on disconnect (short-lived connection)
			try:
				await clear_sse_connected()
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


# ─────────────────────────────────────────────────────────────────────────────
# Node Speedtest Submission
# ─────────────────────────────────────────────────────────────────────────────


class SpeedtestProgressEvent(BaseModel):
	"""Speedtest progress event submitted by a node."""
	phase: str = Field(..., max_length=64, description="Current test phase")
	progress: float = Field(..., ge=0, le=1, description="Progress fraction (0-1)")
	message: str = Field("", max_length=256, description="Progress message")
	detail: dict[str, Any] | str | None = Field(None, description="Optional detail payload")


@router.post("/speedtest/progress")
async def submit_node_speedtest_progress(
	body: SpeedtestProgressEvent,
	node: sqlite3.Row = Depends(get_current_node),
):
	"""Receive speedtest progress update from a node and broadcast to SSE clients."""
	node_id = node["id"]
	
	event_data = {
		"phase": body.phase,
		"progress": body.progress,
		"message": body.message,
	}
	if body.detail:
		event_data["detail"] = body.detail
	
	async with _get_progress_lock():
		state = _node_speedtest_progress.setdefault(
			node_id,
			_new_speedtest_progress_state(),
		)
		state["progress"] = event_data
		state["timestamp"] = time.time()

		# Broadcast to all waiting SSE clients
		for queue in state["queues"]:
			try:
				queue.put_nowait(event_data)
			except asyncio.QueueFull:
				# Keep latest progress by dropping the oldest buffered event.
				try:
					queue.get_nowait()
				except asyncio.QueueEmpty:
					continue
				try:
					queue.put_nowait(event_data)
				except asyncio.QueueFull:
					continue
	
	return ok_response(message="Progress update received")


class SpeedtestSubmission(BaseModel):
	"""Speedtest result submitted by a node."""
	status: str = Field(..., max_length=16, description="Result status: ok | error")
	server: str | None = Field(None, max_length=256, description="Speedtest server name")
	download_mbit: float | None = Field(None, ge=0, le=100000, description="Download speed in Mbit/s")
	upload_mbit: float | None = Field(None, ge=0, le=100000, description="Upload speed in Mbit/s")
	rtt_ms: float | None = Field(None, ge=0, le=10000, description="Round-trip time in ms")
	jitter_ms: float | None = Field(None, ge=0, le=10000, description="Jitter in ms")
	reason: str | None = Field(None, max_length=512, description="Error reason if status=error")


@router.post("/speedtest")
def submit_node_speedtest(
	body: SpeedtestSubmission,
	node: sqlite3.Row = Depends(get_current_node),
	tsdb_dir: Path = Depends(get_tsdb_dir),
):
	"""Receive speedtest result from a node and persist to TSDB.
	
	The result is tagged with node_id to distinguish from master speedtests.
	"""
	node_id = node["id"]
	node_name = node["name"]
	
	# Only persist successful results (don't pollute TSDB with errors)
	if body.status != "ok":
		_log.warning(
			"NODE_SPEEDTEST node=%s name=%s status=error reason=%s",
			node_id, node_name, body.reason or "unknown"
		)
		return ok_response(message="Speedtest error recorded (not persisted to history)")
	
	# Build result payload with node_id tag
	result = {
		"status": "ok",
		"node_id": node_id,
		"node_name": node_name,
	}
	
	if body.download_mbit is not None:
		result["download_mbit"] = round(body.download_mbit, 2)
	if body.upload_mbit is not None:
		result["upload_mbit"] = round(body.upload_mbit, 2)
	if body.rtt_ms is not None:
		result["rtt_ms"] = round(body.rtt_ms, 2)
	if body.jitter_ms is not None:
		result["jitter_ms"] = round(body.jitter_ms, 2)
	if body.server:
		result["server"] = body.server
	
	_log.info(
		"NODE_SPEEDTEST node=%s name=%s dl=%.2f ul=%.2f rtt=%.2fms",
		node_id,
		node_name,
		body.download_mbit or 0,
		body.upload_mbit or 0,
		body.rtt_ms or 0,
	)
	
	# Persist to TSDB
	try:
		tsdb.append_point(
			tsdb_dir,
			peer_key=SPEEDTEST_TSDB_KEY,
			metric=SPEEDTEST_TSDB_METRIC,
			value=result,
		)
	except Exception as exc:
		_log.error("Failed to persist node speedtest: %s", exc)
		raise HTTPException(status_code=500, detail="Failed to persist speedtest result") from None
	
	return ok_response(message="Speedtest result received")
