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
import json
import logging
import os
from pathlib import Path
import re
import sqlite3
import time
from collections.abc import Callable
from typing import Any, TypeVar
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from ..api.auth import _is_https
from ..api.response import ok_response
from ..api.speedtest import SPEEDTEST_TSDB_KEY, SPEEDTEST_TSDB_METRIC
from ..api.sse import format_sse_close, format_sse_event, format_sse_keepalive
from ..db.sqlite_interfaces import list_interfaces
from ..db.sqlite_nodes import (
	ack_node_command as db_ack_node_command,
	bump_node_config_version,
	claim_pending_node_commands,
	clear_node_sse_connected,
	create_node_interface,
	enroll_node,
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
from ..db.sqlite_runtime import thread_connection, transaction
from ..db.sqlite_settings import set_node_speedtest_last_result

from ..utils.config import get_config
from ..utils.crypto import hash_token, new_token
from ..utils.deps import get_conn, get_tsdb_dir
from ..utils.time import utcnow
from ..utils.network import parse_ip_str
from ..db import tsdb
from ..utils.node_token import get_cert_fingerprint, verify_enrollment_token
from ..api.wireguard_utils import generate_keypair, run_wg_command
from ..utils.rate_limit import limiter
from ..node import notifier as node_notifier
from ..node.events import NodeCommandPayload, NodeCommandType, SpeedtestProgressPayload

_log = logging.getLogger(__name__)

router = APIRouter(tags=["nodes-sync"])

_SSE_CONNECTED_DB_UPDATE_INTERVAL_S = 60.0
_NODE_RATE_LIMIT_POLL = "600/minute"
_NODE_RATE_LIMIT_EVENTS = "300/minute"
_NODE_RATE_LIMIT_PROGRESS = "1800/minute"
_NODE_COMMAND_REPLAY_AFTER_SECONDS = 30
_NODE_COMMAND_CLAIM_LIMIT = 20
_CLIENT_CERT_FP_HEADER = "X-Client-Cert-Fingerprint"
_CLIENT_CERT_FP_RE = re.compile(r"^[a-f0-9]{64}$")
_NODE_MTLS_PROXY_CIDRS_ENV = "WIREBUDDY_NODE_MTLS_PROXY_CIDRS"
T = TypeVar("T")


def _load_node_mtls_proxy_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
	"""Load explicitly trusted proxy CIDRs for node mTLS certificate headers."""
	raw = str(os.environ.get(_NODE_MTLS_PROXY_CIDRS_ENV, "")).strip()
	if not raw:
		return ()
	networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
	for item in (part.strip() for part in raw.split(",")):
		if not item:
			continue
		try:
			networks.append(ipaddress.ip_network(item, strict=False))
		except ValueError:
			_log.warning("Ignoring invalid %s entry: %r", _NODE_MTLS_PROXY_CIDRS_ENV, item)
	return tuple(networks)


_NODE_MTLS_PROXY_NETWORKS = _load_node_mtls_proxy_networks()


def _get_socket_ip(request: Request) -> str | None:
	"""Return the normalized socket peer IP for the current request."""
	scope_client = request.scope.get("client")
	if not scope_client or not scope_client[0]:
		return None
	return parse_ip_str(scope_client[0])


def _socket_ip_is_trusted_mtls_proxy(request: Request) -> bool:
	"""Return True when the request came through an explicitly trusted mTLS proxy."""
	if not _NODE_MTLS_PROXY_NETWORKS:
		return False
	socket_ip = _get_socket_ip(request)
	if not socket_ip:
		return False
	try:
		ip_obj = ipaddress.ip_address(socket_ip)
	except ValueError:
		return False
	return any(ip_obj.version == network.version and ip_obj in network for network in _NODE_MTLS_PROXY_NETWORKS)


def _get_verified_client_cert_fingerprint(request: Request) -> str | None:
	"""Return a verified client certificate fingerprint from a trusted proxy, if any.

	Without an explicitly trusted mTLS proxy, self-asserted fingerprint headers are
	ignored and node auth falls back to the bearer session secret alone.
	"""
	header_value = str(request.headers.get(_CLIENT_CERT_FP_HEADER, "") or "").strip().lower()
	if not header_value:
		return None
	if not _socket_ip_is_trusted_mtls_proxy(request):
		_log.warning(
			"Ignoring %s from untrusted source ip=%s",
			_CLIENT_CERT_FP_HEADER,
			_get_socket_ip(request) or "unknown",
		)
		return None
	if not _CLIENT_CERT_FP_RE.fullmatch(header_value):
		raise HTTPException(status_code=403, detail="Invalid client certificate fingerprint")
	return header_value


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


def _resolve_country_from_url(server_url: str) -> str | None:
	"""Return a best-effort ISO country hint derived from a server URL hostname.

	This is intentionally conservative: only a 2-letter ccTLD is accepted.
	Hostnames under generic TLDs or IP literals return ``None``.
	"""
	if not server_url:
		return None

	raw_url = server_url.strip()
	if not raw_url:
		return None

	parsed = urlsplit(raw_url if "://" in raw_url else f"https://{raw_url}")
	hostname = (parsed.hostname or "").strip().rstrip(".").lower()
	if not hostname:
		return None

	try:
		ipaddress.ip_address(hostname)
		return None
	except ValueError:
		pass

	labels = [label for label in hostname.split(".") if label]
	if not labels:
		return None

	country_code = labels[-1]
	if len(country_code) == 2 and country_code.isalpha():
		return country_code
	return None


async def _run_with_short_lived_conn(
	db_path: Path,
	fn: Callable[..., T],
	*args: Any,
	**kwargs: Any,
) -> T:
	"""Run a DB operation in a thread using a short-lived connection."""
	def _exec():
		with thread_connection(db_path) as thread_conn:
			return fn(thread_conn, *args, **kwargs)

	return await run_in_threadpool(_exec)


def _get_node_event_bus(request: Request):
	"""Return the lifespan-scoped node event bus from app state."""
	bus = getattr(request.app.state, "node_event_bus", None)
	if bus is None:
		raise HTTPException(status_code=503, detail="Node event runtime unavailable")
	return bus


def _command_event_name(command: NodeCommandType) -> str:
	"""Map durable command type to SSE event name."""
	if command is NodeCommandType.CONFIG_CHANGED:
		return "config_changed"
	if command is NodeCommandType.RESTART:
		return "restart_requested"
	if command is NodeCommandType.SPEEDTEST:
		return "run_speedtest"
	if command is NodeCommandType.REMOVED:
		return "node_removed"
	return f"{command.value}_requested"


def _format_command_sse(command_row: dict[str, Any]) -> str | None:
	"""Convert one durable command row into an SSE event string."""
	command_name = str(command_row.get("command_type") or "").strip().lower()
	try:
		command = NodeCommandType(command_name)
	except ValueError:
		_log.warning("Unknown durable node command ignored: %r", command_name)
		return None

	payload_dict = command_row.get("payload") if isinstance(command_row.get("payload"), dict) else {}
	payload = NodeCommandPayload(
		command_id=int(command_row["id"]),
		command=command,
		config_version=str(payload_dict.get("config_version")) if payload_dict.get("config_version") is not None else None,
	)
	return format_sse_event(_command_event_name(command), payload.model_dump())


async def _claim_pending_command_events(db_path: Path, node_id: str) -> list[str]:
	"""Claim replayable commands from SQLite and return formatted SSE events."""
	rows = await _run_with_short_lived_conn(
		db_path,
		claim_pending_node_commands,
		node_id,
		replay_after_seconds=_NODE_COMMAND_REPLAY_AFTER_SECONDS,
		limit=_NODE_COMMAND_CLAIM_LIMIT,
	)
	formatted: list[str] = []
	for row in rows:
		event = _format_command_sse(row)
		if event is not None:
			formatted.append(event)
	return formatted


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


def _recover_node_enrollment_sync(
	conn: sqlite3.Connection,
	node_id: str,
	fingerprint: str,
	session_secret: str,
) -> dict[str, Any]:
	"""Complete recovery enrollment inside a single blocking DB section."""
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

	return get_node_config(conn, node_id)


def _enroll_pending_node_sync(
	conn: sqlite3.Connection,
	node_id: str,
	node_name: str,
	tunnel_peer_id_hint: int | None,
	fingerprint: str,
	keypairs: list[tuple[str, tuple[str, str]]],
	session_secret: str,
) -> tuple[tuple[str, str, str, str | None] | None, dict[str, Any]]:
	"""Enroll a pending node and return tunnel update info plus rendered config."""
	tunnel_info: tuple[str, str, str, str | None] | None = None

	with transaction(conn, immediate=True):
		if not enroll_node(conn, node_id, fingerprint):
			raise HTTPException(status_code=409, detail="Node already enrolled")

		for iface_name, (privkey, pubkey) in keypairs:
			create_node_interface(conn, node_id, iface_name, privkey, pubkey)

		if keypairs:
			first_iface_name, (_, first_pubkey) = keypairs[0]
			existing_tunnel_peer = None
			if tunnel_peer_id_hint:
				existing_tunnel_peer = get_peer_by_id(conn, int(tunnel_peer_id_hint))

			if existing_tunnel_peer and existing_tunnel_peer["peer_address"]:
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
					(first_pubkey, f"[Node] {node_name}", int(existing_tunnel_peer["id"])),
				)
				set_node_tunnel_peer(conn, node_id, int(existing_tunnel_peer["id"]))
				tunnel_info = (
					tunnel_iface,
					first_pubkey,
					tunnel_allowed_ips,
					old_pubkey if old_pubkey and old_pubkey != first_pubkey else None,
				)
				_log.info(
					"Reused tunnel peer for node=%s, peer_id=%d, address=%s",
					node_id,
					int(existing_tunnel_peer["id"]),
					existing_tunnel_peer["peer_address"],
				)
			else:
				tunnel_address = allocate_peer_ip(conn, first_iface_name)
				if tunnel_address:
					new_tunnel_peer_id = create_peer(
						conn,
						public_key=first_pubkey,
						allowed_ips=tunnel_address,
						name=f"[Node] {node_name}",
						interface=first_iface_name,
						peer_address=tunnel_address,
						allowed_ips_mode="custom",
						use_adblocker=False,
						dns_logging_enabled=False,
					)
					set_node_tunnel_peer(conn, node_id, new_tunnel_peer_id)
					tunnel_info = (first_iface_name, first_pubkey, tunnel_address, None)
					_log.info(
						"Created tunnel peer for node=%s, peer_id=%d, address=%s",
						node_id,
						new_tunnel_peer_id,
						tunnel_address,
					)
				else:
					_log.warning("Could not allocate tunnel address for node=%s (pool exhausted?)", node_id)

		bump_node_config_version(conn, node_id)
		rotate_node_session_secret(conn, node_id, hash_token(session_secret))

	return tunnel_info, get_node_config(conn, node_id)


# ─────────────────────────────────────────────────────────────────────────────
# Node Authentication Dependency
# ─────────────────────────────────────────────────────────────────────────────


def get_current_node(
	request: Request,
	authorization: str = Header(..., alias="Authorization"),
	conn: sqlite3.Connection = Depends(get_conn),
) -> sqlite3.Row:
	"""Authenticate a node via Bearer session secret.

	Security model:
	- The Bearer token proves possession of the current node session secret.
	- An optional certificate fingerprint check is only applied when an explicitly
	  trusted mTLS proxy injects the fingerprint header.
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

	client_cert_fp = _get_verified_client_cert_fingerprint(request)
	if client_cert_fp is not None:
		stored_cert_fp = (node["cert_fingerprint"] or "").strip().lower()
		if not stored_cert_fp:
			_log.error("Node %s is enrolled without a stored certificate fingerprint", node["id"])
			raise HTTPException(status_code=500, detail="Node enrollment state is invalid")
		if not hmac.compare_digest(client_cert_fp, stored_cert_fp):
			_log.warning(
				"Cert fingerprint mismatch for node=%s: got=%s... stored=%s...",
				node["id"],
				client_cert_fp[:16],
				stored_cert_fp[:16],
			)
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
	node = await run_in_threadpool(get_node, conn, node_id)
	if node is None:
		raise HTTPException(status_code=404, detail="Enrollment token invalid or node deleted")

	# Extract cert fingerprint from request (needed for both paths)
	try:
		cert_pem_bytes = body.cert_pem.encode("utf-8")
		fingerprint = get_cert_fingerprint(cert_pem_bytes)
	except (ValueError, UnicodeDecodeError) as exc:
		_log.warning("Node enrollment rejected due to invalid certificate for node=%s: %s", node_id, exc)
		raise HTTPException(status_code=422, detail="Invalid certificate") from exc

	if node["status"] != "pending":
		_log.warning(
			"Rejecting enrollment reuse for already-enrolled node id=%s name=%s",
			node_id,
			node["name"],
		)
		raise HTTPException(
			status_code=409,
			detail="Node is already enrolled; generate recovery credentials from the admin UI",
		)

	# ── First enrollment path: Node is pending ──
	# Verify api_secret matches stored hash (only for pending nodes)
	if not hmac.compare_digest(hash_token(api_secret), node["api_secret_hash"]):
		raise HTTPException(status_code=401, detail="API secret mismatch")

	# Generate keypairs BEFORE transaction (async + SQLite = race condition risk)
	interfaces = await run_in_threadpool(list_interfaces, conn)
	keypairs = list(zip(
		[iface["name"] for iface in interfaces],
		await asyncio.gather(*(generate_keypair() for _ in interfaces)),
	))

	# Enroll atomically — status check, keypairs, tunnel peer, secret rotation,
	# and config-version bump all commit together or not at all.
	session_secret = new_token()
	tunnel_info, config = await run_in_threadpool(
		_enroll_pending_node_sync,
		conn,
		node_id,
		str(node["name"]),
		int(node["tunnel_peer_id"]) if node["tunnel_peer_id"] else None,
		fingerprint,
		keypairs,
		session_secret,
	)

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


def _process_heartbeat(
	conn: sqlite3.Connection,
	tsdb_dir: Path,
	node: sqlite3.Row,
	body: HeartbeatRequest,
) -> dict:
	"""Persist heartbeat metadata, peer stats, and queued metrics for one node.

	Heartbeat metadata and peer last-seen updates are idempotent. If TSDB metric
	writes fail later in the function, the node is intentionally not acked so it
	can retry the metrics batch on the next heartbeat.
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

		new_metrics = [
			m for m in batch.metrics
			if last_seq is None or m.seq > last_seq
		]

		skipped = len(batch.metrics) - len(new_metrics)
		if skipped > 0:
			_log.debug(
				"Node %s: skipped %d already-processed metrics (last_seq=%s)",
				node_id, skipped, last_seq,
			)

		if new_metrics:
			seqs = [m.seq for m in new_metrics]
			expected = list(range(seqs[0], seqs[-1] + 1))
			if seqs != expected:
				_log.warning(
					"Node %s submitted non-contiguous metric sequence: %s",
					node_id,
					seqs,
				)
				return {"acked_seq": None, "failed": True}

			unsupported = [m.type for m in new_metrics if m.type not in _METRIC_WRITERS]
			if unsupported:
				_log.warning(
					"Node %s submitted unsupported metric types: %s",
					node_id,
					sorted(set(unsupported)),
				)
				return {"acked_seq": None, "failed": True}

		if new_metrics:
			try:
				points_written = 0
				highest_written_seq: int | None = None
				for m in new_metrics:
					writer = _METRIC_WRITERS[m.type]
					points_written += writer(tsdb_dir, m.data)
					highest_written_seq = m.seq

				_log.debug(
					"Node %s: wrote %d TSDB points from %d metrics (seq %s-%s)",
					node_id, points_written, len(new_metrics),
					new_metrics[0].seq, new_metrics[-1].seq,
				)
			except Exception:
				_log.warning("Failed to write TSDB metrics from node %s", node_id, exc_info=True)
				# Heartbeat metadata and peer stats are idempotent, so a node retry is
				# safe even though those writes already happened above.
				# Do NOT ack — node will retry on next heartbeat.
				return {"acked_seq": None, "failed": True}
			if highest_written_seq is not None:
				set_node_last_metric_seq(conn, node_id, highest_written_seq)
				acked_seq = highest_written_seq

		elif batch.seq_to is not None and last_seq is not None and batch.seq_to <= last_seq:
			acked_seq = batch.seq_to

	return {"acked_seq": acked_seq, "failed": False}


@router.post("/heartbeat")
@limiter.limit(_NODE_RATE_LIMIT_POLL)
async def heartbeat(
	request: Request,
	body: HeartbeatRequest,
	node: sqlite3.Row = Depends(get_current_node),
	conn: sqlite3.Connection = Depends(get_conn),
	tsdb_dir: Path = Depends(get_tsdb_dir),
):
	"""Receive heartbeat with metrics from a remote node.

	Async: the threadpool slot is only held during actual blocking I/O
	(DB writes, TSDB file appends) via an explicit ``run_in_threadpool`` call.

	Implements reliable at-least-once delivery:
	- Accepts batched metrics with sequence numbers
	- Skips already-processed sequences (idempotency)
	- Returns acked_seq to confirm receipt
	"""
	_ = request
	result = await run_in_threadpool(_process_heartbeat, conn, tsdb_dir, node, body)

	if result["failed"]:
		return ok_response(
			data={"acked_seq": None},
			message="Heartbeat received (metrics write failed)",
		)
	return ok_response(
		data={"acked_seq": result["acked_seq"]},
		message="Heartbeat received",
	)


# ─────────────────────────────────────────────────────────────────────────────
# Config Pull
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/config")
@limiter.limit(_NODE_RATE_LIMIT_POLL)
def get_config_endpoint(
	request: Request,
	version: str | None = None,
	node: sqlite3.Row = Depends(get_current_node),
	conn: sqlite3.Connection = Depends(get_conn),
):
	"""Return the current WireGuard configuration for a node.

	If ``version`` matches the current ``config_version``, returns an
	unchanged response with ``data=None`` for node-daemon compatibility.
	"""
	_ = request
	node_id = node["id"]

	# ETag-style: skip full payload if version matches
	if version is not None and node["config_version"] is not None and version == str(node["config_version"]):
		_log.debug("NODE_CONFIG_UNCHANGED node=%s version=%s", node_id, version[:16] if version else "none")
		return ok_response(data={"config_version": node["config_version"]}, message="Config unchanged")

	config = get_node_config(conn, node["id"])
	peer_count = len(config.get("peers", []))
	config_ver_str = str(node["config_version"]) if node["config_version"] is not None else "none"
	_log.info(
		"NODE_CONFIG_DELIVERED node=%s peers=%d version=%s",
		node_id, peer_count, config_ver_str[:16],
	)
	return ok_response(data=config)


@router.get("/events")
@limiter.limit(_NODE_RATE_LIMIT_EVENTS)
async def node_events(
	request: Request,
	node: sqlite3.Row = Depends(get_current_node),
):
	"""Server-Sent Events stream for real-time node commands.

	Nodes subscribe to receive push notifications for:
	- ``config_changed``: pull updated config via ``GET /api/nodes/config``
	- ``restart_requested``: restart the node service gracefully
	- ``run_speedtest``: trigger an on-demand speedtest

	Event format:
		event: <command_name>
		data: <payload>
	"""
	node_id = node["id"]
	db_path = request.app.state.db_path
	shutdown_event = getattr(request.app.state, "shutdown_signal_event", None)
	_log.info("Node %s connected to SSE event stream", node_id)

	async def mark_sse_connected() -> None:
		await _run_with_short_lived_conn(db_path, update_node_sse_connected, node_id)

	async def clear_sse_connected() -> None:
		await _run_with_short_lived_conn(db_path, clear_node_sse_connected, node_id)

	async def event_generator():
		try:
			close_event = format_sse_close()
			await mark_sse_connected()
			last_sse_connected_write = time.monotonic()
			
			# Check for any command that was queued while we were connecting
			for pending_event in await _claim_pending_command_events(db_path, node_id):
				yield pending_event
			
			# Send initial keepalive
			yield format_sse_keepalive()
			
			async for event in node_notifier.subscribe(node_id, shutdown_event=shutdown_event):
				if shutdown_event is not None and shutdown_event.is_set():
					_log.debug("SSE shutdown for node %s", node_id)
					yield close_event
					break
				if await request.is_disconnected():
					break
				# On keepalive events, also check DB for pending commands
				if event.startswith(":") or event.startswith("event: ping\n"):
					now_monotonic = time.monotonic()
					if now_monotonic - last_sse_connected_write >= _SSE_CONNECTED_DB_UPDATE_INTERVAL_S:
						await mark_sse_connected()
						last_sse_connected_write = now_monotonic
					for pending_event in await _claim_pending_command_events(db_path, node_id):
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
@limiter.limit(_NODE_RATE_LIMIT_PROGRESS)
async def submit_node_speedtest_progress(
	request: Request,
	body: SpeedtestProgressEvent,
	node: sqlite3.Row = Depends(get_current_node),
):
	"""Receive speedtest progress update from a node and broadcast to SSE clients."""
	bus = _get_node_event_bus(request)
	node_id = node["id"]
	payload = SpeedtestProgressPayload(
		phase=body.phase,
		progress=body.progress,
		message=body.message,
		detail=body.detail,
	)
	await bus.publish_speedtest(node_id, payload)
	
	return ok_response(message="Progress update received")


@router.post("/commands/{command_id}/ack")
@limiter.limit(_NODE_RATE_LIMIT_POLL)
async def ack_node_command_endpoint(
	command_id: int,
	request: Request,
	node: sqlite3.Row = Depends(get_current_node),
):
	"""Acknowledge one durable control-plane command after the node handled it."""
	if command_id <= 0:
		raise HTTPException(status_code=422, detail="Invalid command_id")
	stored = await _run_with_short_lived_conn(
		request.app.state.db_path,
		db_ack_node_command,
		node["id"],
		command_id,
	)
	if not stored:
		raise HTTPException(status_code=404, detail="Command not found or already acknowledged")
	return ok_response(message="Command acknowledged")


class SpeedtestSubmission(BaseModel):
	"""Speedtest result submitted by a node."""
	status: str = Field(..., max_length=16, description="Result status: ok | error")
	server: str | None = Field(None, max_length=256, description="Speedtest server name")
	server_url: str | None = Field(None, max_length=512, description="Speedtest server URL (used for GeoIP fallback)")
	country_code: str | None = Field(None, min_length=2, max_length=2, description="ISO 3166-1 alpha-2 country code")
	download_mbit: float | None = Field(None, ge=0, le=100000, description="Download speed in Mbit/s")
	upload_mbit: float | None = Field(None, ge=0, le=100000, description="Upload speed in Mbit/s")
	rtt_ms: float | None = Field(None, ge=0, le=10000, description="Round-trip time in ms")
	jitter_ms: float | None = Field(None, ge=0, le=10000, description="Jitter in ms")
	reason: str | None = Field(None, max_length=512, description="Error reason if status=error")


@router.post("/speedtest")
@limiter.limit(_NODE_RATE_LIMIT_POLL)
def submit_node_speedtest(
	request: Request,
	body: SpeedtestSubmission,
	node: sqlite3.Row = Depends(get_current_node),
	conn: sqlite3.Connection = Depends(get_conn),
	tsdb_dir: Path = Depends(get_tsdb_dir),
):
	"""Receive speedtest result from a node and persist to TSDB.
	
	The result is tagged with node_id to distinguish from master speedtests.
	"""
	_ = request
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
		"ts": utcnow().isoformat(),
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

	# Resolve country_code: prefer submitted value, otherwise use a hostname ccTLD hint.
	country_code = (body.country_code or "").strip().lower() or None
	if not country_code and body.server_url:
		country_code = _resolve_country_from_url(body.server_url)
	if country_code:
		result["country_code"] = country_code
	
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
		raise HTTPException(status_code=500, detail="Failed to persist speedtest result") from exc

	try:
		set_node_speedtest_last_result(conn, node_id, result)
	except Exception as exc:
		_log.warning("Failed to persist node speedtest result in settings: %s", exc)
	
	return ok_response(message="Speedtest result received")
