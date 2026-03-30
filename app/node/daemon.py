#!/usr/bin/env python3
#
# app/node/daemon.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Node daemon — minimal WireGuard runtime that syncs with a master.

Reads WIREBUDDY_ENROLLMENT_TOKEN from environment, enrolls with the
master if not yet enrolled, then enters a sync loop polling for
configuration changes and pushing heartbeats.

No database, no web server, no DNS, no scheduler.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import signal
import sys
from pathlib import Path
from typing import Any

import httpx

from ..utils.banner import print_banner_once
from ..utils.node_token import get_cert_fingerprint, verify_enrollment_token
from .cert import clear_node_cert, ensure_node_cert
from .metrics_queue import (
	init_queue,
	close_queue,
	enqueue_peer_traffic,
	get_pending_batch,
	ack_up_to_seq,
	serialize_batch_for_api,
	get_queue_stats,
)
from .wg_manager import apply_config, get_wg_dump, has_running_interfaces, shutdown_all_interfaces

_log = logging.getLogger(__name__)

SYNC_INTERVAL = int(os.environ.get("WIREBUDDY_NODE_SYNC_INTERVAL", "30"))
ENROLLMENT_RETRY_ATTEMPTS = max(1, int(os.environ.get("WIREBUDDY_ENROLLMENT_RETRY_ATTEMPTS", "3")))
SESSION_PROPAGATION_DELAY = 0.5  # Delay after enrollment to ensure master has committed session secret
DATA_DIR = Path("/app/data")
STATE_FILE = DATA_DIR / "node_state.json"


def _build_request_headers(api_secret: str, cert_fingerprint: str) -> dict[str, str]:
	"""Build per-request authentication headers."""
	return {
		"Authorization": f"Bearer {api_secret}",
		"X-Client-Cert-Fingerprint": cert_fingerprint,
	}


def _extract_error_detail(response: httpx.Response) -> str:
	"""Extract error detail from HTTP response for logging."""
	try:
		data = response.json()
		return str(data.get("detail", ""))[:200]
	except Exception:
		return response.text[:200] if response.text else ""


def _decode_enrollment_token_payload(token_string: str) -> dict[str, Any]:
	"""Decode the token payload without verifying its HMAC signature."""
	try:
		raw = base64.urlsafe_b64decode(token_string.encode("ascii")).decode("utf-8")
		payload_json, _signature = raw.rsplit(".", 1)
		payload = json.loads(payload_json)
	except Exception as exc:
		raise ValueError("Failed to decode enrollment token") from exc

	for field in ("master_url", "node_id", "api_secret"):
		if field not in payload:
			raise ValueError(f"Enrollment token missing required field: {field}")
	return payload


def _parse_enrollment_token(token_string: str, verify_key: str | None = None) -> dict[str, Any]:
	"""Parse the enrollment token, verifying it when an HMAC key is provided."""
	if verify_key:
		return verify_enrollment_token(token_string, verify_key)

	# Token signature is verified by the master during enrollment anyway,
	# local verification is an optional extra security layer for paranoid setups
	_log.warning("Enrollment token verification disabled — token signature will only be checked by master")
	return _decode_enrollment_token_payload(token_string)


def _load_state() -> dict[str, Any] | None:
	"""Load persisted node runtime state."""
	if not STATE_FILE.exists():
		return None

	try:
		state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
	except (OSError, json.JSONDecodeError) as exc:
		raise RuntimeError(f"Failed to load node state from {STATE_FILE}: {exc}") from exc

	required_fields = ("master_url", "node_id", "api_secret")
	for field in required_fields:
		value = state.get(field)
		if not isinstance(value, str) or not value.strip():
			raise RuntimeError(f"Persisted node state is missing a valid '{field}'")

	config_version = state.get("config_version")
	if config_version is not None and not isinstance(config_version, str):
		raise RuntimeError("Persisted node state has an invalid 'config_version'")

	return state


def _save_state(state: dict[str, Any]) -> None:
	"""Persist node runtime state with restrictive permissions."""
	DATA_DIR.mkdir(parents=True, exist_ok=True)
	tmp = STATE_FILE.with_suffix(".tmp")
	try:
		fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
		with os.fdopen(fd, "w", encoding="utf-8") as handle:
			json.dump(state, handle, separators=(",", ":"), sort_keys=True)
		os.replace(tmp, STATE_FILE)
	except Exception:
		tmp.unlink(missing_ok=True)
		raise


def _clear_enrollment_state() -> None:
	"""Clear all enrollment state for re-enrollment with a new token.

	Removes node state and certificates.
	"""
	if STATE_FILE.exists():
		STATE_FILE.unlink()
		_log.info("Removed old node state file")

	clear_node_cert(DATA_DIR)


def _resolve_tls_verify(state: dict[str, Any] | None) -> tuple[bool | str, str | None]:
	"""Resolve TLS verification settings for master API calls."""
	ca_file_raw = os.getenv("WIREBUDDY_MASTER_CA_FILE")
	if not ca_file_raw and state is not None:
		ca_file_raw = state.get("master_ca_file")

	if not ca_file_raw:
		return True, None

	ca_path = Path(str(ca_file_raw)).expanduser()
	if not ca_path.exists() or not ca_path.is_file():
		raise RuntimeError(f"Configured master CA file does not exist: {ca_path}")

	return str(ca_path), str(ca_path)


async def main() -> None:
	"""Entry point for the node daemon."""
	print_banner_once()
	logging.basicConfig(
		level=os.environ.get("LOG_LEVEL", "INFO").upper(),
		format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
		datefmt="%Y-%m-%d %H:%M:%S",
	)
	for name in ("httpcore", "httpx", "hpack"):
		logging.getLogger(name).setLevel(logging.WARNING)
	_log.info("WireBuddy Node Daemon starting...")

	DATA_DIR.mkdir(parents=True, exist_ok=True)

	try:
		state = _load_state()
	except RuntimeError as exc:
		_log.critical("%s", exc)
		sys.exit(1)

	token_str = os.getenv("WIREBUDDY_ENROLLMENT_TOKEN")
	verify_key = os.getenv("WIREBUDDY_ENROLLMENT_VERIFY_KEY")
	payload: dict[str, Any] | None = None

	if state is None:
		if not token_str:
			_log.critical("WIREBUDDY_ENROLLMENT_TOKEN is required for first bootstrap")
			sys.exit(1)
		try:
			payload = _parse_enrollment_token(token_str, verify_key)
		except ValueError as exc:
			_log.critical("Failed to parse enrollment token: %s", exc)
			sys.exit(1)
	else:
		if token_str:
			# Check if the new token differs from stored state (re-enrollment scenario)
			try:
				payload = _parse_enrollment_token(token_str, verify_key)
				needs_reenroll = False
				reason = ""

				# Compare via enrollment_secret_hash (not api_secret, which was
				# replaced by a session secret after the first enrollment).
				token_secret_hash = hashlib.sha256(
					payload["api_secret"].encode("utf-8")
				).hexdigest()
				stored_hash = state.get("enrollment_secret_hash", "")

				if payload["node_id"] != state["node_id"]:
					needs_reenroll = True
					reason = f"node_id changed ({payload['node_id']} vs {state['node_id']})"
				elif not stored_hash:
					# No enrollment hash stored — force re-enrollment to
					# establish session secret rotation.
					needs_reenroll = True
					reason = "no enrollment hash in state (clean re-enrollment required)"
				elif token_secret_hash != stored_hash:
					needs_reenroll = True
					reason = "enrollment token was regenerated"

				if needs_reenroll:
					_log.warning("Enrollment token changed: %s — clearing old state for re-enrollment", reason)
					_clear_enrollment_state()
					state = None  # Force re-enrollment
				else:
					_log.info("Ignoring WIREBUDDY_ENROLLMENT_TOKEN — already enrolled with this token")
					payload = None  # Not needed, using existing state
			except ValueError as exc:
				_log.critical("Failed to parse enrollment token: %s", exc)
				sys.exit(1)

	# Use persisted state if available, otherwise use enrollment token payload
	source = state if state is not None else payload
	master_url = str(source["master_url"]).rstrip("/")
	node_id = str(source["node_id"])
	api_secret = str(source["api_secret"])
	node_name = str(source.get("node_name", "unknown"))
	current_config_version = None if state is None else state.get("config_version")

	_log.info("Node: id=%s, name=%s, master=%s", node_id, node_name, master_url)

	# Ensure self-signed certificate
	cert_pem, _key_pem = ensure_node_cert(DATA_DIR, node_id)
	cert_fingerprint = get_cert_fingerprint(cert_pem)

	try:
		tls_verify, master_ca_file = _resolve_tls_verify(state)
	except RuntimeError as exc:
		_log.critical("%s", exc)
		sys.exit(1)

	# Graceful shutdown
	shutdown_event = asyncio.Event()
	loop = asyncio.get_running_loop()

	def _request_shutdown(sig: int) -> None:
		_log.info("Received signal %s, shutting down...", signal.Signals(sig).name)
		shutdown_event.set()

	def _fallback_signal_handler(sig: int, _frame: object) -> None:
		loop.call_soon_threadsafe(shutdown_event.set)

	for sig in (signal.SIGTERM, signal.SIGINT):
		try:
			loop.add_signal_handler(sig, _request_shutdown, sig)
		except (NotImplementedError, RuntimeError):
			signal.signal(sig, _fallback_signal_handler)

	node_state: dict[str, Any] = {
		"api_secret": api_secret,
		"config_version": current_config_version,
		"master_ca_file": master_ca_file,
		"master_url": master_url,
		"node_id": node_id,
		"node_name": node_name,
	}

	# Initialize metrics queue for reliable delivery
	metrics_queue_conn = init_queue(DATA_DIR)
	queue_stats = get_queue_stats(metrics_queue_conn)
	if queue_stats["pending"] > 0:
		_log.info(
			"Metrics queue: %d pending metrics (seq %s-%s, oldest: %s)",
			queue_stats["pending"],
			queue_stats["min_seq"],
			queue_stats["max_seq"],
			queue_stats["oldest_ts"],
		)

	async with httpx.AsyncClient(
		timeout=30.0,
		verify=tls_verify,
	) as client:
		# Enrollment phase
		if state is None:
			current_config_version = None
			session_secret: str | None = None
			enrolled = False
			for attempt in range(1, ENROLLMENT_RETRY_ATTEMPTS + 1):
				enroll_res = await _enroll(
					client,
					master_url,
					token_str,
					cert_pem,
					api_secret,
					cert_fingerprint,
				)
				if enroll_res.success:
					enrolled = True
					current_config_version = enroll_res.config_version
					session_secret = enroll_res.session_secret
					break
				if attempt >= ENROLLMENT_RETRY_ATTEMPTS:
					break

				# Exponential backoff with jitter to avoid thundering herd
				delay = min(2 ** (attempt - 1), 30) * random.uniform(0.8, 1.2)
				_log.warning(
					"Enrollment attempt %d/%d failed, retrying in %.1fs",
					attempt,
					ENROLLMENT_RETRY_ATTEMPTS,
					delay,
				)
				try:
					await asyncio.wait_for(shutdown_event.wait(), timeout=delay)
					break
				except asyncio.TimeoutError:
					pass

			if not enrolled:
				_log.critical("Enrollment failed — exiting")
				sys.exit(1)

			# Replace the enrollment api_secret with the session secret
			# returned by the master.  This makes the enrollment token
			# worthless — an attacker who captured it cannot authenticate.
			if session_secret:
				# Store a hash of the original token secret so we can detect
				# genuinely new tokens on future restarts.
				node_state["enrollment_secret_hash"] = hashlib.sha256(
					api_secret.encode("utf-8")
				).hexdigest()
				api_secret = session_secret
				node_state["api_secret"] = api_secret
				# Log first 8 chars of the new secret hash for debugging
				new_secret_hash = hashlib.sha256(api_secret.encode("utf-8")).hexdigest()
				_log.info("Switched to session secret (hash=%s...)", new_secret_hash[:8])
				# Small delay to ensure master has fully committed the session secret
				# before we attempt authenticated requests with it
				await asyncio.sleep(SESSION_PROPAGATION_DELAY)

			current_config_version = current_config_version or None
			node_state["config_version"] = current_config_version
			_save_state(node_state)

			if current_config_version is None:
				_log.info("Enrollment completed without config payload, fetching full config...")
				try:
					current_config_version = await _pull_config(
						client,
						master_url,
						node_id,
						None,
						api_secret,
						cert_fingerprint,
					)
				except httpx.HTTPError as exc:
					_log.warning("Initial config pull after enrollment failed: %s", exc)
				except Exception as exc:
					_log.exception("Unexpected error during initial config pull: %s", exc)
				else:
					node_state["config_version"] = current_config_version
					_save_state(node_state)

			_log.info("Enrollment successful, starting sync loop")
		else:
			if state.get("master_ca_file") != master_ca_file:
				_save_state(node_state)
			_log.info("Already enrolled, resuming sync loop")
			
			# Check if we have a cached config but no running interfaces
			# This can happen after container restart - state is preserved but WG is down
			if current_config_version and not has_running_interfaces():
				_log.warning("Cached config version exists but no WG interfaces running — forcing full config pull")
				current_config_version = None
			
			# Initial config pull on resume (before entering loop)
			# This ensures we have config even if heartbeat fails
			if current_config_version is None:
				_log.info("Pulling initial config...")
				try:
					current_config_version = await _pull_config(
						client,
						master_url,
						node_id,
						None,  # Force full pull (no ETag)
						api_secret,
						cert_fingerprint,
					)
					if current_config_version:
						node_state["config_version"] = current_config_version
						_save_state(node_state)
				except Exception as exc:
					_log.warning("Initial config pull failed: %s", exc)

		# Debug: log which secret hash will be used for authentication
		_log.debug("Using api_secret hash=%s... for sync requests",
			hashlib.sha256(api_secret.encode("utf-8")).hexdigest()[:8])

		# Start SSE listener for instant push notifications
		config_changed_event = asyncio.Event()
		sse_task = asyncio.create_task(
			_sse_listener(
				master_url,
				api_secret,
				cert_fingerprint,
				tls_verify,
				config_changed_event,
				shutdown_event,
			)
		)

		# Sync loop
		backoff = 1
		last_saved_state = dict(node_state)  # Track for write guard
		try:
			while not shutdown_event.is_set():
				_log.debug("Sync loop: iteration start")
				heartbeat_failed = False
				config_failed = False
				
				# Check if SSE triggered a config change
				config_push_received = config_changed_event.is_set()
				if config_push_received:
					config_changed_event.clear()
					_log.info("Config push received via SSE — pulling config immediately")
				
				# Sample WireGuard stats ONCE per iteration (avoid double syscalls)
				wg_dump: dict[str, Any] = {}
				try:
					wg_dump = await asyncio.to_thread(get_wg_dump)
					if wg_dump:
						peer_stats = [
							{
								"public_key": pub_key,
								"endpoint": stats.get("endpoint"),
								"latest_handshake": stats.get("latest_handshake"),
								"transfer_rx": stats.get("transfer_rx", 0),
								"transfer_tx": stats.get("transfer_tx", 0),
							}
							for pub_key, stats in wg_dump.items()
						]
						await asyncio.to_thread(enqueue_peer_traffic, metrics_queue_conn, peer_stats)
				except Exception as exc:
					_log.debug("Failed to sample/enqueue WG metrics: %s", exc)
				
				try:
					_log.debug("Sync loop: sending heartbeat...")
					await _push_heartbeat(
						client,
						master_url,
						node_id,
						api_secret,
						cert_fingerprint,
						metrics_queue_conn,
						wg_dump,  # Pass pre-sampled dump (avoid double syscall)
					)
					_log.debug("Sync loop: heartbeat OK")
				except httpx.HTTPStatusError as exc:
					detail = _extract_error_detail(exc.response)
					_log.warning("Heartbeat failed: HTTP %d (detail: %s)", exc.response.status_code, detail)
					heartbeat_failed = True
				except httpx.HTTPError as exc:
					_log.warning("Heartbeat failed: %s", exc)
					heartbeat_failed = True
				except Exception as exc:
					_log.exception("Unexpected heartbeat failure: %s", exc)
					heartbeat_failed = True

				try:
					# Always try to pull config, regardless of heartbeat status
					# Config and heartbeat are separate concerns - a heartbeat failure
					# shouldn't block getting the initial/updated configuration
					_log.debug("Sync loop: pulling config...")
					new_version = await _pull_config(
						client,
						master_url,
						node_id,
						current_config_version,
						api_secret,
						cert_fingerprint,
					)
					if new_version is not None:
						_log.debug("Sync loop: config updated to %s...", new_version[:16])
						current_config_version = new_version
						node_state["config_version"] = current_config_version
						# Write guard: only save if state actually changed
						if node_state != last_saved_state:
							_save_state(node_state)
							last_saved_state = dict(node_state)
					else:
						_log.debug("Sync loop: config unchanged")

				except httpx.HTTPStatusError as exc:
					detail = _extract_error_detail(exc.response)
					_log.warning("Config sync error: HTTP %d (detail: %s)", exc.response.status_code, detail)
					config_failed = True
				except httpx.HTTPError as exc:
					_log.warning("Config sync error: %s", exc)
					config_failed = True
				except Exception as exc:
					_log.exception("Unexpected error while pulling config: %s", exc)
					config_failed = True

				if heartbeat_failed or config_failed:
					# Exponential backoff with jitter
					backoff = min(backoff * 2, 60) * random.uniform(0.8, 1.2)
					if config_failed:
						_log.warning("Retrying config pull in %.1fs", backoff)
				else:
					backoff = 1  # Reset on success

				# Wait for interval, SSE push event, or shutdown
				wait_time = backoff if backoff > 1 else SYNC_INTERVAL
				_log.debug("Sync loop: waiting %ds (backoff=%d)", wait_time, backoff)
				done, pending = await asyncio.wait(
					[
						asyncio.create_task(shutdown_event.wait()),
						asyncio.create_task(config_changed_event.wait()),
						asyncio.create_task(asyncio.sleep(wait_time)),
					],
					return_when=asyncio.FIRST_COMPLETED,
				)
				_log.debug("Sync loop: wait returned, %d done, %d pending", len(done), len(pending))
				
				# Cancel remaining tasks and await them to prevent warnings
				for task in pending:
					task.cancel()
				if pending:
					await asyncio.gather(*pending, return_exceptions=True)
				
				if shutdown_event.is_set():
					_log.debug("Sync loop: shutdown requested")
					break
				# If config_changed_event is set, loop continues immediately
				_log.debug("Sync loop: continuing iteration")

		except Exception as exc:
			_log.exception("Sync loop crashed with unexpected error: %s", exc)
			raise
		finally:
			# Cancel SSE listener
			sse_task.cancel()
			try:
				await sse_task
			except asyncio.CancelledError:
				pass

	# Graceful shutdown
	_log.info("Closing metrics queue...")
	close_queue(metrics_queue_conn)
	_log.info("Shutting down WireGuard interfaces...")
	await asyncio.to_thread(shutdown_all_interfaces)
	_log.info("Node daemon stopped")


from typing import NamedTuple

class EnrollResult(NamedTuple):
	success: bool
	config_version: str | None
	session_secret: str | None

async def _enroll(
	client: httpx.AsyncClient,
	master_url: str,
	enrollment_token: str,
	cert_pem: bytes,
	api_secret: str,
	cert_fingerprint: str,
) -> EnrollResult:
	"""Enroll with the master.

	Returns:
		EnrollResult on success or if properly enrolled, or on failure.
	"""
	_log.info("Enrolling with master...")
	try:
		resp = await client.post(
			f"{master_url}/api/nodes/enroll",
			headers=_build_request_headers(api_secret, cert_fingerprint),
			json={
				"enrollment_token": enrollment_token,
				"cert_pem": cert_pem.decode("utf-8"),
			},
		)
		if resp.status_code == 409:
			_log.info("Node already enrolled (409), will fetch config in sync loop")
			return EnrollResult(success=True, config_version=None, session_secret=None)
		resp.raise_for_status()
		data = resp.json()
		config = data.get("data", {})
		session_secret = config.pop("session_secret", None) if config else None
		version = ""
		if config:
			version = await asyncio.to_thread(apply_config, config)
		if session_secret:
			_log.info("Received session secret from master (enrollment token is now invalidated)")
		return EnrollResult(success=True, config_version=version, session_secret=session_secret)
	except httpx.HTTPStatusError as exc:
		_log.error("Enrollment HTTP error %d: %s", exc.response.status_code, exc.response.text[:200])
		return EnrollResult(success=False, config_version=None, session_secret=None)
	except Exception as exc:
		_log.exception("Enrollment failed: %s", exc)
		return EnrollResult(success=False, config_version=None, session_secret=None)


async def _push_heartbeat(
	client: httpx.AsyncClient,
	master_url: str,
	node_id: str,
	api_secret: str,
	cert_fingerprint: str,
	metrics_queue_conn: "sqlite3.Connection",
	wg_dump: dict[str, Any] | None = None,
) -> None:
	"""Push heartbeat with queued metrics to master.
	
	Implements reliable at-least-once delivery:
	1. Get pending metrics batch from local queue
	2. Send to master with sequence numbers
	3. Delete only metrics that master ACKed
	
	Args:
		wg_dump: Pre-sampled WireGuard dump (avoids double syscall if caller
		         already sampled). If None, will sample fresh.
	"""
	import sqlite3
	from ..utils.version import get_version
	uptime = _get_uptime()

	# Get pending metrics batch from queue
	pending_batch = await asyncio.to_thread(get_pending_batch, metrics_queue_conn)
	metrics_batch = serialize_batch_for_api(pending_batch)
	
	pending_count = len(pending_batch)
	if pending_count > 0:
		_log.debug(
			"Heartbeat: sending %d metrics (seq %s-%s)",
			pending_count,
			metrics_batch["seq_from"],
			metrics_batch["seq_to"],
		)

	# Use pre-sampled WG dump or sample fresh if not provided
	if wg_dump is None:
		try:
			wg_dump = await asyncio.to_thread(get_wg_dump)
		except Exception as exc:
			_log.debug("Failed to collect wg dump for heartbeat: %s", exc)
			wg_dump = {}

	peer_stats = [
		{
			"public_key": pub_key,
			"endpoint": stats.get("endpoint"),
			"latest_handshake": stats.get("latest_handshake"),
			"transfer_rx": stats.get("transfer_rx", 0),
			"transfer_tx": stats.get("transfer_tx", 0),
		}
		for pub_key, stats in wg_dump.items()
	]

	resp = await client.post(
		f"{master_url}/api/nodes/heartbeat",
		headers=_build_request_headers(api_secret, cert_fingerprint),
		json={
			"uptime": uptime,
			"version": get_version(),
			"peer_stats": peer_stats,
			"metrics_batch": metrics_batch,
		},
	)
	resp.raise_for_status()
	
	# Handle ACK: delete confirmed metrics from local queue
	try:
		data = resp.json()
		acked_seq = data.get("data", {}).get("acked_seq")
		if acked_seq is not None:
			deleted = await asyncio.to_thread(ack_up_to_seq, metrics_queue_conn, acked_seq)
			if deleted > 0:
				_log.debug("Heartbeat ACK: master confirmed %d metrics (up to seq %d)", deleted, acked_seq)
	except Exception as exc:
		_log.warning("Failed to process heartbeat ACK: %s", exc)


async def _sse_listener(
	master_url: str,
	api_secret: str,
	cert_fingerprint: str,
	tls_verify: bool | str,
	config_changed_event: asyncio.Event,
	shutdown_event: asyncio.Event,
) -> None:
	"""Listen for Server-Sent Events from master for instant config push.
	
	When a config_changed event is received, sets config_changed_event
	to trigger an immediate config pull in the main sync loop.
	
	When a restart_requested event is received, sets shutdown_event
	to trigger a graceful restart (Docker/systemd will restart the daemon).
	
	Uses a persistent client to avoid TLS handshake overhead on reconnect.
	"""
	reconnect_delay = 1
	max_reconnect_delay = 60
	
	# Create client outside loop to reuse connections and avoid TLS overhead
	async with httpx.AsyncClient(
		timeout=None,  # SSE connections are long-lived
		verify=tls_verify,
	) as sse_client:
		while not shutdown_event.is_set():
			try:
				_log.info("Connecting to master SSE event stream...")
				async with sse_client.stream(
					"GET",
					f"{master_url}/api/nodes/events",
					headers=_build_request_headers(api_secret, cert_fingerprint),
				) as response:
					if response.status_code != 200:
						_log.warning("SSE connection failed: HTTP %d", response.status_code)
						raise httpx.HTTPStatusError(
							f"SSE failed with {response.status_code}",
							request=response.request,
							response=response,
						)
					
					_log.info("SSE event stream connected — config changes will be pushed instantly")
					reconnect_delay = 1  # Reset on successful connection
					
					# Trigger immediate config pull when SSE reconnects
					# This ensures quick recovery when master comes back online
					config_changed_event.set()
					
					event_type = None  # Track current event type across lines
					async for line in response.aiter_lines():
						if shutdown_event.is_set():
							break
						
						line = line.strip()
						if not line or line.startswith(":"):
							continue  # Comment or keepalive
						
						if line.startswith("event:"):
							event_type = line[6:].strip()
						elif line.startswith("data:"):
							# Process data for the current event type
							if event_type == "config_changed":
								_log.info("Received config_changed event from master")
								config_changed_event.set()
							elif event_type == "restart_requested":
								_log.warning("Received restart_requested event from master — initiating graceful shutdown")
								shutdown_event.set()
								return
							event_type = None  # Reset after processing
						
			except httpx.HTTPStatusError as exc:
				if exc.response.status_code == 401:
					detail = _extract_error_detail(exc.response)
					_log.error("SSE authentication failed: %s", detail or "Invalid API secret")
				else:
					detail = _extract_error_detail(exc.response)
					_log.warning("SSE HTTP error: %d (detail: %s)", exc.response.status_code, detail or "unknown")
			except (httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError) as exc:
				_log.warning("SSE connection error: %s", exc)
			except asyncio.CancelledError:
				_log.debug("SSE listener cancelled")
				return
			except Exception as exc:
				_log.exception("Unexpected SSE error: %s", exc)
			
			if shutdown_event.is_set():
				break
			
			# Exponential backoff with jitter
			jittered_delay = reconnect_delay * random.uniform(0.8, 1.2)
			_log.info("SSE reconnecting in %.1fs...", jittered_delay)
			try:
				await asyncio.wait_for(shutdown_event.wait(), timeout=jittered_delay)
				break  # Shutdown requested
			except asyncio.TimeoutError:
				pass
			
			reconnect_delay = min(reconnect_delay * 2, max_reconnect_delay)


async def _pull_config(
	client: httpx.AsyncClient,
	master_url: str,
	node_id: str,
	current_version: str | None,
	api_secret: str,
	cert_fingerprint: str,
) -> str | None:
	"""Pull config from master. Returns new version if changed, else None."""
	params = {}
	if current_version:
		params["version"] = current_version

	resp = await client.get(
		f"{master_url}/api/nodes/config",
		headers=_build_request_headers(api_secret, cert_fingerprint),
		params=params,
	)
	resp.raise_for_status()
	data = resp.json()

	config = data.get("data")
	if config is None:
		# 304-equivalent: config unchanged
		return None

	peer_count = len(config.get("peers", []))
	_log.info("Received config from master: peers=%d interfaces=%d", peer_count, len(config.get("interfaces", [])))
	new_version = await asyncio.to_thread(apply_config, config)
	_log.info("Applied new config (version=%s...)", new_version[:16] if new_version else "none")
	return new_version


def _get_uptime() -> float | None:
	"""Read system uptime in seconds."""
	try:
		with open("/proc/uptime") as f:
			return float(f.read().split()[0])
	except (OSError, ValueError):
		return None


def run() -> None:
	"""Synchronous entry point for the node daemon."""
	asyncio.run(main())


if __name__ == "__main__":
	run()
