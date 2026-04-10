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
import ssl
import sys
import time
from datetime import datetime as dt, timedelta
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
SYNC_INTERVAL_FAST = int(os.environ.get("WIREBUDDY_NODE_SYNC_INTERVAL_FAST", "5"))
ENROLLMENT_RETRY_ATTEMPTS = max(1, int(os.environ.get("WIREBUDDY_ENROLLMENT_RETRY_ATTEMPTS", "3")))
SESSION_PROPAGATION_DELAY = 0.5  # Delay after enrollment to ensure master has committed session secret

# Speedtest scheduler constants (same window as master)
_SPEEDTEST_NIGHT_WINDOW_START_HOUR = 2
_SPEEDTEST_NIGHT_WINDOW_END_HOUR = 4
_SPEEDTEST_RUN_TIMEOUT_SECONDS = 120
_SPEEDTEST_LAST_RUN_FILE = "speedtest_last_run"
DATA_DIR = Path("/app/data")
STATE_FILE = DATA_DIR / "node_state.json"

# Failure detection thresholds
_MAX_AUTH_FAILURES = 3  # Consecutive 401 errors before assuming node removal
_MAX_RECONNECT_DELAY = 60  # Maximum SSE reconnection delay in seconds


def _build_request_headers(api_secret: str, cert_fingerprint: str) -> dict[str, str]:
	"""Build per-request authentication headers."""
	return {
		"Authorization": f"Bearer {api_secret}",
		"X-Client-Cert-Fingerprint": cert_fingerprint,
	}


def _extract_error_detail(response: httpx.Response) -> str:
	"""Extract error detail from HTTP response for logging.
	
	Safely handles both complete and streaming responses.
	"""
	try:
		data = response.json()
		if isinstance(data, dict):
			detail = data.get("detail", "")
			return str(detail)[:200]
	except httpx.ResponseNotRead:
		return ""
	except Exception:
		pass

	try:
		text = response.text
		return text[:200] if text else ""
	except httpx.ResponseNotRead:
		return ""
	except Exception:
		return ""


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

	env_name = os.getenv("WIREBUDDY_ENV", "").strip().lower()
	if env_name in {"prod", "production"}:
		raise ValueError("WIREBUDDY_ENROLLMENT_VERIFY_KEY is required in production")

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
			handle.flush()
			os.fsync(handle.fileno())
		os.replace(tmp, STATE_FILE)
	except Exception:
		tmp.unlink(missing_ok=True)
		raise


def _clear_enrollment_state() -> None:
	"""Clear all enrollment state for re-enrollment with a new token.

	Removes node state, certificates, and metrics queue.
	"""
	if STATE_FILE.exists():
		STATE_FILE.unlink()
		_log.info("Removed old node state file")

	clear_node_cert(DATA_DIR)

	# Clear metrics queue — old metrics are for a different master/context
	queue_file = DATA_DIR / "metrics_queue.db"
	cleared = False
	for suffix in ("", "-wal", "-shm"):
		f = queue_file.parent / (queue_file.name + suffix)
		if f.exists():
			f.unlink()
			cleared = True
	if cleared:
		_log.info("Cleared old metrics queue")


def _resolve_tls_verify(state: dict[str, Any] | None) -> tuple[ssl.SSLContext | bool, str | None]:
	"""Resolve TLS verification settings for master API calls.
	
	Returns an SSLContext with TLS 1.2 minimum enforced to prevent
	downgrade attacks. If a custom CA file is configured, it will be
	loaded into the context.
	"""
	ca_file_raw = os.getenv("WIREBUDDY_MASTER_CA_FILE")
	if not ca_file_raw and state is not None:
		ca_file_raw = state.get("master_ca_file")

	return _create_ssl_context(ca_file_raw)


def _create_ssl_context(ca_file: str | None = None) -> tuple[ssl.SSLContext, str | None]:
	"""Create a fresh SSLContext with TLS 1.2 minimum.
	
	Creates a new context instance to avoid sharing contexts between
	httpx clients (contexts may have internal state).
	"""
	# Create SSL context with TLS 1.2 minimum (prevents downgrade attacks)
	ssl_ctx = ssl.create_default_context()
	ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
	
	if not ca_file:
		# Use system CA certificates with TLS 1.2+ enforced
		return ssl_ctx, None

	ca_path = Path(str(ca_file)).expanduser()
	if not ca_path.exists() or not ca_path.is_file():
		raise RuntimeError(f"Configured master CA file does not exist: {ca_path}")

	# Load custom CA certificate
	ssl_ctx.load_verify_locations(cafile=str(ca_path))
	return ssl_ctx, str(ca_path)


# ─────────────────────────────────────────────────────────────────────────────
# Daily Speedtest Scheduler
# ─────────────────────────────────────────────────────────────────────────────


def _local_wall_clock_timestamp(day, hour: int) -> float:
	"""Return the local timestamp for a wall-clock hour using system DST rules."""
	wall_time = dt(day.year, day.month, day.day, hour, 0, 0)
	return time.mktime(wall_time.timetuple())


def _seconds_until_night_window() -> float:
	"""Calculate seconds until a jittered start time in the local night window.
	
	The target window is 02:00-04:00 local time.
	"""
	now_ts = time.time()
	now_local = dt.fromtimestamp(now_ts)
	today = now_local.date()
	start_today = _local_wall_clock_timestamp(today, _SPEEDTEST_NIGHT_WINDOW_START_HOUR)
	end_today = _local_wall_clock_timestamp(today, _SPEEDTEST_NIGHT_WINDOW_END_HOUR)
	min_test_runtime_seconds = 300.0

	# Currently within night window
	if start_today <= now_ts < end_today:
		remaining = max(0.0, end_today - now_ts)
		if remaining <= min_test_runtime_seconds:
			next_day = today + timedelta(days=1)
			next_start = _local_wall_clock_timestamp(next_day, _SPEEDTEST_NIGHT_WINDOW_START_HOUR)
			next_end = _local_wall_clock_timestamp(next_day, _SPEEDTEST_NIGHT_WINDOW_END_HOUR)
			window_duration_seconds = max(0.0, next_end - next_start)
			jitter_cap = max(0.0, window_duration_seconds - min_test_runtime_seconds)
			jitter_seconds = random.uniform(0.0, jitter_cap) if jitter_cap > 0 else 0.0
			return max(0.0, (next_start - now_ts) + jitter_seconds)
		max_jitter = max(0.0, remaining - min_test_runtime_seconds)
		return random.uniform(0.0, min(600.0, max_jitter))

	# Calculate next window start
	if now_ts < start_today:
		next_start = start_today
		next_end = end_today
	else:
		next_day = today + timedelta(days=1)
		next_start = _local_wall_clock_timestamp(next_day, _SPEEDTEST_NIGHT_WINDOW_START_HOUR)
		next_end = _local_wall_clock_timestamp(next_day, _SPEEDTEST_NIGHT_WINDOW_END_HOUR)

	window_duration_seconds = max(0.0, next_end - next_start)
	jitter_cap = max(0.0, window_duration_seconds - min_test_runtime_seconds)
	jitter_seconds = random.uniform(0.0, jitter_cap) if jitter_cap > 0 else 0.0

	return max(0.0, (next_start - now_ts) + jitter_seconds)


def _read_last_speedtest_run() -> float | None:
	"""Read the timestamp of the last speedtest run."""
	path = DATA_DIR / _SPEEDTEST_LAST_RUN_FILE
	if not path.exists():
		return None
	try:
		return float(path.read_text().strip())
	except (ValueError, OSError):
		return None


def _write_last_speedtest_run(ts: float) -> None:
	"""Write the timestamp of the last speedtest run."""
	path = DATA_DIR / _SPEEDTEST_LAST_RUN_FILE
	try:
		path.write_text(str(ts))
	except OSError as exc:
		_log.warning("Failed to write speedtest last run timestamp: %s", exc)


async def _send_speedtest_progress(
	client: httpx.AsyncClient,
	master_url: str,
	api_secret: str,
	cert_fingerprint: str,
	event: dict,
) -> None:
	"""Send speedtest progress update to master (best-effort, no retry)."""
	try:
		await client.post(
			f"{master_url}/api/nodes/speedtest/progress",
			headers=_build_request_headers(api_secret, cert_fingerprint),
			json={
				"phase": event.get("phase", ""),
				"progress": event.get("progress", 0),
				"message": event.get("message", ""),
				"detail": event.get("detail"),
			},
			timeout=5.0,  # Short timeout for progress updates
		)
	except Exception as exc:
		_log.debug("Failed to send speedtest progress to master: %s", exc)


async def _run_node_speedtest(
	client: httpx.AsyncClient,
	master_url: str,
	api_secret: str,
	cert_fingerprint: str,
) -> bool:
	"""Run a speedtest and submit results to master.
	
	Sends progress updates to master during the test for real-time UI feedback.
	
	Returns True if successful, False otherwise.
	"""
	from ..speedtest.tester import run_speedtest
	
	_log.info("NODE_SPEEDTEST starting bandwidth measurement")
	
	# Progress callback to send updates to master
	def progress_callback(event: dict) -> None:
		"""Send progress update to master (non-blocking)."""
		try:
			task = asyncio.create_task(
				_send_speedtest_progress(client, master_url, api_secret, cert_fingerprint, event)
			)

			def _consume_progress_exception(done_task: asyncio.Task[None]) -> None:
				if done_task.cancelled():
					return
				exc = done_task.exception()
				if exc is not None:
					_log.debug("Failed to send speedtest progress: %s", exc)

			task.add_done_callback(_consume_progress_exception)
		except Exception as exc:
			_log.debug("Failed to send speedtest progress: %s", exc)
	
	try:
		result = await asyncio.wait_for(
			run_speedtest(progress_callback=progress_callback),
			timeout=_SPEEDTEST_RUN_TIMEOUT_SECONDS
		)
	except asyncio.TimeoutError:
		_log.error("NODE_SPEEDTEST timeout after %ds", _SPEEDTEST_RUN_TIMEOUT_SECONDS)
		result = {"status": "error", "reason": f"Timeout after {_SPEEDTEST_RUN_TIMEOUT_SECONDS}s"}
	except Exception as exc:
		_log.error("NODE_SPEEDTEST failed: %s", exc)
		result = {"status": "error", "reason": str(exc)}
	
	# Submit result to master
	try:
		resp = await client.post(
			f"{master_url}/api/nodes/speedtest",
			headers=_build_request_headers(api_secret, cert_fingerprint),
			json=result,
		)
		resp.raise_for_status()
		_log.info(
			"NODE_SPEEDTEST submitted to master: status=%s dl=%.2f ul=%.2f",
			result.get("status"),
			result.get("download_mbit", 0),
			result.get("upload_mbit", 0),
		)
		return True
	except httpx.HTTPError as exc:
		_log.warning("NODE_SPEEDTEST failed to submit to master: %s", exc)
		return False


async def _speedtest_scheduler(
	client: httpx.AsyncClient,
	master_url: str,
	api_secret: str,
	cert_fingerprint: str,
	shutdown_event: asyncio.Event,
) -> None:
	"""Background task that runs daily speedtests during the night window.
	
	Runs once per day, during 02:00-04:00 local time with jitter to avoid
	all nodes running simultaneously.
	"""
	while not shutdown_event.is_set():
		try:
			# Check if we already ran a test today
			last_run = _read_last_speedtest_run()
			now = time.time()
			if last_run and (now - last_run) < 20 * 3600:  # Less than 20 hours ago
				# Already ran recently, wait until next day
				wait_seconds = _seconds_until_night_window()
				_log.debug("NODE_SPEEDTEST already ran %.1fh ago, next in %.0fs", (now - last_run) / 3600, wait_seconds)
			else:
				wait_seconds = _seconds_until_night_window()
				hours_since_last = (now - last_run) / 3600 if last_run else None
				_log.info(
					"NODE_SPEEDTEST scheduled in %.0f seconds (last run: %s)",
					wait_seconds,
					f"{hours_since_last:.1f}h ago" if hours_since_last else "never",
				)
			
			# Wait for the night window, checking for shutdown periodically
			remaining = wait_seconds
			while remaining > 0 and not shutdown_event.is_set():
				sleep_chunk = min(60.0, remaining)
				try:
					await asyncio.wait_for(shutdown_event.wait(), timeout=sleep_chunk)
					return  # Shutdown requested
				except asyncio.TimeoutError:
					remaining -= sleep_chunk
			
			if shutdown_event.is_set():
				return
			
			# Run the speedtest
			success = await _run_node_speedtest(client, master_url, api_secret, cert_fingerprint)
			if success:
				_write_last_speedtest_run(time.time())
			
			# Wait at least 20 hours before next potential run
			await asyncio.sleep(60)  # Brief sleep before rechecking
			
		except asyncio.CancelledError:
			raise
		except Exception as exc:
			_log.warning("NODE_SPEEDTEST scheduler error: %s", exc)
			# Wait a bit before retrying
			try:
				await asyncio.wait_for(shutdown_event.wait(), timeout=300)
				return
			except asyncio.TimeoutError:
				pass


async def _speedtest_on_demand_handler(
	client: httpx.AsyncClient,
	master_url: str,
	api_secret: str,
	cert_fingerprint: str,
	speedtest_requested_event: asyncio.Event,
	shutdown_event: asyncio.Event,
) -> None:
	"""Background task that runs speedtests when requested via SSE.
	
	Waits for speedtest_requested_event to be set, then runs a speedtest
	and clears the event. Can run multiple tests if event is set again.
	"""
	while not shutdown_event.is_set():
		try:
			# Wait for a speedtest request or shutdown
			await asyncio.wait(
				[
					asyncio.create_task(speedtest_requested_event.wait()),
					asyncio.create_task(shutdown_event.wait()),
				],
				return_when=asyncio.FIRST_COMPLETED,
			)
			
			if shutdown_event.is_set():
				return
			
			if speedtest_requested_event.is_set():
				speedtest_requested_event.clear()
				_log.info("NODE_SPEEDTEST on-demand request received from master")
				await _run_node_speedtest(client, master_url, api_secret, cert_fingerprint)
		except asyncio.CancelledError:
			return
		except Exception as exc:
			_log.warning("NODE_SPEEDTEST on-demand handler error: %s", exc)
			await asyncio.sleep(5)  # Brief delay before continuing


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
				stored_hash = state.get("enrollment_secret_hash")

				if payload["node_id"] != state["node_id"]:
					needs_reenroll = True
					reason = f"node_id changed ({payload['node_id']} vs {state['node_id']})"
				elif not stored_hash:
					# Legacy state without enrollment_secret_hash: token is present, so force
					# a clean enrollment to avoid stale session credentials.
					needs_reenroll = True
					reason = "legacy enrollment state without token hash"
				elif token_secret_hash != stored_hash:
					# Token secret changed from last enrollment
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
				if enroll_res.fatal:
					# Permanent error (token invalid, node deleted) — no point retrying
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
				# No cached state (we're in enrollment phase where state is None) and enrollment failed — fatal
				_log.critical("Enrollment failed and no cached state available — exiting")
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
			_log.info("Cached config version exists but no WG interfaces running — forcing full config pull")
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
		node_removed_event = asyncio.Event()  # Set when 401 auth failures indicate node removal
		speedtest_requested_event = asyncio.Event()  # Set when master requests on-demand speedtest
		sse_connected_event = asyncio.Event()  # Tracks whether SSE is currently connected
		sse_task = asyncio.create_task(
			_sse_listener(
				master_url,
				api_secret,
				cert_fingerprint,
				tls_verify,
				master_ca_file,
				config_changed_event,
				shutdown_event,
				node_removed_event,
				speedtest_requested_event,
				sse_connected_event,
			)
		)
		
		# Start daily speedtest scheduler
		speedtest_task = asyncio.create_task(
			_speedtest_scheduler(
				client,
				master_url,
				api_secret,
				cert_fingerprint,
				shutdown_event,
			)
		)
		
		# Start on-demand speedtest handler (triggered via SSE from master)
		speedtest_on_demand_task = asyncio.create_task(
			_speedtest_on_demand_handler(
				client,
				master_url,
				api_secret,
				cert_fingerprint,
				speedtest_requested_event,
				shutdown_event,
			)
		)

		# Sync loop
		backoff = 1
		consecutive_401_failures = 0  # Track auth failures to detect removal
		last_saved_state = dict(node_state)  # Track for write guard
		try:
			while not shutdown_event.is_set():
				# Check if node was removed (via SSE 401 or explicit event)
				if node_removed_event.is_set():
					_log.warning("Node removal detected (authentication failure) — clearing state")
					_clear_enrollment_state()
					break
				
				_log.debug("Sync loop: iteration start")
				heartbeat_failed = False
				config_failed = False
				auth_failed = False  # Track 401 errors specifically
				
				# Check if SSE triggered a config change
				config_push_received = config_changed_event.is_set()
				if config_push_received:
					config_changed_event.clear()
					_log.info("Config push received via SSE — pulling config immediately")
				
				# Sample WireGuard stats ONCE per iteration (avoid double syscalls)
				# Note: Heartbeat will handle both queue delivery and live peer_stats submission
				wg_dump: dict[str, Any] = {}
				try:
					wg_dump = await asyncio.to_thread(get_wg_dump)
				except Exception as exc:
					_log.debug("Failed to sample WG metrics: %s", exc)
				
				# Enqueue peer metrics for reliable delivery to master
				# Convert wg_dump dict to list format expected by enqueue_peer_traffic
				if wg_dump:
					peer_stats_list = [
						{
							"public_key": pub_key,
							"endpoint": stats.get("endpoint"),
							"latest_handshake": stats.get("latest_handshake"),
							"transfer_rx": stats.get("transfer_rx", 0),
							"transfer_tx": stats.get("transfer_tx", 0),
						}
						for pub_key, stats in wg_dump.items()
					]
					try:
						await asyncio.to_thread(enqueue_peer_traffic, metrics_queue_conn, peer_stats_list)
					except Exception as exc:
						_log.debug("Failed to enqueue peer metrics: %s", exc)
				
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
					consecutive_401_failures = 0  # Reset on success
				except httpx.HTTPStatusError as exc:
					detail = _extract_error_detail(exc.response)
					_log.warning("Heartbeat failed: HTTP %d (detail: %s)", exc.response.status_code, detail)
					heartbeat_failed = True
					if exc.response.status_code == 401:
						auth_failed = True
						consecutive_401_failures += 1
						if consecutive_401_failures >= _MAX_AUTH_FAILURES:
							_log.error(
								"Multiple consecutive 401 errors (%d) — node likely removed from master",
								consecutive_401_failures
							)
							node_removed_event.set()
					else:
						consecutive_401_failures = 0  # Reset on non-auth errors
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
					backoff = min(backoff * 2, 60)
					wait_time = backoff * random.uniform(0.8, 1.2)
					if config_failed:
						_log.warning("Retrying config pull in %.1fs", wait_time)
				else:
					backoff = 1  # Reset on success
					# Adaptive polling: use fast interval when SSE is disconnected
					# to ensure near-real-time config updates even without SSE push
					if sse_connected_event.is_set():
						wait_time = SYNC_INTERVAL
					else:
						wait_time = SYNC_INTERVAL_FAST
						_log.debug("SSE disconnected — using fast polling interval (%ds)", SYNC_INTERVAL_FAST)
				
				_log.debug("Sync loop: waiting %.1fs (backoff=%d)", wait_time, backoff)
				
				# Wait for interval with interruptible check for events
				while wait_time > 0 and not shutdown_event.is_set() and not config_changed_event.is_set():
					sleep_chunk = min(1.0, wait_time)
					try:
						await asyncio.wait_for(shutdown_event.wait(), timeout=sleep_chunk)
						break  # Shutdown requested
					except asyncio.TimeoutError:
						wait_time -= sleep_chunk
				
				if shutdown_event.is_set():
					_log.debug("Sync loop: shutdown requested")
					break
				# If config_changed_event is set, loop continues immediately
				_log.debug("Sync loop: continuing iteration")

		except Exception as exc:
			_log.exception("Sync loop crashed with unexpected error: %s", exc)
			raise
		finally:
			# Cancel SSE listener and speedtest tasks
			sse_task.cancel()
			speedtest_task.cancel()
			speedtest_on_demand_task.cancel()
			try:
				await sse_task
			except asyncio.CancelledError:
				pass
			except Exception as exc:
				_log.error("SSE listener task crashed: %s", exc, exc_info=True)
			try:
				await speedtest_task
			except asyncio.CancelledError:
				pass
			except Exception as exc:
				_log.error("Speedtest scheduler task crashed: %s", exc, exc_info=True)
			try:
				await speedtest_on_demand_task
			except asyncio.CancelledError:
				pass
			except Exception as exc:
				_log.error("On-demand speedtest task crashed: %s", exc, exc_info=True)

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
	fatal: bool = False  # Permanent error — do not retry

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
	_log.info("Enrolling with master at %s...", master_url)
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
			# 409 = Node enrolled with different certificate — cannot recover automatically.
			# User needs to delete the node on master and re-create with fresh token.
			_log.error(
				"Enrollment rejected: Node is enrolled with a different certificate. "
				"Delete the node in the master UI and generate a new enrollment token."
			)
			return EnrollResult(success=False, config_version=None, session_secret=None, fatal=True)
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
		status_code = exc.response.status_code
		detail = _extract_error_detail(exc.response)
		# 401 = invalid/expired token, 404 = node deleted on master — both permanent
		if status_code in (401, 404):
			_log.error(
				"Enrollment rejected by master (HTTP %d): %s — enrollment token is invalid or expired",
				status_code,
				detail or "no details",
			)
			return EnrollResult(success=False, config_version=None, session_secret=None, fatal=True)
		_log.error("Enrollment HTTP error %d: %s", status_code, detail or exc.response.text[:200])
		return EnrollResult(success=False, config_version=None, session_secret=None)
	except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout) as exc:
		_log.error("Enrollment timeout: %s", type(exc).__name__)
		return EnrollResult(success=False, config_version=None, session_secret=None)
	except httpx.ConnectError as exc:
		_log.error("Enrollment connection failed: master unreachable")
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
	tls_verify: ssl.SSLContext | bool,
	master_ca_file: str | None,
	config_changed_event: asyncio.Event,
	shutdown_event: asyncio.Event,
	node_removed_event: asyncio.Event,
	speedtest_requested_event: asyncio.Event,
	sse_connected_event: asyncio.Event | None = None,
) -> None:
	"""Listen for Server-Sent Events from master for instant config push.
	
	When a config_changed event is received, sets config_changed_event
	to trigger an immediate config pull in the main sync loop.
	
	When a restart_requested event is received, sets shutdown_event
	to trigger a graceful restart (Docker/systemd will restart the daemon).
	
	When a node_removed event is received, clears enrollment state and
	sets shutdown_event to trigger a clean exit.
	
	When a run_speedtest event is received, sets speedtest_requested_event
	to trigger an immediate speedtest.
	
	Args:
		master_ca_file: CA file path (if custom CA configured) for creating fresh SSL context
		tls_verify: TLS verification mode (passed for type compatibility, but fresh context is created)
	
	Uses a persistent client to avoid TLS handshake overhead on reconnect.
	"""
	_log.debug("SSE listener task started")
	_ = tls_verify  # Kept for API compatibility; listener uses a fresh context.
	reconnect_delay = 1
	consecutive_401_count = 0  # Track auth failures
	
	try:
		# Create fresh SSL context for this client (avoid sharing state)
		sse_tls_context, _ = _create_ssl_context(master_ca_file)
		
		# Create client outside loop to reuse connections and avoid TLS overhead
		async with httpx.AsyncClient(
			timeout=None,  # SSE connections are long-lived
			verify=sse_tls_context,  # Use fresh context
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
						consecutive_401_count = 0  # Reset on successful connection

						# Signal that SSE is connected (sync loop uses normal interval)
						if sse_connected_event is not None:
							sse_connected_event.set()

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
								elif event_type == "node_removed":
									_log.warning("Received node_removed event from master — clearing state and exiting")
									# Clear enrollment state so node doesn't keep trying to reconnect
									_clear_enrollment_state()
									shutdown_event.set()
									return
								elif event_type == "run_speedtest":
									_log.info("Received run_speedtest event from master — triggering on-demand speedtest")
									speedtest_requested_event.set()
								event_type = None  # Reset after processing
						
				except httpx.HTTPStatusError as exc:
					# Signal SSE disconnected so sync loop switches to fast polling
					if sse_connected_event is not None:
						sse_connected_event.clear()
					if exc.response.status_code == 401:
						consecutive_401_count += 1
						detail = _extract_error_detail(exc.response)
						detail_msg = f": {detail}" if detail else ""
						_log.error("SSE authentication failed (consecutive: %d)%s", consecutive_401_count, detail_msg)
						if consecutive_401_count >= _MAX_AUTH_FAILURES:
							_log.error("Multiple SSE auth failures — node likely removed from master")
							node_removed_event.set()
							return
					else:
						consecutive_401_count = 0  # Reset on non-auth errors
						detail = _extract_error_detail(exc.response)
						detail_msg = f" - {detail}" if detail else ""
						_log.warning("SSE HTTP error: %d%s", exc.response.status_code, detail_msg)
				except (httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError) as exc:
					_log.warning("SSE connection error: %s", exc)
					# Signal SSE disconnected so sync loop switches to fast polling
					if sse_connected_event is not None:
						sse_connected_event.clear()
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
				
				reconnect_delay = min(reconnect_delay * 2, _MAX_RECONNECT_DELAY)
	except Exception as exc:
		_log.exception("SSE listener task failed with unexpected error: %s", exc)
		raise
	finally:
		_log.debug("SSE listener task stopped")


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
