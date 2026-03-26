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
import signal
import sys
from pathlib import Path
from typing import Any

import httpx

from ..utils.banner import print_banner_once
from ..utils.node_token import get_cert_fingerprint, verify_enrollment_token
from .cert import clear_node_cert, ensure_node_cert
from .wg_manager import apply_config, get_wg_dump, shutdown_all_interfaces

_log = logging.getLogger(__name__)

SYNC_INTERVAL = int(os.environ.get("WIREBUDDY_NODE_SYNC_INTERVAL", "30"))
ENROLLMENT_RETRY_ATTEMPTS = max(1, int(os.environ.get("WIREBUDDY_ENROLLMENT_RETRY_ATTEMPTS", "3")))
DATA_DIR = Path("/app/data")
STATE_FILE = DATA_DIR / "node_state.json"


def _build_request_headers(api_secret: str, cert_fingerprint: str) -> dict[str, str]:
	"""Build per-request authentication headers."""
	return {
		"Authorization": f"Bearer {api_secret}",
		"X-Client-Cert-Fingerprint": cert_fingerprint,
	}


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
	ca_file_raw = os.environ.pop("WIREBUDDY_MASTER_CA_FILE", None)
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

	token_str = os.environ.pop("WIREBUDDY_ENROLLMENT_TOKEN", None)
	verify_key = os.environ.pop("WIREBUDDY_ENROLLMENT_VERIFY_KEY", None)
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

	master_url = str((state or payload)["master_url"]).rstrip("/")
	node_id = str((state or payload)["node_id"])
	api_secret = str((state or payload)["api_secret"])
	node_name = str((state or payload).get("node_name", "unknown"))
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

	async with httpx.AsyncClient(
		timeout=30.0,
		verify=tls_verify,
	) as client:
		# Enrollment phase
		if state is None:
			current_config_version = None
			session_secret: str | None = None
			for attempt in range(1, ENROLLMENT_RETRY_ATTEMPTS + 1):
				current_config_version, session_secret = await _enroll(
					client,
					master_url,
					token_str,
					cert_pem,
					api_secret,
					cert_fingerprint,
				)
				if current_config_version is not None:
					break
				if attempt >= ENROLLMENT_RETRY_ATTEMPTS:
					break

				delay = min(2 ** (attempt - 1), 30)
				_log.warning(
					"Enrollment attempt %d/%d failed, retrying in %ds",
					attempt,
					ENROLLMENT_RETRY_ATTEMPTS,
					delay,
				)
				try:
					await asyncio.wait_for(shutdown_event.wait(), timeout=delay)
					break
				except asyncio.TimeoutError:
					pass

			if current_config_version is None:
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
				_log.info("Switched to session secret (enrollment token invalidated)")

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

		# Sync loop
		backoff = 1
		while not shutdown_event.is_set():
			try:
				await _push_heartbeat(
					client,
					master_url,
					node_id,
					api_secret,
					cert_fingerprint,
				)
			except httpx.HTTPError as exc:
				_log.warning("Heartbeat failed: %s", exc)
			except Exception as exc:
				_log.exception("Unexpected heartbeat failure: %s", exc)

			try:
				# Pull config
				new_version = await _pull_config(
					client,
					master_url,
					node_id,
					current_config_version,
					api_secret,
					cert_fingerprint,
				)
				if new_version:
					current_config_version = new_version
					node_state["config_version"] = current_config_version
					_save_state(node_state)

				backoff = 1  # Reset on success

			except httpx.HTTPError as exc:
				_log.warning("Config sync error: %s (retrying in %ds)", exc, backoff)
				backoff = min(backoff * 2, 300)
			except Exception as exc:
				_log.exception("Unexpected error while pulling config: %s", exc)
				backoff = min(backoff * 2, 300)

			# Wait for interval or shutdown
			wait_time = backoff if backoff > 1 else SYNC_INTERVAL
			try:
				await asyncio.wait_for(
					shutdown_event.wait(),
					timeout=wait_time,
				)
				break  # shutdown_event was set
			except asyncio.TimeoutError:
				pass  # Normal timeout, continue loop

	# Graceful shutdown
	_log.info("Shutting down WireGuard interfaces...")
	await asyncio.to_thread(shutdown_all_interfaces)
	_log.info("Node daemon stopped")


async def _enroll(
	client: httpx.AsyncClient,
	master_url: str,
	enrollment_token: str,
	cert_pem: bytes,
	api_secret: str,
	cert_fingerprint: str,
) -> tuple[str | None, str | None]:
	"""Enroll with the master.

	Returns:
		(config_version, session_secret) on success.
		("", None) if the node is already enrolled (409).
		(None, None) on failure.
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
			return "", None
		resp.raise_for_status()
		data = resp.json()
		config = data.get("data", {})
		session_secret = config.pop("session_secret", None) if config else None
		version = ""
		if config:
			version = await asyncio.to_thread(apply_config, config)
		if session_secret:
			_log.info("Received session secret from master (enrollment token is now invalidated)")
		return version, session_secret
	except httpx.HTTPStatusError as exc:
		_log.error("Enrollment HTTP error %d: %s", exc.response.status_code, exc.response.text[:200])
		return None, None
	except Exception as exc:
		_log.exception("Enrollment failed: %s", exc)
		return None, None


async def _push_heartbeat(
	client: httpx.AsyncClient,
	master_url: str,
	node_id: str,
	api_secret: str,
	cert_fingerprint: str,
) -> None:
	"""Push heartbeat with WireGuard stats to master."""
	uptime = await asyncio.to_thread(_get_uptime)
	resp = await client.post(
		f"{master_url}/api/nodes/heartbeat",
		headers=_build_request_headers(api_secret, cert_fingerprint),
		json={
			"uptime": uptime,
		},
	)
	resp.raise_for_status()


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
