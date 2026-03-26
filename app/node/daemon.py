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
import logging
import os
import signal
import sys
import time
from pathlib import Path

import httpx

from ..utils.node_token import get_cert_fingerprint, verify_enrollment_token
from .cert import ensure_node_cert
from .wg_manager import apply_config, get_wg_dump, shutdown_all_interfaces

_log = logging.getLogger(__name__)

SYNC_INTERVAL = int(os.environ.get("WIREBUDDY_NODE_SYNC_INTERVAL", "30"))
DATA_DIR = Path(os.environ.get("WIREBUDDY_DATA_DIR", "/data"))
ENROLLED_FILE = DATA_DIR / ".enrolled"


async def main() -> None:
	"""Entry point for the node daemon."""
	logging.basicConfig(
		level=os.environ.get("LOG_LEVEL", "INFO").upper(),
		format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
		datefmt="%Y-%m-%d %H:%M:%S",
	)
	_log.info("WireBuddy Node Daemon starting...")

	# Parse enrollment token
	token_str = os.environ.get("WIREBUDDY_ENROLLMENT_TOKEN")
	if not token_str:
		_log.critical("WIREBUDDY_ENROLLMENT_TOKEN environment variable is required")
		sys.exit(1)

	# We need the secret key ONLY for token verification on the node side
	# Actually, nodes don't verify the token — they just decode it.
	# The token is base64(json_payload.hmac_sig) — the node extracts the payload.
	# Verification happens on the master during enrollment.
	try:
		import base64
		import json
		raw = base64.urlsafe_b64decode(token_str.encode("ascii")).decode("utf-8")
		payload_json, _ = raw.rsplit(".", 1)
		payload = json.loads(payload_json)
	except Exception as exc:
		_log.critical("Failed to decode enrollment token: %s", exc)
		sys.exit(1)

	master_url = payload["master_url"].rstrip("/")
	node_id = payload["node_id"]
	api_secret = payload["api_secret"]
	node_name = payload.get("node_name", "unknown")

	_log.info("Node: id=%s, name=%s, master=%s", node_id, node_name, master_url)

	# Ensure self-signed certificate
	DATA_DIR.mkdir(parents=True, exist_ok=True)
	cert_pem, _key_pem = ensure_node_cert(DATA_DIR, node_id)
	cert_fingerprint = get_cert_fingerprint(cert_pem)

	# Setup HTTP client
	headers = {
		"Authorization": f"Bearer {api_secret}",
		"X-Client-Cert-Fingerprint": cert_fingerprint,
		"Content-Type": "application/json",
	}

	# Graceful shutdown
	shutdown_event = asyncio.Event()

	def _signal_handler(sig: int, _frame: object) -> None:
		_log.info("Received signal %s, shutting down...", signal.Signals(sig).name)
		shutdown_event.set()

	signal.signal(signal.SIGTERM, _signal_handler)
	signal.signal(signal.SIGINT, _signal_handler)

	current_config_version: str | None = None

	async with httpx.AsyncClient(
		timeout=30.0,
		headers=headers,
		verify=False,  # Master may use self-signed cert too
	) as client:
		# Enrollment phase
		if not ENROLLED_FILE.exists():
			current_config_version = await _enroll(client, master_url, token_str, cert_pem)
			if current_config_version is None:
				_log.critical("Enrollment failed — exiting")
				sys.exit(1)
			ENROLLED_FILE.write_text(node_id)
			_log.info("Enrollment successful, starting sync loop")
		else:
			_log.info("Already enrolled, resuming sync loop")

		# Sync loop
		backoff = 1
		while not shutdown_event.is_set():
			try:
				# Push heartbeat
				await _push_heartbeat(client, master_url, node_id)

				# Pull config
				new_version = await _pull_config(client, master_url, node_id, current_config_version)
				if new_version:
					current_config_version = new_version

				backoff = 1  # Reset on success

			except httpx.HTTPError as exc:
				_log.warning("Sync error: %s (retrying in %ds)", exc, backoff)
				backoff = min(backoff * 2, 300)
			except Exception as exc:
				_log.exception("Unexpected error in sync loop: %s", exc)
				backoff = min(backoff * 2, 300)

			# Wait for interval or shutdown
			try:
				await asyncio.wait_for(
					shutdown_event.wait(),
					timeout=max(SYNC_INTERVAL, backoff),
				)
				break  # shutdown_event was set
			except asyncio.TimeoutError:
				pass  # Normal timeout, continue loop

	# Graceful shutdown
	_log.info("Shutting down WireGuard interfaces...")
	shutdown_all_interfaces()
	_log.info("Node daemon stopped")


async def _enroll(
	client: httpx.AsyncClient,
	master_url: str,
	enrollment_token: str,
	cert_pem: bytes,
) -> str | None:
	"""Enroll with the master. Returns initial config_version or None on failure."""
	_log.info("Enrolling with master...")
	try:
		resp = await client.post(
			f"{master_url}/api/nodes/enroll",
			json={
				"enrollment_token": enrollment_token,
				"cert_pem": cert_pem.decode("utf-8"),
			},
		)
		if resp.status_code == 409:
			_log.info("Node already enrolled (409), continuing...")
			return ""
		resp.raise_for_status()
		data = resp.json()
		config = data.get("data", {})
		if config:
			version = apply_config(config)
			return version
		return ""
	except httpx.HTTPStatusError as exc:
		_log.error("Enrollment HTTP error %d: %s", exc.response.status_code, exc.response.text[:200])
		return None
	except Exception as exc:
		_log.error("Enrollment failed: %s", exc)
		return None


async def _push_heartbeat(
	client: httpx.AsyncClient,
	master_url: str,
	node_id: str,
) -> None:
	"""Push heartbeat with WireGuard stats to master."""
	wg_data = get_wg_dump()
	uptime = _get_uptime()
	resp = await client.post(
		f"{master_url}/api/nodes/{node_id}/heartbeat",
		json={
			"wg_dump": wg_data,
			"uptime": uptime,
		},
	)
	resp.raise_for_status()


async def _pull_config(
	client: httpx.AsyncClient,
	master_url: str,
	node_id: str,
	current_version: str | None,
) -> str | None:
	"""Pull config from master. Returns new version if changed, else None."""
	params = {}
	if current_version:
		params["version"] = current_version

	resp = await client.get(
		f"{master_url}/api/nodes/{node_id}/config",
		params=params,
	)
	resp.raise_for_status()
	data = resp.json()

	config = data.get("data")
	if config is None:
		# 304-equivalent: config unchanged
		return None

	new_version = apply_config(config)
	_log.info("Applied new config (version=%s...)", new_version[:16] if new_version else "none")
	return new_version


def _get_uptime() -> float:
	"""Read system uptime in seconds."""
	try:
		with open("/proc/uptime") as f:
			return float(f.read().split()[0])
	except (OSError, ValueError):
		return 0.0


def run() -> None:
	"""Synchronous entry point for the node daemon."""
	asyncio.run(main())


if __name__ == "__main__":
	run()
