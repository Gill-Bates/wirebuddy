#!/usr/bin/env python3
#
# app/node/wg_manager.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard configuration management for remote nodes.

Applies configuration diffs received from the master: creates/removes
interfaces and adds/removes peers.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

WG_CONFIG_DIR = Path(os.environ.get("WG_CONFIG_PATH", "/etc/wireguard"))


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
	"""Run a shell command and return (returncode, stdout, stderr)."""
	try:
		result = subprocess.run(
			cmd,
			capture_output=True,
			text=True,
			timeout=timeout,
		)
		return result.returncode, result.stdout, result.stderr
	except subprocess.TimeoutExpired:
		_log.error("Command timed out: %s", cmd)
		return -1, "", "timeout"
	except FileNotFoundError:
		_log.error("Command not found: %s", cmd[0])
		return -1, "", f"command not found: {cmd[0]}"


def _write_interface_config(name: str, config: dict) -> None:
	"""Write a WireGuard interface config file."""
	lines = [
		"# Managed by WireBuddy Node Daemon — do not edit manually",
		"[Interface]",
		f"PrivateKey = {config['private_key']}",
		f"Address = {config['address']}",
		f"ListenPort = {config['listen_port']}",
	]
	if config.get("address6"):
		lines[3] = f"Address = {config['address']}, {config['address6']}"
	if config.get("post_up"):
		lines.append(f"PostUp = {config['post_up']}")
	if config.get("post_down"):
		lines.append(f"PostDown = {config['post_down']}")
	lines.append("")

	content = "\n".join(lines) + "\n"
	conf_path = WG_CONFIG_DIR / f"{name}.conf"
	WG_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

	tmp = conf_path.with_suffix(".tmp")
	try:
		tmp.write_text(content)
		os.chmod(tmp, 0o600)
		os.replace(tmp, conf_path)
	except BaseException:
		tmp.unlink(missing_ok=True)
		raise
	_log.info("Wrote WireGuard config: %s", conf_path)


def _get_running_interfaces() -> set[str]:
	"""Return set of currently running WireGuard interfaces."""
	code, stdout, _ = _run(["wg", "show", "interfaces"])
	if code != 0:
		return set()
	return set(stdout.strip().split())


def apply_config(config: dict[str, Any]) -> str:
	"""Apply a full configuration from the master.

	Config format:
		{
			"config_version": "abc123",
			"interfaces": [{name, private_key, public_key, address, ...}],
			"peers": [{public_key, preshared_key, peer_address, ...}],
		}

	Returns the applied config_version.
	"""
	version = config.get("config_version", "")
	interfaces = config.get("interfaces", [])
	peers = config.get("peers", [])

	# 1. Ensure interfaces are up
	running = _get_running_interfaces()
	for iface in interfaces:
		name = iface["name"]
		_write_interface_config(name, iface)
		if name not in running:
			_log.info("Bringing up interface %s...", name)
			code, _, stderr = _run(["wg-quick", "up", name])
			if code != 0:
				_log.error("Failed to bring up %s: %s", name, stderr.strip())
			else:
				_log.info("Interface %s is up", name)

	# 2. Sync peers
	desired_ifaces = {i["name"] for i in interfaces}
	for iface_name in desired_ifaces:
		_sync_peers_for_interface(iface_name, peers)

	# 3. Bring down interfaces that are no longer in config
	for name in running - desired_ifaces:
		if name.startswith("wg"):
			_log.info("Bringing down removed interface %s...", name)
			_run(["wg-quick", "down", name])

	return version


def _sync_peers_for_interface(iface_name: str, desired_peers: list[dict]) -> None:
	"""Synchronise peers for a single interface (add/remove diff)."""
	# Get current peers
	code, stdout, _ = _run(["wg", "show", iface_name, "peers"])
	current_keys: set[str] = set()
	if code == 0 and stdout.strip():
		current_keys = {line.strip() for line in stdout.strip().split("\n") if line.strip()}

	desired_keys: set[str] = set()
	desired_map: dict[str, dict] = {}
	for p in desired_peers:
		desired_keys.add(p["public_key"])
		desired_map[p["public_key"]] = p

	# Remove peers that shouldn't be on this interface
	for key in current_keys - desired_keys:
		_log.info("Removing peer %s... from %s", key[:8], iface_name)
		_run(["wg", "set", iface_name, "peer", key, "remove"])

	# Add/update desired peers
	for key in desired_keys:
		p = desired_map[key]
		cmd = ["wg", "set", iface_name, "peer", key, "allowed-ips", p.get("peer_address", "")]
		psk = p.get("preshared_key")
		if psk:
			# Write PSK to temp file (avoid stdin issues in containers)
			psk_path = Path(f"/tmp/.wg_psk_{key[:8]}")
			try:
				psk_path.write_text(psk + "\n")
				os.chmod(psk_path, 0o600)
				cmd.extend(["preshared-key", str(psk_path)])
				_run(cmd)
			finally:
				psk_path.unlink(missing_ok=True)
		else:
			_run(cmd)

	_log.info("Synced %d peers for %s", len(desired_keys), iface_name)


def shutdown_all_interfaces() -> None:
	"""Bring down all WireGuard interfaces (for graceful shutdown)."""
	running = _get_running_interfaces()
	for name in running:
		_log.info("Shutting down interface %s...", name)
		_run(["wg-quick", "down", name])


def get_wg_dump() -> dict:
	"""Collect `wg show all dump` and return structured data.

	Returns dict of {public_key: {endpoint, handshake, rx, tx}}.
	"""
	code, stdout, _ = _run(["wg", "show", "all", "dump"])
	if code != 0 or not stdout.strip():
		return {}

	result: dict[str, dict] = {}
	for line in stdout.strip().split("\n"):
		parts = line.split("\t")
		if len(parts) < 8:
			continue
		# Skip interface lines (4 fields)
		if len(parts) == 4:
			continue
		pubkey = parts[1]
		result[pubkey] = {
			"endpoint": parts[3] if parts[3] != "(none)" else None,
			"latest_handshake": int(parts[5]) if parts[5] != "0" else None,
			"transfer_rx": int(parts[6]),
			"transfer_tx": int(parts[7]),
		}
	return result
