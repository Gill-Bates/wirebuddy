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

import fcntl
import ipaddress
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

WG_CONFIG_DIR = Path(os.environ.get("WG_CONFIG_PATH", "/etc/wireguard"))
_MANAGED_HEADER = "# Managed by WireBuddy Node Daemon - do not edit manually"
_INTERFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,14}$")
_WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
# Strict hostname: labels of alnum+hyphen, no leading/trailing hyphen, max 253 chars
_HOSTNAME_RE = re.compile(
	r'^(?=.{1,253}$)(?!-)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
	r'[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
)
_LOCK_PATH = Path("/run/wirebuddy_wg.lock")

# Input size limits to prevent DoS via oversized config payloads
_MAX_INTERFACES = 32
_MAX_PEERS_PER_INTERFACE = 512
_MAX_CSV_ITEMS = 64  # For allowed_ips, addresses, etc.


# Tuned timeouts for different WireGuard operations
_TIMEOUT_WG_SHOW = 5
_TIMEOUT_WG_SET = 15
_TIMEOUT_WG_QUICK = 30


def _redact_keys(text: str) -> str:
	"""Truncate WireGuard keys in error messages to first 8 chars."""
	return _WG_KEY_RE.sub(lambda m: m.group()[:8] + "...", text)


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


def _run_checked(cmd: list[str], timeout: int = 30) -> tuple[str, str]:
	"""Run a command and raise when it fails (keys redacted in errors)."""
	code, stdout, stderr = _run(cmd, timeout=timeout)
	if code != 0:
		err = stderr.strip() or stdout.strip() or f"exit code {code}"
		redacted_cmd = _redact_keys(" ".join(cmd))
		raise RuntimeError(f"Command failed ({redacted_cmd}): {_redact_keys(err)}")
	return stdout, stderr


def _sanitize_config_value(key: str, value: Any) -> str:
	"""Reject control characters that would break config file structure."""
	text = str(value).strip()
	if not text:
		raise ValueError(f"Missing required value for {key!r}")
	if any(ch in text for ch in ("\n", "\r", "\x00")):
		raise ValueError(f"Unsafe control character in {key!r}")
	return text


def _validate_interface_name(name: Any) -> str:
	"""Validate Linux interface naming constraints."""
	value = _sanitize_config_value("name", name)
	if _INTERFACE_RE.fullmatch(value) is None:
		raise ValueError(f"Invalid interface name: {value!r}")
	return value


def _validate_wg_key(key: Any, *, field_name: str) -> str:
	"""Validate WireGuard base64 key format."""
	value = _sanitize_config_value(field_name, key)
	if _WG_KEY_RE.fullmatch(value) is None:
		raise ValueError(f"Invalid WireGuard key for {field_name!r}")
	return value


def _normalize_csv(value: Any, *, field_name: str) -> list[str]:
	"""Split and validate comma-separated config values."""
	text = _sanitize_config_value(field_name, value)
	items = [item.strip() for item in text.split(",") if item.strip()]
	if not items:
		raise ValueError(f"{field_name!r} must not be empty")
	if len(items) > _MAX_CSV_ITEMS:
		raise ValueError(f"{field_name!r} exceeds maximum of {_MAX_CSV_ITEMS} items")
	return items


def _validate_interface_addresses(value: Any, *, field_name: str) -> str:
	"""Validate interface address list (IPv4/IPv6 interface notation)."""
	items = _normalize_csv(value, field_name=field_name)
	normalized: list[str] = []
	for item in items:
		try:
			normalized.append(str(ipaddress.ip_interface(item)))
		except ValueError as exc:
			raise ValueError(f"Invalid address in {field_name!r}: {item!r}") from exc
	return ", ".join(normalized)


def _validate_peer_allowed_ips(value: Any, *, field_name: str) -> str:
	"""Validate peer tunnel addresses used as server-side allowed-ips."""
	items = _normalize_csv(value, field_name=field_name)
	normalized: list[str] = []
	for item in items:
		try:
			iface = ipaddress.ip_interface(item)
		except ValueError as exc:
			raise ValueError(f"Invalid allowed-ips entry in {field_name!r}: {item!r}") from exc
		if iface.network.num_addresses != 1:
			raise ValueError(f"Peer allowed-ips must be a host route, got {item!r}")
		normalized.append(str(iface))
	return ", ".join(normalized)


def _validate_port(value: Any, *, field_name: str) -> int:
	"""Validate TCP/UDP port range."""
	try:
		port = int(value)
	except (TypeError, ValueError) as exc:
		raise ValueError(f"Invalid integer for {field_name!r}: {value!r}") from exc
	if not (1 <= port <= 65535):
		raise ValueError(f"Port out of range for {field_name!r}: {port}")
	return port


def _validate_endpoint(value: Any, *, field_name: str) -> str:
	"""Validate WireGuard endpoint format (host:port or [ipv6]:port).

	Host part is validated as an IP address (v4/v6) or strict hostname.
	"""
	text = _sanitize_config_value(field_name, value)

	# Split host and port
	if text.startswith("["):
		# IPv6: [addr]:port
		if "]:" not in text:
			raise ValueError(f"Malformed IPv6 endpoint for {field_name!r}: {text!r}")
		host_part, port_str = text.rsplit("]:", 1)
		host_part = host_part[1:]  # strip leading [
		try:
			ipaddress.IPv6Address(host_part)
		except ValueError as exc:
			raise ValueError(f"Invalid IPv6 address in endpoint for {field_name!r}: {text!r}") from exc
	else:
		if ":" not in text:
			raise ValueError(f"Malformed endpoint for {field_name!r}: {text!r}")
		host_part, port_str = text.rsplit(":", 1)
		# Try IPv4 first, then hostname
		try:
			ipaddress.IPv4Address(host_part)
		except ValueError:
			if not _HOSTNAME_RE.fullmatch(host_part):
				raise ValueError(f"Invalid host in endpoint for {field_name!r}: {host_part!r}")

	_validate_port(port_str, field_name=f"{field_name} port")
	return text


def _validate_interface_config(raw: dict[str, Any]) -> dict[str, Any]:
	"""Validate and normalize a single interface config payload.

	Note: public_key and post_up/post_down from master are intentionally
	ignored — the node generates its own NAT hooks and never needs the
	master's public key for config rendering.
	"""
	name = _validate_interface_name(raw.get("name"))
	return {
		"name": name,
		"private_key": _validate_wg_key(raw.get("private_key"), field_name="private_key"),
		"address": _validate_interface_addresses(raw.get("address"), field_name="address"),
		"address6": _validate_interface_addresses(raw.get("address6"), field_name="address6") if raw.get("address6") else None,
		"listen_port": _validate_port(raw.get("listen_port"), field_name="listen_port"),
	}


def _validate_peer_config(raw: dict[str, Any], valid_ifaces: set[str]) -> dict[str, Any]:
	"""Validate and normalize a single peer config payload."""
	iface_name = _validate_interface_name(raw.get("interface"))
	if iface_name not in valid_ifaces:
		raise ValueError(f"Peer references unknown interface {iface_name!r}")
	return {
		"interface": iface_name,
		"public_key": _validate_wg_key(raw.get("public_key"), field_name="public_key"),
		"preshared_key": _validate_wg_key(raw.get("preshared_key"), field_name="preshared_key") if raw.get("preshared_key") else None,
		"peer_address": _validate_peer_allowed_ips(raw.get("peer_address"), field_name="peer_address"),
	}


def _get_config_dir() -> Path:
	"""Return the managed WireGuard config directory."""
	WG_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
	return WG_CONFIG_DIR.resolve()


def _get_interface_conf_path(name: str) -> Path:
	"""Return validated config path for an interface."""
	valid_name = _validate_interface_name(name)
	config_dir = _get_config_dir()
	conf_path = (config_dir / f"{valid_name}.conf").resolve()
	if conf_path.parent != config_dir:
		raise ValueError(f"Path traversal detected for interface {valid_name!r}")
	return conf_path


def _read_managed_config(path: Path) -> str | None:
	"""Return file content when it belongs to WireBuddy, else None."""
	if not path.exists():
		return None
	content = path.read_text(encoding="utf-8")
	if content.startswith(_MANAGED_HEADER):
		return content
	return None


def _get_default_route_iface() -> str | None:
	"""Detect the default-route network interface via `ip route get`."""
	try:
		code, stdout, _ = _run(
			["ip", "-4", "route", "get", "1.1.1.1"], timeout=_TIMEOUT_WG_SHOW,
		)
		if code == 0 and stdout.strip():
			# "1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.2 uid 0"
			parts = stdout.strip().split()
			if "dev" in parts:
				return parts[parts.index("dev") + 1]
	except Exception:
		_log.debug("Failed to detect default route interface", exc_info=True)
	return None


def _build_node_post_up(iface_name: str) -> str:
	"""Build PostUp rules for a node: IP forwarding + NAT/MASQUERADE."""
	phy = _get_default_route_iface() or "eth0"
	return (
		# sysctl may fail in unprivileged containers; use || true since
		# host-level forwarding is often already enabled via docker --sysctl
		f"sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 || true; "
		f"iptables -A FORWARD -i %i -j ACCEPT; "
		f"iptables -A FORWARD -o %i -j ACCEPT; "
		f"iptables -t nat -A POSTROUTING -o {phy} -j MASQUERADE; "
		f"ip6tables -A FORWARD -i %i -j ACCEPT; "
		f"ip6tables -A FORWARD -o %i -j ACCEPT; "
		f"ip6tables -t nat -A POSTROUTING -o {phy} -j MASQUERADE"
	)


def _build_node_post_down(iface_name: str) -> str:
	"""Build PostDown rules for a node: remove NAT/MASQUERADE."""
	phy = _get_default_route_iface() or "eth0"
	return (
		f"iptables -D FORWARD -i %i -j ACCEPT; "
		f"iptables -D FORWARD -o %i -j ACCEPT; "
		f"iptables -t nat -D POSTROUTING -o {phy} -j MASQUERADE; "
		f"ip6tables -D FORWARD -i %i -j ACCEPT; "
		f"ip6tables -D FORWARD -o %i -j ACCEPT; "
		f"ip6tables -t nat -D POSTROUTING -o {phy} -j MASQUERADE"
	)


def _render_interface_config(name: str, config: dict[str, Any]) -> str:
	"""Render sanitized WireGuard interface config content."""
	address_parts = [config["address"]]
	if config.get("address6"):
		address_parts.append(config["address6"])

	lines = [
		_MANAGED_HEADER,
		"[Interface]",
		f"PrivateKey = {config['private_key']}",
		f"Address = {', '.join(address_parts)}",
		f"ListenPort = {config['listen_port']}",
	]

	# Node: always generate own NAT rules (master PostUp/PostDown are ignored
	# because they reference the master's physical interface, not the node's)
	post_up = _build_node_post_up(name)
	post_down = _build_node_post_down(name)
	lines.append(f"PostUp = {post_up}")
	lines.append(f"PostDown = {post_down}")
	lines.append("")

	return "\n".join(lines) + "\n"


def _write_interface_config(name: str, config: dict[str, Any]) -> bool:
	"""Write a WireGuard interface config file and return True when content changed."""
	conf_path = _get_interface_conf_path(name)
	new_content = _render_interface_config(name, config)
	existing_managed = _read_managed_config(conf_path)
	if conf_path.exists() and existing_managed is None:
		raise ValueError(f"Refusing to overwrite unmanaged WireGuard config: {conf_path}")
	if existing_managed == new_content:
		return False

	fd: int | None = None
	tmp_path: str | None = None
	try:
		fd, tmp_path = tempfile.mkstemp(
			prefix=f".{name}.",
			suffix=".tmp",
			dir=str(conf_path.parent),
		)
		os.fchmod(fd, 0o600)
		os.write(fd, new_content.encode("utf-8"))
		os.close(fd)
		fd = None
		os.replace(tmp_path, conf_path)
	except Exception:
		if fd is not None:
			try:
				os.close(fd)
			except OSError:
				pass
		if tmp_path is not None:
			Path(tmp_path).unlink(missing_ok=True)
		raise
	_log.info("Wrote WireGuard config: %s", conf_path)
	return True


def _runtime_tmp_dir() -> Path | None:
	"""Prefer a root-owned runtime directory for ephemeral key material."""
	candidate = Path("/run")
	if candidate.is_dir():
		return candidate
	_log.warning("Runtime dir /run not available, using %s for PSK tempfiles", WG_CONFIG_DIR)
	return _get_config_dir()


def _write_psk_tempfile(psk: str, iface_name: str) -> Path:
	"""Write PSK to a secure temporary file and return its path."""
	fd, tmp_path = tempfile.mkstemp(
		prefix=f"wg_psk_{iface_name}_",
		dir=str(_runtime_tmp_dir()),
	)
	try:
		os.fchmod(fd, 0o600)
		os.write(fd, (psk + "\n").encode("utf-8"))
	finally:
		os.close(fd)
	return Path(tmp_path)


def _is_managed_interface(name: str) -> bool:
	"""Return True when the interface is backed by a WireBuddy-managed config."""
	try:
		conf_path = _get_interface_conf_path(name)
	except ValueError:
		return False
	return _read_managed_config(conf_path) is not None


def _remove_interface_config(name: str) -> None:
	"""Delete a managed WireGuard config file if present."""
	conf_path = _get_interface_conf_path(name)
	if _read_managed_config(conf_path) is not None:
		conf_path.unlink(missing_ok=True)
		_log.info("Removed WireGuard config: %s", conf_path)


def _get_running_interfaces() -> set[str]:
	"""Return set of currently running WireGuard interfaces."""
	code, stdout, stderr = _run(["wg", "show", "interfaces"], timeout=_TIMEOUT_WG_SHOW)
	if code != 0:
		_log.warning("Failed to query running WireGuard interfaces: %s", stderr.strip() or "unknown error")
		return set()
	return set(stdout.strip().split())


def has_running_interfaces() -> bool:
	"""Check if any WireGuard interfaces are currently running.
	
	Used by daemon to detect if config needs to be re-applied after restart.
	"""
	return len(_get_running_interfaces()) > 0


def apply_config(config: dict[str, Any]) -> str:
	"""Apply a full configuration from the master.

	Config format:
		{
			"config_version": "abc123",
			"interfaces": [{name, private_key, public_key, address, ...}],
			"peers": [{interface, public_key, preshared_key, peer_address, ...}],
			"master_peer": {interface, public_key, endpoint, allowed_ips, tunnel_address} or None,
		}

	Returns the applied config_version.
	"""
	# Serialize concurrent calls with a file lock
	lock_fd = os.open(str(_LOCK_PATH), os.O_CREAT | os.O_RDWR, 0o600)
	try:
		fcntl.flock(lock_fd, fcntl.LOCK_EX)
		return _apply_config_locked(config)
	finally:
		fcntl.flock(lock_fd, fcntl.LOCK_UN)
		os.close(lock_fd)


def _apply_config_locked(config: dict[str, Any]) -> str:
	"""Inner apply_config, called under file lock."""
	# Validate config structure
	if not isinstance(config, dict):
		raise ValueError("Config must be a dictionary")
	
	version = config.get("config_version", "")
	if not isinstance(version, str):
		raise ValueError(f"config_version must be string, got {type(version).__name__}")
	
	raw_interfaces = config.get("interfaces", [])
	raw_peers = config.get("peers", [])
	master_peer = config.get("master_peer")
	if not isinstance(raw_interfaces, list) or not isinstance(raw_peers, list):
		raise ValueError("Invalid config payload: interfaces/peers must be lists")

	interfaces = [_validate_interface_config(iface) for iface in raw_interfaces]
	if len(interfaces) > _MAX_INTERFACES:
		raise ValueError(f"Config exceeds maximum of {_MAX_INTERFACES} interfaces")
	
	desired_ifaces = {iface["name"] for iface in interfaces}
	if len(desired_ifaces) != len(interfaces):
		raise ValueError("Duplicate interface names in config payload")

	peers = [_validate_peer_config(peer, desired_ifaces) for peer in raw_peers]
	if len(peers) > _MAX_INTERFACES * _MAX_PEERS_PER_INTERFACE:
		raise ValueError(f"Config exceeds maximum total peer count")
	
	peers_by_interface: dict[str, list[dict[str, Any]]] = {name: [] for name in desired_ifaces}
	for peer in peers:
		peers_by_interface[peer["interface"]].append(peer)
	
	# Validate per-interface peer limits
	for iface_name, iface_peers in peers_by_interface.items():
		if len(iface_peers) > _MAX_PEERS_PER_INTERFACE:
			raise ValueError(f"Interface {iface_name} exceeds maximum of {_MAX_PEERS_PER_INTERFACE} peers")

	# 1. Ensure interfaces are up
	running = _get_running_interfaces()
	for iface in interfaces:
		name = iface["name"]
		changed = _write_interface_config(name, iface)
		if name not in running:
			_log.info("Bringing up interface %s...", name)
			_run_checked(["wg-quick", "up", name], timeout=_TIMEOUT_WG_QUICK)
			_log.info("Interface %s is up", name)
		elif changed:
			# wg syncconf only handles PrivateKey/ListenPort/peers;
			# Address and PostUp/PostDown require full wg-quick cycle.
			_log.info("Reloading interface %s (config changed)...", name)
			_run_checked(["wg-quick", "down", name], timeout=_TIMEOUT_WG_QUICK)
			_run_checked(["wg-quick", "up", name], timeout=_TIMEOUT_WG_QUICK)
			_log.info("Interface %s reloaded", name)

	# 2. Sync peers
	for iface_name in desired_ifaces:
		_sync_peers_for_interface(iface_name, peers_by_interface.get(iface_name, []))

	# 3. Configure master peer for DNS tunnel (Node→Master)
	if master_peer:
		_configure_master_peer(master_peer)

	# 4. Bring down interfaces that are no longer in config
	for name in running - desired_ifaces:
		if _is_managed_interface(name):
			_log.info("Bringing down removed interface %s...", name)
			_run_checked(["wg-quick", "down", name], timeout=_TIMEOUT_WG_QUICK)
			_remove_interface_config(name)

	return version


def _configure_master_peer(master_peer: dict[str, Any]) -> None:
	"""Configure the master as a WireGuard peer for DNS routing.

	This allows the node to route DNS queries through the tunnel to the master's
	Unbound DNS resolver.
	"""
	try:
		iface_name = _validate_interface_name(master_peer.get("interface"))
		public_key = _validate_wg_key(master_peer.get("public_key"), field_name="master_peer.public_key")
		endpoint = _validate_endpoint(master_peer.get("endpoint"), field_name="master_peer.endpoint")
		allowed_ips = _validate_peer_allowed_ips(master_peer.get("allowed_ips"), field_name="master_peer.allowed_ips")
	except (ValueError, KeyError) as exc:
		_log.error("Invalid master_peer config: %s", exc)
		return

	# Add master as a peer
	cmd = [
		"wg", "set", iface_name,
		"peer", public_key,
		"allowed-ips", allowed_ips,
		"endpoint", endpoint,
		"persistent-keepalive", "25",
	]
	code, _, stderr = _run(cmd, timeout=_TIMEOUT_WG_SET)
	if code != 0:
		_log.error("Failed to configure master peer on %s: %s", iface_name, _redact_keys(stderr.strip()))
		return

	_log.info(
		"Configured master peer for DNS tunnel: iface=%s, endpoint=%s, allowed_ips=%s",
		iface_name, endpoint, allowed_ips,
	)


def _get_current_peer_state(iface_name: str) -> dict[str, str]:
	"""Return {public_key: allowed_ips} for all current peers on an interface."""
	code, stdout, stderr = _run(
		["wg", "show", iface_name, "dump"], timeout=_TIMEOUT_WG_SHOW,
	)
	if code != 0:
		raise RuntimeError(f"Failed to query peers for {iface_name}: {_redact_keys(stderr.strip() or 'unknown error')}")
	state: dict[str, str] = {}
	for line in stdout.strip().split("\n"):
		parts = line.split("\t")
		# dump format: iface\tprivkey\tpubkey\tlistenport\tfwmark (interface line)
		# or: iface\tpubkey\tpsk\tendpoint\tallowed-ips\thandshake\trx\ttx\tkeepalive (peer line)
		# Actually wg show <iface> dump has a different format:
		# first line: privkey\tpubkey\tlistenport\tfwmark
		# peer lines: pubkey\tpsk\tendpoint\tallowed-ips\thandshake\trx\ttx\tkeepalive
		if len(parts) >= 4 and _WG_KEY_RE.fullmatch(parts[0]):
			# peer line
			state[parts[0]] = parts[3]  # allowed-ips
	return state


def _sync_peers_for_interface(iface_name: str, desired_peers: list[dict[str, Any]]) -> None:
	"""Synchronise peers for a single interface (diff-based: skip unchanged)."""
	current_state = _get_current_peer_state(iface_name)
	current_keys = set(current_state)

	desired_keys: set[str] = set()
	desired_map: dict[str, dict[str, Any]] = {}
	for p in desired_peers:
		key = p["public_key"]
		if key in desired_map:
			raise ValueError(f"Duplicate peer public key in config for {iface_name}: {key[:8]}...")
		desired_keys.add(key)
		desired_map[key] = p

	# Remove peers that shouldn't be on this interface
	for key in current_keys - desired_keys:
		_log.info("Removing peer %s... from %s", key[:8], iface_name)
		_run_checked(["wg", "set", iface_name, "peer", key, "remove"], timeout=_TIMEOUT_WG_SET)

	# Add/update desired peers (skip if allowed-ips unchanged and no PSK)
	changed = 0
	for key in desired_keys:
		p = desired_map[key]
		# Normalise for comparison: wg dump uses comma-separated without spaces
		desired_ips = p["peer_address"].replace(" ", "")
		current_ips = current_state.get(key, "").replace(" ", "")

		psk = p.get("preshared_key")
		if key in current_keys and desired_ips == current_ips and not psk:
			continue  # unchanged peer, skip

		cmd = ["wg", "set", iface_name, "peer", key, "allowed-ips", p["peer_address"]]
		if psk:
			psk_path = _write_psk_tempfile(psk, iface_name)
			try:
				cmd.extend(["preshared-key", str(psk_path)])
				_run_checked(cmd, timeout=_TIMEOUT_WG_SET)
			finally:
				psk_path.unlink(missing_ok=True)
		else:
			_run_checked(cmd, timeout=_TIMEOUT_WG_SET)
		changed += 1
		_log.debug("Synced peer %s (%s...) on %s", p.get("name") or key[:8], key[:8], iface_name)

	_log.info(
		"Peer sync for %s: %d desired, %d changed, %d removed",
		iface_name, len(desired_keys), changed, len(current_keys - desired_keys),
	)


def shutdown_all_interfaces() -> None:
	"""Bring down all WireGuard interfaces (for graceful shutdown)."""
	running = _get_running_interfaces()
	for name in running:
		if _is_managed_interface(name):
			_log.info("Shutting down interface %s...", name)
			_run(["wg-quick", "down", name])


def get_wg_dump() -> dict:
	"""Collect `wg show all dump` and return structured data.

	Returns dict of {public_key: {endpoint, handshake, rx, tx}}.
	"""
	code, stdout, _ = _run(["wg", "show", "all", "dump"], timeout=_TIMEOUT_WG_SHOW)
	if code != 0 or not stdout.strip():
		return {}

	result: dict[str, dict] = {}
	for line in stdout.strip().split("\n"):
		parts = line.split("\t")
		if len(parts) != 9:
			continue
		pubkey = parts[1]
		try:
			result[pubkey] = {
				"endpoint": parts[3] if parts[3] != "(none)" else None,
				"latest_handshake": int(parts[5]) if parts[5] != "0" else None,
				"transfer_rx": int(parts[6]),
				"transfer_tx": int(parts[7]),
			}
		except ValueError:
			_log.debug("Skipping malformed wg dump line for peer %s", pubkey[:8] if pubkey else "unknown")
	return result
