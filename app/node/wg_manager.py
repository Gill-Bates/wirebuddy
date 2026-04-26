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
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "apply_config",
    "shutdown_all_interfaces",
    "has_running_interfaces",
    "get_wg_dump",
]

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
_LOCK_TIMEOUT = 60  # Seconds to wait for file lock acquisition


@dataclass(slots=True, frozen=True)
class InterfaceConfig:
    name: str
    private_key: str
    address: str
    address6: str | None
    listen_port: int

@dataclass(slots=True, frozen=True)
class PeerConfig:
    interface: str
    public_key: str
    preshared_key: str | None
    peer_address: str
    endpoint: str | None = None
    persistent_keepalive: int | None = None

@dataclass(slots=True, frozen=True)
class PeerState:
    allowed_ips: str
    endpoint: str | None


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
        return result.returncode, result.stdout, _redact_keys(result.stderr)
    except subprocess.TimeoutExpired:
        _log.error("Command timed out: %s", _redact_keys(str(cmd)))
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
        raise RuntimeError(f"Command failed ({redacted_cmd}): {err}")
    return stdout, stderr


def _sanitize_config_value(key: str, value: Any) -> str:
    """Reject control characters that would break config file structure."""
    text = str(value).strip() if value is not None else ""
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
    """Validate WireGuard endpoint format (host:port or [ipv6]:port)."""
    text = _sanitize_config_value(field_name, value)

    if text.startswith("["):
        if "]:" not in text:
            raise ValueError(f"Malformed IPv6 endpoint for {field_name!r}: {text!r}")
        host_part, port_str = text.rsplit("]:", 1)
        host_part = host_part[1:]
        try:
            ipaddress.IPv6Address(host_part)
        except ValueError as exc:
            raise ValueError(f"Invalid IPv6 address in endpoint for {field_name!r}: {text!r}") from exc
    else:
        if ":" not in text:
            raise ValueError(f"Malformed endpoint for {field_name!r}: {text!r}")
        host_part, port_str = text.rsplit(":", 1)
        try:
            ipaddress.IPv4Address(host_part)
        except ValueError:
            if not _HOSTNAME_RE.fullmatch(host_part):
                raise ValueError(f"Invalid host in endpoint for {field_name!r}: {host_part!r}") from None

    _validate_port(port_str, field_name=f"{field_name} port")
    return text


def _validate_interface_config(raw: dict[str, Any]) -> InterfaceConfig:
    name = _validate_interface_name(raw.get("name"))
    return InterfaceConfig(
        name=name,
        private_key=_validate_wg_key(raw.get("private_key"), field_name="private_key"),
        address=_validate_interface_addresses(raw.get("address"), field_name="address"),
        address6=_validate_interface_addresses(raw.get("address6"), field_name="address6") if raw.get("address6") else None,
        listen_port=_validate_port(raw.get("listen_port"), field_name="listen_port"),
    )


def _validate_peer_config(raw: dict[str, Any], valid_ifaces: set[str], is_master: bool = False) -> PeerConfig:
    iface_name = _validate_interface_name(raw.get("interface"))
    if iface_name not in valid_ifaces:
        raise ValueError(f"Peer references unknown interface {iface_name!r}")
    
    endpoint = raw.get("endpoint")
    return PeerConfig(
        interface=iface_name,
        public_key=_validate_wg_key(raw.get("public_key"), field_name="public_key"),
        preshared_key=_validate_wg_key(raw.get("preshared_key"), field_name="preshared_key") if raw.get("preshared_key") else None,
        peer_address=_validate_peer_allowed_ips(raw.get("peer_address", raw.get("allowed_ips")), field_name="peer_address/allowed_ips"),
        endpoint=_validate_endpoint(endpoint, field_name="endpoint") if endpoint else None,
        persistent_keepalive=25 if is_master else None,
    )


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


def _fw_rules(family: str, action: str, phy: str) -> list[str]:
    return [
        f"{family} -{action} FORWARD 1 -i %i -j ACCEPT",
        f"{family} -{action} FORWARD 1 -o %i -j ACCEPT",
        f"{family} -t nat -{action.replace('I', 'A').replace('D', 'D')} POSTROUTING -o {phy} -j MASQUERADE",
    ]


def _build_node_post_up(_iface_name: str, cached_phy: str | None = None) -> str:
    phy = cached_phy or _get_default_route_iface() or "eth0"
    if _INTERFACE_RE.fullmatch(phy) is None:
        raise RuntimeError(f"Unsafe default route interface name: {phy!r}")
    rules = ["sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 || true"]
    rules.extend(_fw_rules("iptables", "I", phy))
    rules.extend(_fw_rules("ip6tables", "I", phy))
    return "; ".join(rules)


def _build_node_post_down(_iface_name: str, cached_phy: str | None = None) -> str:
    phy = cached_phy or _get_default_route_iface() or "eth0"
    if _INTERFACE_RE.fullmatch(phy) is None:
        raise RuntimeError(f"Unsafe default route interface name: {phy!r}")
    rules = _fw_rules("iptables", "D", phy)
    rules.extend(_fw_rules("ip6tables", "D", phy))
    return "; ".join(rules)


def _render_interface_config(name: str, config: InterfaceConfig, cached_phy: str | None = None) -> str:
    """Render sanitized WireGuard interface config content."""
    address_parts = [config.address]
    if config.address6:
        address_parts.append(config.address6)

    lines = [
        _MANAGED_HEADER,
        "[Interface]",
        f"PrivateKey = {config.private_key}",
        f"Address = {', '.join(address_parts)}",
        f"ListenPort = {config.listen_port}",
    ]

    post_up = _build_node_post_up(name, cached_phy)
    post_down = _build_node_post_down(name, cached_phy)
    lines.append(f"PostUp = {post_up}")
    lines.append(f"PostDown = {post_down}")
    lines.append("")

    return "\n".join(lines) + "\n"


def _write_interface_config(name: str, config: InterfaceConfig, cached_phy: str | None = None) -> bool:
    """Write a WireGuard interface config file and return True when content changed."""
    conf_path = _get_interface_conf_path(name)
    new_content = _render_interface_config(name, config, cached_phy)
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


def _runtime_tmp_dir() -> Path:
    """Prefer a root-owned runtime directory for ephemeral key material."""
    for candidate in (Path("/run"), Path("/dev/shm")):
        if candidate.is_dir():
            return candidate
    raise RuntimeError(
        "No ephemeral runtime directory available (/run, /dev/shm). "
        "Cannot securely store PSK tempfiles."
    )


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
        pass # Explicitly ignore, close is done and fd is collected.
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
    """Check if any WireGuard interfaces are currently running."""
    return len(_get_running_interfaces()) > 0


def apply_config(config: dict[str, Any]) -> str:
    """Apply a full configuration from the master."""
    lock_fd = os.open(str(_LOCK_PATH), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        start_time = time.monotonic()
        for attempt in range(_LOCK_TIMEOUT):
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if attempt == 0:
                    _log.info("Waiting for WireGuard config lock...")
                elapsed = time.monotonic() - start_time
                if elapsed >= _LOCK_TIMEOUT:
                    raise RuntimeError(f"Failed to acquire WireGuard config lock after {_LOCK_TIMEOUT}s")
                time.sleep(min(5.0, _LOCK_TIMEOUT - elapsed))
        return _apply_config_locked(config)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _parse_and_validate(config: dict[str, Any]) -> tuple[str, list[InterfaceConfig], dict[str, list[PeerConfig]]]:
    """Phase 0: Parse and validate all config objects safely."""
    if not isinstance(config, dict):
        raise ValueError("Config must be a dictionary")
    
    version = config.get("config_version", "")
    if not isinstance(version, str):
        raise ValueError(f"config_version must be string, got {type(version).__name__}")
    
    raw_interfaces = config.get("interfaces", [])
    raw_peers = config.get("peers", [])
    raw_master = config.get("master_peer")
    
    if not isinstance(raw_interfaces, list) or not isinstance(raw_peers, list):
        raise ValueError("Invalid config payload: interfaces/peers must be lists")

    interfaces = [_validate_interface_config(iface) for iface in raw_interfaces]
    if len(interfaces) > _MAX_INTERFACES:
        raise ValueError(f"Config exceeds maximum of {_MAX_INTERFACES} interfaces")
    
    desired_ifaces = {iface.name for iface in interfaces}
    if len(desired_ifaces) != len(interfaces):
        raise ValueError("Duplicate interface names in config payload")

    peers = [_validate_peer_config(peer, desired_ifaces) for peer in raw_peers]
    if len(peers) > _MAX_INTERFACES * _MAX_PEERS_PER_INTERFACE:
        raise ValueError(f"Config exceeds maximum total peer count")
    
    peers_by_interface: dict[str, list[PeerConfig]] = {name: [] for name in desired_ifaces}
    for peer in peers:
        peers_by_interface[peer.interface].append(peer)

    if raw_master is not None:
        if not isinstance(raw_master, dict):
            raise ValueError("master_peer must be a dict or null")
        master_peer = _validate_peer_config(raw_master, desired_ifaces, is_master=True)
        peers_by_interface[master_peer.interface].append(master_peer)

    all_peer_keys: set[str] = set()
    for iface_peers in peers_by_interface.values():
        if len(iface_peers) > _MAX_PEERS_PER_INTERFACE + 1: # +1 for master
            raise ValueError(f"Interface exceeds maximum peer limits")
        for peer in iface_peers:
            if peer.public_key in all_peer_keys:
                raise ValueError(f"Duplicate peer public key across interfaces: {peer.public_key[:8]}...")
            all_peer_keys.add(peer.public_key)

    return version, interfaces, peers_by_interface


def _write_interface_configs(interfaces: list[InterfaceConfig]) -> dict[str, bool]:
    """Phase 1: Write all configurations."""
    default_route_iface = _get_default_route_iface()
    changed_map: dict[str, bool] = {}
    for iface in interfaces:
        changed_map[iface.name] = _write_interface_config(iface.name, iface, default_route_iface)
    return changed_map


def _sync_interface_states(interfaces: list[InterfaceConfig], changed_map: dict[str, bool]) -> None:
    """Phase 2: Start or reload interfaces."""
    running = _get_running_interfaces()
    for iface in interfaces:
        name = iface.name
        changed = changed_map.get(name, False)
        if name not in running:
            _log.info("Bringing up interface %s...", name)
            _run_checked(["wg-quick", "up", name], timeout=_TIMEOUT_WG_QUICK)
            _log.info("Interface %s is up", name)
        elif changed:
            _log.info("Reloading interface %s (config changed)...", name)
            conf_path = _get_interface_conf_path(name)
            backup_content = conf_path.read_text(encoding="utf-8")
            try:
                _run_checked(["wg-quick", "down", name], timeout=_TIMEOUT_WG_QUICK)
                _run_checked(["wg-quick", "up", name], timeout=_TIMEOUT_WG_QUICK)
                _log.info("Interface %s reloaded", name)
            except RuntimeError as exc:
                _log.critical("Interface reload failed for %s: %s", name, exc)
                _log.warning("Attempting to restore previous config for %s...", name)
                try:
                    conf_path.write_text(backup_content, encoding="utf-8")
                    _run_checked(["wg-quick", "up", name], timeout=_TIMEOUT_WG_QUICK)
                    _log.warning("Successfully restored previous config for %s", name)
                except Exception as restore_exc:
                    _log.critical("Failed to restore %s (interface offline): %s", name, restore_exc)
                raise


def _remove_orphaned_interfaces(desired_ifaces: set[str]) -> None:
    """Phase 4: Turn off interfaces no longer in config."""
    running = _get_running_interfaces()
    for name in running - desired_ifaces:
        if _is_managed_interface(name):
            _log.info("Bringing down removed interface %s...", name)
            _run_checked(["wg-quick", "down", name], timeout=_TIMEOUT_WG_QUICK)
            _remove_interface_config(name)


def _apply_config_locked(config: dict[str, Any]) -> str:
    """Inner apply_config orchestration."""
    version, interfaces, peers_by_interface = _parse_and_validate(config)
    
    # Phase 1 & 2: Interfaces
    changed_map = _write_interface_configs(interfaces)
    _sync_interface_states(interfaces, changed_map)
    
    # Phase 3: Peers (handles normal node peers + master peer)
    for iface in interfaces:
        _sync_peers_for_interface(iface.name, peers_by_interface.get(iface.name, []))
    
    # Phase 4: Teardown old
    desired_ifaces = {i.name for i in interfaces}
    _remove_orphaned_interfaces(desired_ifaces)
    
    return version


def _ensure_routes_for_allowed_ips(iface_name: str, allowed_ips: str) -> None:
    """Add routes for allowed-ips to the WireGuard interface."""
    for ip_str in allowed_ips.split(","):
        ip_str = ip_str.strip()
        if not ip_str:
            continue
        ip_family_flag = "-6" if ":" in ip_str.split("/")[0] else "-4"
        code, _, stderr = _run(
            ["ip", ip_family_flag, "route", "replace", ip_str, "dev", iface_name],
            timeout=_TIMEOUT_WG_SET
        )
        if code != 0:
            _log.warning("Failed to add route %s dev %s: %s", ip_str, iface_name, stderr.strip())
        else:
            _log.debug("Added route %s dev %s", ip_str, iface_name)


def _get_current_peer_state(iface_name: str) -> dict[str, PeerState]:
    """Return dict mapping public_key -> PeerState for current peers."""
    code, stdout, stderr = _run(
        ["wg", "show", iface_name, "dump"], timeout=_TIMEOUT_WG_SHOW,
    )
    if code != 0:
        raise RuntimeError(f"Failed to query peers for {iface_name}: {_redact_keys(stderr.strip() or 'unknown error')}")
    state: dict[str, PeerState] = {}
    for line in stdout.strip().split("\n"):
        parts = line.split("\t")
        if len(parts) == 4:
            continue
        if len(parts) == 8 and _WG_KEY_RE.fullmatch(parts[0]):
            state[parts[0]] = PeerState(
                allowed_ips=parts[3],
                endpoint=parts[2] if parts[2] != "(none)" else None
            )
    return state


def _sync_peers_for_interface(iface_name: str, desired_peers: list[PeerConfig]) -> None:
    """Synchronise peers for an interface (diff-based). Handles additions and removals."""
    current_state = _get_current_peer_state(iface_name)
    current_keys = set(current_state)

    desired_keys: set[str] = set()
    desired_map: dict[str, PeerConfig] = {}
    for p in desired_peers:
        desired_keys.add(p.public_key)
        desired_map[p.public_key] = p

    for key in current_keys - desired_keys:
        _log.info("Removing peer %s... from %s", key[:8], iface_name)
        ip_str = current_state[key].allowed_ips
        _run_checked(["wg", "set", iface_name, "peer", key, "remove"], timeout=_TIMEOUT_WG_SET)
        
        for ip in ip_str.split(","):
            ip = ip.strip()
            if ip:
                ip_family_flag = "-6" if ":" in ip else "-4"
                _run(["ip", ip_family_flag, "route", "delete", ip, "dev", iface_name])

    changed = 0
    for key in desired_keys:
        p = desired_map[key]
        desired_ips = p.peer_address.replace(" ", "")
        current_ips = current_state.get(key, PeerState("", None)).allowed_ips.replace(" ", "")
        current_endpoint = current_state.get(key, PeerState("", None)).endpoint
        
        needs_update = (
            key not in current_keys or
            desired_ips != current_ips or
            (p.endpoint is not None and p.endpoint != current_endpoint) or
            p.preshared_key is not None
        )
        
        if not needs_update:
            continue

        cmd = ["wg", "set", iface_name, "peer", key, "allowed-ips", p.peer_address]
        if p.endpoint:
            cmd.extend(["endpoint", p.endpoint])
        if p.persistent_keepalive:
            cmd.extend(["persistent-keepalive", str(p.persistent_keepalive)])

        if p.preshared_key:
            psk_path = _write_psk_tempfile(p.preshared_key, iface_name)
            try:
                cmd.extend(["preshared-key", str(psk_path)])
                _run_checked(cmd, timeout=_TIMEOUT_WG_SET)
            finally:
                psk_path.unlink(missing_ok=True)
        else:
            cmd.extend(["preshared-key", "/dev/null"])
            _run_checked(cmd, timeout=_TIMEOUT_WG_SET)

        _ensure_routes_for_allowed_ips(iface_name, p.peer_address)
        changed += 1
        _log.debug("Synced peer on %s: %s...", iface_name, key[:8])

    _log.info(
        "Peer sync for %s: %d desired, %d changed, %d removed",
        iface_name, len(desired_keys), changed, len(current_keys - desired_keys),
    )


def shutdown_all_interfaces() -> None:
    """Bring down all WireGuard interfaces."""
    running = _get_running_interfaces()
    for name in running:
        if _is_managed_interface(name):
            _log.info("Shutting down interface %s...", name)
            _run(["wg-quick", "down", name])


def get_wg_dump() -> dict[str, dict[str, Any]]:
    """Collect `wg show all dump` and return structured data."""
    code, stdout, _ = _run(["wg", "show", "all", "dump"], timeout=_TIMEOUT_WG_SHOW)
    if code != 0 or not stdout.strip():
        return {}

    result: dict[str, dict[str, Any]] = {}
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
