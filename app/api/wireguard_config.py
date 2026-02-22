#!/usr/bin/env python3
#
# app/api/wireguard_config.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard configuration file generation.

SECURITY WARNING: Generated configs contain decrypted private keys and PSKs.
Ensure config_path is on tmpfs (memory-backed filesystem) to prevent keys
from persisting on disk across reboots or in filesystem snapshots.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import sqlite3
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..db.sqlite_interfaces import (
	get_interface,
	list_interfaces,
)
from ..utils.network import allowed_ips_with_dns_routes
from ..utils.vault import decrypt as vault_decrypt
from .wireguard_isolation import build_client_isolation_post_rules, extract_peer_ips

_log = logging.getLogger(__name__)

__all__ = [
    "write_interface_config",
    "regenerate_all_configs",
    "sync_interface_config",
    "allowed_ips_with_dns_routes",
    "RegenResult",
    "InterfaceNotFoundError",
    "ConfigWriteError",
]

# Regex for detecting potentially dangerous shell commands in PostUp/PostDown
_DANGEROUS_SHELL = re.compile(r'[`$\\]|\.\.|\$\(|/etc/passwd|/etc/shadow')


class InterfaceNotFoundError(Exception):
    """Raised when interface does not exist in database."""

    pass


class ConfigWriteError(Exception):
    """Raised when config write operation fails."""

    pass


@dataclass
class RegenResult:
    """Result of regenerating all interface configs."""

    succeeded: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)  # interface_name → error


def _validate_hook(value: str, label: str) -> str:
    """Validate PostUp/PostDown hook for safe shell execution.

    Raises:
        ValueError: If hook contains unsafe patterns.
    """
    if not value:
        return value

    # Check for obviously dangerous patterns
    if _DANGEROUS_SHELL.search(value):
        raise ValueError(f"Unsafe {label} hook contains dangerous shell characters")

    # Validate each command in the hook
    for cmd in value.split(";"):
        cmd = cmd.strip()
        if not cmd:
            continue
        # Allow only known-safe network/firewall commands
        if not cmd.startswith(("iptables ", "ip6tables ", "ip ", "sysctl ", "nft ")):
            raise ValueError(
                f"Unsafe {label} command: {cmd!r}. Only iptables/ip6tables/ip/sysctl/nft commands allowed."
            )

    return value


def write_interface_config(
    config_path: Path,
    name: str,
    private_key: str,
    address: str,
    listen_port: int,
    dns: str | None,
    post_up: str | None,
    post_down: str | None,
    conn: sqlite3.Connection,
    address6: str | None = None,
    pepper: str = "",
) -> None:
    """Write a WireGuard interface config file including all peers.

    NOTE: This function mixes concerns (DB queries + file I/O). For testability,
    consider refactoring into separate query/render/write functions.

    Config files are regenerated from the encrypted database on each container
    restart, so persistence on disk is acceptable.
    """

    if post_up:
        post_up = _validate_hook(post_up, "PostUp")
    if post_down:
        post_down = _validate_hook(post_down, "PostDown")

    private_key_plain = vault_decrypt(private_key, pepper)

    addr_parts = [address]
    if address6:
        addr_parts.append(address6)

    config_lines = [
        "[Interface]",
        f"PrivateKey = {private_key_plain}",
        f"Address = {', '.join(addr_parts)}",
        f"ListenPort = {listen_port}",
    ]


    del private_key_plain

    # NOTE: DNS is intentionally omitted from the server-side config.
    # wg-quick rewrites /etc/resolv.conf when DNS is set, which breaks
    # container-internal DNS resolution.  DNS belongs only in the CLIENT
    # config (PeerConfig) that peers download.

    # Query all peers (enabled + disabled) for this interface
    cur = conn.execute(
        """
        SELECT public_key, preshared_key, peer_address, allowed_ips_mode, client_isolation, is_enabled
        FROM peers
        WHERE interface = ?
        ORDER BY is_enabled DESC, public_key
        """,
        (name,),
    )
    peer_rows = cur.fetchall()
    isolated_v4_ips: list[str] = []
    isolated_v6_ips: list[str] = []

    for peer_row in peer_rows:
        # Disabled peers: add a comment for audit trail
        if not peer_row["is_enabled"]:
            config_lines.append("")
            config_lines.append(f"# [Peer] {peer_row['public_key'][:16]}... (DISABLED)")
            continue

        if not peer_row["peer_address"]:
            continue  # Skip peers without assigned address

        # Check client_isolation flag for server-side firewall rules
        if peer_row["client_isolation"]:
            ipv4, ipv6 = extract_peer_ips(peer_row["peer_address"])
            if ipv4:
                isolated_v4_ips.append(ipv4)
            if ipv6:
                isolated_v6_ips.append(ipv6)

        config_lines.append("")
        config_lines.append("[Peer]")
        config_lines.append(f"PublicKey = {peer_row['public_key']}")

        if peer_row["preshared_key"]:
            # Decrypt PSK, use immediately, then clear from memory
            psk_plain = vault_decrypt(peer_row["preshared_key"], pepper)
            config_lines.append(f"PresharedKey = {psk_plain}")
            del psk_plain  # Minimize window for secret in memory

        config_lines.append(f"AllowedIPs = {peer_row['peer_address']}")

    # Append dynamic client-isolation firewall rules.
    v4_subnet = None
    try:
        v4_subnet = str(ipaddress.ip_interface(address).network)
    except ValueError:
        pass

    v6_subnet = None
    if address6:
        try:
            v6_subnet = str(ipaddress.ip_interface(address6).network)
        except ValueError:
            pass

    isolation_up, isolation_down = build_client_isolation_post_rules(
        name,
        v4_subnet=v4_subnet,
        v6_subnet=v6_subnet,
        isolated_v4_ips=isolated_v4_ips,
        isolated_v6_ips=isolated_v6_ips,
    )

    post_up_parts: list[str] = []
    post_down_parts: list[str] = []
    if post_up:
        post_up_parts.append(post_up)
    if post_down:
        post_down_parts.append(post_down)
    post_up_parts.extend(isolation_up)
    post_down_parts.extend(isolation_down)

    # Insert PostUp/PostDown before first [Peer] section (or at end of [Interface] block)
    peer_start = next(
        (i for i, line in enumerate(config_lines) if line == "[Peer]"),
        len(config_lines),
    )
    if post_down_parts:
        config_lines.insert(peer_start, f"PostDown = {'; '.join(post_down_parts)}")
    if post_up_parts:
        config_lines.insert(peer_start, f"PostUp = {'; '.join(post_up_parts)}")

    config_content = "\n".join(config_lines) + "\n"

    # NOTE: config_path.mkdir() should ideally be done once at startup, not per-write.
    # Doing it here masks deployment issues but ensures robustness.
    config_path.mkdir(parents=True, exist_ok=True)
    conf_file = config_path / f"{name}.conf"

    # Atomic write: write to temp file, chmod, then replace
    fd, temp_path = tempfile.mkstemp(dir=str(config_path), suffix=".tmp")
    try:
        os.write(fd, config_content.encode("utf-8"))
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)

    try:
        # os.replace is atomic on same filesystem and cross-platform
        os.replace(temp_path, str(conf_file))
    except Exception:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


    del config_content, config_lines


def regenerate_all_configs(
    config_path: Path,
    conn: sqlite3.Connection,
    pepper: str = "",
) -> RegenResult:
    """Regenerate all WireGuard configs from database.

    Returns:
        RegenResult with lists of succeeded/failed interfaces.
    """
    interfaces = list_interfaces(conn)
    result = RegenResult()

    for iface in interfaces:
        if not iface["is_enabled"]:
            continue
        try:
            write_interface_config(
                config_path,
                iface["name"],
                iface["private_key"],
                iface["address"],
                iface["listen_port"],
                iface["dns"],
                iface["post_up"],
                iface["post_down"],
                conn,
                address6=iface["address6"],
                pepper=pepper,
            )
            result.succeeded.append(iface["name"])
            _log.info("CONFIG_REGENERATED interface=%s", iface["name"])
        except Exception as e:
            error_msg = str(e)
            result.failed[iface["name"]] = error_msg
            _log.error("CONFIG_REGENERATE_FAILED interface=%s error=%s", iface["name"], error_msg)

    return result


def sync_interface_config(
    config_path: Path,
    interface_name: str,
    conn: sqlite3.Connection,
    pepper: str = "",
) -> None:
    """Sync a single interface config file with DB state.

    Raises:
        InterfaceNotFoundError: If interface does not exist in database.
        ConfigWriteError: If config write fails.
    """
    iface = get_interface(conn, interface_name)
    if not iface:
        raise InterfaceNotFoundError(f"Interface not found: {interface_name}")

    try:
        write_interface_config(
            config_path,
            iface["name"],
            iface["private_key"],
            iface["address"],
            iface["listen_port"],
            iface["dns"],
            iface["post_up"],
            iface["post_down"],
            conn,
            address6=iface["address6"],
            pepper=pepper,
        )
    except Exception as e:
        _log.warning("CONFIG_SYNC_FAILED interface=%s error=%s", interface_name, e)
        raise ConfigWriteError(f"Failed to write config for {interface_name}") from e


# Backwards-compatible alias for legacy imports
_sync_interface_config = sync_interface_config


# Re-export shared utility from network module for backwards compatibility
# (This avoids breaking existing imports of wireguard_config.allowed_ips_with_dns_routes)
__all__.append("allowed_ips_with_dns_routes")
