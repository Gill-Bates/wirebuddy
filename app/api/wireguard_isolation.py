#!/usr/bin/env python3
#
# app/api/wireguard_isolation.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard client isolation firewall rules.

SECURITY NOTE: Client isolation only blocks peer-to-peer traffic through the
FORWARD chain. Isolated peers can still reach the WireGuard host itself
(INPUT chain) and any services bound to the tunnel interface. To fully
isolate peers from the host, additional INPUT rules would be required.
"""

from __future__ import annotations

from ..db.sqlite_interfaces import (
	get_interface,
)

import hashlib
import ipaddress
import logging
import re
import sqlite3
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_interface
from typing import Awaitable, Callable


_log = logging.getLogger(__name__)

__all__ = [
    "client_iso_chain_name",
    "extract_peer_ips",
    "build_client_isolation_post_rules",
    "apply_client_isolation_runtime",
    "IsolationResult",
]

# Linux interface name validation (IFNAMSIZ=16, but 15 chars max)
_IFACE_RE = re.compile(r"^[a-zA-Z0-9_-]{1,15}$")

# IP/subnet validation regex (IPv4 and IPv6 with optional CIDR)
_IP_SUBNET_RE = re.compile(r"^[0-9a-fA-F.:]+(/\d{1,3})?$")

# Firewall configuration per IP version
_FW_CONFIG = {
    "v4": {"cmd": "iptables", "host_mask": "/32", "ipv6": False},
    "v6": {"cmd": "ip6tables", "host_mask": "/128", "ipv6": True},
}

# Maximum stale rules to remove in one pass (prevents infinite loops)
MAX_STALE_RULES = 50


@dataclass
class IsolationResult:
    """Result of applying client isolation rules."""

    applied: bool = False
    rules_ok: int = 0
    rules_failed: int = 0
    errors: list[str] = field(default_factory=list)


def _validate_ip_or_subnet(value: str, label: str) -> str:
    """Validate IP or subnet string before embedding in iptables rules.

    Raises:
        ValueError: If value contains unsafe characters.
    """
    if not _IP_SUBNET_RE.match(value):
        raise ValueError(f"Refusing to embed unsafe {label} in iptables rule: {value!r}")
    return value


def _parse_subnet(addr: str | None) -> str | None:
    """Parse an interface address and return the network in CIDR notation."""
    if not addr:
        return None
    try:
        return str(ip_interface(addr).network)
    except ValueError:
        return None


def _sorted_ips(ip_list: set[str]) -> list[str]:
    """Sort IP addresses in natural numeric order."""

    def _sort_key(ip_str: str) -> tuple[int, IPv4Address | IPv6Address]:
        try:
            addr = ip_address(ip_str)
            return (0 if isinstance(addr, IPv4Address) else 1, addr)
        except ValueError:
            # Fallback for invalid IPs - shouldn't happen but be safe
            return (2, IPv4Address("0.0.0.0"))

    return sorted(ip_list, key=_sort_key)


def client_iso_chain_name(interface_name: str, *, ipv6: bool = False) -> str:
    """Return deterministic firewall chain name for client-isolation rules.

    SECURITY: Truncates the base name BEFORE appending the hash suffix to
    ensure the hash is never clipped. This prevents collisions when different
    interface names normalize to the same truncated base.
    """
    prefix = "WBISO6_" if ipv6 else "WBISO4_"

    # Hash suffix for collision prevention (6 hex chars = 24 bits)
    hash_suffix = hashlib.sha256(interface_name.encode()).hexdigest()[:6]

    # iptables chain names limited to 28 chars
    # Structure: prefix (7) + base (variable) + "_" (1) + hash (6) = 14 + base
    # max_base = 28 - 7 - 1 - 6 = 14
    MAX_CHAIN = 28
    max_base = MAX_CHAIN - len(prefix) - 1 - len(hash_suffix)

    # Normalize and truncate base FIRST
    base = re.sub(r"[^A-Za-z0-9_]", "_", interface_name)[:max_base]

    return f"{prefix}{base}_{hash_suffix}"


def extract_peer_ips(peer_address: str | None) -> tuple[str | None, str | None]:
    """Extract IPv4/IPv6 host addresses from a stored peer_address string."""
    if not peer_address:
        return None, None
    v4: str | None = None
    v6: str | None = None
    for part in str(peer_address).split(","):
        item = part.strip()
        if not item:
            continue
        try:
            addr = ip_interface(item)
        except ValueError:
            continue
        if isinstance(addr.ip, IPv4Address):
            v4 = str(addr.ip)
        else:
            v6 = str(addr.ip)
    return v4, v6


def _build_rules_for_version(
    interface_name: str,
    *,
    subnet: str | None,
    isolated_ips: list[str],
    ipv6: bool,
) -> tuple[list[str], list[str]]:
    """Build PostUp/PostDown rules for a single IP version."""
    up_rules: list[str] = []
    down_rules: list[str] = []

    if not subnet:
        return up_rules, down_rules

    config = _FW_CONFIG["v6" if ipv6 else "v4"]
    cmd = config["cmd"]
    host_mask = config["host_mask"]
    chain = client_iso_chain_name(interface_name, ipv6=ipv6)

    # Validate subnet before embedding
    try:
        safe_subnet = _validate_ip_or_subnet(subnet, "subnet")
    except ValueError as e:
        _log.error("CLIENT_ISO: %s", e)
        return up_rules, down_rules

    # Create/flush chain (2>/dev/null masks "chain exists" errors which are expected)
    up_rules.extend([
        f"{cmd} -N {chain} 2>/dev/null || true",
        f"{cmd} -F {chain}",
        f"{cmd} -D FORWARD -i %i -o %i -j {chain} 2>/dev/null || true",
    ])

    if isolated_ips:
        up_rules.append(f"{cmd} -I FORWARD 1 -i %i -o %i -j {chain}")
        for ip in _sorted_ips(set(isolated_ips)):
            try:
                safe_ip = _validate_ip_or_subnet(ip, "peer IP")
            except ValueError as e:
                _log.error("CLIENT_ISO: %s", e)
                continue
            up_rules.append(f"{cmd} -A {chain} -s {safe_ip}{host_mask} -d {safe_subnet} -j DROP")
            up_rules.append(f"{cmd} -A {chain} -s {safe_subnet} -d {safe_ip}{host_mask} -j DROP")
    else:
        up_rules.append(f"{cmd} -X {chain} 2>/dev/null || true")

    down_rules.extend([
        f"{cmd} -D FORWARD -i %i -o %i -j {chain} 2>/dev/null || true",
        f"{cmd} -F {chain} 2>/dev/null || true",
        f"{cmd} -X {chain} 2>/dev/null || true",
    ])

    return up_rules, down_rules


def build_client_isolation_post_rules(
    interface_name: str,
    *,
    v4_subnet: str | None,
    v6_subnet: str | None,
    isolated_v4_ips: list[str],
    isolated_v6_ips: list[str],
) -> tuple[list[str], list[str]]:
    """Build PostUp/PostDown shell commands for peer-to-peer isolation.

    NOTE: Error output is silenced for chain-exists/chain-not-found cases
    which are expected during normal operation. Check logs for other failures.
    """
    all_up: list[str] = []
    all_down: list[str] = []

    # IPv4 rules
    up4, down4 = _build_rules_for_version(
        interface_name,
        subnet=v4_subnet,
        isolated_ips=isolated_v4_ips,
        ipv6=False,
    )
    all_up.extend(up4)
    all_down.extend(down4)

    # IPv6 rules
    up6, down6 = _build_rules_for_version(
        interface_name,
        subnet=v6_subnet,
        isolated_ips=isolated_v6_ips,
        ipv6=True,
    )
    all_up.extend(up6)
    all_down.extend(down6)

    return all_up, all_down


async def apply_client_isolation_runtime(
    interface_name: str,
    conn: sqlite3.Connection,
    run_wg_command: Callable[..., Awaitable[tuple[int, str, str]]] | None = None,
) -> IsolationResult:
    """Apply per-peer client-isolation rules to a running interface.

    Returns:
        IsolationResult with counts of successful/failed rule applications.
    """
    result = IsolationResult()

    # Validate interface name to prevent iptables argument injection
    if not _IFACE_RE.match(interface_name):
        _log.error("CLIENT_ISO: refusing invalid interface name: %r", interface_name)
        result.errors.append(f"Invalid interface name: {interface_name}")
        return result

    # Import default run_wg_command if not provided
    if run_wg_command is None:
        from .wireguard_utils import run_wg_command as _run_wg_command

        run_wg_command = _run_wg_command

    iface = get_interface(conn, interface_name)
    if not iface:
        return result

    # Skip when interface is down
    code, _, _ = await run_wg_command("wg", "show", interface_name)
    if code != 0:
        return result

    v4_subnet = _parse_subnet(iface["address"])
    v6_subnet = _parse_subnet(iface["address6"])

    # Fetch isolated peers
    cur = conn.execute(
        """
        SELECT peer_address
        FROM peers
        WHERE interface = ? AND is_enabled = 1 AND client_isolation = 1
        """,
        (interface_name,),
    )
    isolated_v4: list[str] = []
    isolated_v6: list[str] = []
    for row in cur.fetchall():
        ipv4, ipv6 = extract_peer_ips(row["peer_address"])
        if ipv4:
            isolated_v4.append(ipv4)
        if ipv6:
            isolated_v6.append(ipv6)

    async def _run_ignore(*args: str) -> int:
        """Execute command, log failures, return exit code."""
        cmd_name = args[0] if args else ""
        code_inner, _, stderr_inner = await run_wg_command(*args)
        if code_inner == 0:
            result.rules_ok += 1
        else:
            if stderr_inner and "No chain/target/match" not in stderr_inner:
                _log.debug("CLIENT_ISO runtime cmd failed (%s): %s", cmd_name, stderr_inner.strip())
                result.rules_failed += 1
        return code_inner

    async def _apply_for_version(
        subnet: str | None,
        isolated_ips: list[str],
        ipv6: bool,
    ) -> None:
        """Apply isolation rules for one IP version."""
        if not subnet:
            return

        config = _FW_CONFIG["v6" if ipv6 else "v4"]
        cmd = config["cmd"]
        host_mask = config["host_mask"]
        chain = client_iso_chain_name(interface_name, ipv6=ipv6)

        # Validate subnet
        try:
            safe_subnet = _validate_ip_or_subnet(subnet, "subnet")
        except ValueError as e:
            _log.error("CLIENT_ISO: %s", e)
            result.errors.append(str(e))
            return

        # Create/flush chain
        await _run_ignore(cmd, "-N", chain)
        await _run_ignore(cmd, "-F", chain)

        # Remove stale FORWARD jump rules (capped to prevent infinite loop)
        for _ in range(MAX_STALE_RULES):
            if await _run_ignore(cmd, "-D", "FORWARD", "-i", interface_name, "-o", interface_name, "-j", chain) != 0:
                break
        else:
            _log.warning("CLIENT_ISO: hit removal limit (%d) for chain %s", MAX_STALE_RULES, chain)

        if isolated_ips:
            await _run_ignore(cmd, "-I", "FORWARD", "1", "-i", interface_name, "-o", interface_name, "-j", chain)
            for ip in _sorted_ips(set(isolated_ips)):
                try:
                    safe_ip = _validate_ip_or_subnet(ip, "peer IP")
                except ValueError as e:
                    _log.error("CLIENT_ISO: %s", e)
                    result.errors.append(str(e))
                    continue
                await _run_ignore(cmd, "-A", chain, "-s", f"{safe_ip}{host_mask}", "-d", safe_subnet, "-j", "DROP")
                await _run_ignore(cmd, "-A", chain, "-s", safe_subnet, "-d", f"{safe_ip}{host_mask}", "-j", "DROP")
        else:
            await _run_ignore(cmd, "-X", chain)

    # Apply for both IP versions
    await _apply_for_version(v4_subnet, isolated_v4, ipv6=False)
    await _apply_for_version(v6_subnet, isolated_v6, ipv6=True)

    result.applied = True
    return result


# Backwards-compatible alias for existing imports
_apply_client_isolation_runtime = apply_client_isolation_runtime
