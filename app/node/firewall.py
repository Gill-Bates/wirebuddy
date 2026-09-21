#!/usr/bin/env python3
#
# app/node/firewall.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

from __future__ import annotations

import logging
import os
import re
import subprocess
from pathlib import Path

_log = logging.getLogger(__name__)

__all__ = ["check_firewall_dns_rules"]

_IFACE_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,15}$")
_UNSUPPORTED_BACKENDS: set[str] = set()

# `ip`, `iptables` and `ip6tables` must never be resolved via a bare name.
# The node daemon runs as root, so a writable PATH entry shadowing any of
# these would be root code execution - the same risk app/main.py's
# _resolve_trusted_binary exists to rule out for the master.
#
# The candidate lists are duplicated rather than imported: that helper lives
# in app/main.py, and importing it here would pull the whole FastAPI
# application into the node daemon, which deliberately does not depend on it.
_IP_BIN_CANDIDATES = (
    Path("/usr/sbin/ip"), Path("/sbin/ip"), Path("/usr/bin/ip"), Path("/bin/ip"),
)
_IPTABLES_BIN_CANDIDATES: dict[str, tuple[Path, ...]] = {
    "iptables": (
        Path("/usr/sbin/iptables"), Path("/sbin/iptables"),
        Path("/usr/bin/iptables"), Path("/bin/iptables"),
    ),
    "ip6tables": (
        Path("/usr/sbin/ip6tables"), Path("/sbin/ip6tables"),
        Path("/usr/bin/ip6tables"), Path("/bin/ip6tables"),
    ),
}


def _resolve_trusted_binary(candidates: tuple[Path, ...]) -> str | None:
    """Return the first existing absolute path from a fixed candidate list."""
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _resolve_ip_binary() -> str | None:
    """Return the first existing absolute `ip` path, or None if there is none."""
    return _resolve_trusted_binary(_IP_BIN_CANDIDATES)


def _resolve_iptables_binary(name: str) -> str | None:
    """Return the first existing absolute path for `iptables`/`ip6tables`."""
    return _resolve_trusted_binary(_IPTABLES_BIN_CANDIDATES[name])


def check_firewall_dns_rules(iface: str = "wg0") -> None:
    """Check if firewall allows DNS traffic on wireguard interface and fix if possible.

    DNS forwarding through the VPN tunnel requires port 53 to be open.
    Without this, clients connected via this node cannot resolve DNS.
    """
    if not _IFACE_RE.fullmatch(iface):
        raise ValueError(f"Invalid interface name: {iface!r}")

    if os.environ.get("SERVER_MODE", "").strip().lower() != "node":
        _log.debug("Skipping firewall DNS rule check outside node mode")
        return

    if os.environ.get("WIREBUDDY_NO_FIREWALL_FIX", "").lower() in ("1", "true", "yes"):
        _log.debug("Firewall auto-fix disabled via WIREBUDDY_NO_FIREWALL_FIX")
        return

    ip_bin = _resolve_ip_binary()
    if not ip_bin:
        _log.warning("No trusted `ip` binary found; skipping firewall DNS rule check")
        return

    try:
        result = subprocess.run(
            [ip_bin, "link", "show", iface],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode != 0:
            _log.debug("%s interface not yet present, deferring firewall check", iface)
            return
    except subprocess.TimeoutExpired:
        _log.warning("Timed out checking whether interface %s exists", iface)
        return
    except PermissionError:
        _log.warning("Permission denied while checking interface %s for firewall DNS rules", iface)
        return
    except Exception as exc:
        _log.warning("Failed to inspect interface %s before firewall DNS check: %s", iface, exc)
        return

    try:
        rules_added = []
        for iptables_cmd in ("iptables", "ip6tables"):
            if iptables_cmd in _UNSUPPORTED_BACKENDS:
                continue

            iptables_path = _resolve_iptables_binary(iptables_cmd)
            if not iptables_path:
                continue

            for chain in ("FORWARD", "INPUT"):
                for proto in ("udp", "tcp"):
                    result = subprocess.run(
                        [iptables_path, "-w", "-C", chain, "-i", iface, "-p", proto, "--dport", "53", "-j", "ACCEPT"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    stderr = (result.stderr or "").lower()
                    rule_missing = result.returncode == 1 and (
                        "does a matching rule exist" in stderr
                        or "bad rule" in stderr
                    )
                    if result.returncode == 0:
                        continue
                    if not rule_missing:
                        if iptables_cmd == "ip6tables" and (
                            "table does not exist" in stderr
                            or "protocol not supported" in stderr
                            or "can't initialize ip6tables table" in stderr
                            or "couldn't load target" in stderr
                        ):
                            _UNSUPPORTED_BACKENDS.add(iptables_cmd)
                            _log.debug("Skipping unsupported %s backend", iptables_cmd)
                            break
                        _log.warning(
                            "Failed to check %s %s rule for DNS/%s: %s",
                            iptables_cmd,
                            chain,
                            proto.upper(),
                            (result.stderr or result.stdout or "").strip(),
                        )
                        continue

                    result = subprocess.run(
                        [iptables_path, "-w", "-I", chain, "1", "-i", iface, "-p", proto, "--dport", "53", "-j", "ACCEPT"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    if result.returncode == 0:
                        v = "IPv6" if iptables_cmd == "ip6tables" else "IPv4"
                        rules_added.append(f"{v} {chain} {proto.upper()}/53")
                    else:
                        stderr = (result.stderr or result.stdout or "").strip()
                        if iptables_cmd == "ip6tables" and (
                            "table does not exist" in stderr.lower()
                            or "protocol not supported" in stderr.lower()
                            or "can't initialize ip6tables table" in stderr.lower()
                        ):
                            _UNSUPPORTED_BACKENDS.add(iptables_cmd)
                            _log.debug("Skipping unsupported %s backend", iptables_cmd)
                            break
                        _log.warning("Failed to add %s %s rule for DNS/%s: %s", iptables_cmd, chain, proto.upper(), stderr)

        if rules_added:
            _log.info("FIREWALL_DNS_RULES_ADDED iface=%s rules=%s", iface, ", ".join(rules_added))
        else:
            _log.debug("Firewall: DNS rules already present for %s", iface)

    except subprocess.TimeoutExpired:
        _log.warning("Timed out while checking or applying firewall DNS rules for %s", iface)
    except PermissionError:
        _log.warning(
            "Cannot check/fix firewall rules (permission denied). "
            "DNS may not work for clients."
        )
    except Exception as exc:
        _log.warning("Firewall DNS rule check failed for %s: %s", iface, exc)
