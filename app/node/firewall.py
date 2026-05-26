#!/usr/bin/env python3
#
# app/node/firewall.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

from __future__ import annotations

import re
import logging
import os
import shutil
import subprocess

_log = logging.getLogger(__name__)

__all__ = ["check_firewall_dns_rules"]

_IFACE_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,15}$")
_UNSUPPORTED_BACKENDS: set[str] = set()


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
    
    try:
        result = subprocess.run(
            ["ip", "link", "show", iface],
            capture_output=True,
            text=True,
            timeout=5,
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

            iptables_path = shutil.which(iptables_cmd)
            if not iptables_path:
                continue
                
            for chain in ("FORWARD", "INPUT"):
                for proto in ("udp", "tcp"):
                    result = subprocess.run(
                        [iptables_path, "-w", "-C", chain, "-i", iface, "-p", proto, "--dport", "53", "-j", "ACCEPT"],
                        capture_output=True,
                        text=True,
                        timeout=5,
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
