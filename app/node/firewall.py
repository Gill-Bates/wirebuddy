#!/usr/bin/env python3
#
# app/node/firewall.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

from __future__ import annotations

import logging
import os
import shutil
import subprocess

_log = logging.getLogger(__name__)

__all__ = ["check_firewall_dns_rules"]

def check_firewall_dns_rules(iface: str = "wg0") -> None:
    """Check if firewall allows DNS traffic on wireguard interface and fix if possible.
    
    DNS forwarding through the VPN tunnel requires port 53 to be open.
    Without this, clients connected via this node cannot resolve DNS.
    """
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
    except Exception:
        return
    
    try:
        rules_added = []
        for iptables_cmd in ("iptables", "ip6tables"):
            iptables_path = shutil.which(iptables_cmd)
            if not iptables_path:
                continue
                
            for chain in ("FORWARD", "INPUT"):
                for proto in ("udp", "tcp"):
                    result = subprocess.run(
                        [iptables_path, "-C", chain, "-i", iface, "-p", proto, "--dport", "53", "-j", "ACCEPT"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if result.returncode != 0:
                        result = subprocess.run(
                            [iptables_path, "-I", chain, "1", "-i", iface, "-p", proto, "--dport", "53", "-j", "ACCEPT"],
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        if result.returncode == 0:
                            v = "IPv6" if iptables_cmd == "ip6tables" else "IPv4"
                            rules_added.append(f"{v} {chain} {proto.upper()}/53")
                        else:
                            _log.warning("Failed to add %s %s rule for DNS/%s: %s", iptables_cmd, chain, proto.upper(), result.stderr.strip())
        
        if rules_added:
            _log.info("🔧 Auto-configured firewall: added DNS rules (%s) on %s", ", ".join(rules_added), iface)
        else:
            _log.debug("Firewall: DNS rules already present for %s", iface)
        
    except subprocess.TimeoutExpired:
        _log.debug("iptables check timed out")
    except PermissionError:
        _log.warning(
            "⚠️ Cannot check/fix firewall rules (permission denied). "
            "DNS may not work for clients."
        )
    except Exception as exc:
        _log.debug("Firewall check failed: %s", exc)
