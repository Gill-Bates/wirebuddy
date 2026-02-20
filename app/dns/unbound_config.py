#!/usr/bin/env python3
#
# app/dns/unbound_config.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Unbound DNS configuration generation and management."""

from __future__ import annotations

import ipaddress
import logging
import os
import shutil
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .unbound_constants import (
	BLOCKLIST_REGISTRY,
	DNSSEC_ROOT_KEY,
	HOST_LABEL_RE,
	QUERY_LOG,
	UNBOUND_CONF,
	UNBOUND_CONF_DIR,
	UNBOUND_PID_FILE,
	UPSTREAM_ADDR_RE,
	atomic_write_text,
	get_blocklist_file,
)

_log = logging.getLogger(__name__)

# Default upstream DNS-over-TLS servers
_DEFAULT_UPSTREAM_DOT: list[str] = [
	"1.1.1.1@853#cloudflare-dns.com",
	"9.9.9.9@853#dns.quad9.net",
	"91.239.100.100@853#anycast.censurfridns.dk",
	"45.90.28.0@853#dns.nextdns.io",
	"194.242.2.2@853#dns.mullvad.net",
]

# ---------------------------------------------------------------------------
# Configuration Helpers
# ---------------------------------------------------------------------------

def _read_total_memory_mb() -> int | None:
	"""Best-effort detection of total system memory in MB."""
	try:
		with Path("/proc/meminfo").open("r", encoding="utf-8") as f:
			for line in f:
				if line.startswith("MemTotal:"):
					parts = line.split()
					if len(parts) >= 3 and parts[1].isdigit() and parts[2].lower() == "kb":
						return int(parts[1]) // 1024
	except Exception:
		return None
	return None


def _auto_num_threads() -> int:
	"""Choose a sane default thread count.
	
	Capped at 8 — higher counts add lock contention in typical
	WireGuard-gateway workloads with <1000 clients.
	"""
	cpu = os.cpu_count() or 1
	return max(1, min(cpu, 8))


def _auto_cache_sizes() -> tuple[str, str]:
	"""Choose msg/rrset cache sizes based on memory."""
	mem_mb = _read_total_memory_mb()
	if mem_mb is None:
		return ("32m", "64m")
	if mem_mb < 1024:
		return ("16m", "32m")
	if mem_mb < 2048:
		return ("32m", "64m")
	return ("64m", "128m")


def is_dnssec_available() -> bool:
	"""Return True if Unbound root trust anchor exists on disk."""
	return DNSSEC_ROOT_KEY.exists()


def _normalize_hostname(hostname: str) -> str:
	"""Validate and normalize a hostname to ASCII (IDNA)."""
	value = hostname.strip().strip(".").lower()
	if not value:
		raise ValueError("hostname is required")
	try:
		ascii_host = value.encode("idna").decode("ascii")
	except UnicodeError as exc:
		raise ValueError(f"invalid hostname: {hostname!r}") from exc
	if len(ascii_host) > 253:
		raise ValueError(f"hostname too long: {hostname!r}")
	for label in ascii_host.split("."):
		if not HOST_LABEL_RE.fullmatch(label):
			raise ValueError(f"invalid hostname label: {label!r}")
		if label.startswith("-") or label.endswith("-"):
			raise ValueError(f"invalid hostname label: {label!r}")
	return ascii_host


def _validate_upstream_dot(addr: str) -> str:
	"""Validate one DoT upstream address and normalize to ip@port#hostname."""
	addr = addr.strip()
	if "\n" in addr or "\r" in addr or "\x00" in addr:
		raise ValueError(f"upstream address contains control characters: {addr!r}")
	match = UPSTREAM_ADDR_RE.fullmatch(addr)
	if not match:
		raise ValueError("expected format <ip>@<port>#<hostname>")
	ip_part = match.group(1).strip()
	port_part = match.group(2)
	hostname_part = match.group(3).strip()
	# ipaddress.ip_address validates strictly (rejects garbage)
	normalized_ip = str(ipaddress.ip_address(ip_part))
	port = int(port_part) if port_part else 853
	if not 1 <= port <= 65535:
		raise ValueError(f"invalid port: {port}")
	hostname = _normalize_hostname(hostname_part)
	return f"{normalized_ip}@{port}#{hostname}"


# ---------------------------------------------------------------------------
# Configuration Generation
# ---------------------------------------------------------------------------

def _resolve_upstream(upstream_dns: list[str] | None) -> list[str]:
	"""Validate and return upstream DoT addresses, falling back to defaults."""
	upstream = upstream_dns or _DEFAULT_UPSTREAM_DOT[:]
	valid: list[str] = []
	invalid: list[str] = []
	for addr in upstream:
		addr = addr.strip()
		if not addr:
			continue
		try:
			valid.append(_validate_upstream_dot(addr))
		except Exception:
			invalid.append(addr)
			_log.warning("DNS_CONFIG upstream %r dropped (invalid DoT format)", addr)
	
	if invalid and not valid:
		raise ValueError(f"All upstream DNS entries invalid: {invalid}")
	if not valid:
		# All user-provided entries invalid; fall back to defaults
		_log.warning("DNS_CONFIG all upstream entries invalid, using defaults")
		valid = _DEFAULT_UPSTREAM_DOT[:]
	return valid


def generate_config(
	listen_addr: str = "0.0.0.0",
	listen_port: int = 53,
	enable_logging: bool = True,
	upstream_dns: list[str] | None = None,
	enable_blocklist: bool = True,
	enable_dnssec: bool = True,
	cache_min_ttl: int = 60,
	listen_addrs_ipv6: list[str] | None = None,
) -> str:
	"""Generate unbound.conf content.
	
	Args:
		cache_min_ttl: Minimum TTL for cached entries. Some CDNs use low TTLs
		              for fast failover; override with care.
		listen_addrs_ipv6: Optional list of IPv6 addresses to listen on
		                   (e.g., interface gateway addresses for dual-stack peers).
	"""
	try:
		ipaddress.ip_address(listen_addr)
	except ValueError as exc:
		raise ValueError(f"Invalid listen address: {listen_addr!r}") from exc
	if not isinstance(listen_port, int):
		raise TypeError(f"listen_port must be int, got {type(listen_port).__name__}")
	if not 1 <= listen_port <= 65535:
		raise ValueError(f"Invalid listen port: {listen_port!r}")
	try:
		cache_min_ttl_num = int(cache_min_ttl)
	except (TypeError, ValueError) as exc:
		raise ValueError(f"cache_min_ttl must be an integer: {cache_min_ttl!r}") from exc
	if not 0 <= cache_min_ttl_num <= 86400:
		raise ValueError(f"cache_min_ttl out of range: {cache_min_ttl_num}")

	upstream = _resolve_upstream(upstream_dns)
	
	# Check if DNSSEC root key is available
	dnssec_available = is_dnssec_available() and enable_dnssec
	num_threads = _auto_num_threads()
	msg_cache_size, rrset_cache_size = _auto_cache_sizes()

	# Build interface lines (IPv4 + optional IPv6 addresses)
	interface_lines = [f"    interface: {listen_addr}"]
	validated_v6: list[str] = []
	if listen_addrs_ipv6:
		for v6_raw in listen_addrs_ipv6:
			v6_raw = v6_raw.strip()
			if not v6_raw:
				continue
			try:
				v6_obj = ipaddress.ip_address(v6_raw)
				if v6_obj.version != 6:
					raise ValueError(f"Expected IPv6, got IPv4: {v6_raw!r}")
				validated_v6.append(str(v6_obj))
			except ValueError:
				_log.warning("DNS_CONFIG invalid IPv6 listen address %r, skipping", v6_raw)
	for v6_addr in validated_v6:
		interface_lines.append(f"    interface: {v6_addr}")
	interface_block = "\n".join(interface_lines)

	conf = f"""# WireBuddy Unbound Configuration
# Auto-generated – do not edit manually

server:
{interface_block}
    port: {listen_port}

    # Access control – only allow private/internal networks
    access-control: 127.0.0.0/8 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 192.168.0.0/16 allow
    access-control: ::1/128 allow
    access-control: fc00::/7 allow
    do-ip6: yes
    prefer-ip6: no

    # Blocklist tags for per-peer filtering
    define-tag: "{' '.join(BLOCKLIST_REGISTRY.keys())}"

    # Per-peer tag assignments (generated separately)
    include: {UNBOUND_CONF_DIR / "peer-tags.conf"}

    # Performance
    num-threads: {num_threads}
    msg-cache-slabs: 4
    rrset-cache-slabs: 4
    infra-cache-slabs: 4
    key-cache-slabs: 4
    msg-cache-size: {msg_cache_size}
    rrset-cache-size: {rrset_cache_size}
    cache-min-ttl: {cache_min_ttl_num}
    cache-max-ttl: 86400
    prefetch: yes
    prefetch-key: yes

    # Upstream server selection (round-robin with failover)
    # infra-host-ttl: how long to remember server RTT/status
    # infra-cache-min-rtt: minimum jitter for RTT-based selection (enables load distribution)
    # infra-lame-ttl: how long to avoid a non-responding/timeout server
    infra-host-ttl: 300
    infra-cache-min-rtt: 50
    infra-lame-ttl: 120

    # Privacy & Security
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    aggressive-nsec: {"yes" if dnssec_available else "no"}
    harden-glue: yes
    harden-dnssec-stripped: {"yes" if dnssec_available else "no"}
    harden-referral-path: yes
    use-caps-for-id: yes

    # TLS upstream
    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt
    username: "unbound"
    chroot: ""
    pidfile: /var/run/unbound.pid
"""
	
	# Add DNSSEC trust anchor only if enabled and root.key exists
	if dnssec_available:
		conf += """
    # DNSSEC
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
"""

	if enable_logging:
		conf += """
    # Query logging
    use-syslog: no
    log-queries: yes
    log-replies: yes
    log-tag-queryreply: yes
    logfile: /var/log/unbound/queries.log
    log-time-ascii: no
    verbosity: 4
"""

	if enable_blocklist:
		conf += f"""
    # Ad-blocking
    include: {get_blocklist_file()}
"""

	conf += """
# Upstream DNS (round-robin with automatic failover)
# Queries distributed across servers based on RTT; timeout servers avoided for infra-lame-ttl
forward-zone:
    name: "."
    forward-tls-upstream: yes
"""
	for dns in upstream:
		conf += f"    forward-addr: {dns}\n"

	return conf + "\n"


def get_interface_ipv6_gateways(interfaces: Sequence[Any]) -> list[str]:
	"""Extract IPv6 gateway addresses from interface rows.
	
	Accepts dicts, dataclass instances, or SQLAlchemy Row objects.
	
	Args:
		interfaces: Sequence of interface objects with 'address6' field.
	
	Returns:
		List of valid IPv6 gateway addresses (e.g., ['fd13:13:13::1']).
	"""
	ipv6_addrs: list[str] = []
	for iface in interfaces:
		try:
			addr6 = (
				iface.get("address6")
				if isinstance(iface, dict)
				else getattr(iface, "address6", None)
			)
		except Exception:
			continue
		if not addr6:
			continue
		try:
			v6_iface = ipaddress.ip_interface(addr6.strip())
			ipv6_addrs.append(str(v6_iface.ip))
		except ValueError:
			_log.debug("Invalid IPv6 interface address: %r", addr6)
	return ipv6_addrs


def write_config(**kwargs) -> None:
	"""Write unbound.conf to disk."""
	UNBOUND_CONF_DIR.mkdir(parents=True, exist_ok=True)
	QUERY_LOG.parent.mkdir(parents=True, exist_ok=True)
	UNBOUND_PID_FILE.parent.mkdir(parents=True, exist_ok=True)
	QUERY_LOG.touch(exist_ok=True)
	
	# Fix permissions: unbound runs as 'unbound' user and needs to write logs
	try:
		shutil.chown(QUERY_LOG, user="unbound", group="unbound")
		shutil.chown(QUERY_LOG.parent, user="unbound", group="unbound")
	except (OSError, LookupError) as exc:
		_log.debug("Could not chown query log to unbound user: %s", exc)
	
	# Ensure blocklist file exists (even if empty) so config include doesn't fail
	blocklist_path = get_blocklist_file()
	if not blocklist_path.exists():
		atomic_write_text(blocklist_path, "# Empty blocklist - will be populated on update\n")
	
	# Ensure peer-tags.conf exists (even if empty)
	peer_tags_path = UNBOUND_CONF_DIR / "peer-tags.conf"
	if not peer_tags_path.exists():
		atomic_write_text(peer_tags_path, "# Per-peer blocklist tags - auto-generated\n")

	content = generate_config(**kwargs)
	atomic_write_text(UNBOUND_CONF, content)
	_log.info("DNS_CONFIG written to %s", UNBOUND_CONF)


def write_peer_tags(peers: list[dict]) -> None:
	"""Generate peer-tags.conf for per-peer blocklist filtering.
	
	Args:
		peers: List of peer dicts with 'peer_address' and 'blocklist_ids' keys.
		       peer_address: e.g., "10.13.13.2/32, fd13:13:13::2/128"
		       blocklist_ids: list of enabled blocklist IDs, or None for all
	"""
	UNBOUND_CONF_DIR.mkdir(parents=True, exist_ok=True)
	peer_tags_path = UNBOUND_CONF_DIR / "peer-tags.conf"
	
	all_tags = list(BLOCKLIST_REGISTRY.keys())
	lines = [
		"# Per-peer blocklist tag assignments",
		f"# Auto-generated – {datetime.now(timezone.utc).isoformat()}",
		"# IMPORTANT: This file MUST be included inside the server: block",
		"",
	]
	
	for peer in peers:
		peer_address = peer.get("peer_address")
		use_adblocker = peer.get("use_adblocker", True)
		blocklist_ids = peer.get("blocklist_ids")
		
		if not peer_address or not use_adblocker:
			continue
		
		# Determine which tags this peer should have
		if blocklist_ids is None:
			# None = all blocklists enabled
			tags = all_tags
		else:
			# Filter to only valid tags
			tags = [bid for bid in blocklist_ids if bid in BLOCKLIST_REGISTRY]
		
		if not tags:
			continue
		
		# Parse peer_address (may contain multiple addresses: "10.x.x.x/32, fd13::x/128")
		for addr_part in peer_address.split(","):
			addr = addr_part.strip()
			if not addr:
				continue
			try:
				network = ipaddress.ip_network(addr, strict=False)
			except ValueError:
				_log.warning("DNS_PEER_TAGS invalid address %r, skipping", addr)
				continue
			lines.append(f'    access-control-tag: {network} "{" ".join(tags)}"')
	
	atomic_write_text(peer_tags_path, "\n".join(lines) + "\n")
	_log.info("DNS_PEER_TAGS written %d entries to %s", len([l for l in lines if l.startswith("    access")]), peer_tags_path)


__all__ = [
	"is_dnssec_available",
	"generate_config",
	"get_interface_ipv6_gateways",
	"write_config",
	"write_peer_tags",
]
