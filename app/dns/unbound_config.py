#!/usr/bin/env python3
#
# app/dns/unbound_config.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
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

from typing import TYPE_CHECKING

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
	get_custom_client_rules_file,
	get_local_data_file,
)

if TYPE_CHECKING:
	from .custom_rules import ParsedRule

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
						total_mb = int(parts[1]) // 1024
						return total_mb if total_mb > 0 else None
	except Exception:
		return None
	return None


def _get_field(obj: Any, key: str, default: Any = None) -> Any:
	"""Safely get a field from dict, sqlite3.Row, or object."""
	try:
		return obj[key]
	except (KeyError, TypeError, IndexError):
		pass
	try:
		return obj.get(key, default)
	except AttributeError:
		pass
	return getattr(obj, key, default)


def _safe_unbound_value(value: str) -> str:
	"""Reject values that could break Unbound config syntax."""
	if any(c in value for c in ('"', "\n", "\r", "\x00")):
		raise ValueError(f"Unsafe value for Unbound config: {value!r}")
	return value


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
		valid = [_validate_upstream_dot(addr) for addr in _DEFAULT_UPSTREAM_DOT]
	return valid


def generate_config(
	listen_addr: str = "127.0.0.1",
	listen_port: int = 53,
	enable_logging: bool = True,
	upstream_dns: list[str] | None = None,
	enable_blocklist: bool = True,
	enable_dnssec: bool = True,
	cache_min_ttl: int = 60,
	listen_addrs_ipv6: list[str] | None = None,
	listen_addrs_ipv4: list[str] | None = None,
) -> str:
	"""Generate unbound.conf content.
	
	Args:
		listen_addr: Single IPv4 address (legacy, use listen_addrs_ipv4 instead).
		listen_addrs_ipv4: List of IPv4 addresses to listen on.
		                   If provided, overrides listen_addr.
		                   Example: ["127.0.0.1", "10.20.0.1"] for WireGuard-only binding.
		cache_min_ttl: Minimum TTL for cached entries. Some CDNs use low TTLs
		              for fast failover; override with care.
		listen_addrs_ipv6: Optional list of IPv6 addresses to listen on
		                   (e.g., interface gateway addresses for dual-stack peers).
	"""
	# Use explicit list if provided, otherwise fall back to single address
	ipv4_addrs: list[str] = []
	if listen_addrs_ipv4:
		for addr in listen_addrs_ipv4:
			try:
				parsed = ipaddress.ip_address(addr.strip())
				if parsed.version == 4:
					ipv4_addrs.append(str(parsed))
			except ValueError:
				_log.warning("DNS_CONFIG invalid IPv4 listen address %r, skipping", addr)
	if not ipv4_addrs:
		# No explicit WireGuard IPs provided - check legacy single address
		# Host-mode safety: never use 0.0.0.0, and avoid 127.0.0.1 which may conflict
		# with host-side DNS resolver (systemd-resolved, dnsmasq, etc.)
		if listen_addr not in ("0.0.0.0", "127.0.0.1"):
			try:
				ipaddress.ip_address(listen_addr)
				ipv4_addrs = [listen_addr]
			except ValueError as exc:
				raise ValueError(f"Invalid listen address: {listen_addr!r}") from exc
		else:
			# Use link-local address that won't conflict with host services
			# This ensures Unbound doesn't bind to 0.0.0.0 or system DNS ports
			ipv4_addrs = ["169.254.53.53"]
			_log.debug("DNS_CONFIG no WireGuard interface IPs found, binding to %s", ipv4_addrs[0])
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
	# NOTE: Do NOT bind to 127.0.0.1 to avoid conflicts with host DNS
	# in Docker host network mode. Container DNS is configured via resolv.conf.
	interface_lines = [f"    interface: {addr}" for addr in ipv4_addrs]
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

	conf += f"""
    # Client-specific custom DNS overrides
    include: {get_custom_client_rules_file()}

    # Split-DNS local-data overrides (auto-generated from WG interfaces)
    include: {get_local_data_file()}
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
	
	Accepts dicts, dataclass instances, sqlite3.Row, or SQLAlchemy Row objects.
	
	Args:
		interfaces: Sequence of interface objects with 'address6' field.
	
	Returns:
		List of valid IPv6 gateway addresses (e.g., ['fd13:13:13::1']).
	"""
	ipv6_addrs: list[str] = []
	for iface in interfaces:
		addr6 = _get_field(iface, "address6")
		if not addr6:
			continue
		try:
			v6_iface = ipaddress.ip_interface(str(addr6).strip())
			ipv6_addrs.append(str(v6_iface.ip))
		except ValueError:
			_log.debug("Invalid IPv6 interface address: %r", addr6)
	return ipv6_addrs


def write_config(**kwargs) -> None:
	"""Write unbound.conf to disk."""
	content = generate_config(**kwargs)

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

	# Ensure custom client rule override file exists (even if empty)
	custom_client_rules_path = get_custom_client_rules_file()
	if not custom_client_rules_path.exists():
		atomic_write_text(custom_client_rules_path, "# Client-specific custom DNS overrides - auto-generated\n")
	
	# Ensure peer-tags.conf exists (even if empty)
	peer_tags_path = UNBOUND_CONF_DIR / "peer-tags.conf"
	if not peer_tags_path.exists():
		atomic_write_text(peer_tags_path, "# Per-peer blocklist tags - auto-generated\n")

	# Ensure local-data.conf exists (even if empty)
	local_data_path = get_local_data_file()
	if not local_data_path.exists():
		atomic_write_text(local_data_path, "# Split-DNS local-data overrides - auto-generated\n")

	atomic_write_text(UNBOUND_CONF, content)
	_log.info("DNS_CONFIG written to %s", UNBOUND_CONF)


def write_custom_client_rules(rules: list["ParsedRule"]) -> None:
	"""Generate client-specific local-zone overrides from custom rules.

	Rules with ``client_scope`` are emitted into a dedicated include file.
	Supported scoped targets: exact domain rules only.
	"""
	UNBOUND_CONF_DIR.mkdir(parents=True, exist_ok=True)
	path = get_custom_client_rules_file()

	# (client_cidr, domain) -> effective action, ALLOW wins over BLOCK
	effective: dict[tuple[str, str], str] = {}
	for rule in rules:
		if rule.client_scope is None or rule.domain is None:
			continue
		try:
			client_scope = _safe_unbound_value(str(rule.client_scope).strip())
			domain = _safe_unbound_value(_normalize_hostname(str(rule.domain)))
		except ValueError as exc:
			_log.warning("DNS_CUSTOM_CLIENT_RULES dropped unsafe rule: %s", exc)
			continue
		key = (client_scope, domain)
		if rule.action.value == "allow":
			effective[key] = "allow"
		elif key not in effective:
			effective[key] = "block"

	# Domains that require a baseline transparent local-zone for block overrides
	block_domains = sorted({domain for (_, domain), action in effective.items() if action == "block"})

	lines = [
		"# Client-specific custom DNS overrides",
		f"# Auto-generated – {datetime.now(timezone.utc).isoformat()}",
		"# Do not edit manually",
		"",
	]

	for domain in block_domains:
		lines.append(f'    local-zone: "{domain}." transparent')

	for (client_cidr, domain), action in sorted(effective.items()):
		override_action = "always_nxdomain" if action == "block" else "transparent"
		lines.append(f'    local-zone-override: "{domain}." {client_cidr} {override_action}')

	if len(lines) == 4:
		lines.append("# (none)")

	atomic_write_text(path, "\n".join(lines) + "\n")
	_log.info("DNS_CUSTOM_CLIENT_RULES wrote %d overrides to %s", len(effective), path)


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


def write_local_data_overrides(interfaces: Sequence[Any], fqdn: str | None) -> int:
	"""Generate local-data overrides for split-DNS (VPN endpoint → internal IP).

	When a WireGuard client resolves the VPN endpoint (e.g., vpn.example.com),
	this override returns the internal WireGuard gateway address instead of
	the public IP, enabling access to /status and other internal services
	through the tunnel.

	Args:
		interfaces: Sequence of interface objects with 'address' and 'address6' fields.
		fqdn: The public FQDN of the WireGuard server (e.g., "vpn.example.com").

	Returns:
		Number of local-data records written.
	"""
	UNBOUND_CONF_DIR.mkdir(parents=True, exist_ok=True)
	path = get_local_data_file()

	lines = [
		"# Split-DNS local-data overrides",
		f"# Auto-generated – {datetime.now(timezone.utc).isoformat()}",
		"# Maps public FQDN to internal WireGuard addresses for VPN clients",
		"",
	]

	record_count = 0
	fqdn_clean = (fqdn or "").strip().rstrip(".")

	if not fqdn_clean:
		lines.append("# No wg_fqdn configured - no overrides generated")
		atomic_write_text(path, "\n".join(lines) + "\n")
		_log.debug("DNS_LOCAL_DATA no fqdn configured, wrote empty file to %s", path)
		return 0

	# Validate FQDN format (basic check)
	if not all(HOST_LABEL_RE.fullmatch(label) for label in fqdn_clean.split(".")):
		lines.append(f"# Invalid FQDN format: {fqdn_clean!r}")
		atomic_write_text(path, "\n".join(lines) + "\n")
		_log.warning("DNS_LOCAL_DATA invalid fqdn %r, wrote empty file", fqdn_clean)
		return 0

	try:
		fqdn_clean = _safe_unbound_value(_normalize_hostname(fqdn_clean))
	except ValueError:
		lines.append(f"# Unsafe or invalid FQDN format: {fqdn_clean!r}")
		atomic_write_text(path, "\n".join(lines) + "\n")
		_log.warning("DNS_LOCAL_DATA unsafe fqdn %r, wrote empty file", fqdn_clean)
		return 0

	# Collect gateway IPs from all enabled interfaces
	ipv4_gateways: list[str] = []
	ipv6_gateways: list[str] = []

	for iface in interfaces:
		# Skip disabled interfaces
		is_enabled = _get_field(iface, "is_enabled", True)
		if not is_enabled:
			continue

		# Extract IPv4 gateway
		addr4 = _get_field(iface, "address")
		if addr4:
			try:
				v4_iface = ipaddress.ip_interface(str(addr4).strip())
				ipv4_gateways.append(str(v4_iface.ip))
			except ValueError:
				pass

		# Extract IPv6 gateway
		addr6 = _get_field(iface, "address6")
		if addr6:
			try:
				v6_iface = ipaddress.ip_interface(str(addr6).strip())
				ipv6_gateways.append(str(v6_iface.ip))
			except ValueError:
				pass

	# Generate local-data entries (use first gateway of each type)
	if ipv4_gateways:
		lines.append(f'    local-data: "{fqdn_clean}. A {ipv4_gateways[0]}"')
		record_count += 1

	if ipv6_gateways:
		lines.append(f'    local-data: "{fqdn_clean}. AAAA {ipv6_gateways[0]}"')
		record_count += 1

	if record_count == 0:
		lines.append("# No interface addresses found - no overrides generated")

	atomic_write_text(path, "\n".join(lines) + "\n")
	_log.debug("DNS_LOCAL_DATA wrote %d records for %s to %s", record_count, fqdn_clean, path)
	return record_count


__all__ = [
	"is_dnssec_available",
	"generate_config",
	"get_interface_ipv6_gateways",
	"write_config",
	"write_custom_client_rules",
	"write_local_data_overrides",
	"write_peer_tags",
]
