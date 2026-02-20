#!/usr/bin/env python3
#
# app/dns/ingestion_parser.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""DNS query log parser for Unbound log format."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

__all__ = ["DnsQueryPoint", "parse_unbound_line"]


@dataclass
class DnsQueryPoint:
	"""Normalized DNS query for TSDB storage."""
	ts: str  # ISO8601 UTC timestamp
	client: str  # Client IP address
	domain: str  # Queried domain (without trailing dot)
	qtype: str  # Query type (A, AAAA, HTTPS, etc.)
	rcode: str  # Response code (NOERROR, NXDOMAIN, etc.) - empty for queries
	blocked: bool  # Whether domain is in blocklist


def parse_unbound_line(line: str, blocked_domains: set[str]) -> DnsQueryPoint | None:
	"""Fast parser for Unbound log lines.
	
	Format: [epoch] unbound[pid:tid] query: 10.0.0.5 example.com. A IN
	        [epoch] unbound[pid:tid] reply: 10.0.0.5 example.com. A IN NOERROR 0.05 0 124
	
	Returns None for unparseable lines or status messages.
	"""
	try:
		# Fast path: check for query/reply markers
		if " query: " not in line and " reply: " not in line:
			return None
		
		# Extract timestamp (seconds since epoch)
		bracket_start = line.find('[')
		bracket_end = line.find(']', bracket_start)
		if bracket_start == -1 or bracket_end == -1:
			return None
		
		epoch_str = line[bracket_start + 1:bracket_end]
		try:
			epoch = int(epoch_str)
			ts = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
		except (ValueError, OSError):
			return None
		
		# Split on query: or reply:
		if " query: " in line:
			is_reply = False
			_, payload = line.split(" query: ", 1)
		else:
			is_reply = True
			_, payload = line.split(" reply: ", 1)
		
		# Parse payload: <client> <domain>. <qtype> IN [<rcode> ...]
		parts = payload.split()
		if len(parts) < 4:  # Need at least: client domain qtype IN
			return None
		
		client = parts[0]
		domain = parts[1].rstrip('.')
		qtype = parts[2]
		
		# Validate client is an IP (skip service messages)
		if not _is_ip_like(client):
			return None
		
		# Extract response code from reply lines
		rcode = ""
		if is_reply and len(parts) >= 5 and parts[3] == "IN":
			rcode = parts[4]
		
		# Check if domain is blocked
		blocked = _is_domain_blocked(domain, blocked_domains)
		
		return DnsQueryPoint(
			ts=ts,
			client=client,
			domain=domain,
			qtype=qtype,
			rcode=rcode,
			blocked=blocked,
		)
	except Exception:
		return None


def _is_ip_like(s: str) -> bool:
	"""Fast check if string looks like IPv4 or IPv6 address.
	
	Accepts:
	- IPv4: 192.168.1.1
	- IPv6: ::1, fe80::1, 2001:db8::1
	
	Rejects:
	- IP:port (contains port)
	- Partial IPv4 like 1.2.3
	- Zone IDs (fe80::1%eth0)
	"""
	if not s:
		return False
	
	# Reject if contains port separator or zone ID
	if s.startswith('[') or '%' in s:
		return False
	
	# IPv4: must have exactly 3 dots
	if '.' in s and ':' not in s:
		parts = s.split('.')
		if len(parts) != 4:
			return False
		for p in parts:
			if not p.isdigit():
				return False
			if not 0 <= int(p) <= 255:
				return False
		return True
	
	# IPv6: hex and colons only
	if ':' in s:
		if s.count(':') < 2:
			return False
		stripped = s.replace(':', '')
		return all(c in '0123456789abcdefABCDEF' for c in stripped)
	
	return False


def _is_domain_blocked(domain: str, blocked_domains: set[str]) -> bool:
	"""Check if domain matches blocklist (exact or parent domain)."""
	if not domain or not blocked_domains:
		return False
	
	domain_lower = domain.lower()
	if domain_lower in blocked_domains:
		return True
	
	# Check parent domains
	labels = domain_lower.split('.')
	for i in range(1, len(labels) - 1):
		parent = '.'.join(labels[i:])
		if parent in blocked_domains:
			return True
	
	return False
