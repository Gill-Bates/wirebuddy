#!/usr/bin/env python3
#
# app/dns/ingestion_parser.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""DNS query log parser for Unbound log format."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from .custom_rules import ParsedRule, rule_applies_to_client

_log = logging.getLogger(__name__)

__all__ = ["DnsQueryPoint", "parse_unbound_line"]


@dataclass
class DnsQueryPoint:
	"""Normalized DNS query for TSDB storage."""
	ts: str  # ISO8601 UTC timestamp
	client: str  # Client IP address
	domain: str  # Queried domain (without trailing dot, lowercase)
	qtype: str  # Query type (A, AAAA, HTTPS, etc.)
	rcode: str  # Response code (NOERROR, NXDOMAIN, etc.) - empty for queries
	blocked: bool  # Whether domain is in blocklist


def parse_unbound_line(
	line: str,
	blocked_domains: set[str],
	allow_rules: list[ParsedRule] | None = None,
	block_rules: list[ParsedRule] | None = None,
) -> DnsQueryPoint | None:
	"""Fast parser for Unbound log lines.
	
	Format: [epoch] unbound[pid:tid] query: 10.0.0.5 example.com. A IN
	        [epoch] unbound[pid:tid] reply: 10.0.0.5 example.com. A IN NOERROR 0.05 0 124
	
	Args:
		line: Raw log line.
		blocked_domains: Set of blocked domain names (exact match, lowercase).
		allow_rules: Custom allow rules for whitelist override.
		block_rules: Custom wildcard/regex block rules for runtime matching.
	
	Priority (whitelist wins always):
		1. Allow rules → if matched, NOT blocked (absolute override)
		2. Exact blocked domains set
		3. Wildcard/regex block rules
	
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
		# Normalize domain once: strip trailing dot + lowercase
		domain = parts[1].rstrip('.').lower()
		qtype = parts[2]
		
		# Validate client is an IP (skip service messages)
		if not _is_ip_like(client):
			return None
		
		# Extract response code from reply lines
		rcode = ""
		if is_reply and len(parts) >= 5:
			# Find "IN" marker and take next part as rcode
			try:
				in_idx = parts.index("IN")
				if in_idx + 1 < len(parts):
					rcode = parts[in_idx + 1]
			except ValueError:
				pass
		
		# === Block/Allow Priority Logic ===
		# Priority 1: Allow rules (absolute whitelist override)
		if allow_rules:
			for rule in allow_rules:
				if not rule_applies_to_client(rule, client):
					continue
				if rule.matches(domain):
					# Whitelisted - not blocked, skip all other checks
					return DnsQueryPoint(
						ts=ts,
						client=client,
						domain=domain,
						qtype=qtype,
						rcode=rcode,
						blocked=False,
					)
		
		# Priority 2: Check exact blocked domains (already lowercase)
		blocked = _is_domain_blocked(domain, blocked_domains)
		
		# Priority 3: Check wildcard/regex block rules
		if not blocked and block_rules:
			for rule in block_rules:
				if not rule_applies_to_client(rule, client):
					continue
				if rule.matches(domain):
					blocked = True
					break
		
		return DnsQueryPoint(
			ts=ts,
			client=client,
			domain=domain,
			qtype=qtype,
			rcode=rcode,
			blocked=blocked,
		)
	except Exception as exc:
		_log.debug("DNS_PARSER failed to parse line: %s", exc)
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
	- Invalid structures (::::::::::)
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
	
	# IPv6: structural validation
	if ':' in s:
		# Must have 2-7 colons (8 groups with :: allowed)
		colon_count = s.count(':')
		if colon_count < 2 or colon_count > 7:
			return False
		
		# Check for valid :: usage (only one allowed)
		if '::' in s:
			if s.count('::') > 1:
				return False
		else:
			# Without ::, must have exactly 7 colons
			if colon_count != 7:
				return False
		
		# Validate each group is valid hex (0-4 chars)
		groups = s.split(':')
		for g in groups:
			if g == '':
				continue  # Empty from ::
			if len(g) > 4:
				return False
			if not all(c in '0123456789abcdefABCDEF' for c in g):
				return False
		return True
	
	return False


def _is_domain_blocked(domain: str, blocked_domains: set[str]) -> bool:
	"""Check if domain matches blocklist (exact or parent domain).
	
	Args:
		domain: Already normalized (lowercase, no trailing dot)
		blocked_domains: Set of blocked domains (lowercase)
	"""
	if not domain or not blocked_domains:
		return False
	
	# Exact match (domain already lowercase)
	if domain in blocked_domains:
		return True
	
	# Check parent domains using partition (faster than split+join)
	check = domain
	while '.' in check:
		_, _, check = check.partition('.')
		if check in blocked_domains:
			return True
	
	return False
