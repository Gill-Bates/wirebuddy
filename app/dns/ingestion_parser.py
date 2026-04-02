#!/usr/bin/env python3
#
# app/dns/ingestion_parser.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""DNS query log parser for Unbound log format."""

from __future__ import annotations

import ipaddress
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
	custom_rule: bool = False  # Whether a custom rule affected this query


def parse_unbound_line(
	line: str,
	blocked_domains: set[str],
	allow_rules: list[ParsedRule] | None = None,
	block_rules: list[ParsedRule] | None = None,
) -> DnsQueryPoint | None:
	"""Fast parser for Unbound log lines.
	
	Format: [epoch] unbound[pid:tid] reply: 10.0.0.5 example.com. A IN NOERROR 0.05 0 124
	
	Note: Only reply lines are processed to avoid double-counting.
	Query lines are logged before the actual lookup, replies contain the result.
	
	Args:
		line: Raw log line.
		blocked_domains: Set of blocked domain names (exact match, lowercase).
		allow_rules: Custom allow rules for whitelist override.
		block_rules: Custom wildcard/regex block rules for runtime matching.
	
	Priority (whitelist wins always):
		1. Allow rules → if matched, NOT blocked (absolute override)
		2. Exact blocked domains set
		3. Wildcard/regex block rules
	
	Returns None for unparseable lines, query lines, or status messages.
	"""
	try:
		# Only process reply lines to avoid double-counting
		# Query lines are logged before lookup, reply lines contain the result
		if " reply: " not in line:
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
		
		# Parse reply payload: <client> <domain>. <qtype> IN <rcode> ...
		_, payload = line.split(" reply: ", 1)
		parts = payload.split()
		if len(parts) < 5:  # Need at least: client domain qtype IN rcode
			return None
		
		client = parts[0]
		# Normalize domain once: strip trailing dot + lowercase
		domain = parts[1].rstrip('.').lower()
		qtype = parts[2]
		
		# Validate client is an IP (skip service messages)
		if not _is_ip_like(client):
			return None
		
		# Extract response code from reply (after "IN")
		rcode = ""
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
					# Whitelisted - not blocked, custom rule applied
					return DnsQueryPoint(
						ts=ts,
						client=client,
						domain=domain,
						qtype=qtype,
						rcode=rcode,
						blocked=False,
						custom_rule=True,
					)
		
		# Priority 2: Check exact blocked domains (already lowercase)
		blocked = _is_domain_blocked(domain, blocked_domains)
		custom_rule = False
		
		# Priority 3: Check wildcard/regex block rules
		if not blocked and block_rules:
			for rule in block_rules:
				if not rule_applies_to_client(rule, client):
					continue
				if rule.matches(domain):
					blocked = True
					custom_rule = True
					break
		
		return DnsQueryPoint(
			ts=ts,
			client=client,
			domain=domain,
			qtype=qtype,
			rcode=rcode,
			blocked=blocked,
			custom_rule=custom_rule,
		)
	except Exception as exc:
		_log.debug("DNS_PARSER failed to parse line: %s", exc)
		return None


def _is_ip_like(s: str) -> bool:
	"""Check if string is a valid IPv4 or IPv6 address.
	
	Uses stdlib ipaddress for correctness and maintainability.
	Slightly slower than manual parsing but handles all edge cases.
	"""
	if not s:
		return False
	try:
		ipaddress.ip_address(s)
		return True
	except ValueError:
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
