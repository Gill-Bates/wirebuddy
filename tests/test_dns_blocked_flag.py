#!/usr/bin/env python3
#
# tests/test_dns_blocked_flag.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""``DnsQueryPoint.blocked`` mirrors what Unbound actually refused.

The flag feeds the DNS page's blocked/allowed filter, the blockrate KPIs and
"Top Blocked Domains", so it must be True for exactly the rules the resolver
enforces:

  - global exact blocks     → ``local-zone … always_nxdomain`` (blocklist.conf)
  - client-scoped exact     → ``local-zone-override … always_nxdomain``
                              (custom-client-rules.conf)
  - global wildcard/regex   → no Unbound primitive, visibility only

A regression after v1.6.0 dropped the client-scoped case, which silently
emptied "Top Blocked Domains" for setups that block via custom client rules.
"""

from __future__ import annotations

from app.dns.custom_rules import get_custom_allow_rules, get_custom_block_rules, parse_rules
from app.dns.ingestion_parser import parse_unbound_line

CLIENT = "10.13.13.2"


def _reply(domain: str, rcode: str = "NOERROR", client: str = CLIENT) -> str:
	return f"[1774000000] unbound[42:0] reply: {client} {domain}. A IN {rcode} 0.019543 0 76"


def _rules(text: str):
	parsed, errors = parse_rules(text)
	assert errors == [], errors
	return get_custom_allow_rules(parsed), get_custom_block_rules(parsed)


def _parse(line: str, blocked_domains: set[str] | None = None, rules_text: str = ""):
	allow_rules, block_rules = _rules(rules_text)
	point = parse_unbound_line(
		line,
		blocked_domains or set(),
		allow_rules=allow_rules or None,
		block_rules=block_rules or None,
	)
	assert point is not None
	return point


def test_global_exact_blocklist_domain_is_blocked():
	point = _parse(_reply("ads.example.com", rcode="NXDOMAIN"), blocked_domains={"ads.example.com"})

	assert point.blocked is True
	assert point.custom_rule is False


def test_parent_domain_on_blocklist_blocks_subdomain():
	point = _parse(_reply("tracker.ads.example.com", rcode="NXDOMAIN"), blocked_domains={"ads.example.com"})

	assert point.blocked is True


def test_client_scoped_exact_block_rule_is_reported_as_blocked():
	# Emitted by write_custom_client_rules() as an always_nxdomain override,
	# so Unbound really did refuse this query even though the domain is absent
	# from blocklist.conf (and therefore from blocked_domains).
	point = _parse(
		_reply("social.example.com", rcode="NXDOMAIN"),
		rules_text=f"||social.example.com^$client={CLIENT}",
	)

	assert point.blocked is True
	assert point.custom_rule is True


def test_client_scoped_rule_does_not_affect_other_clients():
	point = _parse(
		_reply("social.example.com", client="10.13.13.9"),
		rules_text=f"||social.example.com^$client={CLIENT}",
	)

	assert point.blocked is False
	assert point.custom_rule is False


def test_global_wildcard_block_rule_is_visibility_only():
	# No Unbound wildcard local-zone primitive exists: the client already got
	# the resolved answer, so the match is recorded without claiming a block.
	point = _parse(_reply("ads17.example.com"), rules_text="||ads*.example.com^")

	assert point.blocked is False
	assert point.custom_rule is True


def test_global_regex_block_rule_is_visibility_only():
	point = _parse(_reply("metrics.example.com"), rules_text="/metrics/")

	assert point.blocked is False
	assert point.custom_rule is True


def test_allow_rule_overrides_blocklist():
	point = _parse(
		_reply("ads.example.com"),
		blocked_domains={"ads.example.com"},
		rules_text="@@||ads.example.com^",
	)

	assert point.blocked is False
	assert point.custom_rule is True


def test_allow_rule_overrides_client_scoped_block_rule():
	point = _parse(
		_reply("social.example.com"),
		rules_text=f"||social.example.com^$client={CLIENT}\n@@||social.example.com^",
	)

	assert point.blocked is False
