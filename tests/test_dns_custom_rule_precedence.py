#!/usr/bin/env python3
#
# tests/test_dns_custom_rule_precedence.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""One precedence rule for custom DNS rules, shared by config and parser.

``resolve_effective_action`` is the single source of truth for "ALLOW wins
always". Both the Unbound config generator (``write_custom_client_rules``) and
the ingestion log parser use it, so the resolver's decision cannot disagree
with what the resolver actually enforces.

Regression: a global ``@@`` allow combined with a client-scoped block used to
emit ``always_nxdomain`` for that client while the parser reported the query as
allowed — Unbound refused a domain the UI called allowed.

Also covers the regex grammar reduction (P3.1): catastrophic-backtracking
patterns are rejected structurally and quickly, with no reliance on a wall-clock
probe that stdlib ``re`` cannot honour.
"""

from __future__ import annotations

import time

import pytest

from app.dns import unbound_config
from app.dns.custom_rules import RuleAction, parse_rules, resolve_effective_action


def _rules(text: str):
	parsed, errors = parse_rules(text)
	assert errors == [], errors
	return parsed


# ---------------------------------------------------------------------------
# resolve_effective_action precedence
# ---------------------------------------------------------------------------


def test_global_allow_beats_client_block():
	rules = _rules("@@||example.com^\n||example.com^$client=10.0.0.5")
	assert resolve_effective_action("example.com", "10.0.0.5", rules) == RuleAction.ALLOW


def test_client_block_applies_when_no_allow():
	rules = _rules("||example.com^$client=10.0.0.5")
	assert resolve_effective_action("example.com", "10.0.0.5", rules) == RuleAction.BLOCK


def test_client_block_does_not_apply_to_other_client():
	rules = _rules("||example.com^$client=10.0.0.5")
	assert resolve_effective_action("example.com", "10.0.0.9", rules) is None


def test_overlapping_network_allow_beats_narrow_block():
	# /24 ALLOW + /32 BLOCK for a host inside that /24: ALLOW still wins.
	rules = _rules("@@||example.com^$client=10.0.0.0/24\n||example.com^$client=10.0.0.5")
	assert resolve_effective_action("example.com", "10.0.0.5", rules) == RuleAction.ALLOW


def test_no_match_returns_none():
	rules = _rules("||other.com^$client=10.0.0.5")
	assert resolve_effective_action("example.com", "10.0.0.5", rules) is None


# ---------------------------------------------------------------------------
# write_custom_client_rules honours the shared precedence
# ---------------------------------------------------------------------------


@pytest.fixture
def _client_rules_file(tmp_path, monkeypatch):
	"""Redirect the generated client-rules file into a temp directory."""
	conf_dir = tmp_path / "unbound"
	conf_dir.mkdir()
	out = tmp_path / "custom-client-rules.conf"
	monkeypatch.setattr(unbound_config, "UNBOUND_CONF_DIR", conf_dir)
	monkeypatch.setattr(unbound_config, "get_custom_client_rules_file", lambda: out)
	monkeypatch.setattr(unbound_config, "_ensure_unbound_readable", lambda path: None)
	return out


def test_config_suppresses_block_when_global_allow_wins(_client_rules_file):
	# The repro: global allow + client block for the same domain.
	rules = _rules("@@||example.com^\n||example.com^$client=10.0.0.5")
	unbound_config.write_custom_client_rules(rules)
	content = _client_rules_file.read_text(encoding="utf-8")

	# No contradicting refusal may be emitted for this domain+client.
	assert "always_nxdomain" not in content


def test_config_emits_block_without_allow(_client_rules_file):
	rules = _rules("||example.com^$client=10.0.0.5")
	unbound_config.write_custom_client_rules(rules)
	content = _client_rules_file.read_text(encoding="utf-8")

	assert "always_nxdomain" in content
	assert '"example.com."' in content


def test_config_overlapping_allow_suppresses_block(_client_rules_file):
	rules = _rules("@@||example.com^$client=10.0.0.0/24\n||example.com^$client=10.0.0.5")
	unbound_config.write_custom_client_rules(rules)
	content = _client_rules_file.read_text(encoding="utf-8")

	assert "always_nxdomain" not in content


# ---------------------------------------------------------------------------
# P3.1 — regex grammar reduction rejects catastrophic patterns fast
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
	"pattern",
	[
		"/(a{0,10}){10}b/",  # the repro that blew the old wall-clock probe
		"/(a+)+b/",
		"/(a|a)+b/",
		"/(a|aa){25}b/",
		"/((ab)*)*c/",  # nested groups
	],
)
def test_catastrophic_regex_rejected_quickly(pattern):
	start = time.monotonic()
	parsed, errors = parse_rules(pattern)
	elapsed = time.monotonic() - start

	assert parsed == []
	assert len(errors) == 1
	# Must be rejected structurally, far below the old 1.5s external kill.
	assert elapsed < 0.5


def test_simple_regex_rule_still_accepted():
	parsed, errors = parse_rules("/metrics/")
	assert errors == []
	assert len(parsed) == 1
