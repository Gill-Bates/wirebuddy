#!/usr/bin/env python3
#
# app/dns/custom_rules.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Custom DNS rules with AdGuard-compatible syntax.

Supported syntax:
  ||example.com^        Block example.com and all subdomains
  @@||example.com^      Allow (whitelist) — overrides blocks
  ||ads*.example.com^   Wildcard block (* matches any characters)
  /regex/               Regex-based matching (substring match, case-insensitive)
  ! comment             Comment line (ignored)
  # comment             Comment line (ignored)
  (empty lines)         Ignored

Matching semantics:
  - Domain rules (||domain^): Match exact domain AND all subdomains
  - Wildcard rules: Match against full domain AND all parent segments
  - Regex rules: Substring match (re.search), case-insensitive

Priority:
  - Allow rules ALWAYS override block rules (whitelist wins)
"""

from __future__ import annotations

import fnmatch
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import NamedTuple

_log = logging.getLogger(__name__)

# Safety limits
MAX_REGEX_PATTERN_LENGTH = 500  # Prevent ReDoS with overly complex patterns

__all__ = [
	"RuleAction",
	"ParsedRule",
	"ParseError",
	"parse_rules",
	"apply_custom_rules",
	"evaluate_domain",
	"is_domain_allowed_by_custom_rules",
]


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class RuleAction(str, Enum):
	"""Rule action type."""
	BLOCK = "block"
	ALLOW = "allow"


class ParseError(NamedTuple):
	"""A single parse error with line number."""
	line: int
	text: str
	error: str


@dataclass
class ParsedRule:
	"""A single parsed custom DNS rule."""
	action: RuleAction
	raw: str  # Original rule text
	# Exact domain match (normalized, no trailing dot)
	domain: str | None = None
	# Wildcard pattern (fnmatch-style, lowercase)
	wildcard: str | None = None
	# Compiled regex pattern
	regex: re.Pattern[str] | None = field(default=None, repr=False)

	def matches(self, domain: str) -> bool:
		"""Check if this rule matches the given domain.
		
		Matching rules:
		  - Exact domain: matches domain itself AND all subdomains
		  - Wildcard: fnmatch against full domain AND each parent segment
		  - Regex: substring search (re.search), case-insensitive
		"""
		d = domain.lower().rstrip(".")
		if self.domain is not None:
			# Exact match or subdomain match
			if d == self.domain:
				return True
			if d.endswith("." + self.domain):
				return True
			return False
		if self.wildcard is not None:
			# Match against full domain and all parent segments
			# e.g., ||ads*.com^ should match "ads1.com" and "sub.ads1.com"
			parts = d.split(".")
			for i in range(len(parts)):
				candidate = ".".join(parts[i:])
				if fnmatch.fnmatch(candidate, self.wildcard):
					return True
			return False
		if self.regex is not None:
			# Substring match (consistent with AdGuard behavior)
			return bool(self.regex.search(d))
		return False


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

# Looser pattern for initial capture; validation happens after
_ADGUARD_DOMAIN_RE = re.compile(
	r"^\|\|"           # Leading ||
	r"([a-z0-9.*_-]+)" # Domain pattern (may include wildcard *)
	r"\^$",            # Trailing ^
	re.IGNORECASE,
)

# Valid DNS label (RFC 1123): alphanumeric, hyphens allowed in middle
_VALID_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$|^[a-z0-9]$")


def _validate_domain_pattern(pattern: str, is_wildcard: bool) -> str | None:
	"""Validate a domain pattern. Returns error message or None if valid."""
	if not pattern:
		return "Empty domain pattern"
	
	# Check for consecutive dots
	if ".." in pattern:
		return "Invalid domain: consecutive dots"
	
	# Must have at least one dot (TLD required)
	if "." not in pattern:
		return "Domain must have at least two labels (e.g. example.com)"
	
	labels = pattern.split(".")
	
	# Check each label
	for label in labels:
		if not label:
			return "Invalid domain: empty label"
		if len(label) > 63:
			return f"Label too long: {label!r}"
		
		# For wildcard patterns, allow * in labels
		if is_wildcard and "*" in label:
			# Remove wildcards for basic validation
			test_label = label.replace("*", "a")
			if not _VALID_LABEL_RE.fullmatch(test_label):
				return f"Invalid wildcard label: {label!r}"
		else:
			if not _VALID_LABEL_RE.fullmatch(label):
				return f"Invalid domain label: {label!r}"
	
	return None


def _parse_single_rule(text: str, lineno: int) -> ParsedRule | ParseError:
	"""Parse one rule line. Returns ParsedRule on success, ParseError on failure."""
	text = text.strip()

	# Determine action (allow vs block)
	if text.startswith("@@"):
		action = RuleAction.ALLOW
		body = text[2:]
	else:
		action = RuleAction.BLOCK
		body = text

	# --- Regex rule: /pattern/ ---
	if body.startswith("/") and body.endswith("/") and len(body) >= 3:
		pattern = body[1:-1]
		
		# Safety: limit pattern length to prevent ReDoS
		if len(pattern) > MAX_REGEX_PATTERN_LENGTH:
			return ParseError(
				line=lineno,
				text=text,
				error=f"Regex pattern too long (max {MAX_REGEX_PATTERN_LENGTH} chars)",
			)
		
		try:
			compiled = re.compile(pattern, re.IGNORECASE)
		except re.error as exc:
			return ParseError(line=lineno, text=text, error=f"Invalid regex: {exc}")
		
		return ParsedRule(
			action=action,
			raw=text,
			regex=compiled,
		)

	# --- AdGuard domain rule: ||domain^ ---
	m = _ADGUARD_DOMAIN_RE.match(body)
	if not m:
		return ParseError(
			line=lineno,
			text=text,
			error="Unsupported syntax. Use ||domain.com^ or @@||domain.com^ or /regex/ or ! comment",
		)

	domain_pattern = m.group(1).lower()
	is_wildcard = "*" in domain_pattern

	# Validate domain pattern (applies to both exact and wildcard rules)
	validation_error = _validate_domain_pattern(domain_pattern, is_wildcard)
	if validation_error:
		return ParseError(line=lineno, text=text, error=validation_error)

	if is_wildcard:
		return ParsedRule(
			action=action,
			raw=text,
			wildcard=domain_pattern,
		)

	return ParsedRule(
		action=action,
		raw=text,
		domain=domain_pattern,
	)


def parse_rules(text: str) -> tuple[list[ParsedRule], list[ParseError]]:
	"""Parse a multi-line custom rules text block.

	Returns:
		(rules, errors) — list of valid parsed rules and list of parse errors.
	"""
	rules: list[ParsedRule] = []
	errors: list[ParseError] = []

	for lineno, raw_line in enumerate(text.splitlines(), start=1):
		line = raw_line.strip()

		# Skip empty lines and comments
		if not line or line.startswith("!") or line.startswith("#"):
			continue

		result = _parse_single_rule(line, lineno)
		if isinstance(result, ParseError):
			errors.append(result)
			_log.debug("DNS_CUSTOM_RULE parse error line %d: %s", lineno, result.error)
		else:
			rules.append(result)

	if rules:
		_log.debug("DNS_CUSTOM_RULE parsed %d rules (%d errors)", len(rules), len(errors))

	return rules, errors


# ---------------------------------------------------------------------------
# Application helpers
# ---------------------------------------------------------------------------

def apply_custom_rules(
	blocked_domains: set[str],
	rules: list[ParsedRule],
) -> tuple[set[str], set[str]]:
	"""Apply custom rules to modify the blocked domain set.

	Processing order:
	  1. Add exact BLOCK domains to blocked set
	  2. Remove exact ALLOW domains from blocked set (fast set operation)
	  3. Remove wildcard/regex ALLOW matches from blocked set

	Allow rules always win over block rules (whitelist overrides).

	Args:
		blocked_domains: Mutable set of currently blocked domains.
		rules: Parsed custom rules.

	Returns:
		(domains_added, domains_removed) — sets of domain names that
		were added or removed by custom rules (for logging).
	"""
	added: set[str] = set()
	removed: set[str] = set()

	# Separate rules by type for efficient processing
	block_exact: set[str] = set()
	allow_exact: set[str] = set()
	allow_pattern: list[ParsedRule] = []  # Wildcard + regex

	for rule in rules:
		if rule.action == RuleAction.BLOCK:
			if rule.domain is not None:
				block_exact.add(rule.domain)
			# Wildcard/regex blocks: handled at query-time (can't add to Unbound)
		else:  # ALLOW
			if rule.domain is not None:
				allow_exact.add(rule.domain)
			else:
				allow_pattern.append(rule)

	# Phase 1: Add custom block domains
	for domain in block_exact:
		if domain not in blocked_domains:
			blocked_domains.add(domain)
			added.add(domain)

	# Phase 2: Remove exact allow domains (O(1) set operations)
	exact_removed = blocked_domains & allow_exact
	blocked_domains -= exact_removed
	removed.update(exact_removed)

	# Phase 3: Remove wildcard/regex allow matches (only if we have patterns)
	if allow_pattern:
		for domain in list(blocked_domains):
			for rule in allow_pattern:
				if rule.matches(domain):
					blocked_domains.discard(domain)
					removed.add(domain)
					break

	return added, removed


def get_custom_block_rules(rules: list[ParsedRule]) -> list[ParsedRule]:
	"""Return only block rules that need runtime matching (wildcard/regex).

	Exact domain blocks are handled by Unbound local-zone entries.
	This returns only wildcard and regex blocks that need to be checked
	at query time in the ingestion parser.
	"""
	return [
		r for r in rules
		if r.action == RuleAction.BLOCK and (r.wildcard is not None or r.regex is not None)
	]


def get_custom_allow_rules(rules: list[ParsedRule]) -> list[ParsedRule]:
	"""Return only allow (whitelist) rules for runtime checking."""
	return [r for r in rules if r.action == RuleAction.ALLOW]


def evaluate_domain(
	domain: str,
	blocked_domains: set[str],
	allow_rules: list[ParsedRule],
	block_rules: list[ParsedRule],
) -> bool:
	"""Evaluate if a domain should be blocked, applying all rule types.

	Priority (highest to lowest):
	  1. Allow rules (whitelist) — if matched, domain is NOT blocked
	  2. Blocked domains set (exact + parent match)
	  3. Block rules (wildcard/regex runtime matching)

	Args:
		domain: Domain to evaluate (e.g., "ads.example.com")
		blocked_domains: Set of blocked domain names from blocklist
		allow_rules: Custom allow rules for whitelist override
		block_rules: Custom wildcard/regex block rules

	Returns:
		True if domain should be blocked, False if allowed.
	"""
	d = domain.lower().rstrip(".")

	# Priority 1: Allow rules override everything
	for rule in allow_rules:
		if rule.matches(d):
			return False

	# Priority 2: Check blocked domains set (exact + parent)
	if d in blocked_domains:
		return True
	labels = d.split(".")
	for i in range(1, len(labels) - 1):
		parent = ".".join(labels[i:])
		if parent in blocked_domains:
			return True

	# Priority 3: Check wildcard/regex block rules
	for rule in block_rules:
		if rule.matches(d):
			return True

	return False


def is_domain_allowed_by_custom_rules(
	domain: str,
	allow_rules: list[ParsedRule],
) -> bool:
	"""Check if a domain is explicitly allowed (whitelisted) by custom rules."""
	for rule in allow_rules:
		if rule.matches(domain):
			return True
	return False


def is_domain_blocked_by_custom_rules(
	domain: str,
	block_rules: list[ParsedRule],
) -> bool:
	"""Check if a domain matches a wildcard/regex custom block rule.

	This is for runtime matching of rules that can't be expressed
	as Unbound local-zone entries (wildcards, regex).
	"""
	for rule in block_rules:
		if rule.matches(domain):
			return True
	return False
