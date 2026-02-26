#!/usr/bin/env python3
#
# app/dns/custom_rules.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
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
import ipaddress
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
	"normalize_client_scope",
	"rule_applies_to_client",
	"canonical_rule_text",
	"canonical_rule_key",
	"parse_rules",
	"apply_custom_rules",
	"get_custom_block_rules",
	"get_custom_allow_rules",
	"evaluate_domain",
	"is_domain_allowed_by_custom_rules",
	"is_domain_blocked_by_custom_rules",
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
	# Optional client scope in canonical CIDR format (e.g. 10.0.0.2/32)
	client_scope: str | None = None
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


def normalize_client_scope(value: str) -> str:
	"""Normalize client scope to canonical CIDR.

	Examples:
	  10.0.0.5     -> 10.0.0.5/32
	  fd13::2      -> fd13::2/128
	  10.0.0.0/24  -> 10.0.0.0/24
	"""
	text = str(value or "").strip()
	if not text:
		raise ValueError("client scope must not be empty")
	if "/" in text:
		net = ipaddress.ip_network(text, strict=False)
		return str(net)
	ip = ipaddress.ip_address(text)
	if ip.version == 4:
		return f"{ip}/32"
	return f"{ip}/128"


def rule_applies_to_client(rule: ParsedRule, client_ip: str) -> bool:
	"""Return True when rule scope matches the query client IP.

	- Global rules (no client_scope) apply to all clients.
	- Client-scoped rules apply only if client IP is inside the scoped CIDR.
	"""
	if rule.client_scope is None:
		return True
	if not client_ip:
		return False
	try:
		ip_obj = ipaddress.ip_address(client_ip.strip())
		net = ipaddress.ip_network(rule.client_scope, strict=False)
		return ip_obj in net
	except ValueError:
		return False


def canonical_rule_key(rule: ParsedRule) -> tuple[str, str, str | None]:
	"""Canonical key used for duplicate detection and conflict checks."""
	if rule.domain is not None:
		target = f"domain:{rule.domain}"
	elif rule.wildcard is not None:
		target = f"wildcard:{rule.wildcard}"
	elif rule.regex is not None:
		target = f"regex:{rule.regex.pattern}"
	else:
		target = "unknown:"
	return (rule.action.value, target, rule.client_scope)


def _canonical_target(rule: ParsedRule) -> str:
	"""Return canonical target without action for conflict detection."""
	if rule.domain is not None:
		return f"domain:{rule.domain}"
	if rule.wildcard is not None:
		return f"wildcard:{rule.wildcard}"
	if rule.regex is not None:
		return f"regex:{rule.regex.pattern}"
	return "unknown:"


def canonical_rule_text(action: RuleAction, domain: str, client_scope: str | None = None) -> str:
	"""Build canonical text form for exact-domain rules."""
	prefix = "@@" if action == RuleAction.ALLOW else ""
	base = f"{prefix}||{domain.lower().rstrip('.')}^"
	if client_scope:
		return f"{base}$client={normalize_client_scope(client_scope)}"
	return base


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

# Heuristic guard against catastrophic backtracking patterns like /(a+)+b/
_NESTED_REGEX_QUANTIFIER_RE = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*]")


def _parse_rule_options(options_raw: str, *, lineno: int, text: str) -> tuple[str | None, ParseError | None]:
	"""Parse optional rule suffix options (currently only client=...)."""
	client_scope: str | None = None
	for option in options_raw.split(","):
		option = option.strip()
		if not option:
			continue
		if not option.startswith("client="):
			return None, ParseError(
				line=lineno,
				text=text,
				error=f"Unsupported rule option: {option}",
			)
		client_raw = option.split("=", 1)[1].strip()
		try:
			client_scope = normalize_client_scope(client_raw)
		except ValueError as exc:
			return None, ParseError(line=lineno, text=text, error=f"Invalid client scope: {exc}")
	return client_scope, None


def _split_regex_body_and_options(body: str) -> tuple[str, str | None] | None:
	"""Split '/regex/' and optional '$options' without breaking '$' inside regex.

	Returns (regex_literal, options_raw_or_none), or None when body is not a
	proper regex-literal rule.
	"""
	if not body.startswith("/"):
		return None

	escaped = False
	closing_index = -1
	for idx, ch in enumerate(body[1:], start=1):
		if escaped:
			escaped = False
			continue
		if ch == "\\":
			escaped = True
			continue
		if ch == "/":
			closing_index = idx
			break

	if closing_index <= 0:
		return None

	regex_literal = body[:closing_index + 1]
	suffix = body[closing_index + 1:]
	if not suffix:
		return regex_literal, None
	if not suffix.startswith("$"):
		return None
	return regex_literal, suffix[1:]


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

	# --- Regex rule: /pattern/[$options] ---
	regex_split = _split_regex_body_and_options(body)
	if regex_split is not None:
		regex_literal, regex_options = regex_split
		client_scope: str | None = None
		if regex_options is not None:
			client_scope, opt_err = _parse_rule_options(regex_options, lineno=lineno, text=text)
			if opt_err is not None:
				return opt_err

		if client_scope is not None:
			return ParseError(
				line=lineno,
				text=text,
				error="Client-scoped regex rules are not supported",
			)
		pattern = regex_literal[1:-1]
		
		# Safety: limit pattern length to prevent ReDoS
		if len(pattern) > MAX_REGEX_PATTERN_LENGTH:
			return ParseError(
				line=lineno,
				text=text,
				error=f"Regex pattern too long (max {MAX_REGEX_PATTERN_LENGTH} chars)",
			)
		if _NESTED_REGEX_QUANTIFIER_RE.search(pattern):
			return ParseError(
				line=lineno,
				text=text,
				error="Potentially unsafe regex (nested quantifiers)",
			)
		
		try:
			compiled = re.compile(pattern, re.IGNORECASE)
		except re.error as exc:
			return ParseError(line=lineno, text=text, error=f"Invalid regex: {exc}")
		
		return ParsedRule(
			action=action,
			raw=text,
			client_scope=client_scope,
			regex=compiled,
		)

	# Optional scope options for non-regex rules
	client_scope: str | None = None
	if "$" in body:
		body, options_raw = body.split("$", 1)
		client_scope, opt_err = _parse_rule_options(options_raw, lineno=lineno, text=text)
		if opt_err is not None:
			return opt_err

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
		if client_scope is not None:
			return ParseError(
				line=lineno,
				text=text,
				error="Client-scoped wildcard rules are not supported",
			)
		return ParsedRule(
			action=action,
			raw=text,
			client_scope=client_scope,
			wildcard=domain_pattern,
		)

	return ParsedRule(
		action=action,
		raw=text,
		client_scope=client_scope,
		domain=domain_pattern,
	)


def parse_rules(text: str) -> tuple[list[ParsedRule], list[ParseError]]:
	"""Parse a multi-line custom rules text block.

	Returns:
		(rules, errors) — list of valid parsed rules and list of parse errors.
	"""
	rules: list[ParsedRule] = []
	errors: list[ParseError] = []
	seen_keys: dict[tuple[str, str, str | None], int] = {}
	seen_target_scope: dict[tuple[str, str | None], tuple[RuleAction, int]] = {}

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
			key = canonical_rule_key(result)
			first_seen = seen_keys.get(key)
			if first_seen is not None:
				_log.warning(
					"DNS_CUSTOM_RULE duplicate line %d (first line %d): %s",
					lineno,
					first_seen,
					result.raw,
				)
			else:
				seen_keys[key] = lineno

			target_scope = (_canonical_target(result), result.client_scope)
			prev = seen_target_scope.get(target_scope)
			if prev is not None and prev[0] != result.action:
				_log.warning(
					"DNS_CUSTOM_RULE conflicting action line %d (first line %d): %s",
					lineno,
					prev[1],
					result.raw,
				)
			else:
				seen_target_scope[target_scope] = (result.action, lineno)

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
		if rule.client_scope is not None:
			continue
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

	# Phase 2: Remove exact allow domains and all their subdomains.
	for allow_domain in allow_exact:
		to_remove = {
			domain
			for domain in blocked_domains
			if domain == allow_domain or domain.endswith("." + allow_domain)
		}
		if to_remove:
			blocked_domains -= to_remove
			removed.update(to_remove)

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
		if r.action == RuleAction.BLOCK
		and (
			# Runtime-only global patterns
			(r.client_scope is None and (r.wildcard is not None or r.regex is not None))
			# Client-scoped exact domain rules (can't be represented in blocked_domains set)
			or (r.client_scope is not None and r.domain is not None)
		)
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
	# Start at 1 (skip self), stop before bare TLD (len-1),
	# so e.g. "malware.io" does not attempt matching only "io".
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
