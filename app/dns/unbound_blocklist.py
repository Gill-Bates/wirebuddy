#!/usr/bin/env python3
#
# app/dns/unbound_blocklist.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Unbound DNS blocklist management and domain filtering."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import random
import re
import socket
import urllib.parse
from collections.abc import Set as AbstractSet
from datetime import datetime, timezone

try:
	import httpx
except ImportError:
	httpx = None  # type: ignore

try:
	import idna
	_IDNAError: type[Exception] = idna.IDNAError
except ImportError:
	idna = None  # type: ignore
	_IDNAError = UnicodeError  # type: ignore[misc,assignment]

from .custom_rules import (
	ParsedRule,
	apply_custom_rules,
	get_custom_allow_rules,
	get_custom_block_rules,
	is_domain_allowed_by_custom_rules,
	is_domain_blocked_by_custom_rules,
	parse_rules,
)
from . import unbound_config
from .unbound_constants import (
	ALLOWED_BLOCKLIST_CONTENT_TYPES,
	BLOCKLIST_MAX_BYTES,
	BLOCKLIST_MAX_DOMAINS,
	BLOCKLIST_MAX_LINES,
	BLOCKLIST_REGISTRY,
	DEFAULT_BLOCKLISTS,
	DOMAIN_LABEL_RE,
	atomic_write,
	get_blocklist_file,
)

# Acceptable text content types for blocklist downloads
_ACCEPTABLE_TEXT_TYPES = frozenset([
	"text/plain",
	"text/x-hosts",
	*ALLOWED_BLOCKLIST_CONTENT_TYPES,
])
_BLOCKLIST_URL_TO_ID = {
	str(meta.get("url")): bid
	for bid, meta in BLOCKLIST_REGISTRY.items()
	if meta.get("url")
}
_BLOCKLIST_TAG_RE = re.compile(r"^[A-Za-z0-9_-]+$")
CUSTOM_RULES_TAG = "custom"

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class _CapacityExceeded(Exception):
	"""Domain/size/line cap hit — not worth retrying."""

# ---------------------------------------------------------------------------
# Domain Cache
# ---------------------------------------------------------------------------

# NOTE: Thread safety relies on CPython's GIL for atomic assignments.
# If moving to free-threaded Python (3.13t+), add a threading.Lock.
_BLOCKED_DOMAINS_CACHE_ENTRY: tuple[frozenset[str], int | None] | None = None

# Runtime custom rules cache (for wildcard/regex matching at query time)
# NOTE: Tuples are immutable, preventing accidental mutation via get_custom_rules_cache().
_CUSTOM_ALLOW_RULES: tuple[ParsedRule, ...] = ()
_CUSTOM_BLOCK_RULES: tuple[ParsedRule, ...] = ()


def _invalidate_blocked_domains_cache() -> None:
	"""Invalidate cached blocked-domain set after blocklist changes."""
	global _BLOCKED_DOMAINS_CACHE_ENTRY
	_BLOCKED_DOMAINS_CACHE_ENTRY = None


def set_custom_rules_cache(rules: list[ParsedRule]) -> None:
	"""Update the runtime custom rules cache after a rules change."""
	global _CUSTOM_ALLOW_RULES, _CUSTOM_BLOCK_RULES
	_CUSTOM_ALLOW_RULES = tuple(get_custom_allow_rules(rules))
	_CUSTOM_BLOCK_RULES = tuple(get_custom_block_rules(rules))


def get_custom_rules_cache() -> tuple[tuple[ParsedRule, ...], tuple[ParsedRule, ...]]:
	"""Return (allow_rules, block_rules) for runtime query-time matching.
	
	Returns immutable tuples to prevent accidental mutation of global state.
	"""
	return _CUSTOM_ALLOW_RULES, _CUSTOM_BLOCK_RULES


# ---------------------------------------------------------------------------
# Domain Normalization
# ---------------------------------------------------------------------------

# Localhost-like domains to exclude from blocklists
_LOCALHOST_DOMAINS = frozenset({
	"localhost",
	"localhost.localdomain",
	"local",
	"broadcasthost",
	"ip6-localhost",
	"ip6-loopback",
})


def _normalize_domain(raw: str) -> str | None:
	"""Normalize and validate a domain; returns ASCII IDNA domain or None."""
	domain = raw.strip().strip(".").lower()
	if not domain or domain in _LOCALHOST_DOMAINS or len(domain) > 253:
		return None
	
	# Reject bare IP addresses (they're not domain names)
	try:
		ipaddress.ip_address(domain)
		return None  # It's an IP, not a domain
	except ValueError:
		pass  # Not an IP, continue with domain validation
	
	try:
		if idna:
			# Use IDNA 2008 for better modern TLD support
			ascii_domain = idna.encode(domain, uts46=True).decode("ascii").rstrip(".")
		else:
			# Fallback to IDNA 2003 (built-in)
			ascii_domain = domain.encode("idna").decode("ascii")
	except (UnicodeError, _IDNAError):
		return None
	except Exception:
		# Unexpected error from idna library - log and skip
		_log.debug("IDNA encoding failed for %r", domain, exc_info=True)
		return None

	labels = ascii_domain.split(".")
	if len(labels) < 2:
		return None
	for label in labels:
		if not DOMAIN_LABEL_RE.fullmatch(label):
			return None
		if label.startswith("-") or label.endswith("-"):
			return None
	return ascii_domain


def _extract_domains_from_hosts_line(line: str) -> list[str]:
	"""Extract all normalized domains from a hosts-format or AdGuard-format line.
	
	Supported formats:
	  - Hosts: 0.0.0.0 example.com www.example.com tracking.example.com
	  - Simple domain list: example.com
	  - AdGuard block rules: ||example.com^
	
	AdGuard whitelist rules (@@||domain^) are ignored since we only collect
	blocked domains. Wildcard rules (||*.domain^) are simplified to the base domain.
	
	Returns:
		List of normalized domain strings (may be empty).
	"""
	line = line.strip()
	# AdGuard comment lines start with !
	if not line or line.startswith("#") or line.startswith("!"):
		return []
	# Skip AdGuard whitelist/exception rules
	if line.startswith("@@"):
		return []
	
	# Handle AdGuard block rule format: ||domain.com^ or ||domain.com^$options
	if line.startswith("||"):
		# Extract domain from AdGuard rule: ||domain.com^ or ||domain.com^$...
		rule = line[2:]  # Strip leading ||
		# Remove trailing ^ and any modifiers ($third-party, etc.)
		if "^" in rule:
			rule = rule.split("^", 1)[0]
		# Handle wildcard prefix: ||*.domain.com → domain.com
		if rule.startswith("*."):
			rule = rule[2:]
		# Skip rules with wildcards in the middle or other unsupported patterns
		if "*" in rule or "/" in rule:
			return []
		norm = _normalize_domain(rule)
		return [norm] if norm else []
	
	# Strip inline # comments (common in hosts files)
	if "#" in line:
		line = line.split("#", 1)[0].strip()
	if not line:
		return []

	parts = line.split()
	if len(parts) == 1:
		# Simple "domain.tld" list format (no IP prefix)
		norm = _normalize_domain(parts[0])
		return [norm] if norm else []

	# First part should be an IP address
	try:
		ipaddress.ip_address(parts[0])
	except ValueError:
		return []

	# Parse ALL domains after the IP (parts[1:], not just parts[1])
	result: list[str] = []
	for raw_domain in parts[1:]:
		norm = _normalize_domain(raw_domain)
		if norm:
			result.append(norm)
	return result


# ---------------------------------------------------------------------------
# Blocklist Download
# ---------------------------------------------------------------------------

async def _download_hosts_domains(
	client: "httpx.AsyncClient",
	url: str,
	existing_domains: set[str],
) -> tuple[int, set[str]]:
	"""Stream and parse domains from one hosts list URL."""
	line_count = 0
	size_bytes = 0
	parsed_domains: set[str] = set()
	unique_new_domains = 0  # Track count of domains not in existing_domains

	async with client.stream("GET", url) as resp:
		resp.raise_for_status()
		content_type = resp.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
		# Allow missing Content-Type (common for plain-text file servers)
		# but reject explicitly non-text types like application/zip
		if content_type and content_type not in _ACCEPTABLE_TEXT_TYPES:
			raise ValueError(f"Unsupported content type: {content_type!r}")

		content_length = resp.headers.get("Content-Length")
		if content_length and content_length.isdigit() and int(content_length) > BLOCKLIST_MAX_BYTES:
			raise _CapacityExceeded(f"Blocklist too large ({content_length} bytes)")

		async for raw_line in resp.aiter_lines():
			line_count += 1
			# Approximate size (ASCII-dominant content) to avoid per-line encoding overhead
			size_bytes += len(raw_line) + 1
			if line_count > BLOCKLIST_MAX_LINES:
				raise _CapacityExceeded(f"Blocklist line limit exceeded ({BLOCKLIST_MAX_LINES})")
			if size_bytes > BLOCKLIST_MAX_BYTES:
				raise _CapacityExceeded(f"Blocklist size limit exceeded ({BLOCKLIST_MAX_BYTES} bytes)")

			domains = _extract_domains_from_hosts_line(raw_line)
			for domain in domains:
				# Track genuinely new domains (not in existing or already parsed)
				if domain not in existing_domains and domain not in parsed_domains:
					unique_new_domains += 1
				parsed_domains.add(domain)
				# Check capacity with accurate count (no double-counting)
				if len(existing_domains) + unique_new_domains > BLOCKLIST_MAX_DOMAINS:
					raise _CapacityExceeded(f"Domain cap exceeded ({BLOCKLIST_MAX_DOMAINS})")

	return line_count, parsed_domains


def _is_ip_unsafe(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
	"""Check if an IP address is unsafe (private, loopback, etc.).
	
	Handles IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1) which
	Python < 3.11 does not correctly identify as loopback/private.
	"""
	check = addr
	# Unwrap IPv4-mapped IPv6 addresses for proper safety checks
	if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
		check = addr.ipv4_mapped
	return (
		check.is_private
		or check.is_loopback
		or check.is_link_local
		or check.is_reserved
		or check.is_multicast
		or check.is_unspecified
	)


def _is_safe_url(url: str) -> bool:
	"""Validate URL and reject SSRF targets (private IPs, localhost, etc.).
	
	Note: This check is subject to DNS rebinding (TOCTOU) since httpx resolves
	the hostname again. Mitigated by only allowing URLs from BLOCKLIST_REGISTRY.
	"""
	parsed = urllib.parse.urlparse(url)
	# Require HTTPS to prevent MITM attacks on blocklist content
	if parsed.scheme != "https" or not parsed.netloc:
		return False
	
	hostname = parsed.hostname
	if not hostname:
		return False
	
	# Check if hostname is an IP address
	try:
		addr = ipaddress.ip_address(hostname)
		if _is_ip_unsafe(addr):
			return False
	except ValueError:
		# It's a hostname, not an IP — resolve and check all addresses
		try:
			for info in socket.getaddrinfo(hostname, None):
				addr = ipaddress.ip_address(info[4][0])
				if _is_ip_unsafe(addr):
					return False
		except socket.gaierror:
			return False
	
	return True


async def _is_safe_url_async(url: str) -> bool:
	"""Async wrapper for _is_safe_url to avoid blocking the event loop."""
	try:
		return await asyncio.wait_for(asyncio.to_thread(_is_safe_url, url), timeout=5.0)
	except asyncio.TimeoutError:
		_log.warning("DNS_BLOCKLIST URL safety check timed out: %s", url)
		return False


def _url_to_blocklist_id(url: str) -> str | None:
	"""Map a blocklist URL to its registry ID."""
	return _BLOCKLIST_URL_TO_ID.get(url)


def _format_tag_string(tags: AbstractSet[str]) -> str:
	"""Format a tag set for unbound config after validating tag names."""
	sorted_tags = sorted(tags)
	for tag in sorted_tags:
		if not _BLOCKLIST_TAG_RE.fullmatch(tag):
			raise ValueError(f"Unsafe blocklist tag: {tag!r}")
	return " ".join(sorted_tags)


async def update_blocklists(
	urls: list[str] | None = None,
	custom_rules_text: str = "",
) -> tuple[int, str]:
	"""Download blocklists and generate tagged local-zone entries.

	Each domain is tagged with its source blocklist ID(s) for per-peer filtering.
	Domains that appear in multiple lists get multiple tags.

	Custom rules (AdGuard syntax) are applied after downloading:
	  - Block rules add domains to the blocklist
	  - Allow rules remove domains from the blocklist
	  - Wildcard/regex rules are cached for runtime matching

	Returns:
		(count_of_blocked_domains, status_message)
	"""
	if httpx is None:
		raise RuntimeError("httpx required for blocklist updates: pip install httpx")

	# Only use default if urls is None (not provided).
	# An empty list [] means user explicitly disabled all blocklists.
	if urls is None:
		urls = DEFAULT_BLOCKLISTS
	
	# Handle empty URLs: clear blocklist and return early
	if not urls:
		blocklist_path = get_blocklist_file()
		def _write_empty_blocklist():
			with atomic_write(blocklist_path) as f:
				f.write("# Blocklist disabled – no sources enabled\n")
				f.write(f"# Updated: {datetime.now(timezone.utc).isoformat()}\n")
		await asyncio.to_thread(_write_empty_blocklist)
		_invalidate_blocked_domains_cache()
		set_custom_rules_cache([])  # Clear custom rules cache too
		_log.info("DNS_BLOCKLIST cleared (no sources enabled)")
		return 0, "Blocklist cleared: no sources enabled"
	
	# Track domains and their source tags: domain -> set of blocklist IDs
	domain_tags: dict[str, set[str]] = {}
	
	# Only registry-backed sources are supported; reject unknown URLs before any DNS lookup.
	known_sources: list[tuple[str, str]] = []
	for url in urls:
		blocklist_id = _url_to_blocklist_id(url)
		if not blocklist_id:
			_log.warning("DNS_BLOCKLIST unknown URL (not in registry): %s", url)
			continue
		known_sources.append((url, blocklist_id))
	if not known_sources:
		return 0, "No supported blocklist URLs provided"

	# Validate scheme/host safety only for supported registry URLs.
	safe_results = await asyncio.gather(*(_is_safe_url_async(url) for url, _ in known_sources))
	safe_sources: list[tuple[str, str]] = []
	for (url, blocklist_id), is_safe in zip(known_sources, safe_results):
		if not is_safe:
			_log.warning("DNS_BLOCKLIST rejected unsafe URL (SSRF risk): %s", url)
			continue
		safe_sources.append((url, blocklist_id))
	if not safe_sources:
		return 0, "No valid blocklist URLs provided"
	loaded_any = False

	async with httpx.AsyncClient(
		timeout=30,
		follow_redirects=True,
		max_redirects=3,  # Limit redirects to mitigate SSRF via redirect chains
		verify=True,
		headers={"User-Agent": "WireBuddy/1.0 DNS-Blocker"},
	) as client:
		for idx, (url, blocklist_id) in enumerate(safe_sources):
			# Add jitter between downloads to avoid hammering servers
			if idx > 0:
				jitter = random.uniform(0.5, 2.0)
				_log.debug("DNS_BLOCKLIST jitter delay %.1fs before %s", jitter, blocklist_id)
				await asyncio.sleep(jitter)
			# Retry up to 3 times with exponential backoff
			for attempt in range(3):
				try:
					existing_domains = set(domain_tags.keys())
					line_count, parsed = await _download_hosts_domains(client, url, existing_domains)
					added = 0
					for domain in parsed:
						if domain not in domain_tags:
							if len(domain_tags) >= BLOCKLIST_MAX_DOMAINS:
								raise _CapacityExceeded(f"Domain cap exceeded ({BLOCKLIST_MAX_DOMAINS})")
							domain_tags[domain] = set()
							added += 1
						domain_tags[domain].add(blocklist_id)
					loaded_any = True
					_log.info("DNS_BLOCKLIST loaded %s [%s] (%d lines, +%d domains)", url, blocklist_id, line_count, added)
					break  # Success, move to next URL
				except _CapacityExceeded as e:
					_log.warning("DNS_BLOCKLIST capacity limit reached processing %s: %s", url, e)
					loaded_any = True  # partial data was still collected
					break  # no point retrying
				except Exception as e:
					if attempt < 2:
						wait = 2 ** attempt  # 1s, 2s
						_log.debug("DNS_BLOCKLIST retry %d for %s in %ds: %s", attempt + 1, url, wait, e)
						await asyncio.sleep(wait)
					else:
						_log.warning("DNS_BLOCKLIST failed to load %s: %s", url, e)
	if not loaded_any:
		return 0, "No blocklist could be downloaded; existing blocklist kept"
	if not domain_tags:
		return 0, "Downloaded blocklists contained no domains; existing blocklist kept"

	# --- Apply custom rules (AdGuard syntax) ---
	custom_added: set[str] = set()
	custom_removed: set[str] = set()
	parsed_custom_rules: list[ParsedRule] = []
	if custom_rules_text.strip():
		parsed_custom_rules, parse_errors = parse_rules(custom_rules_text)
		if parse_errors:
			for pe in parse_errors:
				_log.warning("DNS_CUSTOM_RULE parse error line %d: %s – %s", pe.line, pe.text, pe.error)

		if parsed_custom_rules:
			# Apply rules: exact blocks are added, allows remove domains
			all_domains = set(domain_tags.keys())
			custom_added, custom_removed = apply_custom_rules(all_domains, parsed_custom_rules)
			# NOTE: apply_custom_rules mutates all_domains in-place (adds block domains, removes allow domains).
			# Filter out domains that were added by a block rule but then removed by an allow rule in the same operation.
			custom_added = {domain for domain in custom_added if domain in all_domains}

			# Add new block domains to the tag map (tagged as "custom")
			try:
				for domain in custom_added:
					if domain not in domain_tags:
						if len(domain_tags) >= BLOCKLIST_MAX_DOMAINS:
							raise _CapacityExceeded(f"Domain cap exceeded ({BLOCKLIST_MAX_DOMAINS})")
						domain_tags[domain] = set()
					domain_tags[domain].add(CUSTOM_RULES_TAG)
			except _CapacityExceeded as exc:
				_log.warning("DNS_CUSTOM_RULES capacity limit: %s", exc)

			# Remove allowed domains from the tag map
			for domain in custom_removed:
				domain_tags.pop(domain, None)

			_log.info(
				"DNS_CUSTOM_RULES applied %d rules: +%d blocked, -%d allowed",
				len(parsed_custom_rules), len(custom_added), len(custom_removed),
			)

	# Collect active tags for header documentation
	active_tags = {tag for tag_set in domain_tags.values() for tag in tag_set}

	# Write unbound local-zone file with tags (atomic replace)
	# Offload heavy write/sort to thread pool to avoid blocking event loop
	blocklist_path = get_blocklist_file()
	def _write_blocklist_file() -> None:
		with atomic_write(blocklist_path) as f:
			f.write(f"# Auto-generated blocklist – {len(domain_tags)} domains\n")
			f.write(f"# Updated: {datetime.now(timezone.utc).isoformat()}\n")
			f.write(f"# Active tags: {' '.join(sorted(active_tags))}\n")
			if custom_added or custom_removed:
				f.write(f"# Custom rules: +{len(custom_added)} blocked, -{len(custom_removed)} allowed\n")
			f.write("\n")
			# Sort for deterministic output (helps with diffing/debugging)
			for domain in sorted(domain_tags.keys()):
				tags = domain_tags[domain]
				tag_str = _format_tag_string(tags)
				# tagged local-zone: domain is blocked only for clients with matching tag
				# Domain normalization guarantees no " or \n characters (injection-safe)
				f.write(f'local-zone: "{domain}." always_nxdomain\n')
				f.write(f'local-zone-tag: "{domain}." "{tag_str}"\n')
	
	await asyncio.to_thread(_write_blocklist_file)

	# Update runtime caches AFTER successful file write (state consistency)
	set_custom_rules_cache(parsed_custom_rules)
	
	# Write client-specific custom rule overrides (server include file)
	try:
		unbound_config.write_custom_client_rules(parsed_custom_rules)
	except Exception:
		_log.exception("DNS_CUSTOM_CLIENT_RULES failed to write override file")

	_invalidate_blocked_domains_cache()
	_log.info("DNS_BLOCKLIST wrote %d tagged domains to %s", len(domain_tags), blocklist_path)
	return len(domain_tags), f"Blocklist updated: {len(domain_tags)} domains"


# ---------------------------------------------------------------------------
# Blocklist Queries
# ---------------------------------------------------------------------------

def get_blocklist_count() -> int:
	"""Return number of domains in the current blocklist."""
	blocklist_path = get_blocklist_file()
	if not blocklist_path.exists():
		return 0

	try:
		with blocklist_path.open("r", encoding="utf-8") as f:
			# Fast path: parse precomputed count from header
			first = f.readline()
			match = re.search(r"(\d+)\s+domains", first)
			if match:
				return int(match.group(1))
			# Fallback: stream file and count local-zone entries (including first line)
			count = 1 if first.startswith("local-zone:") else 0
			count += sum(1 for line in f if line.startswith("local-zone:"))
			return count
	except Exception:
		_log.debug("Failed to read blocklist count", exc_info=True)
		return 0


def get_blocklist_source_counts() -> dict[str, int]:
	"""Return per-source domain counts from the generated blocklist file.

	Counts are derived from ``local-zone-tag`` entries in ``blocklist.conf``.
	Each tag corresponds to a blocklist source ID from ``BLOCKLIST_REGISTRY``.
	"""
	blocklist_path = get_blocklist_file()
	counts: dict[str, int] = {bid: 0 for bid in BLOCKLIST_REGISTRY}
	if not blocklist_path.exists():
		return counts

	tag_re = re.compile(r'^local-zone-tag:\s+"[^"]+"\s+"([^"]+)"')
	try:
		with blocklist_path.open("r", encoding="utf-8", errors="replace") as f:
			for line in f:
				if not line.startswith("local-zone-tag:"):
					continue
				match = tag_re.match(line.strip())
				if not match:
					continue
				for tag in set(match.group(1).split()):
					if tag in counts:
						counts[tag] += 1
	except Exception:
		_log.debug("Could not read blocklist source counts", exc_info=True)

	return counts


def _load_blocked_domains() -> frozenset[str]:
	"""Load the set of blocked domains for fast lookup."""
	global _BLOCKED_DOMAINS_CACHE_ENTRY

	blocklist_path = get_blocklist_file()
	blocked: set[str] = set()
	if not blocklist_path.exists():
		empty = frozenset()
		_BLOCKED_DOMAINS_CACHE_ENTRY = (empty, None)
		return empty
	try:
		mtime_ns = blocklist_path.stat().st_mtime_ns
	except OSError:
		return frozenset()

	# Snapshot cache entry to prevent TOCTOU race if another thread invalidates
	# the cache between the None check and the index access.
	entry = _BLOCKED_DOMAINS_CACHE_ENTRY
	if entry is not None and entry[1] == mtime_ns:
		return entry[0]

	try:
		with blocklist_path.open("r", encoding="utf-8") as f:
			for line in f:
				if not line.startswith("local-zone:"):
					continue
				# local-zone: "example.com." always_nxdomain
				parts = line.split('"')
				if len(parts) >= 2:
					# Domains are already normalized when written - just strip trailing dot
					domain = parts[1].rstrip(".").lower()
					if domain:
						blocked.add(domain)
			# Cache against the file we actually read (avoids stat/open replacement race)
			read_mtime_ns = os.fstat(f.fileno()).st_mtime_ns
	except Exception:
		_log.debug("Failed to load blocked domains from blocklist", exc_info=True)
		return frozenset()
	cached = frozenset(blocked)
	_BLOCKED_DOMAINS_CACHE_ENTRY = (cached, read_mtime_ns)
	return cached


def get_blocked_domains() -> frozenset[str]:
	"""Public API: Get the set of currently blocked domains.
	
	Internally cached - safe to call frequently. Cache invalidates
	when blocklist.conf file changes (based on mtime).
	
	Returns:
		Set of blocked domain names (normalized, without trailing dots)
	"""
	return _load_blocked_domains()


def _is_normalized_domain_blocked(norm: str, blocked_domains: AbstractSet[str]) -> bool:
	"""Check exact and parent-domain matches for an already-normalized domain."""
	if norm in blocked_domains:
		return True

	labels = norm.split(".")
	for i in range(1, len(labels) - 1):
		parent = ".".join(labels[i:])
		if parent in blocked_domains:
			return True
	return False


def is_domain_blocked(domain: str, *, client_ip: str | None = None) -> bool:
	"""Check whether *domain* (or any parent) is on the active blocklist.
	
	This function also respects runtime custom rules:
	  - If domain matches a custom ALLOW rule → returns False (whitelist wins)
	  - If domain matches a custom wildcard/regex BLOCK rule → returns True
	  - Otherwise checks the static blocklist file
	
	Args:
		domain: Domain name to check (e.g., "example.com" or "sub.example.com")
		client_ip: Optional client IP used for client-scoped custom rules.
		
	Returns:
		True if the domain or any parent domain is blocked, False otherwise.
		
	Examples:
		>>> is_domain_blocked("ads.example.com")  # if "example.com" is blocked
		True
		>>> is_domain_blocked("safe-site.com")
		False
	"""
	norm = _normalize_domain(domain)
	if not norm:
		return False
	
	# Check runtime custom rules first (allow rules take priority)
	allow_rules, block_rules = get_custom_rules_cache()
	
	# Whitelist wins: if any allow rule matches, domain is NOT blocked
	if is_domain_allowed_by_custom_rules(norm, allow_rules, client_ip=client_ip):
		return False

	# Check custom wildcard/regex block rules
	if is_domain_blocked_by_custom_rules(norm, block_rules, client_ip=client_ip):
		return True
	
	# Fall back to static blocklist file
	return _is_normalized_domain_blocked(norm, _load_blocked_domains())


def check_and_reset_stale_blocklist() -> bool:
	"""Check if blocklist.conf contains unknown tags and reset if needed.
	
	This handles the case where the blocklist registry changes between versions
	(e.g., 'easylist' was removed and replaced with 'hagezi'). Unbound will
	fail to start if blocklist.conf references tags not defined in unbound.conf.
	
	Returns:
		True if blocklist was reset and needs re-download, False if OK.
	"""
	blocklist_path = get_blocklist_file()
	if not blocklist_path.exists():
		return False
	
	known_tags = set(BLOCKLIST_REGISTRY.keys())
	known_tags.add(CUSTOM_RULES_TAG)  # Custom rules also add this tag
	
	unknown_tags: set[str] = set()
	tag_re = re.compile(r'^local-zone-tag:\s+"[^"]+"\s+"([^"]+)"')
	
	try:
		with blocklist_path.open("r", encoding="utf-8", errors="replace") as f:
			for line in f:
				if not line.startswith("local-zone-tag:"):
					continue
				match = tag_re.match(line.strip())
				if not match:
					continue
				for tag in match.group(1).split():
					if tag not in known_tags:
						unknown_tags.add(tag)
						# Early exit - one unknown tag is sufficient to trigger reset
						break
				if unknown_tags:
					break
	except Exception:
		_log.debug("Could not check blocklist tags", exc_info=True)
		return False
	
	if not unknown_tags:
		return False
	
	_log.warning(
		"BLOCKLIST_MIGRATION found unknown tags %s in %s - resetting for re-download",
		unknown_tags,
		blocklist_path,
	)
	
	# Reset the blocklist file to empty
	try:
		with atomic_write(blocklist_path) as f:
			f.write("# Blocklist reset due to tag migration\n")
			f.write("# Will be re-downloaded on next scheduled update\n")
		_invalidate_blocked_domains_cache()
		return True
	except Exception:
		_log.exception("Failed to reset blocklist file")
		return False


__all__ = [
	"update_blocklists",
	"get_blocklist_count",
	"get_blocklist_source_counts",
	"get_blocked_domains",
	"is_domain_blocked",
	"set_custom_rules_cache",
	"get_custom_rules_cache",
	"check_and_reset_stale_blocklist",
]
