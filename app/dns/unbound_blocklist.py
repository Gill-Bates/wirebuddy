#!/usr/bin/env python3
#
# app/dns/unbound_blocklist.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Unbound DNS blocklist management and domain filtering."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import random
import re
import urllib.parse
from collections.abc import Set as AbstractSet
from datetime import datetime, timezone

try:
	import httpx
except ImportError:
	httpx = None  # type: ignore

try:
	import idna
except ImportError:
	idna = None  # type: ignore

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
_BLOCKED_DOMAINS_CACHE: frozenset[str] | None = None
_BLOCKED_DOMAINS_CACHE_MTIME_NS: int | None = None


def _invalidate_blocked_domains_cache() -> None:
	"""Invalidate cached blocked-domain set after blocklist changes."""
	global _BLOCKED_DOMAINS_CACHE
	global _BLOCKED_DOMAINS_CACHE_MTIME_NS
	_BLOCKED_DOMAINS_CACHE = None
	_BLOCKED_DOMAINS_CACHE_MTIME_NS = None


# ---------------------------------------------------------------------------
# Domain Normalization
# ---------------------------------------------------------------------------

def _normalize_domain(raw: str) -> str | None:
	"""Normalize and validate a domain; returns ASCII IDNA domain or None."""
	domain = raw.strip().strip(".").lower()
	if not domain or domain == "localhost" or len(domain) > 253:
		return None
	try:
		if idna:
			# Use IDNA 2008 for better modern TLD support
			ascii_domain = idna.encode(domain, uts46=True).decode("ascii").rstrip(".")
		else:
			# Fallback to IDNA 2003 (built-in)
			ascii_domain = domain.encode("idna").decode("ascii")
	except (UnicodeError, Exception):
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


def _extract_domain_from_hosts_line(line: str) -> str | None:
	"""Extract a normalized domain from a hosts-format line."""
	line = line.strip()
	if not line or line.startswith("#"):
		return None
	if "#" in line:
		line = line.split("#", 1)[0].strip()
	if not line:
		return None

	parts = line.split()
	if len(parts) == 1:
		# Also support simple "domain.tld" list format.
		return _normalize_domain(parts[0])
	if len(parts) < 2:
		return None

	try:
		ipaddress.ip_address(parts[0])
	except ValueError:
		return None

	return _normalize_domain(parts[1])


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

	async with client.stream("GET", url) as resp:
		resp.raise_for_status()
		content_type = resp.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
		if content_type and content_type not in _ACCEPTABLE_TEXT_TYPES:
			raise ValueError(f"Unsupported content type: {content_type!r}")

		content_length = resp.headers.get("Content-Length")
		if content_length and content_length.isdigit() and int(content_length) > BLOCKLIST_MAX_BYTES:
			raise _CapacityExceeded(f"Blocklist too large ({content_length} bytes)")

		async for raw_line in resp.aiter_lines():
			line_count += 1
			size_bytes += len(raw_line.encode("utf-8", errors="ignore")) + 1
			if line_count > BLOCKLIST_MAX_LINES:
				raise _CapacityExceeded(f"Blocklist line limit exceeded ({BLOCKLIST_MAX_LINES})")
			if size_bytes > BLOCKLIST_MAX_BYTES:
				raise _CapacityExceeded(f"Blocklist size limit exceeded ({BLOCKLIST_MAX_BYTES} bytes)")

			domain = _extract_domain_from_hosts_line(raw_line)
			if not domain:
				continue
			parsed_domains.add(domain)
			if len(existing_domains) + len(parsed_domains) > BLOCKLIST_MAX_DOMAINS:
				raise _CapacityExceeded(f"Domain cap exceeded ({BLOCKLIST_MAX_DOMAINS})")

	return line_count, parsed_domains


def _url_to_blocklist_id(url: str) -> str | None:
	"""Map a blocklist URL to its registry ID."""
	for bid, meta in BLOCKLIST_REGISTRY.items():
		if meta["url"] == url:
			return bid
	return None


async def update_blocklists(
	urls: list[str] | None = None,
) -> tuple[int, str]:
	"""Download blocklists and generate tagged local-zone entries.

	Each domain is tagged with its source blocklist ID(s) for per-peer filtering.
	Domains that appear in multiple lists get multiple tags.

	Returns:
		(count_of_blocked_domains, status_message)
	"""
	if httpx is None:
		raise RuntimeError("httpx required for blocklist updates: pip install httpx")

	urls = urls or DEFAULT_BLOCKLISTS
	
	# Track domains and their source tags: domain -> set of blocklist IDs
	domain_tags: dict[str, set[str]] = {}
	
	# Validate URL schemes first (prevent file:// or other attacks).
	safe_urls: list[str] = []
	for url in urls:
		parsed = urllib.parse.urlparse(url)
		if parsed.scheme not in ("http", "https") or not parsed.netloc:
			_log.warning("DNS_BLOCKLIST rejected non-HTTP URL: %s", url)
			continue
		safe_urls.append(url)
	if not safe_urls:
		return 0, "No valid blocklist URLs provided"
	known_sources: list[tuple[str, str]] = []
	for url in safe_urls:
		blocklist_id = _url_to_blocklist_id(url)
		if not blocklist_id:
			_log.warning("DNS_BLOCKLIST unknown URL (not in registry): %s", url)
			continue
		known_sources.append((url, blocklist_id))
	if not known_sources:
		return 0, "No supported blocklist URLs provided"
	loaded_any = False

	async with httpx.AsyncClient(
		timeout=30,
		follow_redirects=True,
		headers={"User-Agent": "WireBuddy/1.0 DNS-Blocker"},
	) as client:
		for idx, (url, blocklist_id) in enumerate(known_sources):
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

	# Write unbound local-zone file with tags (atomic replace)
	blocklist_path = get_blocklist_file()
	with atomic_write(blocklist_path) as f:
		f.write(f"# Auto-generated blocklist – {len(domain_tags)} domains\n")
		f.write(f"# Updated: {datetime.now(timezone.utc).isoformat()}\n")
		f.write(f"# Tags: {' '.join(BLOCKLIST_REGISTRY.keys())}\n\n")
		for domain in sorted(domain_tags.keys()):
			tags = domain_tags[domain]
			tag_str = " ".join(sorted(tags))
			# tagged local-zone: domain is blocked only for clients with matching tag
			f.write(f'local-zone: "{domain}." always_nxdomain\n')
			f.write(f'local-zone-tag: "{domain}." "{tag_str}"\n')

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
			# Fallback: stream file and count local-zone entries
			count = sum(1 for line in f if line.startswith("local-zone:"))
			return count
	except Exception:
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
	global _BLOCKED_DOMAINS_CACHE
	global _BLOCKED_DOMAINS_CACHE_MTIME_NS

	blocklist_path = get_blocklist_file()
	blocked: set[str] = set()
	if not blocklist_path.exists():
		_BLOCKED_DOMAINS_CACHE = frozenset()
		_BLOCKED_DOMAINS_CACHE_MTIME_NS = None
		return _BLOCKED_DOMAINS_CACHE
	try:
		mtime_ns = blocklist_path.stat().st_mtime_ns
	except OSError:
		return frozenset()

	if (
		_BLOCKED_DOMAINS_CACHE is not None
		and _BLOCKED_DOMAINS_CACHE_MTIME_NS == mtime_ns
	):
		return _BLOCKED_DOMAINS_CACHE

	try:
		with blocklist_path.open("r", encoding="utf-8") as f:
			for line in f:
				if not line.startswith("local-zone:"):
					continue
				# local-zone: "example.com." always_nxdomain
				parts = line.split('"')
				if len(parts) >= 2:
					domain = _normalize_domain(parts[1])
					if domain:
						blocked.add(domain)
	except Exception:
		return frozenset()
	_BLOCKED_DOMAINS_CACHE = frozenset(blocked)
	_BLOCKED_DOMAINS_CACHE_MTIME_NS = mtime_ns
	return _BLOCKED_DOMAINS_CACHE


def get_blocked_domains() -> frozenset[str]:
	"""Public API: Get the set of currently blocked domains.
	
	Internally cached - safe to call frequently. Cache invalidates
	when blocklist.conf file changes (based on mtime).
	
	Returns:
		Set of blocked domain names (normalized, without trailing dots)
	"""
	return _load_blocked_domains()


def _is_domain_blocked(domain: str, blocked_domains: AbstractSet[str]) -> bool:
	"""Check exact and parent-domain matches for block status."""
	norm = _normalize_domain(domain)
	if not norm:
		return False
	if norm in blocked_domains:
		return True

	labels = norm.split(".")
	for i in range(1, len(labels) - 1):
		parent = ".".join(labels[i:])
		if parent in blocked_domains:
			return True
	return False


def is_domain_blocked(domain: str) -> bool:
	"""Check whether *domain* (or any parent) is on the active blocklist.
	
	Args:
		domain: Domain name to check (e.g., "example.com" or "sub.example.com")
		
	Returns:
		True if the domain or any parent domain is blocked, False otherwise.
		
	Examples:
		>>> is_domain_blocked("ads.example.com")  # if "example.com" is blocked
		True
		>>> is_domain_blocked("safe-site.com")
		False
	"""
	return _is_domain_blocked(domain, _load_blocked_domains())


__all__ = [
	"update_blocklists",
	"get_blocklist_count",
	"get_blocklist_source_counts",
	"get_blocked_domains",
	"is_domain_blocked",
]
