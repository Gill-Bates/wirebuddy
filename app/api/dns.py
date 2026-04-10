#!/usr/bin/env python3
#
# app/api/dns.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""DNS management API routes."""

from __future__ import annotations

from ..db.sqlite_interfaces import (
	list_interfaces,
)
from ..db.sqlite_peers import (
	get_all_peers,
)
from ..db.sqlite_settings import (
	DNS_LOG_RETENTION_OPTIONS,
	get_dns_blocklist_enabled,
	get_dns_custom_rules,
	get_dns_log_retention_days,
	get_dns_query_logging_enabled,
	get_dns_upstream_servers,
	get_dnssec_enabled,
	get_enabled_blocklists,
	get_blocklist_disabled_until,
	set_blocklist_disabled_until,
	clear_blocklist_disabled_until,
	set_dns_blocklist_enabled,
	set_dns_custom_rules,
	set_dns_log_retention_days,
	set_dns_query_logging_enabled,
	set_dns_service_enabled,
	set_dns_upstream_servers,
	set_dnssec_enabled,
	set_enabled_blocklists,
)

import asyncio
import ipaddress
import logging
import os
import re
import shutil
import sqlite3
import socket
import ssl
import struct
import time
import unicodedata
from collections import OrderedDict
from collections.abc import Coroutine
from typing import Literal
from urllib.parse import urlparse

from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator

from ..db import tsdb
from ..dns import constants as dns_constants
from ..dns import ingestion as dns_ingestion
from ..dns import unbound
from ..dns.custom_rules import (
	RuleAction,
	canonical_rule_text,
	parse_rules as parse_custom_rules,
)
from ..dns.ingestion_writer import DNS_STATS_PEER_KEY, DNS_METRIC_TOTAL, DNS_METRIC_BLOCKED
from ..utils.deps import get_conn, get_dns_dir, get_tsdb_dir
from ..utils.network import parse_ip_str
from .auth import get_current_user, require_admin
from .response import ok_response
from .wireguard_utils import (
	get_enabled_blocklist_ids,
	filter_peer_blocklist_ids,
	parse_blocklist_ids,
)


_log = logging.getLogger(__name__)
_background_tasks: set[asyncio.Task[None]] = set()
_background_tasks_lock = asyncio.Lock()  # Protects _background_tasks set
_DNS_STATUS_CACHE_TTL_SECONDS = 5.0
_DNS_TREND_CACHE_TTL_SECONDS = 60.0
_DNS_TREND_CACHE_STALE_TTL_SECONDS = 300.0  # Serve stale data up to 5min while recomputing
_DNS_TREND_CACHE_MAX_SIZE = 128
_cache_lock = asyncio.Lock()  # Protects status/trend caches
_dns_status_cache: dict[str, tuple[float, dict]] = {}
# OrderedDict for LRU eviction (move_to_end on access, popitem(last=False) to evict)
_dns_trend_cache: OrderedDict[tuple[str, int, int, str], tuple[float, dict]] = OrderedDict()
_dns_trend_lock = asyncio.Lock()  # Prevents thundering herd on trend computation
_ALLOWED_DOT_PORTS = frozenset({853, 8853})
_DOT_TEST_CONCURRENCY = 8

# Rebuild coordination: "latest-wins" pattern to prevent concurrent rebuilds
# while ensuring the most recent request is always processed
_rebuild_lock = asyncio.Lock()  # Protects rebuild state
_rebuild_latest: tuple[list[str], str] | None = None
_rebuild_event: asyncio.Event | None = None
_rebuild_worker_task: asyncio.Task[None] | None = None
_rebuild_in_progress: bool = False


def _spawn_background_task(coro: Coroutine[object, object, None], *, name: str) -> None:
	"""Track fire-and-forget tasks so they are not garbage-collected early.
	
	Note: Uses synchronous set operations which are atomic in CPython due to GIL.
	The lock is used for extra safety in case of future Python implementations.
	"""
	task = asyncio.create_task(coro, name=name)
	_background_tasks.add(task)

	def _cleanup(done_task: asyncio.Task[None]) -> None:
		_background_tasks.discard(done_task)
		if done_task.cancelled():
			return
		try:
			exc = done_task.exception()
		except Exception:
			_log.exception("Background task %s completion check failed", name)
			return
		if exc is not None:
			_log.error("Background task %s failed: %s", name, exc)

	task.add_done_callback(_cleanup)


def _normalize_ip_literal(value: str) -> str:
	"""Normalize IPv4/IPv6 literals, accepting optional brackets for IPv6."""
	text = str(value or "").strip()
	if text.startswith("[") and text.endswith("]"):
		return text[1:-1].strip()
	return text


def _blocklist_mtime() -> str | None:
	"""Return the ISO-8601 mtime of the blocklist file, or None."""
	try:
		blocklist_path = unbound.get_blocklist_file()
		if blocklist_path.exists():
			ts = blocklist_path.stat().st_mtime
			return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
	except Exception:
		_log.debug("Could not read blocklist mtime", exc_info=True)
	return None


def _parse_tsdb_timestamp(raw: str) -> datetime | None:
	"""Parse TSDB ISO timestamp to UTC datetime."""
	value = str(raw or "").strip()
	if not value:
		return None
	try:
		if value.endswith("Z"):
			value = value[:-1] + "+00:00"
		dt = datetime.fromisoformat(value)
		if dt.tzinfo is None:
			return dt.replace(tzinfo=timezone.utc)
		return dt.astimezone(timezone.utc)
	except ValueError:
		return None


def _format_tsdb_timestamp(raw: str) -> str:
	"""Format TSDB timestamp for UI table display."""
	dt = _parse_tsdb_timestamp(raw)
	if dt is None:
		return ""
	return dt.replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")


def _regenerate_peer_tags_for_blocklist(conn: sqlite3.Connection) -> None:
	"""Regenerate Unbound peer-tags.conf after blocklist enable/disable change.
	
	This ensures that blocking takes effect immediately when the global
	blocklist toggle is changed, rather than requiring a peer edit.
	
	IMPORTANT: If the global ad-blocker is disabled, peer-tags.conf is written
	empty to prevent Unbound crash (tags without corresponding local-zone-tag rules).
	"""
	# If global ad-blocker is disabled, write empty peer-tags to avoid crash
	if not get_dns_blocklist_enabled(conn):
		unbound.write_peer_tags([])
		_log.debug("DNS peer tags cleared (ad-blocker disabled globally)")
		return
	
	enabled_blocklist_ids = get_enabled_blocklist_ids(conn)
	peers = get_all_peers(conn)
	peer_list = []
	
	for row in peers:
		blocklist_ids = parse_blocklist_ids(row["blocklist_ids"])
		# Resolve effective blocklists
		if blocklist_ids is None:
			effective_ids = list(enabled_blocklist_ids)
		else:
			filtered = filter_peer_blocklist_ids(blocklist_ids, enabled_blocklist_ids)
			effective_ids = filtered or []
		
		peer_list.append({
			"peer_address": row["peer_address"],
			"use_adblocker": bool(row["use_adblocker"]),
			"blocklist_ids": effective_ids,
		})
	
	unbound.write_peer_tags(peer_list)
	_log.debug("DNS peer tags regenerated for %d peers", len(peer_list))


def _regenerate_peer_tags_safe(db_path: str | Path) -> None:
	"""Thread-safe wrapper for peer tags regeneration.
	
	Creates its own DB connection for use in asyncio.to_thread(),
	since SQLite connections are not thread-safe by default.
	"""
	from ..db.sqlite_runtime import close_connection, connect
	# connect() expects Path (uses db_path.parent), so ensure conversion
	conn = connect(Path(db_path) if isinstance(db_path, str) else db_path)
	try:
		_regenerate_peer_tags_for_blocklist(conn)
	finally:
		close_connection(conn)


def _collect_listen_addresses(
	conn: sqlite3.Connection,
) -> tuple[list[str], list[str] | None]:
	"""Collect WireGuard interface IPs for Unbound to bind to."""
	interfaces = list_interfaces(conn)
	ipv4: list[str] = []
	for iface in interfaces:
		try:
			addr4 = iface["address"]
		except (KeyError, TypeError, IndexError):
			addr4 = getattr(iface, "address", None)
		if addr4:
			ip4 = str(addr4).split("/")[0]
			if ip4 not in ipv4:
				ipv4.append(ip4)
	ipv6 = unbound.get_interface_ipv6_gateways(interfaces)
	return ipv4, ipv6 or None


async def _background_reload_for_blocklist(enable_blocklist: bool) -> None:
	"""Background task: Write full Unbound config and reload after blocklist toggle.
	
	This is called asynchronously after the API response is sent for blocklist-only
	changes to improve UX responsiveness. DB changes and peer-tags are already
	persisted before this runs.
	
	Args:
		enable_blocklist: Current blocklist enabled state from DB.
	"""
	try:
		# Import here to avoid circular dependency
		from ..db.sqlite_runtime import close_connection, connect
		from ..utils.config import get_config
		db_path = get_config().db_path

		def _sync_work() -> None:
			"""Synchronous DB reads and config write (run in thread)."""
			conn = connect(db_path)
			try:
				enable_logging = get_dns_query_logging_enabled(conn)
				upstream_dns = get_dns_upstream_servers(conn)
				dnssec_enabled = get_dnssec_enabled(conn)
				ipv4_gateways, ipv6_gateways = _collect_listen_addresses(conn)
				unbound.write_config(
					enable_logging=enable_logging,
					enable_blocklist=enable_blocklist,
					upstream_dns=upstream_dns,
					enable_dnssec=dnssec_enabled,
					listen_addrs_ipv4=ipv4_gateways,
					listen_addrs_ipv6=ipv6_gateways,
				)
			finally:
				close_connection(conn)

		# Run blocking I/O in thread to avoid blocking event loop
		await asyncio.to_thread(_sync_work)

		# Reload or start unbound (if it crashed, start it instead of waiting for watchdog)
		if await unbound.is_running():
			ok, msg = await unbound.reload_config()
			if ok:
				_log.info("DNS_BG_RELOAD blocklist toggle reload completed successfully")
			else:
				_log.warning("DNS_BG_RELOAD blocklist toggle reload failed: %s", msg)
		else:
			# Unbound not running - start it instead of reload
			_log.info("DNS_BG_RELOAD unbound not running, starting instead of reload")
			ok, msg = await unbound.start()
			if ok:
				_log.info("DNS_BG_RELOAD blocklist toggle start completed successfully")
			else:
				_log.warning("DNS_BG_RELOAD blocklist toggle start failed: %s", msg)
	except Exception as exc:
		_log.error("DNS_BG_RELOAD background reload failed: %s", exc, exc_info=True)


router = APIRouter(tags=["dns"])

# Regex for DNS-over-TLS notation: IP@port#hostname
# Stricter pattern: no whitespace, port 1-5 digits, hostname alphanumeric with dots/hyphens
_DNS_PATTERN = re.compile(r"^([^\s@#]+)(?:@(\d{1,5}))?(?:#([A-Za-z0-9.-]+))?$")
_HOST_LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")


def _require_unbound_installed() -> None:
	"""Raise HTTP 503 if Unbound is not installed."""
	if not unbound.is_unbound_installed():
		raise HTTPException(status_code=503, detail="Unbound not installed")


def _validate_https_urls(urls: list[str]) -> list[str]:
	"""Validate blocklist URLs are HTTPS.
	
	Raises:
		ValueError: If any URL is invalid or non-HTTPS.
	"""
	validated = []
	for url in urls:
		url = url.strip()
		if not url:
			continue
		if len(url) > 2048:
			raise ValueError(f"URL too long: {url}")
		parsed = urlparse(url)
		if parsed.scheme != "https":
			raise ValueError(f"Blocklist URLs must use HTTPS: {url}")
		if not parsed.hostname:
			raise ValueError(f"URL missing hostname: {url}")
		validated.append(url)
	return validated


def _normalize_hostname(hostname: str) -> str:
	"""Validate and normalize hostname to ASCII (IDNA)."""
	value = hostname.strip().strip(".").lower()
	if not value:
		raise ValueError("Hostname is required")
	try:
		ascii_host = value.encode("idna").decode("ascii")
	except UnicodeError as e:
		raise ValueError(f"Invalid hostname: {hostname}") from e

	if len(ascii_host) > 253:
		raise ValueError(f"Hostname too long (max 253): {hostname}")

	for label in ascii_host.split("."):
		if not _HOST_LABEL_RE.fullmatch(label):
			raise ValueError(f"Invalid hostname label: {label}")
		if label.startswith("-") or label.endswith("-"):
			raise ValueError(f"Invalid hostname label: {label}")
	return ascii_host


def _parse_client_ip_filter(client_ips: str | None) -> tuple[set[str] | None, str]:
	"""Parse, validate, and normalize a comma-separated client IP filter."""
	if not client_ips:
		return None, ""
	if len(client_ips) > 4096:
		raise HTTPException(status_code=422, detail="client_ips too long")

	client_filter: set[str] = set()
	for raw_ip in client_ips.split(","):
		ip = raw_ip.strip()
		if not ip:
			continue
		try:
			client_filter.add(str(ipaddress.ip_address(ip)))
		except ValueError:
			raise HTTPException(status_code=422, detail=f"Invalid client IP: {ip}") from None

	if not client_filter:
		return None, ""
	if len(client_filter) > 64:
		raise HTTPException(status_code=422, detail="Too many client IP filters (max 64)")

	return client_filter, ",".join(sorted(client_filter))


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

class DnsConfigUpdate(BaseModel):
	"""Request body for updating DNS configuration.
	
	All fields are optional – only explicitly set fields will be applied.
	"""
	enable_logging: bool | None = None
	enable_blocklist: bool | None = None
	upstream_dns: list[str] | None = None
	dnssec_enabled: bool | None = None
	log_retention_days: int | None = None
	
	@field_validator("upstream_dns")
	@classmethod
	def validate_upstream_dns(cls, v: list[str] | None) -> list[str] | None:
		"""Validate upstream DNS server addresses."""
		if v is None:
			return v
		validated = []
		for addr in v:
			addr = addr.strip()
			if not addr:
				continue
			match = _DNS_PATTERN.match(addr)
			if not match:
				raise ValueError(f"Invalid DNS address format: {addr}")
			ip_part = _normalize_ip_literal(match.group(1))
			port_part = match.group(2)
			hostname_part = match.group(3)
			
			# Validate IP address
			try:
				ipaddress.ip_address(ip_part)
			except ValueError:
				raise ValueError(f"Invalid IP address: {ip_part}") from None
			
			# Validate port range if provided
			if port_part:
				port_int = int(port_part)
				if not 1 <= port_int <= 65535:
					raise ValueError(f"Port must be between 1-65535: {port_int}")
			
			# DNS-over-TLS requires SNI hostname for certificate verification.
			if not hostname_part:
				raise ValueError(
					f"DNS-over-TLS upstream must include hostname as IP@port#hostname: {addr}"
				)
			hostname = _normalize_hostname(hostname_part)
			port = int(port_part) if port_part else 853
			validated.append(f"{ip_part}@{port}#{hostname}")
		if not validated:
			raise ValueError("At least one upstream DNS server is required")
		return validated

	@field_validator("log_retention_days")
	@classmethod
	def validate_log_retention_days(cls, v: int | None) -> int | None:
		"""Validate DNS log retention options."""
		if v is None:
			return v
		if v not in DNS_LOG_RETENTION_OPTIONS:
			raise ValueError(f"Invalid log_retention_days: {v}")
		return v


class BlocklistUpdate(BaseModel):
	"""Request body for updating blocklists."""
	urls: list[str] | None = None
	
	@field_validator("urls")
	@classmethod
	def validate_urls(cls, v: list[str] | None) -> list[str] | None:
		"""Validate blocklist URLs are HTTPS."""
		if v is None:
			return v
		validated = _validate_https_urls(v)
		return validated or None


class BlocklistSourcesUpdate(BaseModel):
	"""Request body for setting enabled blocklist sources."""
	urls: list[str]
	
	@field_validator("urls")
	@classmethod
	def validate_urls(cls, v: list[str]) -> list[str]:
		"""Validate blocklist URLs are HTTPS."""
		return _validate_https_urls(v)


class CustomRulesUpdate(BaseModel):
	"""Request body for updating custom DNS rules."""
	rules: str

	@field_validator("rules")
	@classmethod
	def validate_rules_length(cls, v: str) -> str:
		"""Limit custom rules text size."""
		if len(v) > 100_000:
			raise ValueError("Custom rules text too large (max 100 KB)")
		return v


class CustomRuleActionRequest(BaseModel):
	"""Request body for adding a custom DNS rule from query-log actions."""
	action: Literal["block", "unblock"]
	scope: Literal["global", "client"]
	domain: str
	client: str | None = None
	client_name: str | None = None

	@field_validator("domain")
	@classmethod
	def validate_domain(cls, v: str) -> str:
		domain = str(v or "").strip().lower().rstrip(".")
		if not domain:
			raise ValueError("Domain is required")
		if len(domain) > 253:
			raise ValueError("Domain too long")
		if "." not in domain:
			raise ValueError("Domain must include a TLD")
		for label in domain.split("."):
			if not label or len(label) > 63:
				raise ValueError("Invalid domain label")
			if not re.fullmatch(r"[a-z0-9-]+", label):
				raise ValueError("Invalid domain label")
			if label.startswith("-") or label.endswith("-"):
				raise ValueError("Invalid domain label")
		return domain

	@field_validator("client")
	@classmethod
	def validate_client(cls, v: str | None) -> str | None:
		if v is None:
			return v
		text = v.strip()
		if not text:
			return None
		if "/" in text:
			return str(ipaddress.ip_network(text, strict=False))
		ip_obj = ipaddress.ip_address(text)
		if ip_obj.version == 4:
			return f"{ip_obj}/32"
		return f"{ip_obj}/128"

	@field_validator("client_name")
	@classmethod
	def validate_client_name(cls, v: str | None) -> str | None:
		if v is None:
			return None
		cleaned = []
		for ch in str(v):
			if ch in "\r\n\u0085\u2028\u2029":
				cleaned.append(" ")
				continue
			if unicodedata.category(ch).startswith("C"):
				continue
			cleaned.append(ch)
		name = " ".join("".join(cleaned).split()).strip()
		if not name:
			return None
		if len(name) > 120:
			name = name[:120].rstrip()
		return name


# ---------------------------------------------------------------------------
# Status & Stats
# ---------------------------------------------------------------------------

@router.get("/status")
async def dns_status(
	hours: int | None = Query(None, ge=1, le=8760, description="Optional time window in hours for DNS statistics"),
	client_ips: str | None = Query(None, description="Comma-separated client IPs to filter by"),
	dns_dir: Path = Depends(get_dns_dir),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get DNS resolver status and statistics."""
	dns_key = str(dns_dir.resolve())
	client_filter, client_filter_key = _parse_client_ip_filter(client_ips)
	cache_key = (dns_key, hours or 0, client_filter_key)
	cache_entry = _dns_status_cache.get(cache_key)
	now_mono = time.monotonic()
	if cache_entry and (now_mono - cache_entry[0]) < _DNS_STATUS_CACHE_TTL_SECONDS:
		return ok_response(data=cache_entry[1])

	query_limit = 50000 if hours is None else min(100_000, max(5_000, hours * 5_000))
	queries = await asyncio.to_thread(dns_ingestion.read_recent_queries, dns_dir, query_limit)
	since = datetime.now(timezone.utc) - timedelta(hours=hours) if hours is not None else None
	all_domains: set[str] = set()
	all_clients: set[str] = set()
	blocked_count = 0
	total_queries = 0
	for q in queries:
		if since is not None:
			ts = _parse_tsdb_timestamp(str(q.get("ts", "")))
			if ts is None or ts < since:
				continue
		if client_filter and q.get("client") not in client_filter:
			continue
		domain = str(q.get("domain", "")).strip()
		client = str(q.get("client", "")).strip()
		total_queries += 1
		if domain:
			all_domains.add(domain)
		if client:
			all_clients.add(client)
		if bool(q.get("blocked", False)):
			blocked_count += 1

	unavailable = False
	reason = ""
	running = False
	is_installed = await asyncio.to_thread(unbound.is_unbound_installed)
	if not is_installed:
		unavailable = True
		reason = "Unbound not installed"
	else:
		try:
			running = await unbound.is_running()
		except FileNotFoundError:
			unavailable = True
			reason = "Unbound not installed"
		except Exception as exc:
			_log.debug("DNS status running-check failed: %s", exc)

	if unavailable:
		blocklist_size = 0
	else:
		try:
			blocklist_size = await asyncio.to_thread(unbound.get_blocklist_count)
		except Exception:
			blocklist_size = 0

	data = {
		"is_running": running,
		"total_queries": total_queries,
		"blocked_queries": blocked_count,
		"block_percentage": round(
			(blocked_count / total_queries * 100) if total_queries else 0, 1
		),
		"unique_domains": len(all_domains),
		"unique_clients": len(all_clients),
		"blocklist_size": blocklist_size,
		"blocklist_updated_at": _blocklist_mtime(),
		"unavailable": unavailable,
		"reason": reason,
	}
	_dns_status_cache[cache_key] = (now_mono, data)
	return ok_response(data=data)


@router.get("/selftest")
async def dns_selftest(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Run a lightweight DNS self-test against the configured local Unbound listener."""
	def _query_local_unbound(server_ip: str, qname: str = "cloudflare.com", timeout: float = 2.0) -> tuple[bool, str]:
		try:
			ip_obj = ipaddress.ip_address(server_ip)
			family = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
			# Minimal DNS A query packet
			tid = os.urandom(2)  # Random transaction ID to prevent spoofing
			flags = b"\x01\x00"  # recursion desired
			qdcount = b"\x00\x01"
			header = tid + flags + qdcount + b"\x00\x00\x00\x00\x00\x00"
			labels = qname.strip(".").split(".")
			qname_wire = b"".join(bytes([len(lbl)]) + lbl.encode("ascii", errors="ignore") for lbl in labels) + b"\x00"
			question = qname_wire + b"\x00\x01\x00\x01"  # A IN
			packet = header + question

			with socket.socket(family, socket.SOCK_DGRAM) as s:
				s.settimeout(timeout)
				target = (server_ip, 53, 0, 0) if family == socket.AF_INET6 else (server_ip, 53)
				s.sendto(packet, target)
				data, _ = s.recvfrom(2048)
				if len(data) < 12:
					return False, "short DNS response"
				if data[:2] != tid:
					return False, "mismatched DNS transaction"
				if not (data[2] & 0x80):
					return False, "not a DNS response"
				rcode = data[3] & 0x0F
				ancount = int.from_bytes(data[6:8], "big")
				if rcode != 0:
					return False, f"dns rcode={rcode}"
				if ancount == 0:
					return False, "no answers in response"
				return True, "ok"
		except socket.timeout:
			return False, "query timeout"
		except OSError as exc:
			return False, f"network error: {exc}"

	try:
		running = await unbound.is_running()
		if not running:
			data = {"running": False, "reachable": False, "detail": "unbound not running"}
			return ok_response(data=data)

		ipv4_gateways, ipv6_gateways = _collect_listen_addresses(conn)
		target_ip = ipv4_gateways[0] if ipv4_gateways else (ipv6_gateways[0] if ipv6_gateways else None)
		if not target_ip:
			data = {"running": True, "reachable": False, "detail": "no DNS listen address configured"}
			return ok_response(data=data)

		# Offload blocking socket I/O to a thread to avoid blocking the event loop
		ok, detail = await asyncio.to_thread(_query_local_unbound, target_ip)
		data = {"running": True, "reachable": ok, "detail": detail}
		return ok_response(data=data)
	except FileNotFoundError:
		raise HTTPException(status_code=503, detail="Unbound not installed")
	except Exception as exc:
		_log.exception("DNS selftest failed")
		data = {"running": False, "reachable": False, "detail": f"selftest failed: {exc}"}
		return ok_response(data=data)


@router.get("/trend")
async def dns_trend(
	hours: int = Query(24, ge=1, le=8760),
	bucket_minutes: int = Query(60, ge=5, le=10080),
	client_ips: str | None = Query(None, description="Comma-separated client IPs to filter by"),
	dns_dir: Path = Depends(get_dns_dir),
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Return DNS total/blocked trend buckets for charts.
	
	Data source: TSDB aggregated metrics (preferred) or JSONL raw logs (fallback).
	TSDB provides O(1) reads of pre-aggregated minute buckets vs O(n) JSONL scans.
	"""
	client_filter, client_filter_key = _parse_client_ip_filter(client_ips)
	
	dns_key = str(dns_dir.resolve())
	cache_key = (dns_key, hours, bucket_minutes, client_filter_key)
	now_mono = time.monotonic()
	cache_entry = _dns_trend_cache.get(cache_key)
	
	# Fast path: fresh cache hit
	if cache_entry and (now_mono - cache_entry[0]) < _DNS_TREND_CACHE_TTL_SECONDS:
		return ok_response(data=cache_entry[1])
	
	# Thundering-herd protection: if another request is already computing,
	# serve stale data immediately instead of blocking on the lock.
	if _dns_trend_lock.locked():
		if cache_entry and (now_mono - cache_entry[0]) < _DNS_TREND_CACHE_STALE_TTL_SECONDS:
			return ok_response(data=cache_entry[1])
	
	async with _dns_trend_lock:
		# Re-check after acquiring lock (another request may have refreshed)
		cache_entry = _dns_trend_cache.get(cache_key)
		now_mono = time.monotonic()
		if cache_entry and (now_mono - cache_entry[0]) < _DNS_TREND_CACHE_TTL_SECONDS:
			return ok_response(data=cache_entry[1])
		
		# Use TSDB for unfiltered queries (fast path), JSONL for client-filtered queries
		# TSDB stores aggregated totals; client filtering requires raw JSONL scan
		if client_filter is None:
			data = await _compute_trend_data_tsdb(tsdb_dir, hours, bucket_minutes)
			# Fallback to JSONL if TSDB returns no data (e.g., fresh install, no TSDB yet)
			if not data or sum(data.get("total", [])) == 0:
				data = await _compute_trend_data(dns_dir, hours, bucket_minutes, client_filter)
		else:
			data = await _compute_trend_data(dns_dir, hours, bucket_minutes, client_filter)
		
		# LRU eviction: remove oldest entries if cache is full
		while len(_dns_trend_cache) >= _DNS_TREND_CACHE_MAX_SIZE:
			_dns_trend_cache.popitem(last=False)
		_dns_trend_cache[cache_key] = (time.monotonic(), data)
		return ok_response(data=data)


async def _compute_trend_data(
	dns_dir: Path,
	hours: int,
	bucket_minutes: int,
	client_filter: set[str] | None,
) -> dict:
	"""Heavy computation for trend data — runs under lock."""
	now = datetime.now(timezone.utc)
	since = now - timedelta(hours=hours)

	def _bucket_start(ts: datetime) -> datetime:
		# Floor to bucket boundary in absolute UTC minutes (works for 5..1440+).
		ts = ts.astimezone(timezone.utc).replace(second=0, microsecond=0)
		epoch_minutes = int(ts.timestamp() // 60)
		bucket_epoch_minutes = (epoch_minutes // bucket_minutes) * bucket_minutes
		return datetime.fromtimestamp(bucket_epoch_minutes * 60, tz=timezone.utc)

	# Scale read window to requested horizon to reduce needless JSONL parsing.
	estimated_limit = min(100_000, max(5_000, hours * 5_000))
	queries = await asyncio.to_thread(
		dns_ingestion.read_recent_queries,
		dns_dir,
		estimated_limit,
		None,
		since,
	)
	buckets: dict[datetime, dict[str, int]] = {}

	for q in queries:
		ts = _parse_tsdb_timestamp(str(q.get("ts", "")))
		if ts is None:
			continue
		if ts < since:
			continue
		# Apply client IP filter if specified without expanding the raw scan window.
		if client_filter and q.get("client") not in client_filter:
			continue

		bucket_ts = _bucket_start(ts)
		if bucket_ts not in buckets:
			buckets[bucket_ts] = {"total": 0, "blocked": 0}
		buckets[bucket_ts]["total"] += 1
		if bool(q.get("blocked", False)):
			buckets[bucket_ts]["blocked"] += 1

	# Fill empty buckets so charts have a complete continuous timeline.
	start_bucket = _bucket_start(since)
	end_bucket = _bucket_start(now)
	step = timedelta(minutes=bucket_minutes)

	labels: list[str] = []
	total: list[int] = []
	blocked: list[int] = []
	cursor = start_bucket
	while cursor <= end_bucket:
		labels.append(cursor.isoformat())
		counts = buckets.get(cursor, {"total": 0, "blocked": 0})
		total.append(counts["total"])
		blocked.append(counts["blocked"])
		cursor += step

	block_rate = [
		round((b / t) * 100, 1) if t else 0.0
		for b, t in zip(blocked, total)
	]

	return {
		"hours": hours,
		"bucket_minutes": bucket_minutes,
		"labels": labels,
		"total": total,
		"blocked": blocked,
		"block_rate": block_rate,
	}


async def _compute_trend_data_tsdb(
	tsdb_dir: Path,
	hours: int,
	bucket_minutes: int,
) -> dict:
	"""Compute trend data from TSDB pre-aggregated minute buckets.
	
	Queries two separate counter metrics:
	- queries_total: total DNS queries per minute
	- queries_blocked: blocked DNS queries per minute
	
	Performance: O(n) where n = number of minute buckets in time range,
	vs O(m) where m = number of raw queries for JSONL approach.
	For 720h query: ~43,200 minute buckets vs potentially millions of raw queries.
	"""
	now = datetime.now(timezone.utc)
	since = now - timedelta(hours=hours)

	def _bucket_start(ts: datetime) -> datetime:
		# Floor to bucket boundary in absolute UTC minutes
		ts = ts.astimezone(timezone.utc).replace(second=0, microsecond=0)
		epoch_minutes = int(ts.timestamp() // 60)
		bucket_epoch_minutes = (epoch_minutes // bucket_minutes) * bucket_minutes
		return datetime.fromtimestamp(bucket_epoch_minutes * 60, tz=timezone.utc)

	# Query TSDB for both counter metrics in parallel
	# Limit = exact upper bound for minute buckets in time range + safety margin
	tsdb_limit = hours * 60 + 100
	total_points, blocked_points = await asyncio.gather(
		asyncio.to_thread(
			tsdb.query,
			tsdb_dir,
			peer_key=DNS_STATS_PEER_KEY,
			metric=DNS_METRIC_TOTAL,
			since=since,
			until=now,
			limit=tsdb_limit,
		),
		asyncio.to_thread(
			tsdb.query,
			tsdb_dir,
			peer_key=DNS_STATS_PEER_KEY,
			metric=DNS_METRIC_BLOCKED,
			since=since,
			until=now,
			limit=tsdb_limit,
		),
	)

	# Re-aggregate minute buckets to requested bucket_minutes
	buckets: dict[datetime, dict[str, int]] = {}
	
	for point in total_points:
		if point.ts < since:
			continue
		bucket_ts = _bucket_start(point.ts)
		if bucket_ts not in buckets:
			buckets[bucket_ts] = {"total": 0, "blocked": 0}
		# point.value is an integer counter
		if isinstance(point.value, (int, float)):
			buckets[bucket_ts]["total"] += int(point.value)
	
	for point in blocked_points:
		if point.ts < since:
			continue
		bucket_ts = _bucket_start(point.ts)
		if bucket_ts not in buckets:
			buckets[bucket_ts] = {"total": 0, "blocked": 0}
		if isinstance(point.value, (int, float)):
			buckets[bucket_ts]["blocked"] += int(point.value)

	# Fill empty buckets for continuous timeline
	start_bucket = _bucket_start(since)
	end_bucket = _bucket_start(now)
	step = timedelta(minutes=bucket_minutes)

	labels: list[str] = []
	total: list[int] = []
	blocked: list[int] = []
	cursor = start_bucket
	while cursor <= end_bucket:
		labels.append(cursor.isoformat())
		counts = buckets.get(cursor, {"total": 0, "blocked": 0})
		total.append(counts["total"])
		blocked.append(counts["blocked"])
		cursor += step

	block_rate = [
		round((b / t) * 100, 1) if t else 0.0
		for b, t in zip(blocked, total)
	]

	return {
		"hours": hours,
		"bucket_minutes": bucket_minutes,
		"labels": labels,
		"total": total,
		"blocked": blocked,
		"block_rate": block_rate,
	}


# ---------------------------------------------------------------------------
# Service Control
# ---------------------------------------------------------------------------

@router.post("/start")
async def dns_start(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Start the DNS resolver."""
	_require_unbound_installed()
	
	# Check if any WireGuard interfaces exist (Unbound needs interface IPs to bind)
	interfaces = list_interfaces(conn)
	if not interfaces:
		raise HTTPException(
			status_code=400,
			detail="Cannot start DNS: no WireGuard interfaces configured. Create an interface first."
		)
	try:
		ok, msg = await unbound.start()
	except FileNotFoundError:
		raise HTTPException(status_code=503, detail="Unbound not installed")
	if not ok:
		raise HTTPException(status_code=500, detail=msg)
	set_dns_service_enabled(conn, True)
	return ok_response(message=msg)


@router.post("/stop")
async def dns_stop(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Stop the DNS resolver."""
	_require_unbound_installed()
	
	try:
		ok, msg = await unbound.stop()
	except FileNotFoundError:
		raise HTTPException(status_code=503, detail="Unbound not installed")
	if not ok:
		raise HTTPException(status_code=500, detail=msg)
	set_dns_service_enabled(conn, False)
	return ok_response(message=msg)


@router.post("/restart")
async def dns_restart(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Restart the DNS resolver."""
	_require_unbound_installed()
	
	try:
		ok, msg = await unbound.restart()
	except FileNotFoundError:
		raise HTTPException(status_code=503, detail="Unbound not installed")
	if not ok:
		raise HTTPException(status_code=500, detail=msg)
	set_dns_service_enabled(conn, True)
	return ok_response(message=msg)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@router.get("/config")
async def get_dns_config(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get persisted DNS configuration used by Unbound + DNS ingestion."""
	dnssec_enabled = get_dnssec_enabled(conn)
	dnssec_available = unbound.is_dnssec_available()
	retention_days = get_dns_log_retention_days(conn)

	data = {
		"enable_logging": get_dns_query_logging_enabled(conn),
		"enable_blocklist": get_dns_blocklist_enabled(conn),
		"upstream_dns": get_dns_upstream_servers(conn),
		"dnssec_enabled": dnssec_enabled,
		"dnssec_available": dnssec_available,
		"dnssec_active": dnssec_enabled and dnssec_available,
		"log_retention_days": retention_days,
	}
	return ok_response(data=data)


@router.post("/config")
async def update_dns_config(
	payload: DnsConfigUpdate,
	conn: sqlite3.Connection = Depends(get_conn),
	dns_dir: Path = Depends(get_dns_dir),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Update DNS resolver configuration and reload.
	
	Only explicitly provided fields will be updated.
	
	Performance optimization: If ONLY enable_blocklist is changed, the response
	is returned immediately after DB update and peer-tag regeneration, while
	the Unbound config reload happens in the background. This improves UX
	responsiveness for the common ad-blocker toggle use case.
	"""
	# Guard: Cannot enable blocklist without Unbound installed
	if payload.enable_blocklist is True:
		_require_unbound_installed()
	
	# Validate conflicting fields early
	if payload.enable_logging is not None and payload.log_retention_days is not None:
		if payload.enable_logging and payload.log_retention_days == 0:
			raise HTTPException(
				status_code=422,
				detail="Cannot enable logging with 0 retention days"
			)
		if not payload.enable_logging and payload.log_retention_days > 0:
			raise HTTPException(
				status_code=422,
				detail="Cannot disable logging while setting retention days > 0"
			)
	
	try:
		# Load current persisted settings first.
		enable_logging = get_dns_query_logging_enabled(conn)
		enable_blocklist = get_dns_blocklist_enabled(conn)
		upstream_dns = get_dns_upstream_servers(conn)
		dnssec_enabled = get_dnssec_enabled(conn)
		retention_days = get_dns_log_retention_days(conn)
		retention_result = {"deleted_files": 0, "remaining_files": 0}

		if payload.enable_logging is True and payload.log_retention_days is None and retention_days == 0:
			raise HTTPException(
				status_code=422,
				detail="Cannot enable logging when retention is 0 days. Set log_retention_days > 0 first.",
			)

		# Detect if ONLY enable_blocklist is being changed (fast path)
		is_blocklist_only_change = (
			payload.enable_blocklist is not None
			and payload.enable_logging is None
			and payload.upstream_dns is None
			and payload.dnssec_enabled is None
			and payload.log_retention_days is None
		)

		# Apply explicit updates and persist.
		if payload.enable_logging is not None:
			enable_logging = payload.enable_logging
			set_dns_query_logging_enabled(conn, enable_logging)
		if payload.enable_blocklist is not None:
			enable_blocklist = payload.enable_blocklist
			set_dns_blocklist_enabled(conn, enable_blocklist)
			# Regenerate peer tags so blocking takes effect immediately (thread-safe)
			from ..utils.config import get_config
			await asyncio.to_thread(_regenerate_peer_tags_safe, str(get_config().db_path))
		if payload.upstream_dns is not None:
			upstream_dns = payload.upstream_dns
			set_dns_upstream_servers(conn, upstream_dns)
		if payload.dnssec_enabled is not None:
			dnssec_enabled = payload.dnssec_enabled
			set_dnssec_enabled(conn, dnssec_enabled)
		if payload.log_retention_days is not None:
			retention_days = payload.log_retention_days
			set_dns_log_retention_days(conn, retention_days)
			# Keep logging state explicitly user-controlled; only auto-derive when
			# enable_logging was not part of the current request.
			if payload.enable_logging is None:
				enable_logging = retention_days > 0
				set_dns_query_logging_enabled(conn, enable_logging)
			retention_result = await asyncio.to_thread(
				dns_ingestion.enforce_dns_log_retention,
				dns_dir,
				retention_days,
			)

		# Fast path: For blocklist-only changes, return immediately and reload in background
		if is_blocklist_only_change:
			# Schedule background config reload (peer-tags already written above)
			_spawn_background_task(
				_background_reload_for_blocklist(enable_blocklist),
				name="dns-blocklist-reload",
			)
			dnssec_available = unbound.is_dnssec_available()
			response_data = {
				"reloaded": None,  # Background reload in progress
				"enable_logging": enable_logging,
				"enable_blocklist": enable_blocklist,
				"upstream_dns": upstream_dns,
				"dnssec_enabled": dnssec_enabled,
				"dnssec_available": dnssec_available,
				"dnssec_active": dnssec_enabled and dnssec_available,
				"log_retention_days": retention_days,
				"retention": retention_result,
			}
			return ok_response(
				message="Adblocker configuration saved (reloading in background)",
				data=response_data,
			)

		# Standard path: Write full config and wait for reload
		# Bind ONLY to WireGuard interface IPs to avoid conflicts with host DNS
		# when running in Docker host network mode.
		ipv4_gateways, ipv6_gateways = _collect_listen_addresses(conn)
		unbound.write_config(
			enable_logging=enable_logging,
			enable_blocklist=enable_blocklist,
			upstream_dns=upstream_dns,
			enable_dnssec=dnssec_enabled,
			listen_addrs_ipv4=ipv4_gateways,
			listen_addrs_ipv6=ipv6_gateways,
		)
		ok, msg = await unbound.reload_config()
		dnssec_available = unbound.is_dnssec_available()
		response_data = {
			"reloaded": ok,
			"enable_logging": enable_logging,
			"enable_blocklist": enable_blocklist,
			"upstream_dns": upstream_dns,
			"dnssec_enabled": dnssec_enabled,
			"dnssec_available": dnssec_available,
			"dnssec_active": dnssec_enabled and dnssec_available,
			"log_retention_days": retention_days,
			"retention": retention_result,
		}
		if not ok:
			_log.warning("DNS config reload failed: %s", msg)
			# Config is written but unbound not reloaded
			return ok_response(
				message="Configuration saved but reload failed",
				data={**response_data, "error": msg},
			)
		return ok_response(
			message="Configuration updated and reloaded",
			data=response_data,
		)
	except FileNotFoundError:
		raise HTTPException(status_code=503, detail="Unbound not installed")
	except HTTPException:
		raise
	except (OSError, sqlite3.Error, RuntimeError, ValueError) as e:
		_log.exception("DNS config update failed")
		raise HTTPException(
			status_code=500,
			detail=f"DNS configuration update failed: {type(e).__name__}"
		)


# ---------------------------------------------------------------------------
# Blocklist
# ---------------------------------------------------------------------------

@router.get("/blocklist/sources")
async def get_blocklist_sources(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get available blocklist sources and which are enabled."""
	enabled = get_enabled_blocklists(conn)
	enabled_normalized = {str(url).strip() for url in enabled if str(url).strip()}
	source_counts = await asyncio.to_thread(unbound.get_blocklist_source_counts)
	
	# Get combined blocklist file stats if available
	# Note: This is the merged blocklist from all enabled sources
	blocklist_updated = None
	combined_blocklist_size = None
	blocklist_path = dns_constants.get_blocklist_file()
	if blocklist_path.exists():
		try:
			stat = blocklist_path.stat()
			blocklist_updated = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).strftime("%Y-%m-%d")
			# Format size
			size_bytes = stat.st_size
			if size_bytes < 1024:
				combined_blocklist_size = f"{size_bytes} B"
			elif size_bytes < 1024 * 1024:
				combined_blocklist_size = f"{size_bytes // 1024} KB"
			else:
				combined_blocklist_size = f"{size_bytes // (1024 * 1024)} MB"
		except Exception:
			_log.debug("Could not read blocklist file stats", exc_info=True)
	
	# Build sources from registry with enabled status
	sources = []
	for bid, meta in dns_constants.BLOCKLIST_REGISTRY.items():
		is_enabled = str(meta["url"]).strip() in enabled_normalized
		
		sources.append({
			"id": bid,
			"url": meta["url"],
			"name": meta["name"],
			"description": meta["description"],
			"level": meta.get("level", ""),
			"domains": source_counts.get(bid, 0),
			"last_updated": blocklist_updated if is_enabled else "—",
			"enabled": is_enabled,
		})

	data = {"sources": sources, "rebuild_in_progress": _rebuild_in_progress}
	return ok_response(data=data)


@router.post("/blocklist/sources")
async def set_blocklist_sources(
	payload: BlocklistSourcesUpdate,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Save enabled blocklist sources and trigger background update."""
	# Guard: Cannot enable blocklists without Unbound installed
	if payload.urls:
		_require_unbound_installed()
	
	set_enabled_blocklists(conn, payload.urls)
	
	# Auto-toggle ad-blocker based on blocklist selection:
	# - No blocklists selected → disable ad-blocker
	# - Blocklists selected but ad-blocker off → enable ad-blocker
	if not payload.urls:
		set_dns_blocklist_enabled(conn, False)
		_log.info("DNS_ADBLOCKER auto-disabled: no blocklists selected")
	elif not get_dns_blocklist_enabled(conn):
		set_dns_blocklist_enabled(conn, True)
		_log.info("DNS_ADBLOCKER auto-enabled: blocklists selected")
	
	# Global blocklist selection must override peer-specific selections immediately.
	try:
		from ..utils.config import get_config
		await asyncio.to_thread(_regenerate_peer_tags_safe, str(get_config().db_path))
	except Exception as exc:
		_log.warning("Failed to regenerate peer tags after global blocklist change: %s", exc)
	
	# Capture DB-derived values before spawning background task (request-scoped
	# connection may be closed once this handler returns).
	custom_rules_text = get_dns_custom_rules(conn)
	urls_copy = list(payload.urls)
	adblocker_enabled = get_dns_blocklist_enabled(conn)
	
	# Queue rebuild (prevents concurrent rebuilds)
	await _queue_rebuild(urls_copy, custom_rules_text)
	
	return ok_response(
		message="Blocklist update started" if payload.urls else "Blocklist cleared",
		data={
			"enabled_count": len(payload.urls),
			"started": True,
			"adblocker_enabled": adblocker_enabled,
		},
	)


@router.post("/blocklist/update")
async def update_blocklists(
	payload: BlocklistUpdate | None = None,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Trigger background download and update of ad-blocking lists."""
	_require_unbound_installed()
	
	# Use saved blocklists if no URLs provided
	urls = payload.urls if payload and payload.urls else None
	if urls is None:
		urls = get_enabled_blocklists(conn)
	
	# Capture DB-derived values before spawning background task.
	custom_rules_text = get_dns_custom_rules(conn)
	urls_copy = list(urls) if urls else []
	
	# Queue rebuild
	await _queue_rebuild(urls_copy, custom_rules_text)
	
	return ok_response(
		message="Blocklist update queued",
		data={"started": True, "queued": True},
	)


@router.get("/blocklist/count")
async def blocklist_count(_: sqlite3.Row = Depends(get_current_user)):
	"""Get the number of domains in the blocklist."""
	count = await asyncio.to_thread(unbound.get_blocklist_count)
	return ok_response(data={"count": count})


# ---------------------------------------------------------------------------
# Custom DNS Rules
# ---------------------------------------------------------------------------

def _append_action_rule(
	rules_text: str,
	*,
	action: Literal["block", "unblock"],
	scope: Literal["global", "client"],
	domain: str,
	client: str | None,
	client_name: str | None = None,
) -> tuple[str, str, bool, bool]:
	"""Append one canonical exact-domain rule.

	Returns:
		(updated_text, canonical_rule, created, duplicate)
	"""
	rule_action = RuleAction.BLOCK if action == "block" else RuleAction.ALLOW
	client_scope = client if scope == "client" else None
	canonical = canonical_rule_text(rule_action, domain, client_scope)
	opposite = canonical_rule_text(
		RuleAction.ALLOW if rule_action == RuleAction.BLOCK else RuleAction.BLOCK,
		domain,
		client_scope,
	)

	lines = rules_text.splitlines()
	seen = {line.strip().lower() for line in lines if line.strip()}
	if canonical.lower() in seen:
		return rules_text, canonical, False, True

	# Remove exact opposite canonical rule so user intent is deterministic.
	filtered_lines: list[str] = []
	for line in lines:
		if line.strip().lower() == opposite.lower():
			continue
		filtered_lines.append(line)

	if scope == "client" and client_scope and client_name:
		filtered_lines.append(f"! client: {client_name} ({client_scope})")

	# Keep file tidy: ensure exactly one trailing newline when non-empty.
	filtered_lines.append(canonical)
	updated_text = "\n".join(filtered_lines).strip("\n") + "\n"
	return updated_text, canonical, True, False


async def _rebuild_dns_from_rules(conn: sqlite3.Connection, rules_text: str) -> tuple[bool, int, str]:
	"""Regenerate blocklist + client overrides and restart Unbound."""
	urls = get_enabled_blocklists(conn)
	count, msg = await unbound.update_blocklists(urls, custom_rules_text=rules_text)
	reloaded, _ = await unbound.restart()
	return reloaded, count, msg


async def _rebuild_dns_background(urls: list[str], rules_text: str) -> None:
	"""Background task to rebuild blocklist + restart Unbound (fire-and-forget)."""
	global _rebuild_in_progress
	_rebuild_in_progress = True
	try:
		count, msg = await unbound.update_blocklists(urls, custom_rules_text=rules_text)
		reloaded, _ = await unbound.restart()
		_log.info("DNS_BACKGROUND rebuild complete: %s domains, reloaded=%s, %s", count, reloaded, msg)
	except Exception:
		_log.exception("DNS_BACKGROUND rebuild failed")
	finally:
		_rebuild_in_progress = False


async def _rebuild_worker() -> None:
	"""Background worker: processes rebuilds serially using latest-wins pattern.
	
	Instead of a fixed-size queue that drops requests, this worker uses an event
	and a shared variable. Multiple requests simply overwrite _rebuild_latest,
	ensuring the final state is always processed.
	"""
	global _rebuild_latest, _rebuild_event
	if _rebuild_event is None:
		_rebuild_event = asyncio.Event()
	
	while True:
		try:
			await _rebuild_event.wait()
			_rebuild_event.clear()
			work = _rebuild_latest
			_rebuild_latest = None
			if work:
				await _rebuild_dns_background(*work)
		except asyncio.CancelledError:
			_log.debug("DNS_REBUILD_WORKER shutdown requested")
			raise
		except Exception:
			_log.exception("DNS_REBUILD_WORKER unexpected error")


def _ensure_rebuild_worker() -> None:
	"""Ensure rebuild worker is running."""
	global _rebuild_worker_task, _rebuild_event
	if _rebuild_event is None:
		_rebuild_event = asyncio.Event()
	if _rebuild_worker_task is None or _rebuild_worker_task.done():
		_rebuild_worker_task = asyncio.create_task(_rebuild_worker(), name="dns-rebuild-worker")


async def _queue_rebuild(urls: list[str], rules_text: str) -> bool:
	"""Queue a rebuild using latest-wins pattern. Always returns True.
	
	If a rebuild is in progress and another is pending, this overwrites the
	pending request so the most recent configuration is always applied.
	"""
	global _rebuild_latest, _rebuild_event
	_ensure_rebuild_worker()
	_rebuild_latest = (urls, rules_text)
	if _rebuild_event is not None:
		_rebuild_event.set()
	return True


async def shutdown_dns_tasks() -> None:
	"""Gracefully shutdown DNS background tasks.
	
	Call this from the FastAPI app shutdown handler to ensure clean teardown.
	"""
	global _rebuild_worker_task
	
	# Cancel rebuild worker
	if _rebuild_worker_task is not None and not _rebuild_worker_task.done():
		_rebuild_worker_task.cancel()
		try:
			await asyncio.wait_for(_rebuild_worker_task, timeout=2.0)
		except (asyncio.CancelledError, asyncio.TimeoutError):
			pass
		_rebuild_worker_task = None
	
	# Cancel any pending background tasks
	for task in list(_background_tasks):
		if not task.done():
			task.cancel()
	
	# Wait briefly for tasks to complete
	if _background_tasks:
		await asyncio.wait(_background_tasks, timeout=2.0)
	
	_log.debug("DNS background tasks shutdown complete")


@router.get("/custom-rules")
async def get_custom_rules(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get the current custom DNS rules text (read: any user, write: admin only)."""
	rules_text = get_dns_custom_rules(conn)
	# Validate / parse for display
	parsed, errors = parse_custom_rules(rules_text) if rules_text.strip() else ([], [])
	return ok_response(
		data={
			"rules": rules_text,
			"rule_count": len(parsed),
			"error_count": len(errors),
			"errors": [
				{"line": e.line, "text": e.text, "error": e.error}
				for e in errors
			],
		},
	)


@router.patch("/custom-rules")
async def update_custom_rules(
	payload: CustomRulesUpdate,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Save custom DNS rules and rebuild the blocklist.

	Rules use AdGuard syntax:
	  ||example.com^         Block domain + subdomains
	  @@||example.com^       Allow (whitelist override)
	  ||ads*.example.com^    Wildcard block
	  /regex/                Regex match
	  ! comment              Comment line
	"""
	_require_unbound_installed()
	
	rules_text = payload.rules

	# Parse and validate
	parsed, errors = parse_custom_rules(rules_text) if rules_text.strip() else ([], [])

	# Persist regardless of errors (user may want to save work-in-progress)
	set_dns_custom_rules(conn, rules_text)

	# Queue rebuild (serial processing prevents concurrent interference)
	urls = get_enabled_blocklists(conn)
	await _queue_rebuild(urls, rules_text)

	# Return immediately - rebuild happens in background
	return ok_response(
		message="Custom rules saved. Blocklist update in progress.",
		data={
			"rules": rules_text,
			"rule_count": len(parsed),
			"error_count": len(errors),
			"errors": [
				{"line": e.line, "text": e.text, "error": e.error}
				for e in errors
			],
			"domains_blocked": None,  # Unknown until rebuild completes
			"reloaded": None,  # Pending
		},
	)


@router.post("/custom-rules/actions")
async def add_custom_rule_action(
	payload: CustomRuleActionRequest,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Add one exact-domain custom rule from Query Log actions.

	The endpoint enforces canonical form and prevents duplicate creation.
	"""
	_require_unbound_installed()
	
	if payload.scope == "client" and not payload.client:
		raise HTTPException(status_code=400, detail="Client scope requires a client address")

	rules_text = get_dns_custom_rules(conn)
	updated_rules, canonical, created, duplicate = _append_action_rule(
		rules_text,
		action=payload.action,
		scope=payload.scope,
		domain=payload.domain,
		client=payload.client,
		client_name=payload.client_name,
	)

	if duplicate:
		return ok_response(
			message="Rule already exists",
			data={
				"created": False,
				"duplicate": True,
				"rule": canonical,
			},
		)

	set_dns_custom_rules(conn, updated_rules)

	# Route through the rebuild queue to prevent race conditions with concurrent rebuilds
	urls = get_enabled_blocklists(conn)
	await _queue_rebuild(list(urls), updated_rules)
	
	return ok_response(
		message="Rule applied, rebuild queued",
		data={
			"created": created,
			"duplicate": False,
			"rule": canonical,
			"reloaded": None,  # Rebuild happens in background
		},
	)


# ---------------------------------------------------------------------------
# Query Log
# ---------------------------------------------------------------------------

@router.get("/logs")
async def dns_logs(
	lines: int = 200,
	client_ips: str | None = Query(None, description="Comma-separated client IPs to filter by"),
	dns_dir: Path = Depends(get_dns_dir),
	conn: sqlite3.Connection = Depends(get_conn),
	user_row: sqlite3.Row = Depends(get_current_user),
):
	"""Get recent DNS query log entries.

	Returns the most recent queries with blocked status from TSDB.
	For non-admin users, client-identifying fields are obfuscated.
	Client names are resolved from peer_address→name mapping.
	"""
	lines = min(max(lines, 10), 5000)
	client_filter, _ = _parse_client_ip_filter(client_ips)
	queries = await asyncio.to_thread(
		dns_ingestion.read_recent_queries,
		dns_dir,
		lines,
		client_filter,
	)
	is_admin = bool(user_row["is_admin"])
	masked = "*****"

	# Build peer IP→name mapping for client name resolution
	# peer_address can be dual-stack: "10.13.13.2/32, fd13:13:13::2/128"
	peer_ip_map: dict[str, str] = {}
	for peer in get_all_peers(conn):
		addr = peer["peer_address"]
		name = peer["name"]
		if addr and name:
			for part in str(addr).split(","):
				part = part.strip()
				if not part:
					continue
				# Strip CIDR suffix (e.g., 10.13.13.2/32 → 10.13.13.2)
				client_ip = parse_ip_str(part.split("/")[0].strip()) or part.split("/")[0].strip()
				if client_ip:
					peer_ip_map[client_ip] = name

	def _normalize_client_ip(value: str) -> str:
		"""Return canonical client IP text for matching/display."""
		return parse_ip_str(value) or str(value or "").strip()

	def _format_client(client_ip: str) -> str:
		"""Format client display: 'PeerName (IP)' or just 'IP'."""
		normalized_ip = _normalize_client_ip(client_ip)
		peer_name = peer_ip_map.get(normalized_ip)
		if peer_name:
			return f"{peer_name} ({normalized_ip})"
		return normalized_ip

	data = {
		"queries": [
			{
				"timestamp": _format_tsdb_timestamp(str(q.get("ts", ""))),
				"client": _format_client(str(q.get("client", ""))) if is_admin else masked,
				"client_name": peer_ip_map.get(_normalize_client_ip(str(q.get("client", ""))), "") if is_admin else masked,
				"domain": str(q.get("domain", "")),
				"type": str(q.get("qtype", "")),
				"blocked": bool(q.get("blocked", False)),
				"custom_rule": bool(q.get("custom_rule", False)),
			}
			for q in queries  # read_recent_queries() already returns newest first
			],
		"total": len(queries),
	}
	return ok_response(data=data)


@router.get("/top-domains")
async def top_domains(
	limit: int = Query(20, ge=1, le=100),
	hours: int | None = Query(None, ge=1, le=8760, description="Optional time window in hours for top domains"),
	client_ips: str | None = Query(None, description="Comma-separated client IPs to filter by"),
	dns_dir: Path = Depends(get_dns_dir),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get top queried and blocked domains."""
	client_filter, _ = _parse_client_ip_filter(client_ips)
	query_limit = 50000 if hours is None else min(100_000, max(5_000, hours * 5_000))
	since = datetime.now(timezone.utc) - timedelta(hours=hours) if hours is not None else None
	queries = await asyncio.to_thread(
		dns_ingestion.read_recent_queries,
		dns_dir,
		query_limit,
		None,
		since,
	)
	domain_counts: dict[str, int] = {}
	blocked_counts: dict[str, int] = {}

	for q in queries:
		if client_filter and q.get("client") not in client_filter:
			continue
		domain = str(q.get("domain", "")).strip()
		if not domain:
			continue
		domain_counts[domain] = domain_counts.get(domain, 0) + 1
		if bool(q.get("blocked", False)):
			blocked_counts[domain] = blocked_counts.get(domain, 0) + 1

	sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
	sorted_blocked = sorted(blocked_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

	data = {
		"top_queried": [{"domain": d, "count": c} for d, c in sorted_domains],
		"top_blocked": [{"domain": d, "count": c} for d, c in sorted_blocked],
	}
	return ok_response(data=data)


# ---------------------------------------------------------------------------
# DNS Server Validation
# ---------------------------------------------------------------------------

class DnsTestRequest(BaseModel):
	"""Request body for testing upstream DNS servers."""
	servers: list[str]


def _test_dot_server(addr: str, timeout: float = 5.0) -> dict:
	"""Test a single DoT server for connectivity and valid response.
	
	Returns dict with 'server', 'success', 'error', 'latency_ms'.
	"""
	result = {"server": addr, "success": False, "error": None, "latency_ms": None}
	
	# Parse IP@port#hostname
	match = _DNS_PATTERN.match(addr.strip())
	if not match:
		result["error"] = "Invalid format (expected IP@port#hostname)"
		return result
	
	ip_part = _normalize_ip_literal(match.group(1))
	port_part = match.group(2)
	hostname_part = match.group(3)
	
	if not hostname_part:
		result["error"] = "Hostname required for DoT (IP@port#hostname)"
		return result
	
	try:
		ip_obj = ipaddress.ip_address(ip_part)
	except ValueError:
		result["error"] = f"Invalid IP address: {ip_part}"
		return result
	
	# Unwrap IPv4-mapped IPv6 to check the real address (SSRF protection)
	# On Python < 3.11, ::ffff:127.0.0.1 reports is_loopback=False
	check_ip = ip_obj
	if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
		check_ip = ip_obj.ipv4_mapped
	
	if (
		check_ip.is_private
		or check_ip.is_loopback
		or check_ip.is_link_local
		or check_ip.is_reserved
		or check_ip.is_multicast
		or check_ip.is_unspecified
	):
		result["error"] = "Private/reserved addresses not allowed"
		return result
	
	port = int(port_part) if port_part else 853
	if port not in _ALLOWED_DOT_PORTS:
		result["error"] = f"Only DoT ports allowed: {sorted(_ALLOWED_DOT_PORTS)}"
		return result
	
	try:
		hostname = _normalize_hostname(hostname_part)
	except ValueError as e:
		result["error"] = str(e)
		return result
	
	# Build a minimal DNS query for "example.com" A record
	# Transaction ID (2 bytes) + Flags (2 bytes) + Questions (2 bytes) + 
	# Answer/Auth/Additional RRs (6 bytes) + Query
	transaction_id = os.urandom(2)
	flags = b'\x01\x00'  # Standard query, recursion desired
	questions = b'\x00\x01'
	answer_rrs = b'\x00\x00'
	authority_rrs = b'\x00\x00'
	additional_rrs = b'\x00\x00'
	# example.com query
	query_name = b'\x07example\x03com\x00'
	query_type = b'\x00\x01'  # A record
	query_class = b'\x00\x01'  # IN class
	
	dns_query = (
		transaction_id + flags + questions + answer_rrs + 
		authority_rrs + additional_rrs + query_name + query_type + query_class
	)
	
	# Prepend 2-byte length for TCP/TLS
	dns_message = struct.pack('>H', len(dns_query)) + dns_query
	
	try:
		start_time = time.monotonic()
		
		# Create SSL context for DoT
		context = ssl.create_default_context()
		context.check_hostname = True
		context.verify_mode = ssl.CERT_REQUIRED
		
		with socket.create_connection((str(ip_obj), port), timeout=timeout) as sock:
			with context.wrap_socket(sock, server_hostname=hostname) as ssock:
				ssock.sendall(dns_message)
				
				# Read response length (2 bytes)
				length_data = ssock.recv(2)
				if len(length_data) < 2:
					result["error"] = "No response from server"
					return result
				
				response_length = struct.unpack('>H', length_data)[0]
				
				# Read DNS response
				response = b''
				while len(response) < response_length:
					chunk = ssock.recv(response_length - len(response))
					if not chunk:
						break
					response += chunk
				
				end_time = time.monotonic()
				latency_ms = round((end_time - start_time) * 1000, 1)
				
				# Verify we got a valid DNS response (check transaction ID matches)
				if len(response) >= 12 and response[:2] == transaction_id:
					result["success"] = True
					result["latency_ms"] = latency_ms
				else:
					result["error"] = "Invalid DNS response"
					
	except ssl.SSLCertVerificationError as e:
		result["error"] = f"TLS certificate error: {e.verify_message}"
	except ssl.SSLError as e:
		result["error"] = f"TLS error: {str(e)}"
	except socket.timeout:
		result["error"] = "Connection timeout"
	except ConnectionRefusedError:
		result["error"] = "Connection refused"
	except OSError as e:
		result["error"] = f"Network error: {e.strerror or str(e)}"
	except Exception as e:
		result["error"] = f"Error: {str(e)}"
	
	return result


@router.post("/test-upstream")
async def test_upstream_dns(
	payload: DnsTestRequest,
	_: sqlite3.Row = Depends(require_admin),
):
	"""Test upstream DNS servers for connectivity and valid responses.
	
	Returns test results for each server including success status,
	latency, and any error messages.
	"""
	if not payload.servers:
		raise HTTPException(status_code=400, detail="No servers provided")
	
	if len(payload.servers) > 20:
		raise HTTPException(status_code=400, detail="Maximum 20 servers allowed")
	
	servers = [str(server).strip() for server in payload.servers if str(server).strip()]
	sem = asyncio.Semaphore(_DOT_TEST_CONCURRENCY)

	async def _run_test(server: str) -> dict:
		async with sem:
			return await asyncio.to_thread(_test_dot_server, server)

	results = await asyncio.gather(*[_run_test(server) for server in servers]) if servers else []
	
	all_success = all(r["success"] for r in results) if results else False
	failed_count = sum(1 for r in results if not r["success"])
	
	return ok_response(
		data={"results": results, "all_success": all_success, "failed_count": failed_count},
	)


@router.delete("/logs")
async def delete_dns_logs(
	dns_dir: Path = Depends(get_dns_dir),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Delete all DNS query log data (admin only)."""
	def _purge() -> int:
		base_dir = dns_dir.resolve()
		queries_dir = (dns_dir / "queries").resolve()
		try:
			queries_dir.relative_to(base_dir)
		except ValueError as exc:
			raise RuntimeError("Invalid queries directory") from exc
		if not queries_dir.exists():
			return 0
		if not queries_dir.is_dir():
			raise RuntimeError("Invalid queries directory")
		count = sum(1 for f in queries_dir.glob("*.jsonl"))
		shutil.rmtree(queries_dir)
		_log.info("DNS_LOGS_PURGE deleted %d log files", count)
		return count

	try:
		deleted = await asyncio.to_thread(_purge)
	except RuntimeError as exc:
		raise HTTPException(status_code=500, detail=str(exc)) from exc
	dns_key = str(dns_dir.resolve())
	_dns_status_cache.pop(dns_key, None)
	for key in [k for k in _dns_trend_cache if k[0] == dns_key]:
		_dns_trend_cache.pop(key, None)
	return ok_response(
		message=f"Deleted {deleted} DNS log files",
		data={"deleted": deleted},
	)


@router.get("/storage")
async def get_dns_storage_stats(
	dns_dir: Path = Depends(get_dns_dir),
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get DNS query log storage statistics."""
	def _stats() -> dict:
		queries_dir = dns_dir / "queries"
		if not queries_dir.exists():
			return {
				"size_bytes": 0,
				"file_count": 0,
			}
		total_size = 0
		file_count = 0
		for f in queries_dir.iterdir():
			if f.is_file() and f.suffix == ".jsonl":
				try:
					total_size += f.stat().st_size
					file_count += 1
				except OSError:
					pass
		return {
			"size_bytes": total_size,
			"file_count": file_count,
		}

	data = await asyncio.to_thread(_stats)
	data["retention_days"] = get_dns_log_retention_days(conn)
	data["path"] = str(dns_dir / "queries")
	return ok_response(data=data)


# ---------------------------------------------------------------------------
# Ad-Blocker Mode (enable / disable / timed disable)
# ---------------------------------------------------------------------------

_ADBLOCKER_MODES = {"enable", "disable", "disable_1h", "disable_today"}


class AdblockerModePayload(BaseModel):
	"""Request body for changing the ad-blocker mode."""
	mode: str

	@field_validator("mode")
	@classmethod
	def validate_mode(cls, v: str) -> str:
		v = v.strip().lower()
		if v not in _ADBLOCKER_MODES:
			raise ValueError(f"Invalid mode. Allowed: {sorted(_ADBLOCKER_MODES)}")
		return v


@router.get("/adblocker/status")
async def get_adblocker_status(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Return current ad-blocker state including any active timer."""
	enabled = get_dns_blocklist_enabled(conn)
	disabled_until = get_blocklist_disabled_until(conn)
	now = int(time.time())

	remaining = 0
	if disabled_until > now:
		remaining = disabled_until - now
	elif disabled_until > 0:
		# Timer expiry is handled by the scheduled adblocker timer task.
		# Keep this GET endpoint side-effect free.
		disabled_until = 0

	return ok_response(data={
		"enabled": enabled,
		"disabled_until": disabled_until,
		"remaining_seconds": remaining,
	})


@router.post("/adblocker/mode")
async def set_adblocker_mode(
	payload: AdblockerModePayload,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Change ad-blocker mode (admin only).

	Modes:
	- enable: enable immediately, clear any timer
	- disable: disable indefinitely, clear any timer
	- disable_1h: disable for 1 hour (server-side timer)
	- disable_today: disable until midnight local server time
	
	Performance: DB changes and peer-tags are applied immediately, then
	Unbound config reload happens in the background for fast response.
	"""
	_require_unbound_installed()

	mode = payload.mode
	now = int(time.time())

	if mode == "enable":
		set_dns_blocklist_enabled(conn, True)
		clear_blocklist_disabled_until(conn)
		from ..utils.config import get_config
		await asyncio.to_thread(_regenerate_peer_tags_safe, str(get_config().db_path))
		_spawn_background_task(
			_background_reload_for_blocklist(True),
			name="adblocker-mode-enable",
		)
		return ok_response(
			message="Ad-Blocker enabled",
			data={"enabled": True, "disabled_until": 0, "remaining_seconds": 0},
		)

	if mode == "disable":
		set_dns_blocklist_enabled(conn, False)
		clear_blocklist_disabled_until(conn)
		from ..utils.config import get_config
		await asyncio.to_thread(_regenerate_peer_tags_safe, str(get_config().db_path))
		_spawn_background_task(
			_background_reload_for_blocklist(False),
			name="adblocker-mode-disable",
		)
		return ok_response(
			message="Ad-Blocker disabled",
			data={"enabled": False, "disabled_until": 0, "remaining_seconds": 0},
		)

	# Timed disable modes
	if mode == "disable_1h":
		until = now + 3600
	else:  # disable_today
		# Compute end-of-day in server local time (23:59:59.999999)
		local_now = datetime.now().astimezone()
		end_of_day = local_now.replace(hour=23, minute=59, second=59, microsecond=999999)
		until = int(end_of_day.timestamp())
		# Ensure at least 60 seconds
		if until - now < 60:
			until = now + 60

	set_dns_blocklist_enabled(conn, False)
	set_blocklist_disabled_until(conn, until)
	from ..utils.config import get_config
	await asyncio.to_thread(_regenerate_peer_tags_safe, str(get_config().db_path))
	_spawn_background_task(
		_background_reload_for_blocklist(False),
		name="adblocker-mode-timed",
	)

	remaining = until - now
	label = f"{remaining // 3600}h {(remaining % 3600) // 60}m" if remaining >= 3600 else f"{remaining // 60}m"
	return ok_response(
		message=f"Ad-Blocker disabled for {label}",
		data={"enabled": False, "disabled_until": until, "remaining_seconds": remaining},
	)


# ---------------------------------------------------------------------------
# Custom Rules
# ---------------------------------------------------------------------------
