#!/usr/bin/env python3
#
# app/api/dns.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""DNS management API routes."""

from __future__ import annotations

from ..db.sqlite_interfaces import (
	list_interfaces,
)
from ..db.sqlite_settings import (
	DNS_LOG_RETENTION_OPTIONS,
	get_dns_blocklist_enabled,
	get_dns_log_retention_days,
	get_dns_query_logging_enabled,
	get_dns_upstream_servers,
	get_dnssec_enabled,
	get_enabled_blocklists,
	set_dns_blocklist_enabled,
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
import sqlite3
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from ..dns import ingestion as dns_ingestion
from ..dns import unbound
from ..utils.deps import get_conn, get_tsdb_dir
from .auth import get_current_user, require_admin
from .response import ok_response


_log = logging.getLogger(__name__)


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


router = APIRouter(tags=["dns"])

# Regex for DNS-over-TLS notation: IP@port#hostname
_DNS_PATTERN = re.compile(r"^([^@#]+)(?:@(\d+))?(?:#(.+))?$")
_HOST_LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")


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
		# Only allow HTTPS to prevent SSRF attacks
		if not url.startswith("https://"):
			raise ValueError(f"Blocklist URLs must use HTTPS: {url}")
		if len(url) > 2048:
			raise ValueError(f"URL too long: {url}")
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
			ip_part = match.group(1)
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


# ---------------------------------------------------------------------------
# Status & Stats
# ---------------------------------------------------------------------------

@router.get("/status")
async def dns_status(
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get DNS resolver status and statistics."""
	queries = await asyncio.to_thread(dns_ingestion.read_recent_queries, tsdb_dir, 50000)
	all_domains: set[str] = set()
	all_clients: set[str] = set()
	blocked_count = 0
	for q in queries:
		domain = str(q.get("domain", "")).strip()
		client = str(q.get("client", "")).strip()
		if domain:
			all_domains.add(domain)
		if client:
			all_clients.add(client)
		if bool(q.get("blocked", False)):
			blocked_count += 1

	unavailable = False
	reason = ""
	running = False
	try:
		running = await unbound.is_running()
	except FileNotFoundError:
		unavailable = True
		reason = "Unbound not installed (requires Docker)"
	except Exception as exc:
		_log.debug("DNS status running-check failed: %s", exc)

	try:
		blocklist_size = await asyncio.to_thread(unbound.get_blocklist_count)
	except Exception:
		blocklist_size = 0

	data = {
		"is_running": running,
		"total_queries": len(queries),
		"blocked_queries": blocked_count,
		"block_percentage": round(
			(blocked_count / len(queries) * 100) if queries else 0, 1
		),
		"unique_domains": len(all_domains),
		"unique_clients": len(all_clients),
		"blocklist_size": blocklist_size,
		"blocklist_updated_at": _blocklist_mtime(),
		"unavailable": unavailable,
		"reason": reason,
	}
	return ok_response(data=data, **data)


@router.get("/selftest")
async def dns_selftest(_: sqlite3.Row = Depends(get_current_user)):
	"""Run a lightweight DNS self-test against local Unbound."""
	def _query_local_unbound(qname: str = "cloudflare.com", timeout: float = 2.0) -> tuple[bool, str]:
		# Minimal DNS A query packet
		tid = os.urandom(2)  # Random transaction ID to prevent spoofing
		flags = b"\x01\x00"  # recursion desired
		qdcount = b"\x00\x01"
		header = tid + flags + qdcount + b"\x00\x00\x00\x00\x00\x00"
		labels = qname.strip(".").split(".")
		qname_wire = b"".join(bytes([len(lbl)]) + lbl.encode("ascii", errors="ignore") for lbl in labels) + b"\x00"
		question = qname_wire + b"\x00\x01\x00\x01"  # A IN
		packet = header + question

		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
			s.settimeout(timeout)
			s.sendto(packet, ("127.0.0.1", 53))
			data, _ = s.recvfrom(2048)
			if len(data) < 12:
				return False, "short DNS response"
			rcode = data[3] & 0x0F
			if rcode != 0:
				return False, f"dns rcode={rcode}"
			return True, "ok"

	try:
		running = await unbound.is_running()
		if not running:
			data = {"running": False, "reachable": False, "detail": "unbound not running"}
			return ok_response(data=data, **data)

		# Offload blocking socket I/O to a thread to avoid blocking the event loop
		ok, detail = await asyncio.to_thread(_query_local_unbound)
		data = {"running": True, "reachable": ok, "detail": detail}
		return ok_response(data=data, **data)
	except FileNotFoundError:
		raise HTTPException(status_code=503, detail="Unbound not installed (requires Docker)")
	except socket.timeout:
		data = {"running": True, "reachable": False, "detail": "query timeout"}
		return ok_response(data=data, **data)
	except Exception as exc:
		_log.exception("DNS selftest failed")
		data = {"running": False, "reachable": False, "detail": f"selftest failed: {exc}"}
		return ok_response(data=data, **data)


@router.get("/trend")
async def dns_trend(
	hours: int = 24,
	bucket_minutes: int = 60,
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Return DNS total/blocked trend buckets for charts.
	
	Data source: TSDB DNS query store (persisted across restarts).
	"""
	hours = min(max(hours, 1), 720)
	bucket_minutes = min(max(bucket_minutes, 5), 1440)
	now = datetime.now(timezone.utc)
	since = now - timedelta(hours=hours)

	def _bucket_start(ts: datetime) -> datetime:
		# Floor to bucket boundary in absolute UTC minutes (works for 5..1440+).
		ts = ts.astimezone(timezone.utc).replace(second=0, microsecond=0)
		epoch_minutes = int(ts.timestamp() // 60)
		bucket_epoch_minutes = (epoch_minutes // bucket_minutes) * bucket_minutes
		return datetime.fromtimestamp(bucket_epoch_minutes * 60, tz=timezone.utc)

	# Read a large tail window from TSDB so 30-day buckets remain complete.
	queries = await asyncio.to_thread(dns_ingestion.read_recent_queries, tsdb_dir, 100000)
	buckets: dict[datetime, dict[str, int]] = {}

	for q in queries:
		ts = _parse_tsdb_timestamp(str(q.get("ts", "")))
		if ts is None:
			continue
		if ts < since:
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

	data = {
		"hours": hours,
		"bucket_minutes": bucket_minutes,
		"labels": labels,
		"total": total,
		"blocked": blocked,
		"block_rate": block_rate,
	}
	return ok_response(data=data, **data)


# ---------------------------------------------------------------------------
# Service Control
# ---------------------------------------------------------------------------

@router.post("/start")
async def dns_start(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Start the DNS resolver."""
	try:
		ok, msg = await unbound.start()
	except FileNotFoundError:
		raise HTTPException(status_code=503, detail="Unbound not installed (requires Docker)")
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
	try:
		ok, msg = await unbound.stop()
	except FileNotFoundError:
		raise HTTPException(status_code=503, detail="Unbound not installed (requires Docker)")
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
	try:
		ok, msg = await unbound.restart()
	except FileNotFoundError:
		raise HTTPException(status_code=503, detail="Unbound not installed (requires Docker)")
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
	_: sqlite3.Row = Depends(require_admin),
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
	return ok_response(data=data, **data)


@router.post("/config")
async def update_dns_config(
	payload: DnsConfigUpdate,
	conn: sqlite3.Connection = Depends(get_conn),
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Update DNS resolver configuration and reload.
	
	Only explicitly provided fields will be updated.
	"""
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

		# Apply explicit updates and persist.
		if payload.enable_logging is not None:
			enable_logging = payload.enable_logging
			set_dns_query_logging_enabled(conn, enable_logging)
		if payload.enable_blocklist is not None:
			enable_blocklist = payload.enable_blocklist
			set_dns_blocklist_enabled(conn, enable_blocklist)
		if payload.upstream_dns is not None:
			upstream_dns = payload.upstream_dns
			set_dns_upstream_servers(conn, upstream_dns)
		if payload.dnssec_enabled is not None:
			dnssec_enabled = payload.dnssec_enabled
			set_dnssec_enabled(conn, dnssec_enabled)
		if payload.log_retention_days is not None:
			retention_days = payload.log_retention_days
			set_dns_log_retention_days(conn, retention_days)
			# "Keine Logs" disables runtime DNS query logging entirely.
			enable_logging = retention_days > 0
			set_dns_query_logging_enabled(conn, enable_logging)
			retention_result = await asyncio.to_thread(
				dns_ingestion.enforce_dns_log_retention,
				tsdb_dir,
				retention_days,
			)

		# Collect IPv6 gateway addresses from all interfaces for dual-stack DNS
		interfaces = list_interfaces(conn)
		ipv6_gateways = unbound.get_interface_ipv6_gateways(interfaces)
		unbound.write_config(
			enable_logging=enable_logging,
			enable_blocklist=enable_blocklist,
			upstream_dns=upstream_dns,
			enable_dnssec=dnssec_enabled,
			listen_addrs_ipv6=ipv6_gateways if ipv6_gateways else None,
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
				error=msg,
				data={**response_data, "error": msg},
				**response_data,
			)
		return ok_response(
			message="Configuration updated and reloaded",
			data=response_data,
			**response_data,
		)
	except FileNotFoundError:
		raise HTTPException(status_code=503, detail="Unbound not installed (requires Docker)")
	except Exception as e:
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
	from ..dns import constants as dns_constants
	
	enabled = get_enabled_blocklists(conn)
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
		is_enabled = meta["url"] in enabled
		
		sources.append({
			"id": bid,
			"url": meta["url"],
			"name": meta["name"],
			"description": meta["description"],
			"domains": source_counts.get(bid, 0),
			"last_updated": blocklist_updated if is_enabled else "—",
			"enabled": is_enabled,
		})

	data = {"sources": sources}
	return ok_response(data=data, **data)


@router.post("/blocklist/sources")
async def set_blocklist_sources(
	payload: BlocklistSourcesUpdate,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Save enabled blocklist sources and regenerate blocklist file."""
	set_enabled_blocklists(conn, payload.urls)
	# Global blocklist selection must override peer-specific selections immediately.
	try:
		from .wireguard_peers import _regenerate_peer_tags
		_regenerate_peer_tags(conn)
	except Exception as exc:
		_log.warning("Failed to regenerate peer tags after global blocklist change: %s", exc)
	
	# Regenerate blocklist file with new selection
	try:
		count, msg = await unbound.update_blocklists(payload.urls)
		# Reload unbound to pick up changes
		ok, reload_msg = await unbound.reload_config()
		if not ok:
			_log.warning("Blocklist sources saved but reload failed: %s", reload_msg)
		return ok_response(
			message=f"Blocklist sources saved ({count} domains)",
			enabled_count=len(payload.urls),
			domains_blocked=count,
			reloaded=ok,
			data={
				"enabled_count": len(payload.urls),
				"domains_blocked": count,
				"reloaded": ok,
			},
		)
	except Exception as exc:
		_log.warning("Blocklist sources saved but update failed: %s", exc)
		reloaded = False
		try:
			reloaded, reload_msg = await unbound.reload_config()
			if not reloaded:
				_log.warning("Blocklist sources saved but reload failed: %s", reload_msg)
		except Exception as reload_exc:
			_log.warning("Blocklist sources saved but reload errored: %s", reload_exc)
		return ok_response(
			message="Blocklist sources saved (update pending)",
			enabled_count=len(payload.urls),
			reloaded=reloaded,
			data={"enabled_count": len(payload.urls), "reloaded": reloaded},
		)


@router.post("/blocklist/update")
async def update_blocklists(
	payload: BlocklistUpdate | None = None,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Download and update ad-blocking lists."""
	# Use saved blocklists if no URLs provided
	urls = payload.urls if payload and payload.urls else None
	if urls is None:
		urls = get_enabled_blocklists(conn)
	
	try:
		count, msg = await unbound.update_blocklists(urls)
		# Reload unbound to pick up new blocklist
		ok, reload_msg = await unbound.reload_config()
		if not ok:
			_log.warning("Blocklist updated but reload failed: %s", reload_msg)
			return ok_response(
				message=f"{msg} (reload failed)",
				domains_blocked=count,
				reloaded=False,
				data={
					"domains_blocked": count,
					"reloaded": False,
				},
			)
		return ok_response(
			message=msg,
			domains_blocked=count,
			reloaded=True,
			data={
				"domains_blocked": count,
				"reloaded": True,
			},
		)
	except FileNotFoundError:
		raise HTTPException(status_code=503, detail="Unbound not installed (requires Docker)")
	except Exception as e:
		_log.exception("Blocklist update failed")
		raise HTTPException(
			status_code=500,
			detail=f"Blocklist update failed: {type(e).__name__}"
		)


@router.get("/blocklist/count")
async def blocklist_count(_: sqlite3.Row = Depends(get_current_user)):
	"""Get the number of domains in the blocklist."""
	count = await asyncio.to_thread(unbound.get_blocklist_count)
	return ok_response(data={"count": count}, count=count)


# ---------------------------------------------------------------------------
# Query Log
# ---------------------------------------------------------------------------

@router.get("/logs")
async def dns_logs(
	lines: int = 200,
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Get recent DNS query log entries (admin only).

	Returns the most recent queries with blocked status from TSDB.
	"""
	lines = min(max(lines, 10), 5000)
	queries = await asyncio.to_thread(dns_ingestion.read_recent_queries, tsdb_dir, lines)

	data = {
		"queries": [
			{
				"timestamp": _format_tsdb_timestamp(str(q.get("ts", ""))),
				"client": str(q.get("client", "")),
				"domain": str(q.get("domain", "")),
				"type": str(q.get("qtype", "")),
				"blocked": bool(q.get("blocked", False)),
			}
			for q in queries  # read_recent_queries() already returns newest first
			],
		"total": len(queries),
	}
	return ok_response(data=data, **data)


@router.get("/top-domains")
async def top_domains(
	limit: int = 20,
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Get top queried domains (admin only)."""
	queries = await asyncio.to_thread(dns_ingestion.read_recent_queries, tsdb_dir, 50000)
	domain_counts: dict[str, int] = {}
	blocked_counts: dict[str, int] = {}

	for q in queries:
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
	return ok_response(data=data, **data)


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
	import ssl
	import struct
	import time
	
	result = {"server": addr, "success": False, "error": None, "latency_ms": None}
	
	# Parse IP@port#hostname
	match = _DNS_PATTERN.match(addr.strip())
	if not match:
		result["error"] = "Invalid format (expected IP@port#hostname)"
		return result
	
	ip_part = match.group(1).strip()
	port_part = match.group(2)
	hostname_part = match.group(3)
	
	if not hostname_part:
		result["error"] = "Hostname required for DoT (IP@port#hostname)"
		return result
	
	try:
		ipaddress.ip_address(ip_part)
	except ValueError:
		result["error"] = f"Invalid IP address: {ip_part}"
		return result
	
	port = int(port_part) if port_part else 853
	if not 1 <= port <= 65535:
		result["error"] = f"Invalid port: {port}"
		return result
	
	try:
		hostname = _normalize_hostname(hostname_part)
	except ValueError as e:
		result["error"] = str(e)
		return result
	
	# Build a minimal DNS query for "example.com" A record
	# Transaction ID (2 bytes) + Flags (2 bytes) + Questions (2 bytes) + 
	# Answer/Auth/Additional RRs (6 bytes) + Query
	transaction_id = b'\x12\x34'
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
		
		with socket.create_connection((ip_part, port), timeout=timeout) as sock:
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
	
	results = []
	for server in payload.servers:
		server = server.strip()
		if not server:
			continue
		# Run blocking socket operations in thread pool
		test_result = await asyncio.to_thread(_test_dot_server, server)
		results.append(test_result)
	
	all_success = all(r["success"] for r in results) if results else False
	failed_count = sum(1 for r in results if not r["success"])
	
	return ok_response(
		data={"results": results, "all_success": all_success, "failed_count": failed_count},
		results=results,
		all_success=all_success,
		failed_count=failed_count,
	)
