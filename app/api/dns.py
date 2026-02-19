#!/usr/bin/env python3
#
# app/api/dns.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""DNS management API routes."""

from __future__ import annotations

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

from ..db import sqlite as sqlite_db
from ..dns import ingestion as dns_ingestion
from ..dns import unbound
from ..utils.deps import get_conn, get_tsdb_dir
from .auth import get_current_user, require_admin
from .response import ok_response


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

_log = logging.getLogger(__name__)

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
		if v not in sqlite_db.DNS_LOG_RETENTION_OPTIONS:
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
async def dns_status(_: sqlite3.Row = Depends(get_current_user)):
	"""Get DNS resolver status and statistics."""
	try:
		running = await unbound.is_running()
		stats = await unbound.get_stats()
	except FileNotFoundError:
		# Unbound not installed (dev environment)
		data = {
			"is_running": False,
			"total_queries": 0,
			"blocked_queries": 0,
			"block_percentage": 0,
			"unique_domains": 0,
			"unique_clients": 0,
			"blocklist_size": 0,
			"blocklist_updated_at": None,
			"unavailable": True,
			"reason": "Unbound not installed (requires Docker)",
		}
		return ok_response(data=data, **data)
	stats.is_running = running

	data = {
		"is_running": running,
		"total_queries": stats.total_queries,
		"blocked_queries": stats.blocked_queries,
		"block_percentage": round(
			(stats.blocked_queries / stats.total_queries * 100) if stats.total_queries else 0, 1
		),
		"unique_domains": stats.unique_domains,
		"unique_clients": stats.unique_clients,
		"blocklist_size": stats.blocklist_size,
		"blocklist_updated_at": _blocklist_mtime(),
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
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Return DNS total/blocked trend buckets for charts.
	
	Note: Data is limited to the most recent 10,000 log entries.
	For long time ranges (e.g., 168 hours), results may be incomplete
	if the log contains more than 10,000 entries in that period.
	"""
	hours = min(max(hours, 1), 168)
	bucket_minutes = min(max(bucket_minutes, 5), 60)
	since = datetime.now(timezone.utc) - timedelta(hours=hours)

	queries = await asyncio.to_thread(unbound.tail_query_log, 10000)
	buckets: dict[str, dict[str, int]] = {}

	for q in queries:
		if not q.timestamp:
			continue
		try:
			ts = datetime.strptime(q.timestamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
		except ValueError:
			continue
		if ts < since:
			continue

		bucket_ts = ts.replace(second=0, microsecond=0)
		bucket_ts = bucket_ts - timedelta(minutes=bucket_ts.minute % bucket_minutes)
		label = bucket_ts.isoformat()
		if label not in buckets:
			buckets[label] = {"total": 0, "blocked": 0}
		buckets[label]["total"] += 1
		if q.blocked:
			buckets[label]["blocked"] += 1

	labels = sorted(buckets.keys())
	total = [buckets[l]["total"] for l in labels]
	blocked = [buckets[l]["blocked"] for l in labels]
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
async def dns_start(_: sqlite3.Row = Depends(require_admin)):
	"""Start the DNS resolver."""
	try:
		ok, msg = await unbound.start()
	except FileNotFoundError:
		raise HTTPException(status_code=503, detail="Unbound not installed (requires Docker)")
	if not ok:
		raise HTTPException(status_code=500, detail=msg)
	return ok_response(message=msg)


@router.post("/stop")
async def dns_stop(_: sqlite3.Row = Depends(require_admin)):
	"""Stop the DNS resolver."""
	try:
		ok, msg = await unbound.stop()
	except FileNotFoundError:
		raise HTTPException(status_code=503, detail="Unbound not installed (requires Docker)")
	if not ok:
		raise HTTPException(status_code=500, detail=msg)
	return ok_response(message=msg)


@router.post("/restart")
async def dns_restart(_: sqlite3.Row = Depends(require_admin)):
	"""Restart the DNS resolver."""
	try:
		ok, msg = await unbound.restart()
	except FileNotFoundError:
		raise HTTPException(status_code=503, detail="Unbound not installed (requires Docker)")
	if not ok:
		raise HTTPException(status_code=500, detail=msg)
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
	dnssec_enabled = sqlite_db.get_dnssec_enabled(conn)
	dnssec_available = unbound.is_dnssec_available()
	retention_days = sqlite_db.get_dns_log_retention_days(conn)

	data = {
		"enable_logging": sqlite_db.get_dns_query_logging_enabled(conn),
		"enable_blocklist": sqlite_db.get_dns_blocklist_enabled(conn),
		"upstream_dns": sqlite_db.get_dns_upstream_servers(conn),
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
		enable_logging = sqlite_db.get_dns_query_logging_enabled(conn)
		enable_blocklist = sqlite_db.get_dns_blocklist_enabled(conn)
		upstream_dns = sqlite_db.get_dns_upstream_servers(conn)
		dnssec_enabled = sqlite_db.get_dnssec_enabled(conn)
		retention_days = sqlite_db.get_dns_log_retention_days(conn)
		retention_result = {"deleted_files": 0, "remaining_files": 0}

		# Apply explicit updates and persist.
		if payload.enable_logging is not None:
			enable_logging = payload.enable_logging
			sqlite_db.set_dns_query_logging_enabled(conn, enable_logging)
		if payload.enable_blocklist is not None:
			enable_blocklist = payload.enable_blocklist
			sqlite_db.set_dns_blocklist_enabled(conn, enable_blocklist)
		if payload.upstream_dns is not None:
			upstream_dns = payload.upstream_dns
			sqlite_db.set_dns_upstream_servers(conn, upstream_dns)
		if payload.dnssec_enabled is not None:
			dnssec_enabled = payload.dnssec_enabled
			sqlite_db.set_dnssec_enabled(conn, dnssec_enabled)
		if payload.log_retention_days is not None:
			retention_days = payload.log_retention_days
			sqlite_db.set_dns_log_retention_days(conn, retention_days)
			# "Keine Logs" disables runtime DNS query logging entirely.
			enable_logging = retention_days > 0
			sqlite_db.set_dns_query_logging_enabled(conn, enable_logging)
			retention_result = await asyncio.to_thread(
				dns_ingestion.enforce_dns_log_retention,
				tsdb_dir,
				retention_days,
			)

		unbound.write_config(
			enable_logging=enable_logging,
			enable_blocklist=enable_blocklist,
			upstream_dns=upstream_dns,
			enable_dnssec=dnssec_enabled,
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
	from ..dns.unbound import get_blocklist_file, BLOCKLIST_REGISTRY
	
	enabled = sqlite_db.get_enabled_blocklists(conn)
	source_counts = await asyncio.to_thread(unbound.get_blocklist_source_counts)
	
	# Get combined blocklist file stats if available
	# Note: This is the merged blocklist from all enabled sources
	blocklist_updated = None
	blocklist_size = None
	blocklist_path = get_blocklist_file()
	if blocklist_path.exists():
		try:
			stat = blocklist_path.stat()
			blocklist_updated = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).strftime("%Y-%m-%d")
			# Format size
			size_bytes = stat.st_size
			if size_bytes < 1024:
				blocklist_size = f"{size_bytes} B"
			elif size_bytes < 1024 * 1024:
				blocklist_size = f"{size_bytes // 1024} KB"
			else:
				blocklist_size = f"{size_bytes // (1024 * 1024)} MB"
		except Exception:
			_log.debug("Could not read blocklist file stats", exc_info=True)
	
	# Build sources from registry with enabled status
	sources = []
	for bid, meta in BLOCKLIST_REGISTRY.items():
		sources.append({
			"id": bid,
			"url": meta["url"],
			"name": meta["name"],
			"description": meta["description"],
			"domains": source_counts.get(bid, 0),
			"size": blocklist_size or "—",
			"last_updated": blocklist_updated or "—",
			"enabled": meta["url"] in enabled,
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
	sqlite_db.set_enabled_blocklists(conn, payload.urls)
	
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
		return ok_response(
			message="Blocklist sources saved (update pending)",
			enabled_count=len(payload.urls),
			data={"enabled_count": len(payload.urls)},
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
		urls = sqlite_db.get_enabled_blocklists(conn)
	
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
	_: sqlite3.Row = Depends(require_admin),
):
	"""Get recent DNS query log entries (admin only).

	Returns the most recent queries with blocked status.
	"""
	lines = min(max(lines, 10), 5000)
	queries = await asyncio.to_thread(unbound.tail_query_log, lines)

	data = {
		"queries": [
				{
					"timestamp": q.timestamp,
					"client": q.client,
					"domain": q.domain,
					"resolver": q.resolver,
					"type": q.qtype,
					"blocked": q.blocked,
				}
			for q in reversed(queries)  # newest first
		],
		"total": len(queries),
	}
	return ok_response(data=data, **data)


@router.get("/top-domains")
async def top_domains(
	limit: int = 20,
	_: sqlite3.Row = Depends(require_admin),
):
	"""Get top queried domains (admin only)."""
	queries = await asyncio.to_thread(unbound.tail_query_log, 5000)
	domain_counts: dict[str, int] = {}
	blocked_counts: dict[str, int] = {}

	for q in queries:
		domain_counts[q.domain] = domain_counts.get(q.domain, 0) + 1
		if q.blocked:
			blocked_counts[q.domain] = blocked_counts.get(q.domain, 0) + 1

	sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
	sorted_blocked = sorted(blocked_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

	data = {
		"top_queried": [{"domain": d, "count": c} for d, c in sorted_domains],
		"top_blocked": [{"domain": d, "count": c} for d, c in sorted_blocked],
	}
	return ok_response(data=data, **data)
