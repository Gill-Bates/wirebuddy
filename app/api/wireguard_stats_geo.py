#!/usr/bin/env python3
#
# app/api/wireguard_stats_geo.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard geolocation and TSDB management API routes."""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Generic, TypeVar

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, field_validator
from starlette.concurrency import run_in_threadpool

from ..db import tsdb
from ..db.sqlite_nodes import get_all_tunnel_peer_ids
from ..db.sqlite_peers import (
	get_all_peers,
	get_cumulative_transfer,
	get_peer_metrics_stats as get_peer_metrics_stats_db,
	reset_peer_logs,
	update_cumulative_transfer_batch,
	update_peers_last_seen_batch,
)
from ..db.sqlite_settings import (
	get_tsdb_retention_days,
	set_tsdb_retention_days,
	TSDB_RETENTION_OPTIONS,
)
from ..db.sqlite_runtime import close_connection, connect
from ..utils.deps import get_conn, get_tsdb_dir
from ..utils.geoip import lookup_ip
from .auth import get_current_user, require_admin
from .frontend_shared import CONNECTED_THRESHOLD_S
from .response import ok_response
from .wireguard_utils import parse_wg_show_dump, run_wg_command

_log = logging.getLogger(__name__)

router = APIRouter(tags=["wireguard"])

__all__ = ["router"]

# ---------------------------------------------------------------------------
# Generic async TTL cache
# ---------------------------------------------------------------------------

_CACHE_MISS = object()  # Sentinel distinguishing a cached None/[] from a cache miss
_T = TypeVar("_T")
_geo_inflight: dict[str, asyncio.Future] = {}  # Per-IP deduplication for geo lookups


class _AsyncTTLCache(Generic[_T]):
	"""Thread-safe async TTL cache with double-checked locking (prevents thundering herd).
	
	On compute() failure, serves stale data if available; otherwise propagates exception.
	"""

	def __init__(self, ttl: float) -> None:
		self._ttl = ttl
		self._lock = asyncio.Lock()
		self._entry: tuple[float, _T] | None = None

	def get_if_fresh(self) -> _T | object:
		"""Fast-path read without lock; returns _CACHE_MISS when stale or empty."""
		entry = self._entry
		if entry is not None and (time.monotonic() - entry[0]) < self._ttl:
			return entry[1]
		return _CACHE_MISS

	async def get_or_compute(self, compute: Callable[[], Awaitable[_T]]) -> _T:
		"""Return cached value or call *compute*, store the result, and return it.
		
		On compute() failure:
		- If stale data exists: log warning, return stale value
		- If no stale data: propagate exception to caller
		"""
		if (v := self.get_if_fresh()) is not _CACHE_MISS:
			return v  # type: ignore[return-value]
		async with self._lock:
			if (v := self.get_if_fresh()) is not _CACHE_MISS:  # Re-check under lock
				return v  # type: ignore[return-value]
			try:
				v = await compute()
				self._entry = (time.monotonic(), v)
				return v
			except Exception:
				# Serve stale data if available rather than propagating error
				if self._entry is not None:
					_log.warning("Cache recompute failed, serving stale data (ttl expired)")
					return self._entry[1]
				raise

	def invalidate(self) -> None:
		"""Discard the cached value; next call will recompute."""
		self._entry = None


# ---------------------------------------------------------------------------
# Concurrency primitives
# ---------------------------------------------------------------------------

# Configuration constants
_GEO_LOOKUP_CONCURRENCY = 20
_GEO_LOOKUP_CHUNK_SIZE = 100  # Chunk size for batched geo lookups
_GEO_CACHE_TTL_S = 300.0
_GEO_CACHE_MAX_SIZE = 2048
_PEERS_ENRICHED_CACHE_TTL_S = 5.0
_WG_DUMP_CACHE_TTL_S = 2.0  # Short-lived cache for wg show dump
WG_BIN = "wg"

# Concurrency primitives
_geo_lookup_sem = asyncio.Semaphore(_GEO_LOOKUP_CONCURRENCY)
_geo_cache: OrderedDict[str, tuple[float, dict | None]] = OrderedDict()  # LRU cache
_geo_cache_lock = asyncio.Lock()
_peers_enriched_cache_obj: _AsyncTTLCache = _AsyncTTLCache(_PEERS_ENRICHED_CACHE_TTL_S)

# Shared WG dump cache to avoid redundant parsing across endpoints
_wg_dump_cache_obj: _AsyncTTLCache = _AsyncTTLCache(_WG_DUMP_CACHE_TTL_S)


def invalidate_peers_enriched_cache() -> None:
	"""Clear the short-lived enriched peers cache after peer mutations."""
	_peers_enriched_cache_obj.invalidate()


def _valid_nonempty_str(value: object) -> str | None:
	"""Return a stripped non-empty string value, otherwise None."""
	if not isinstance(value, str):
		return None
	candidate = value.strip()
	return candidate if candidate else None


def _safe_int(value: object) -> int:
	"""Coerce a value to int, returning 0 for None/falsy or on conversion error."""
	try:
		return int(value or 0)
	except (TypeError, ValueError):
		return 0


async def _load_peers_with_tunnel_ids(conn: sqlite3.Connection) -> tuple[list[sqlite3.Row], set[int]]:
	"""Load peers and tunnel-peer IDs for a consistent snapshot-like read path."""
	peers = await run_in_threadpool(get_all_peers, conn)
	tunnel_peer_ids = await run_in_threadpool(get_all_tunnel_peer_ids, conn)
	return peers, set(tunnel_peer_ids)


def _peer_handshake_ts(peer: dict) -> int:
	"""Return normalized latest handshake timestamp for a peer dict."""
	return _safe_int(peer.get("latest_handshake"))


def _extract_geo_info(geo_info: dict | None) -> dict[str, object]:
	"""Extract standard GeoIP fields (country/city/asn/as_org) from a lookup result."""
	if not geo_info:
		return {"country": None, "city": None, "asn": None, "as_org": None}
	return {
		"country": geo_info.get("country"),
		"city": geo_info.get("city"),
		"asn": geo_info.get("asn"),
		"as_org": geo_info.get("as_org"),
	}


class TsdbRetentionUpdate(BaseModel):
	"""Request body for TSDB retention updates."""
	retention_days: int

	@field_validator("retention_days")
	@classmethod
	def validate_retention_days(cls, days: int) -> int:
		if days not in TSDB_RETENTION_OPTIONS:
			raise ValueError(f"Invalid retention_days. Allowed: {list(TSDB_RETENTION_OPTIONS)}")
		return days


async def _lookup_geo_cached(ip: str) -> tuple[str, dict | None]:
	"""Resolve GeoIP/ASN with bounded concurrency, per-IP deduplication, and LRU cache.
	
	Per-IP deduplication ensures concurrent requests for the same IP share a single
	lookup (futures), preventing duplicate work on high-concurrency scenarios.
	"""
	now_mono = time.monotonic()
	async with _geo_cache_lock:
		cached = _geo_cache.get(ip)
		if cached and (now_mono - cached[0]) < _GEO_CACHE_TTL_S:
			# Move to end for LRU ordering
			_geo_cache.move_to_end(ip)
			return ip, cached[1]
		# Check for in-flight lookup (deduplication)
		if ip in _geo_inflight:
			future = _geo_inflight[ip]
		else:
			future = asyncio.get_event_loop().create_future()
			_geo_inflight[ip] = future

	if not future.done():
		async with _geo_lookup_sem:
			try:
				info = await run_in_threadpool(lookup_ip, ip)
				future.set_result(info)
			except Exception as exc:
				future.set_exception(exc)
				raise
			finally:
				async with _geo_cache_lock:
					_geo_inflight.pop(ip, None)
					_geo_cache[ip] = (time.monotonic(), info)
					_geo_cache.move_to_end(ip)
					# LRU eviction
					while len(_geo_cache) > _GEO_CACHE_MAX_SIZE:
						_geo_cache.popitem(last=False)
	else:
		info = await asyncio.shield(future)
		async with _geo_cache_lock:
			# Cache the result from deduplication
			_geo_cache[ip] = (time.monotonic(), info)
			_geo_cache.move_to_end(ip)
			while len(_geo_cache) > _GEO_CACHE_MAX_SIZE:
				_geo_cache.popitem(last=False)
	return ip, info


async def _lookup_geo_map(unique_ips: set[str]) -> dict[str, dict | None]:
	"""Resolve GeoIP for multiple IPs with chunking to limit burst."""
	if not unique_ips:
		return {}
	
	result: dict[str, dict | None] = {}
	ips_list = sorted(unique_ips)
	
	# Process in chunks to avoid creating too many concurrent tasks
	for i in range(0, len(ips_list), _GEO_LOOKUP_CHUNK_SIZE):
		chunk = ips_list[i:i + _GEO_LOOKUP_CHUNK_SIZE]
		lookups = await asyncio.gather(*[_lookup_geo_cached(ip) for ip in chunk])
		for ip, info in lookups:
			result[ip] = info
	
	return result


async def _get_wg_dump_cached() -> list:
	"""Get parsed WG dump with short-lived cache to avoid redundant parsing.
	
	Errors (wg command failure) are NOT cached; empty [] is only returned on
	exception and allowed to be served as stale data if cache refresh fails.
	"""
	async def _fetch() -> list:
		code, stdout, stderr = await run_wg_command(WG_BIN, "show", "all", "dump")
		if code != 0:
			# Raise exception instead of returning [] so _AsyncTTLCache doesn't cache the error
			raise RuntimeError(f"wg show all dump failed (code={code}): {stderr.strip() if stderr else 'no output'}")
		return parse_wg_show_dump(stdout)

	try:
		return await _wg_dump_cache_obj.get_or_compute(_fetch)  # type: ignore[return-value]
	except Exception:
		_log.warning("wg show all dump failed", exc_info=True)
		return []


@router.get("/stats/peer-locations")
async def get_peer_locations(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Return geolocated positions of all WireGuard peers with known endpoints.

	Parses ``wg show all dump`` for peer endpoints, resolves each public IP
	via GeoLite2-City + GeoLite2-ASN and returns a list suitable for a
	Leaflet heatmap.  Includes both currently-connected and recently-seen
	peers (any peer with a non-``(none)`` endpoint and a handshake timestamp).
	Also includes peers with persisted last_client_ip from DB.
	"""
	now = time.time()

	# Build peer name lookup and last-seen data from DB (async via threadpool)
	all_db_peers, tunnel_peer_ids = await _load_peers_with_tunnel_ids(conn)
	peer_db_info: dict[str, dict] = {}
	for p in all_db_peers:
		if p["public_key"]:
			peer_db_info[p["public_key"]] = {
				"peer_id": p["id"],
				"name": p["name"] or p["public_key"][:8],
				"last_client_ip": p["last_client_ip"],
				"last_handshake_at": p["last_handshake_at"] or 0,
				"interface": p["interface"],
			}

	# 1. Parse wg show all dump for live stats (using shared cache)
	wg_peers = await _get_wg_dump_cached()
	for peer in wg_peers:
		if peer.public_key not in peer_db_info:
			continue
		# Update DB info with live data
		if peer.handshake_ts > peer_db_info[peer.public_key].get("last_handshake_at", 0):
			peer_db_info[peer.public_key]["last_handshake_at"] = peer.handshake_ts
		if peer.client_ip:
			peer_db_info[peer.public_key]["last_client_ip"] = peer.client_ip
		if peer.interface:
			peer_db_info[peer.public_key]["interface"] = peer.interface

	# 2. Collect unique IPs that need resolution (skip peers with no IP / handshake / node tunnels)
	ip_to_peers: dict[str, list[tuple[str, dict]]] = {}
	skipped_tunnel = 0
	skipped_no_ip = 0
	skipped_no_handshake = 0
	for pub_key, info in peer_db_info.items():
		peer_id = info.get("peer_id")
		if peer_id in tunnel_peer_ids:
			skipped_tunnel += 1
			continue
		ip_str = info.get("last_client_ip")
		if not ip_str:
			skipped_no_ip += 1
			continue
		if not (info.get("last_handshake_at") or 0):
			skipped_no_handshake += 1
			continue
		ip_to_peers.setdefault(ip_str, []).append((pub_key, info))

	# 3. Resolve all unique IPs with bounded concurrency + shared cache
	geo_results = await _lookup_geo_map(set(ip_to_peers))

	# 4. Build location entries — one entry per unique IP, aggregating all peers at that IP
	locations: list[dict] = []
	for ip_str, peers_at_ip in ip_to_peers.items():
		geo_info = geo_results.get(ip_str)
		if not geo_info:
			continue

		# Validate lat/lon to prevent frontend issues with partial geo data
		lat = geo_info.get("lat")
		lon = geo_info.get("lon")
		if lat is None or lon is None:
			continue

		connected = False
		names: list[str] = []
		connected_names: list[str] = []
		for pub_key, info in peers_at_ip:
			handshake_ts = info.get("last_handshake_at") or 0
			peer_name = info.get("name", pub_key[:8])
			names.append(peer_name)
			if (now - handshake_ts) < CONNECTED_THRESHOLD_S:
				connected = True
				connected_names.append(peer_name)

		# Multiple peers can share one public IP (e.g. NAT); use first peer metadata as representative.
		first_info = peers_at_ip[0][1]
		locations.append({
			"lat": lat,
			"lon": lon,
			**_extract_geo_info(geo_info),
			"ip": ip_str,
			"name": connected_names[0] if connected_names else names[0],
			"names": names,
			"connected_names": connected_names,
			"interface": first_info.get("interface"),
			"connected": connected,
			"count": len(names),
			"connected_count": len(connected_names),
		})

	_log.debug(
		"PEER_LOC returning %d location(s), skipped tunnel=%d no_ip=%d no_handshake=%d",
		len(locations),
		skipped_tunnel,
		skipped_no_ip,
		skipped_no_handshake,
	)
	return ok_response(data={"locations": locations})


async def _build_peers_enriched(conn: sqlite3.Connection) -> list[dict]:
	"""Build enriched peer payload and persist side-effect counters."""
	rows, tunnel_peer_ids = await _load_peers_with_tunnel_ids(conn)
	peers_by_key: dict[str, dict] = {}
	# Track original DB handshakes separately; peers_by_key["latest_handshake"] may be replaced by live WG data.
	db_handshakes: dict[str, int] = {}
	for row in rows:
		pub_key = row["public_key"]
		peer_id = row["id"]
		peers_by_key[pub_key] = {
			"id": peer_id,
			"name": row["name"],
			"public_key": pub_key,
			"allowed_ips": row["allowed_ips"],
			"peer_address": row["peer_address"],
			"interface": row["interface"],
			"is_enabled": bool(row["is_enabled"]),
			"is_node_tunnel": peer_id in tunnel_peer_ids,
			"endpoint_ip": row["last_client_ip"],
			"endpoint": None,
			"latest_handshake": _safe_int(row["last_handshake_at"]),
			"connected": False,
			"transfer_rx": 0,
			"transfer_tx": 0,
			"country": None,
			"city": None,
			"asn": None,
			"as_org": None,
		}
		db_handshakes[pub_key] = _safe_int(row["last_handshake_at"])

	now = time.time()
	db_updates: list[tuple[str, int, str]] = []

	# Use shared WG dump cache to avoid redundant parsing
	wg_peers = await _get_wg_dump_cached()
	for wg_peer in wg_peers:
		peer = peers_by_key.get(wg_peer.public_key)
		if not peer:
			continue

		peer["endpoint"] = wg_peer.endpoint_raw
		peer["transfer_rx"] = wg_peer.rx
		peer["transfer_tx"] = wg_peer.tx

		stored_hs = db_handshakes.get(wg_peer.public_key, 0)
		if wg_peer.handshake_ts:
			current_hs = _peer_handshake_ts(peer)
			effective_hs = max(wg_peer.handshake_ts, current_hs)
			peer["latest_handshake"] = effective_hs
			if wg_peer.client_ip:
				peer["endpoint_ip"] = wg_peer.client_ip

			if wg_peer.handshake_ts > stored_hs:
				stored_ip = str(peer.get("endpoint_ip") or "").strip()
				persist_ip = wg_peer.client_ip or stored_ip
				if persist_ip:
					db_updates.append((persist_ip, wg_peer.handshake_ts, wg_peer.public_key))
					db_handshakes[wg_peer.public_key] = wg_peer.handshake_ts
					if not peer.get("endpoint_ip"):
						peer["endpoint_ip"] = persist_ip
		elif wg_peer.client_ip and not _valid_nonempty_str(peer.get("endpoint_ip")):
			peer["endpoint_ip"] = wg_peer.client_ip

	# Compute "connected" status consistently based on latest_handshake for all peers.
	# This ensures Dashboard KPI and "Recent Peer Activity" use the same logic.
	for peer in peers_by_key.values():
		hs = _peer_handshake_ts(peer)
		peer["connected"] = hs > 0 and (now - hs) < CONNECTED_THRESHOLD_S

	# Persist last-seen updates
	if db_updates:
		try:
			await run_in_threadpool(update_peers_last_seen_batch, conn, db_updates)
			_log.debug("PEERS_LAST_SEEN persisted %d peer(s)", len(db_updates))
		except Exception:
			_log.warning("Failed to persist last-seen data", exc_info=True)

	# Process cumulative transfer
	try:
		stored_transfer = await run_in_threadpool(get_cumulative_transfer, conn)
		transfer_updates: list[tuple[int, int, int, int, str]] = []
		for pub_key, peer in peers_by_key.items():
			wg_rx = int(peer["transfer_rx"])
			wg_tx = int(peer["transfer_tx"])
			stored = stored_transfer.get(
				pub_key,
				{"cumulative_rx": 0, "cumulative_tx": 0, "last_wg_rx": 0, "last_wg_tx": 0},
			)

			cum_rx = int(stored["cumulative_rx"])
			cum_tx = int(stored["cumulative_tx"])
			last_rx = int(stored["last_wg_rx"])
			last_tx = int(stored["last_wg_tx"])

			# NOTE: bytes between the last poll and the WG restart are not reconstructable;
			# cum_rx/tx accounts for everything observed before the counter reset.
			if wg_rx < last_rx:
				cum_rx += last_rx
			if wg_tx < last_tx:
				cum_tx += last_tx

			peer["transfer_rx"] = cum_rx + wg_rx
			peer["transfer_tx"] = cum_tx + wg_tx

			if (
				wg_rx != last_rx
				or wg_tx != last_tx
				or cum_rx != int(stored["cumulative_rx"])
				or cum_tx != int(stored["cumulative_tx"])
			):
				transfer_updates.append((cum_rx, cum_tx, wg_rx, wg_tx, pub_key))

		if transfer_updates:
			await run_in_threadpool(update_cumulative_transfer_batch, conn, transfer_updates)
			_log.debug("CUMULATIVE_TRANSFER persisted %d peer(s)", len(transfer_updates))
	except Exception:
		_log.warning("Failed to update cumulative transfer", exc_info=True)

	unique_ips = {
		ip
		for peer in peers_by_key.values()
		for ip in [_valid_nonempty_str(peer.get("endpoint_ip"))]
		if ip is not None
	}
	geo_map = await _lookup_geo_map(unique_ips)
	missing_geo_lookups = 0
	for peer in peers_by_key.values():
		endpoint_ip = _valid_nonempty_str(peer.get("endpoint_ip"))
		if endpoint_ip is None:
			continue
		info = geo_map.get(endpoint_ip)
		if not info:
			missing_geo_lookups += 1
			continue
		peer.update(_extract_geo_info(info))

	if missing_geo_lookups:
		_log.debug("PEERS_ENRICHED geo lookup missing for %d endpoint(s)", missing_geo_lookups)

	return sorted(
		peers_by_key.values(),
		key=lambda p: (not p["connected"], -_peer_handshake_ts(p)),
	)


@router.get("/stats/peers-enriched")
async def get_peers_enriched(
	request: Request,
	_: sqlite3.Row = Depends(require_admin),
):
	"""Return all peers with live WireGuard stats and GeoIP/ASN enrichment."""
	db_path: Path = request.app.state.db_path

	async def _compute() -> list[dict]:
		# Own the connection: a request-scoped conn from Depends(get_conn) may be
		# closed before get_or_compute returns if another coroutine triggers cleanup,
		# causing use-after-close errors on the SQLite handle.
		conn = await run_in_threadpool(connect, db_path)
		try:
			return await _build_peers_enriched(conn)
		finally:
			await run_in_threadpool(close_connection, conn)

	result = await _peers_enriched_cache_obj.get_or_compute(_compute)
	return ok_response(data={"peers": result})


# ---------------------------------------------------------------------------
# TSDB Stats & Management
# ---------------------------------------------------------------------------

@router.get("/stats/tsdb")
async def get_tsdb_stats(
	tsdb_dir: Path = Depends(get_tsdb_dir),
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get TSDB storage statistics."""
	data = await run_in_threadpool(tsdb.get_db_stats, tsdb_dir)
	data["retention_days"] = get_tsdb_retention_days(conn)
	data["retention_options"] = list(TSDB_RETENTION_OPTIONS)
	data["path"] = str(tsdb_dir)
	return ok_response(data=data)


@router.patch("/stats/tsdb/retention")
async def update_tsdb_retention(
	request_body: TsdbRetentionUpdate,
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Update TSDB retention period (admin only)."""
	days = int(request_body.retention_days)
	set_tsdb_retention_days(conn, days)
	return ok_response(
		message=f"TSDB retention set to {days} days",
		data={"retention_days": days},
	)


@router.delete("/stats/tsdb")
async def reset_tsdb(
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Reset/delete all TSDB data (admin only)."""
	deleted = await run_in_threadpool(tsdb.reset_all, tsdb_dir, force=True)
	return ok_response(
		message=f"TSDB reset: {deleted} peer directories deleted",
		data={"deleted": deleted},
	)


@router.post("/stats/tsdb/maintenance")
async def run_tsdb_maintenance(
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Run TSDB retention/rotation/compression maintenance immediately."""
	stats = await run_in_threadpool(tsdb.run_maintenance, tsdb_dir)
	return ok_response(
		message="TSDB maintenance completed",
		data=stats,
	)


# ---------------------------------------------------------------------------
# Peer Metrics Stats & Management
# ---------------------------------------------------------------------------

@router.get("/stats/peer-metrics")
async def get_peer_metrics_stats(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get peer connection-tracking statistics."""
	data = await run_in_threadpool(get_peer_metrics_stats_db, conn)
	return ok_response(data=data)


@router.delete("/stats/peer-logs")
async def delete_peer_logs(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Reset all peer connection-tracking data (admin only).

	Clears last_client_ip, last_handshake_at, and cumulative transfer counters.
	"""
	affected = await run_in_threadpool(reset_peer_logs, conn)
	invalidate_peers_enriched_cache()
	return ok_response(
		message=f"Reset connection data for {affected} peer(s)",
		data={"affected": affected},
	)
