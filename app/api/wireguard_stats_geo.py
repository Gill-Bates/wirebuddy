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
from pathlib import Path

from fastapi import APIRouter, Depends
from pydantic import BaseModel, field_validator
from starlette.concurrency import run_in_threadpool

from ..db import tsdb
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
from ..utils.deps import get_conn, get_tsdb_dir
from ..utils.geoip import lookup_ip
from .auth import get_current_user, require_admin
from .frontend_shared import CONNECTED_THRESHOLD_S
from .response import ok_response
from .wireguard_utils import parse_wg_show_dump, run_wg_command

_log = logging.getLogger(__name__)

router = APIRouter(tags=["wireguard"])

__all__ = ["router"]
_GEO_LOOKUP_CONCURRENCY = 20
_GEO_CACHE_TTL_S = 300.0
_GEO_CACHE_MAX_SIZE = 2048
_PEERS_ENRICHED_CACHE_TTL_S = 5.0
_geo_lookup_sem = asyncio.Semaphore(_GEO_LOOKUP_CONCURRENCY)
_geo_cache: dict[str, tuple[float, dict | None]] = {}
_geo_cache_lock = asyncio.Lock()
_peers_enriched_cache: tuple[float, list[dict]] | None = None
_peers_enriched_lock = asyncio.Lock()


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
	"""Resolve GeoIP/ASN with bounded concurrency and TTL cache."""
	now_mono = time.monotonic()
	async with _geo_cache_lock:
		cached = _geo_cache.get(ip)
		if cached and (now_mono - cached[0]) < _GEO_CACHE_TTL_S:
			return ip, cached[1]

	async with _geo_lookup_sem:
		info = await run_in_threadpool(lookup_ip, ip)

	async with _geo_cache_lock:
		_geo_cache[ip] = (time.monotonic(), info)
		if len(_geo_cache) > _GEO_CACHE_MAX_SIZE:
			oldest_ip = min(_geo_cache.items(), key=lambda item: item[1][0])[0]
			_geo_cache.pop(oldest_ip, None)
	return ip, info


async def _lookup_geo_map(unique_ips: set[str]) -> dict[str, dict | None]:
	if not unique_ips:
		return {}
	lookups = await asyncio.gather(*[_lookup_geo_cached(ip) for ip in sorted(unique_ips)])
	return dict(lookups)


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
	threshold = CONNECTED_THRESHOLD_S

	# Build peer name lookup and last-seen data from DB (async via threadpool)
	all_db_peers = await run_in_threadpool(get_all_peers, conn)
	peer_db_info: dict[str, dict] = {}
	for p in all_db_peers:
		if p["public_key"]:
			peer_db_info[p["public_key"]] = {
				"name": p["name"] or p["public_key"][:8],
				"last_client_ip": p["last_client_ip"],
				"last_handshake_at": p["last_handshake_at"] or 0,
				"interface": p["interface"],
			}

	# 1. Parse wg show all dump for live stats
	try:
		code, stdout, stderr = await run_wg_command("wg", "show", "all", "dump")
	except Exception:
		_log.warning("wg show all dump failed for peer locations", exc_info=True)
		code, stdout, stderr = 1, "", ""
	if code == 0:
		peers = parse_wg_show_dump(stdout)
		for peer in peers:
			if peer.public_key not in peer_db_info:
				continue
			# Update DB info with live data
			if peer.handshake_ts > peer_db_info[peer.public_key].get("last_handshake_at", 0):
				peer_db_info[peer.public_key]["last_handshake_at"] = peer.handshake_ts
			if peer.client_ip:
				peer_db_info[peer.public_key]["last_client_ip"] = peer.client_ip
			if peer.interface:
				peer_db_info[peer.public_key]["interface"] = peer.interface
	else:
		_log.debug(
			"wg show all dump failed (code=%d): %s",
			code,
			stderr.strip() if stderr else "no output",
		)

	# 2. Collect unique IPs that need resolution (skip peers with no IP / handshake)
	ip_to_peers: dict[str, list[tuple[str, dict]]] = {}
	for pub_key, info in peer_db_info.items():
		ip_str = info.get("last_client_ip")
		if not ip_str:
			_log.debug("PEER_LOC skip %s: no IP", pub_key[:8])
			continue
		if not (info.get("last_handshake_at") or 0):
			_log.debug("PEER_LOC skip %s: no handshake", pub_key[:8])
			continue
		ip_to_peers.setdefault(ip_str, []).append((pub_key, info))

	# 3. Resolve all unique IPs with bounded concurrency + shared cache
	geo_results = await _lookup_geo_map(set(ip_to_peers))

	# 4. Build location entries — one entry per unique IP, aggregating all peers at that IP
	locations: list[dict] = []
	for ip_str, peers_at_ip in ip_to_peers.items():
		geo_info = geo_results.get(ip_str)
		if not geo_info:
			_log.debug("PEER_LOC skip ip=%s: no geo data", ip_str)
			continue

		connected = False
		names: list[str] = []
		for pub_key, info in peers_at_ip:
			handshake_ts = info.get("last_handshake_at") or 0
			if (now - handshake_ts) < threshold:
				connected = True
			names.append(info.get("name", pub_key[:8]))

		first_info = peers_at_ip[0][1]
		_log.debug(
			"PEER_LOC add ip=%s lat=%s lon=%s peers=%d",
			ip_str, geo_info.get("lat"), geo_info.get("lon"), len(names),
		)
		locations.append({
			"lat": geo_info.get("lat"),
			"lon": geo_info.get("lon"),
			"city": geo_info.get("city"),
			"country": geo_info.get("country"),
			"asn": geo_info.get("asn"),
			"as_org": geo_info.get("as_org"),
			"ip": ip_str,
			"name": names[0],
			"names": names,
			"interface": first_info.get("interface"),
			"connected": connected,
			"count": len(names),
		})

	_log.debug("PEER_LOC returning %d location(s)", len(locations))
	return ok_response(data={"locations": locations})


async def _build_peers_enriched(conn: sqlite3.Connection) -> list[dict]:
	"""Build enriched peer payload and persist side-effect counters once."""
	rows = await run_in_threadpool(get_all_peers, conn)
	peers_by_key: dict[str, dict] = {}
	db_handshakes: dict[str, int] = {}
	for row in rows:
		pub_key = row["public_key"]
		peers_by_key[pub_key] = {
			"id": row["id"],
			"name": row["name"],
			"public_key": pub_key,
			"allowed_ips": row["allowed_ips"],
			"peer_address": row["peer_address"],
			"interface": row["interface"],
			"is_enabled": bool(row["is_enabled"]),
			"endpoint_ip": row["last_client_ip"],
			"endpoint": None,
			"latest_handshake": int(row["last_handshake_at"] or 0),
			"connected": False,
			"transfer_rx": 0,
			"transfer_tx": 0,
			"country": None,
			"city": None,
			"asn": None,
			"as_org": None,
		}
		db_handshakes[pub_key] = int(row["last_handshake_at"] or 0)

	now = time.time()
	threshold = CONNECTED_THRESHOLD_S
	db_updates: list[tuple[str, int, str]] = []

	try:
		code, stdout, stderr = await run_wg_command("wg", "show", "all", "dump")
		if code != 0:
			_log.debug("wg show all dump failed (code=%d): %s", code, stderr.strip() if stderr else "no output")
		else:
			wg_peers = parse_wg_show_dump(stdout)
			for wg_peer in wg_peers:
				peer = peers_by_key.get(wg_peer.public_key)
				if not peer:
					continue

				peer["endpoint"] = wg_peer.endpoint_raw
				peer["transfer_rx"] = wg_peer.rx
				peer["transfer_tx"] = wg_peer.tx

				stored_hs = db_handshakes.get(wg_peer.public_key, 0)
				stored_ip = str(peer.get("endpoint_ip") or "").strip()
				if wg_peer.handshake_ts:
					current_hs = int(peer.get("latest_handshake") or 0)
					effective_hs = max(wg_peer.handshake_ts, current_hs)
					peer["latest_handshake"] = effective_hs
					if wg_peer.client_ip:
						peer["endpoint_ip"] = wg_peer.client_ip

					if wg_peer.handshake_ts > stored_hs:
						persist_ip = wg_peer.client_ip or stored_ip
						if persist_ip:
							db_updates.append((persist_ip, wg_peer.handshake_ts, wg_peer.public_key))
							db_handshakes[wg_peer.public_key] = wg_peer.handshake_ts
							if not peer.get("endpoint_ip"):
								peer["endpoint_ip"] = persist_ip
				elif wg_peer.client_ip:
					peer["endpoint_ip"] = wg_peer.client_ip
	except Exception:
		_log.warning("Failed to parse wg dump for enriched peers", exc_info=True)

	# Compute "connected" status consistently based on latest_handshake for all peers.
	# This ensures Dashboard KPI and "Recent Peer Activity" use the same logic.
	for peer in peers_by_key.values():
		hs = int(peer.get("latest_handshake") or 0)
		peer["connected"] = hs > 0 and (now - hs) < threshold

	if db_updates:
		try:
			await run_in_threadpool(update_peers_last_seen_batch, conn, db_updates)
			_log.debug("PEERS_LAST_SEEN persisted %d peer(s)", len(db_updates))
		except Exception:
			_log.warning("Failed to persist last-seen data", exc_info=True)

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

			# NOTE: this still cannot reconstruct bytes between WG restart and next poll.
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
		str(peer["endpoint_ip"])
		for peer in peers_by_key.values()
		if isinstance(peer.get("endpoint_ip"), str) and str(peer.get("endpoint_ip")).strip()
	}
	geo_map = await _lookup_geo_map(unique_ips)
	for peer in peers_by_key.values():
		endpoint_ip = peer.get("endpoint_ip")
		if not isinstance(endpoint_ip, str) or not endpoint_ip:
			continue
		info = geo_map.get(endpoint_ip)
		if info:
			peer["country"] = info.get("country")
			peer["city"] = info.get("city")
			peer["asn"] = info.get("asn")
			peer["as_org"] = info.get("as_org")

	return sorted(
		peers_by_key.values(),
		key=lambda p: (not p["connected"], -int(p["latest_handshake"] or 0)),
	)


@router.get("/stats/peers-enriched")
async def get_peers_enriched(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Return all peers with live WireGuard stats and GeoIP/ASN enrichment."""
	global _peers_enriched_cache

	now_mono = time.monotonic()
	cached = _peers_enriched_cache
	if cached and (now_mono - cached[0]) < _PEERS_ENRICHED_CACHE_TTL_S:
		return ok_response(data={"peers": cached[1]})

	async with _peers_enriched_lock:
		now_mono = time.monotonic()
		cached = _peers_enriched_cache
		if cached and (now_mono - cached[0]) < _PEERS_ENRICHED_CACHE_TTL_S:
			return ok_response(data={"peers": cached[1]})

		result = await _build_peers_enriched(conn)
		_peers_enriched_cache = (time.monotonic(), result)

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
	deleted = await run_in_threadpool(tsdb.reset_all, tsdb_dir)
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
	global _peers_enriched_cache
	affected = await run_in_threadpool(reset_peer_logs, conn)
	_peers_enriched_cache = None
	return ok_response(
		message=f"Reset connection data for {affected} peer(s)",
		data={"affected": affected},
	)
