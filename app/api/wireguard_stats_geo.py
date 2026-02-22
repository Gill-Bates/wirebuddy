#!/usr/bin/env python3
#
# app/api/wireguard_stats_geo.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard geolocation and TSDB management API routes."""

from __future__ import annotations

from ..db.sqlite_peers import (
	get_all_peers,
	update_peers_last_seen_batch,
)

import logging
import sqlite3
import time
from pathlib import Path

from fastapi import APIRouter, Depends
from starlette.concurrency import run_in_threadpool

from ..db import tsdb
from ..utils.deps import get_conn, get_tsdb_dir
from ..utils.geoip import lookup_ip
from .auth import get_current_user, require_admin
from .response import ok_response
from .wireguard_utils import parse_wg_show_dump, run_wg_command, safe_int

_log = logging.getLogger(__name__)

router = APIRouter(tags=["wireguard"])

__all__ = ["router"]


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
	try:
		now = time.time()
		connected_threshold = 180  # 3 minutes – still "online"

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

		# Track locations by IP with list of peer names for multi-peer IPs
		seen_ips: dict[str, dict] = {}

		# 1. Parse wg show all dump for live stats
		code, stdout, stderr = await run_wg_command("wg", "show", "all", "dump")
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
			_log.debug("wg show all dump failed (code=%d): %s", code, stderr.strip() if stderr else "no output")

		# 2. Build location list from all peers with known IPs (live + DB)
		for pub_key, info in peer_db_info.items():
			ip_str = info.get("last_client_ip")
			if not ip_str:
				_log.debug("PEER_LOC skip %s: no IP", pub_key[:8])
				continue

			handshake_ts = info.get("last_handshake_at") or 0
			if handshake_ts == 0:
				_log.debug("PEER_LOC skip %s: no handshake", pub_key[:8])
				continue  # No handshake ever

			connected = (now - handshake_ts) < connected_threshold
			peer_name = info.get("name", pub_key[:8])

			if ip_str in seen_ips:
				seen_ips[ip_str]["count"] += 1
				seen_ips[ip_str]["names"].append(peer_name)
				# Upgrade to connected if any peer from this IP is connected
				if connected:
					seen_ips[ip_str]["connected"] = True
				continue

			# Lookup GeoIP data (async via threadpool for disk I/O)
			geo_info = await run_in_threadpool(lookup_ip, ip_str)
			if geo_info:
				_log.debug("PEER_LOC add %s ip=%s lat=%s lon=%s", pub_key[:8], ip_str, geo_info.get("lat"), geo_info.get("lon"))
				seen_ips[ip_str] = {
					"lat": geo_info.get("lat"),
					"lon": geo_info.get("lon"),
					"city": geo_info.get("city"),
					"country": geo_info.get("country"),
					"asn": geo_info.get("asn"),
					"as_org": geo_info.get("as_org"),
					"ip": ip_str,
					"name": peer_name,  # Primary peer name
					"names": [peer_name],  # List of all peer names at this IP
					"interface": info.get("interface"),
					"connected": connected,
					"count": 1,
				}
			else:
				_log.debug("PEER_LOC skip %s ip=%s: no geo data", pub_key[:8], ip_str)

		_log.info("PEER_LOC returning %d location(s)", len(seen_ips))
		locations = list(seen_ips.values())
		return ok_response(data={"locations": locations}, locations=locations)
	except Exception:
		_log.exception("Failed to get peer locations")
		return ok_response(data={"locations": []}, locations=[])


@router.get("/stats/peers-enriched")
async def get_peers_enriched(
	conn: sqlite3.Connection = Depends(get_conn),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Return all peers with live WireGuard stats and GeoIP / ASN data.

	Merges DB peer records with ``wg show all dump`` output and enriches
	each peer's endpoint IP via GeoLite2-City + GeoLite2-ASN.

	Client IP and last-handshake timestamp are **persisted** to the DB so
	they survive container restarts and are always available, even when
	``wg show`` has no live data for a peer.
	"""
	# 1. Load all peers from DB (async via threadpool)
	rows = await run_in_threadpool(get_all_peers, conn)
	peers_by_key: dict[str, dict] = {}
	for row in rows:
		peers_by_key[row["public_key"]] = {
			"id": row["id"],
			"name": row["name"],
			"public_key": row["public_key"],
			"allowed_ips": row["allowed_ips"],
			"peer_address": row["peer_address"],
			"interface": row["interface"],
			"is_enabled": bool(row["is_enabled"]),
			# Live stats (filled below, fall back to DB)
			"endpoint_ip": row["last_client_ip"],
			"endpoint": None,
			"latest_handshake": row["last_handshake_at"],
			"_db_handshake_at": row["last_handshake_at"] or 0,  # For comparison in update check
			"connected": False,
			"transfer_rx": 0,
			"transfer_tx": 0,
			# Geo / ASN (filled below)
			"country": None,
			"city": None,
			"asn": None,
			"as_org": None,
		}

	# 2. Parse wg show all dump for live stats
	now = time.time()
	threshold = 180  # 3 min – consider "connected"
	db_updates: list[tuple[str, int, str]] = []  # (client_ip, handshake_at, pub_key)

	try:
		code, stdout, stderr = await run_wg_command("wg", "show", "all", "dump")
		if code != 0:
			_log.debug("wg show all dump failed (code=%d): %s", code, stderr.strip() if stderr else "no output")
		else:
			wg_peers = parse_wg_show_dump(stdout)
			for wg_peer in wg_peers:
				if wg_peer.public_key not in peers_by_key:
					continue

				peer = peers_by_key[wg_peer.public_key]
				peer["endpoint"] = wg_peer.endpoint_raw
				peer["transfer_rx"] = wg_peer.rx
				peer["transfer_tx"] = wg_peer.tx

				# Keep last-seen/client-ip sticky and update only on newer handshakes.
				stored_hs = int(peer.get("_db_handshake_at") or 0)
				stored_ip = str(peer.get("endpoint_ip") or "").strip()
				if wg_peer.handshake_ts:
					# Never regress to an older timestamp from a transient wg state.
					current_hs = int(peer.get("latest_handshake") or 0)
					effective_hs = wg_peer.handshake_ts if wg_peer.handshake_ts >= current_hs else current_hs
					peer["latest_handshake"] = effective_hs
					peer["connected"] = (now - effective_hs) < threshold
					if wg_peer.client_ip:
						peer["endpoint_ip"] = wg_peer.client_ip

					# Persist only when handshake is newer; keep last known IP if endpoint is missing.
					if wg_peer.handshake_ts > stored_hs:
						persist_ip = wg_peer.client_ip or stored_ip
						if persist_ip:
							db_updates.append((persist_ip, wg_peer.handshake_ts, wg_peer.public_key))
							peer["_db_handshake_at"] = wg_peer.handshake_ts
							if not peer.get("endpoint_ip"):
								peer["endpoint_ip"] = persist_ip
							_log.debug("PEER_SEEN %s ip=%s handshake=%d (stored=%d)", wg_peer.public_key[:8], persist_ip, wg_peer.handshake_ts, stored_hs)
				elif wg_peer.client_ip:
					# Endpoint present but no handshake – still use live IP
					peer["endpoint_ip"] = wg_peer.client_ip
	except Exception:
		_log.warning("Failed to parse wg dump for enriched peers", exc_info=True)

	# Batch-persist updated last-seen data to DB (async via threadpool)
	if db_updates:
		try:
			await run_in_threadpool(update_peers_last_seen_batch, conn, db_updates)
			_log.info("PEERS_LAST_SEEN persisted %d peer(s)", len(db_updates))
		except Exception:
			_log.warning("Failed to persist last-seen data", exc_info=True)

	# 3. GeoIP + ASN enrichment for peers with known client IPs (async via threadpool)
	for peer in peers_by_key.values():
		ip_str = peer.get("endpoint_ip")
		if not ip_str:
			continue
		info = await run_in_threadpool(lookup_ip, ip_str)
		if info:
			peer["country"] = info.get("country")
			peer["city"] = info.get("city")
			peer["asn"] = info.get("asn")
			peer["as_org"] = info.get("as_org")

	# 4. Clean up internal fields before returning
	for peer in peers_by_key.values():
		peer.pop("_db_handshake_at", None)

	# 5. Sort: connected first, then by latest handshake (most recent first)
	result = sorted(
		peers_by_key.values(),
		key=lambda p: (not p["connected"], -(p["latest_handshake"] or 0)),
	)

	return ok_response(data={"peers": result}, peers=result)


# ---------------------------------------------------------------------------
# TSDB Stats & Management
# ---------------------------------------------------------------------------

@router.get("/stats/tsdb")
async def get_tsdb_stats(
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(get_current_user),
):
	"""Get TSDB storage statistics."""
	data = await run_in_threadpool(tsdb.get_db_stats, tsdb_dir)
	return ok_response(data=data, **data)


@router.delete("/stats/tsdb")
async def reset_tsdb(
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Reset/delete all TSDB data (admin only)."""
	deleted = await run_in_threadpool(tsdb.reset_all, tsdb_dir)
	return ok_response(
		message=f"TSDB reset: {deleted} peer directories deleted",
		deleted=deleted,
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
		series=stats.get("series", 0),
		rotated=stats.get("rotated", 0),
		pruned=stats.get("pruned", 0),
	)
