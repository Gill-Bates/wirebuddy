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
from pathlib import Path

from fastapi import APIRouter, Depends

from ..db import tsdb
from ..utils.deps import get_conn, get_tsdb_dir
from ..utils.geoip import lookup_ip
from .auth import get_current_user, require_admin
from .response import ok_response
from .wireguard_utils import safe_int, run_wg_command

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
	"""
	import time as _time

	try:
		code, stdout, stderr = await run_wg_command("wg", "show", "all", "dump")
		if code != 0:
			return ok_response(data={"locations": []}, locations=[])

		now = _time.time()
		connected_threshold = 180  # 3 minutes – still "online"

		# Build peer name lookup from DB
		all_db_peers = get_all_peers(conn)
		name_by_key: dict[str, str] = {
			p["public_key"]: (p["name"] or p["public_key"][:8])
			for p in all_db_peers if p["public_key"]
		}

		seen_ips: dict[str, dict] = {}  # deduplicate by IP
		last_iface: str | None = None

		for line in stdout.strip().split("\n"):
			if not line:
				continue
			parts = line.split("\t")

			pub_key: str | None = None
			endpoint_raw: str | None = None
			handshake_ts = 0
			iface: str | None = None

			# Interface header: iface, privkey, pubkey, listen_port, fwmark
			if len(parts) >= 5 and len(parts) < 8:
				last_iface = parts[0]
				continue

			# Peer line format A (9-col): iface, pubkey, psk, endpoint, allowed-ips, hs, rx, tx, keepalive
			if len(parts) >= 9:
				iface = parts[0] if parts[0] else last_iface
				if iface:
					last_iface = iface
				pub_key = parts[1]
				endpoint_raw = parts[3]
				handshake_ts = safe_int(parts[5])
			# Peer line format B (8-col): pubkey, psk, endpoint, allowed-ips, hs, rx, tx, keepalive
			elif len(parts) >= 8:
				pub_key = parts[0]
				endpoint_raw = parts[2]
				handshake_ts = safe_int(parts[4])
				iface = last_iface

			if not pub_key or not endpoint_raw or endpoint_raw == "(none)":
				continue
			# Include any peer that has ever had a handshake (endpoint known)
			if handshake_ts == 0:
				continue

			# Strip port from endpoint (handle IPv6 [addr]:port)
			if endpoint_raw.startswith("["):
				ip_str = endpoint_raw.split("]")[0].lstrip("[")
			else:
				ip_str = endpoint_raw.rsplit(":", 1)[0]

			connected = (now - handshake_ts) < connected_threshold

			if ip_str in seen_ips:
				seen_ips[ip_str]["count"] += 1
				# Upgrade to connected if any peer from this IP is connected
				if connected:
					seen_ips[ip_str]["connected"] = True
				continue

			info = lookup_ip(ip_str)
			if info:
				peer_name = name_by_key.get(pub_key, pub_key[:8] if pub_key else "")
				seen_ips[ip_str] = {
					"lat": info["lat"],
					"lon": info["lon"],
					"city": info["city"],
					"country": info["country"],
					"asn": info["asn"],
					"as_org": info["as_org"],
					"ip": ip_str,
					"name": peer_name,
					"interface": iface,
					"connected": connected,
					"count": 1,
				}

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
	import time as _time

	# 1. Load all peers from DB
	rows = get_all_peers(conn)
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
	now = _time.time()
	threshold = 180  # 3 min – consider "connected"
	db_updates: list[tuple[str, int, str]] = []  # (client_ip, handshake_at, pub_key)

	try:
		code, stdout, stderr = await run_wg_command("wg", "show", "all", "dump")
		if code != 0:
			_log.debug("wg show all dump failed (code=%d): %s", code, stderr.strip() if stderr else "no output")
		elif code == 0:
			last_iface: str | None = None
			for line in stdout.strip().split("\n"):
				if not line:
					continue
				parts = line.split("\t")
				pub_key: str | None = None
				endpoint_raw: str | None = None
				handshake_ts = 0
				rx = 0
				tx = 0

				# Interface header: iface, privkey, pubkey, listen_port, fwmark
				if len(parts) >= 5 and len(parts) < 8:
					last_iface = parts[0]
					continue

				# Peer line (format A): iface, pubkey, psk, endpoint, …
				if len(parts) >= 9:
					iface = parts[0] if parts[0] else last_iface
					if iface:
						last_iface = iface
					pub_key = parts[1]
					endpoint_raw = parts[3]
					handshake_ts = safe_int(parts[5])
					rx = safe_int(parts[6])
					tx = safe_int(parts[7])
				# Peer line (format B): pubkey, psk, endpoint, …
				elif len(parts) >= 8:
					pub_key = parts[0]
					endpoint_raw = parts[2]
					handshake_ts = safe_int(parts[4])
					rx = safe_int(parts[5])
					tx = safe_int(parts[6])

				if not pub_key or pub_key not in peers_by_key:
					continue

				peer = peers_by_key[pub_key]
				peer["endpoint"] = endpoint_raw if endpoint_raw and endpoint_raw != "(none)" else None
				peer["transfer_rx"] = rx
				peer["transfer_tx"] = tx

				# Extract client IP from endpoint (ip:port or [ipv6]:port)
				client_ip: str | None = None
				if endpoint_raw and endpoint_raw != "(none)":
					if endpoint_raw.startswith("["):
						client_ip = endpoint_raw.split("]")[0].lstrip("[")
					else:
						client_ip = endpoint_raw.rsplit(":", 1)[0]

				# Keep last-seen/client-ip sticky and update only on newer handshakes.
				stored_hs = int(peer.get("_db_handshake_at") or 0)
				stored_ip = str(peer.get("endpoint_ip") or "").strip()
				if handshake_ts:
					# Never regress to an older timestamp from a transient wg state.
					current_hs = int(peer.get("latest_handshake") or 0)
					effective_hs = handshake_ts if handshake_ts >= current_hs else current_hs
					peer["latest_handshake"] = effective_hs
					peer["connected"] = (now - effective_hs) < threshold
					if client_ip:
						peer["endpoint_ip"] = client_ip

					# Persist only when handshake is newer; keep last known IP if endpoint is missing.
					if handshake_ts > stored_hs:
						persist_ip = client_ip or stored_ip
						if persist_ip:
							db_updates.append((persist_ip, handshake_ts, pub_key))
							peer["_db_handshake_at"] = handshake_ts
							if not peer.get("endpoint_ip"):
								peer["endpoint_ip"] = persist_ip
							_log.debug("PEER_SEEN %s ip=%s handshake=%d (stored=%d)", pub_key[:8], persist_ip, handshake_ts, stored_hs)
				elif client_ip:
					# Endpoint present but no handshake – still use live IP
					peer["endpoint_ip"] = client_ip
	except Exception:
		_log.warning("Failed to parse wg dump for enriched peers", exc_info=True)

	# Batch-persist updated last-seen data to DB
	if db_updates:
		try:
			update_peers_last_seen_batch(conn, db_updates)
			_log.info("PEERS_LAST_SEEN persisted %d peer(s)", len(db_updates))
		except Exception:
			_log.warning("Failed to persist last-seen data", exc_info=True)

	# 3. GeoIP + ASN enrichment for peers with known client IPs
	for peer in peers_by_key.values():
		ip_str = peer.get("endpoint_ip")
		if not ip_str:
			continue
		info = lookup_ip(ip_str)
		if info:
			peer["country"] = info["country"]
			peer["city"] = info["city"]
			peer["asn"] = info["asn"]
			peer["as_org"] = info["as_org"]

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
	data = tsdb.get_db_stats(tsdb_dir)
	return ok_response(data=data, **data)


@router.delete("/stats/tsdb")
async def reset_tsdb(
	tsdb_dir: Path = Depends(get_tsdb_dir),
	_: sqlite3.Row = Depends(require_admin),
):
	"""Reset/delete all TSDB data (admin only)."""
	deleted = tsdb.reset_all(tsdb_dir)
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
	stats = tsdb.run_maintenance(tsdb_dir)
	return ok_response(
		message="TSDB maintenance completed",
		data=stats,
		series=stats.get("series", 0),
		rotated=stats.get("rotated", 0),
		pruned=stats.get("pruned", 0),
	)
