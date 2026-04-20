#!/usr/bin/env python3
#
# app/api/wireguard_stats_country.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Traffic-by-country API endpoint.

Shows where WireGuard clients' **internet traffic goes** by analysing
the kernel connection tracking table (conntrack).  Each destination IP
is resolved to a country via GeoLite2-City.

Data pipeline
~~~~~~~~~~~~~
1. Scheduler task (``_sample_country_traffic`` in main.py, every 30 s):
   - Reads ``/proc/net/nf_conntrack``
   - Filters connections originating from WireGuard subnets
   - Computes byte deltas per destination country since last sample
   - Stores a single JSON snapshot in TSDB

2. This endpoint (on demand):
   - Queries TSDB snapshots for the requested time window
   - Sums per-country deltas across all snapshots
   - Returns the aggregated result sorted by total traffic

No external daemons, no InfluxDB, no NetFlow exporter required.
"""

from __future__ import annotations

import logging
import math
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from ..db import tsdb
from ..utils.deps import get_tsdb_dir
from ..utils.time import utcnow
from .auth import require_admin
from .response import ok_response
from .wireguard_stats import TRAFFIC_RANGE_TO_HOURS
from .wireguard_utils import bytes_to_unit, select_display_unit

_log = logging.getLogger(__name__)

router = APIRouter(tags=["wireguard"])

__all__ = ["router"]

# Synthetic TSDB key for country traffic snapshots (written by scheduler)
GEO_TRAFFIC_KEY = "__geo_traffic__"
_TRAFFIC_SNAPSHOT_METRIC = "snapshot"
GEO_TRAFFIC_METRIC = _TRAFFIC_SNAPSHOT_METRIC

# Max data points to query.
# At 30 s sampling, 100k points cover ~34.7 days, so larger windows are truncated.
_MAX_POINTS = 100_000

# Cap peer names per country in the response
_MAX_PEER_NAMES = 20


# ---------------------------------------------------------------------------
# Query Result Cache (TTL-based)
# ---------------------------------------------------------------------------
# Scanning TSDB JSONL files for long time ranges (30d+) is expensive.
# Cache results for a short TTL matching the scheduler sampling interval.

_CACHE_TTL_SECONDS = 30.0  # Match scheduler sampling interval
_CACHE_MAX_ENTRIES = 50    # Bounded LRU (hours × peer combinations)


@dataclass
class _CacheEntry:
	"""Cached query result with timestamp."""
	data: Any
	ts: float


_country_cache: dict[tuple[Path, int, str | None], _CacheEntry] = {}
_asn_cache: dict[tuple[Path, int, str | None], _CacheEntry] = {}
_cache_lock = threading.RLock()


def _cache_get(cache: dict, key: tuple) -> Any | None:
	"""Get cached value if still valid (within TTL)."""
	with _cache_lock:
		entry = cache.get(key)
		if entry is None:
			return None
		if time.monotonic() - entry.ts > _CACHE_TTL_SECONDS:
			# Expired — remove and return None
			cache.pop(key, None)
			return None
		return entry.data


def _cache_set(cache: dict, key: tuple, value: Any) -> None:
	"""Store value in cache with current timestamp."""
	with _cache_lock:
		# Evict oldest entries if at capacity
		while len(cache) >= _CACHE_MAX_ENTRIES:
			# Find oldest entry by timestamp
			oldest_key = min(cache.keys(), key=lambda k: cache[k].ts)
			cache.pop(oldest_key, None)
		cache[key] = _CacheEntry(data=value, ts=time.monotonic())


def _cache_invalidate_all() -> None:
	"""Clear all caches (called on settings change, etc.)."""
	with _cache_lock:
		_country_cache.clear()
		_asn_cache.clear()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class CountryEntry(BaseModel):
	code: str
	name: str
	rx: float
	tx: float
	total: float
	peers: int
	peer_names: list[str]
	peer_names_truncated: bool  # True when the peer list was capped at _MAX_PEER_NAMES


class CountryTrafficData(BaseModel):
	countries: list[CountryEntry]
	display_unit: str
	hours: int
	total_countries: int


# ISO 3166-1 country names (subset covering >99 % of real-world traffic).
# Keeps us dependency-free — no pycountry / babel needed.
_COUNTRY_NAMES: dict[str, str] = {
	"AD": "Andorra", "AE": "United Arab Emirates", "AF": "Afghanistan",
	"AG": "Antigua and Barbuda", "AL": "Albania", "AM": "Armenia",
	"AO": "Angola", "AR": "Argentina", "AT": "Austria", "AU": "Australia",
	"AZ": "Azerbaijan", "BA": "Bosnia and Herzegovina", "BB": "Barbados",
	"BD": "Bangladesh", "BE": "Belgium", "BF": "Burkina Faso",
	"BG": "Bulgaria", "BH": "Bahrain", "BI": "Burundi", "BJ": "Benin",
	"BN": "Brunei", "BO": "Bolivia", "BR": "Brazil", "BS": "Bahamas",
	"BT": "Bhutan", "BW": "Botswana", "BY": "Belarus", "BZ": "Belize",
	"CA": "Canada", "CD": "DR Congo", "CF": "Central African Republic",
	"CG": "Congo", "CH": "Switzerland", "CI": "Côte d'Ivoire",
	"CL": "Chile", "CM": "Cameroon", "CN": "China", "CO": "Colombia",
	"CR": "Costa Rica", "CU": "Cuba", "CV": "Cape Verde", "CY": "Cyprus",
	"CZ": "Czechia", "DE": "Germany", "DJ": "Djibouti", "DK": "Denmark",
	"DM": "Dominica", "DO": "Dominican Republic", "DZ": "Algeria",
	"EC": "Ecuador", "EE": "Estonia", "EG": "Egypt",
	"ER": "Eritrea", "ES": "Spain", "ET": "Ethiopia", "FI": "Finland",
	"FJ": "Fiji", "FR": "France", "GA": "Gabon", "GB": "United Kingdom",
	"GD": "Grenada", "GE": "Georgia", "GH": "Ghana", "GM": "Gambia",
	"GN": "Guinea", "GQ": "Equatorial Guinea", "GR": "Greece",
	"GT": "Guatemala", "GW": "Guinea-Bissau", "GY": "Guyana",
	"HK": "Hong Kong", "HN": "Honduras", "HR": "Croatia", "HT": "Haiti",
	"HU": "Hungary", "ID": "Indonesia", "IE": "Ireland", "IL": "Israel",
	"IN": "India", "IQ": "Iraq", "IR": "Iran", "IS": "Iceland",
	"IT": "Italy", "JM": "Jamaica", "JO": "Jordan", "JP": "Japan",
	"KE": "Kenya", "KG": "Kyrgyzstan", "KH": "Cambodia", "KI": "Kiribati",
	"KM": "Comoros", "KN": "Saint Kitts and Nevis", "KP": "North Korea",
	"KR": "South Korea", "KW": "Kuwait", "KZ": "Kazakhstan",
	"LA": "Laos", "LB": "Lebanon", "LC": "Saint Lucia",
	"LI": "Liechtenstein", "LK": "Sri Lanka", "LR": "Liberia",
	"LS": "Lesotho", "LT": "Lithuania", "LU": "Luxembourg",
	"LV": "Latvia", "LY": "Libya", "MA": "Morocco", "MC": "Monaco",
	"MD": "Moldova", "ME": "Montenegro", "MG": "Madagascar",
	"MK": "North Macedonia", "ML": "Mali", "MM": "Myanmar",
	"MN": "Mongolia", "MO": "Macau", "MR": "Mauritania", "MT": "Malta",
	"MU": "Mauritius", "MV": "Maldives", "MW": "Malawi", "MX": "Mexico",
	"MY": "Malaysia", "MZ": "Mozambique", "NA": "Namibia", "NE": "Niger",
	"NG": "Nigeria", "NI": "Nicaragua", "NL": "Netherlands",
	"NO": "Norway", "NP": "Nepal", "NR": "Nauru", "NZ": "New Zealand",
	"OM": "Oman", "PA": "Panama", "PE": "Peru", "PG": "Papua New Guinea",
	"PH": "Philippines", "PK": "Pakistan", "PL": "Poland",
	"PT": "Portugal", "PY": "Paraguay", "QA": "Qatar", "RO": "Romania",
	"RS": "Serbia", "RU": "Russia", "RW": "Rwanda", "SA": "Saudi Arabia",
	"SB": "Solomon Islands", "SC": "Seychelles", "SD": "Sudan",
	"SE": "Sweden", "SG": "Singapore", "SI": "Slovenia", "SK": "Slovakia",
	"SL": "Sierra Leone", "SM": "San Marino", "SN": "Senegal",
	"SO": "Somalia", "SR": "Suriname", "SS": "South Sudan",
	"ST": "São Tomé and Príncipe", "SV": "El Salvador", "SY": "Syria",
	"SZ": "Eswatini", "TD": "Chad", "TG": "Togo", "TH": "Thailand",
	"TJ": "Tajikistan", "TL": "Timor-Leste", "TM": "Turkmenistan",
	"TN": "Tunisia", "TO": "Tonga", "TR": "Turkey", "TT": "Trinidad and Tobago",
	"TV": "Tuvalu", "TW": "Taiwan", "TZ": "Tanzania", "UA": "Ukraine",
	"UG": "Uganda", "US": "United States", "UY": "Uruguay",
	"UZ": "Uzbekistan", "VA": "Vatican City", "VE": "Venezuela",
	"VN": "Vietnam", "VU": "Vanuatu", "WS": "Samoa", "XK": "Kosovo",
	"YE": "Yemen", "ZA": "South Africa", "ZM": "Zambia", "ZW": "Zimbabwe",
	# Synthetic code for peers whose IP cannot be resolved
	"XX": "Unknown",
}


def _country_name(iso: str) -> str:
	"""Return human-readable country name for ISO 3166-1 alpha-2 code."""
	return _COUNTRY_NAMES.get(iso, iso)


def _validate_peer_filter(peer: str | None) -> str | None:
	"""Validate peer filter parameter.

	Args:
		peer: Peer name to validate.

	Raises:
		HTTPException: If peer name is invalid.

	Returns:
		Validated peer name or None.
	"""
	if peer is None:
		return None

	if not peer.strip():
		raise HTTPException(status_code=400, detail="Peer name cannot be empty")

	if len(peer) > 255:
		raise HTTPException(status_code=400, detail="Peer name too long (max 255 characters)")

	# Basic sanitization: allow alphanumeric, underscore, hyphen, dot, hash
	if not all(c.isalnum() or c in "._- #" for c in peer):
		raise HTTPException(
			status_code=400,
			detail="Peer name contains invalid characters (allowed: alphanumeric, '.', '_', '-', '#', space)"
		)

	return peer


def _aggregate_snapshots(
	points: list,
	peer_filter: str | None,
) -> dict[str, dict[str, Any]]:
	"""Extract and aggregate traffic data from TSDB snapshots.

	Args:
		points: TSDB query results.
		peer_filter: Optional peer name to filter by.

	Returns:
		Dict mapping identifier (country code or ASN) to aggregated traffic stats.
	"""
	agg: dict[str, dict[str, Any]] = {}

	for pt in points:
		snapshot = pt.value
		if not isinstance(snapshot, dict):
			continue

		for key, info in snapshot.items():
			if not isinstance(info, dict):
				continue

			# Extract rx/tx based on peer filter
			if peer_filter:
				by_peer = info.get("by_peer", {})
				if not isinstance(by_peer, dict):
					continue
				peer_data = by_peer.get(peer_filter)
				if not peer_data:
					continue  # This peer has no traffic to this entry in this snapshot
				rx = int(peer_data.get("rx", 0))
				tx = int(peer_data.get("tx", 0))
			else:
				# No filter: use aggregated values
				rx = int(info.get("rx", 0))
				tx = int(info.get("tx", 0))

			if rx == 0 and tx == 0:
				continue

			if key not in agg:
				agg[key] = {
					"rx": 0,
					"tx": 0,
					"name": info.get("name", "Unknown"),
					"peers": set(),
					"peers_seen": set(),
				}

			agg[key]["rx"] += rx
			agg[key]["tx"] += tx

			# Collect peer names (capped at _MAX_PEER_NAMES)
			if peer_filter:
				# When filtering by a specific peer, the result cardinality is 1.
				# We intentionally skip cap checks in this branch.
				agg[key]["peers_seen"].add(peer_filter)
				agg[key]["peers"].add(peer_filter)
			else:
				peers = info.get("peers")
				if peers:
					for name in peers:
						agg[key]["peers_seen"].add(name)
						if len(agg[key]["peers"]) < _MAX_PEER_NAMES:
							agg[key]["peers"].add(name)

	# Freeze sets into sorted lists for deterministic JSON serialization
	for info in agg.values():
		info["peers"] = sorted(info["peers"])

	return agg


def _compute_display_values(
	info: dict[str, Any],
	display_unit: str,
	*,
	entity_type: str,
	entity_key: str,
) -> tuple[float, float, float]:
	"""Convert raw rx/tx bytes to display unit and validate finite results."""
	rx_display = round(bytes_to_unit(info["rx"], display_unit), 2)
	tx_display = round(bytes_to_unit(info["tx"], display_unit), 2)
	total_display = round(bytes_to_unit(info["rx"] + info["tx"], display_unit), 2)

	if not all(math.isfinite(v) and v >= 0 for v in (rx_display, tx_display, total_display)):
		_log.warning(
			"Invalid traffic values for %s %s: rx=%s tx=%s total=%s",
			entity_type,
			entity_key,
			rx_display,
			tx_display,
			total_display,
		)
		raise ValueError("Non-finite or negative traffic calculation")

	return rx_display, tx_display, total_display


def _build_country_entry(code: str, info: dict[str, Any], display_unit: str) -> CountryEntry:
	"""Build a CountryEntry from aggregated data.

	Args:
		code: ISO 3166-1 alpha-2 country code.
		info: Aggregated traffic statistics.
		display_unit: Unit for traffic display (B, KB, MB, GB, TB).

	Returns:
		CountryEntry model.
	"""
	try:
		rx_display, tx_display, total_display = _compute_display_values(
			info,
			display_unit,
			entity_type="country",
			entity_key=code,
		)

		return CountryEntry(
			code=code,
			name=_country_name(code),
			rx=rx_display,
			tx=tx_display,
			total=total_display,
			peers=len(info["peers"]),
			peer_names=info["peers"],
			peer_names_truncated=len(info["peers_seen"]) > _MAX_PEER_NAMES,
		)
	except (ValueError, OverflowError) as exc:
		_log.warning("Failed to build country entry for %s: %s", code, exc)
		raise


def _build_asn_entry(asn_key: str, info: dict[str, Any], display_unit: str) -> ASNEntry:
	"""Build an ASNEntry from aggregated data.

	Args:
		asn_key: ASN number as string.
		info: Aggregated traffic statistics.
		display_unit: Unit for traffic display (B, KB, MB, GB, TB).

	Returns:
		ASNEntry model.
	"""
	try:
		rx_display, tx_display, total_display = _compute_display_values(
			info,
			display_unit,
			entity_type="ASN",
			entity_key=asn_key,
		)

		return ASNEntry(
			asn=asn_key,
			name=info["name"],
			rx=rx_display,
			tx=tx_display,
			total=total_display,
			peers=len(info["peers"]),
			peer_names=info["peers"],
			peer_names_truncated=len(info["peers_seen"]) > _MAX_PEER_NAMES,
		)
	except (ValueError, OverflowError) as exc:
		_log.warning("Failed to build ASN entry for %s: %s", asn_key, exc)
		raise


def _compute_traffic_generic(
	tsdb_dir: Path,
	hours: int,
	peer_filter: str | None,
	*,
	traffic_key: str,
	traffic_metric: str,
	log_prefix: str,
	build_entry_fn: Callable[[str, dict[str, Any], str], Any],
	build_empty_result_fn: Callable[[int], Any],
	build_result_fn: Callable[[list[Any], str, int], Any],
) -> Any:
	"""Generic TSDB traffic aggregation for country and ASN endpoints."""
	since = utcnow() - timedelta(hours=hours)

	try:
		points = tsdb.query(
			tsdb_dir,
			peer_key=traffic_key,
			metric=traffic_metric,
			since=since,
			limit=_MAX_POINTS,
		)
	except Exception as exc:
		_log.error("%s TSDB query failed: %s", log_prefix, exc, exc_info=True)
		return build_empty_result_fn(hours)

	if len(points) >= _MAX_POINTS:
		_log.warning(
			"%s query hit %d-point cap for %dh window; results may be truncated",
			log_prefix,
			_MAX_POINTS,
			hours,
		)

	agg = _aggregate_snapshots(points, peer_filter)
	max_bytes = max((max(info["rx"], info["tx"]) for info in agg.values()), default=0)
	display_unit = select_display_unit(max_bytes)

	entries: list[Any] = []
	for key, info in sorted(
		agg.items(),
		key=lambda kv: kv[1]["rx"] + kv[1]["tx"],
		reverse=True,
	):
		try:
			entry = build_entry_fn(key, info, display_unit)
			if entry.total < 0.01:
				continue
			entries.append(entry)
		except (ValueError, ZeroDivisionError, OverflowError):
			continue

	_log.debug(
		"%s hours=%d points=%d entries=%d display_unit=%s peer_filter=%s",
		log_prefix,
		hours,
		len(points),
		len(entries),
		display_unit,
		peer_filter,
	)

	return build_result_fn(entries, display_unit, hours)


def _compute_country_traffic(
	tsdb_dir: Path,
	hours: int,
	peer_filter: str | None = None,
) -> CountryTrafficData:
	"""Sum TSDB country snapshots for the requested time window (blocking).

	Each TSDB point contains a JSON dict of per-country deltas produced
	by the scheduler task::

	    {"DE": {"rx": 1234, "tx": 5678, "peers": ["Alice"], "by_peer": {"Alice": {"rx": 1234, "tx": 5678}}}, ...}

	This function sums all such snapshots within ``[now - hours, now]``.

	Args:
		tsdb_dir: Path to TSDB directory.
		hours: Number of hours of history to query.
		peer_filter: Optional peer name to filter by. When set, only traffic
		             attributed to this specific peer is included.
	"""
	return _compute_traffic_generic(
		tsdb_dir,
		hours,
		peer_filter,
		traffic_key=GEO_TRAFFIC_KEY,
		traffic_metric=GEO_TRAFFIC_METRIC,
		log_prefix="COUNTRY_TRAFFIC",
		build_entry_fn=_build_country_entry,
		build_empty_result_fn=lambda h: CountryTrafficData(
			countries=[],
			display_unit="B",
			hours=h,
			total_countries=0,
		),
		build_result_fn=lambda countries, unit, h: CountryTrafficData(
			countries=countries,
			display_unit=unit,
			hours=h,
			total_countries=len(countries),
		),
	)


def _resolve_hours(range_key: str | None, hours: int) -> int:
	"""Resolve preset range key to hours, preserving explicit hours as fallback."""
	if range_key:
		return TRAFFIC_RANGE_TO_HOURS.get(range_key, hours)
	return hours


def _get_user_identifier(user: sqlite3.Row) -> str:
	"""Return username or fallback identifier for structured logs."""
	if hasattr(user, "keys") and "username" in user.keys():
		return str(user["username"])
	if hasattr(user, "keys") and "id" in user.keys():
		return str(user["id"])
	return "unknown"


async def _handle_traffic_request(
	*,
	cache: dict[tuple[Path, int, str | None], _CacheEntry],
	compute_fn: Callable[[Path, int, str | None], Any],
	log_prefix: str,
	tsdb_dir: Path,
	hours: int,
	peer: str | None,
	current_user: sqlite3.Row,
) -> Any:
	"""Shared endpoint flow for country and ASN traffic queries."""
	resolved_hours = _resolve_hours(None, hours)
	validated_peer = _validate_peer_filter(peer)
	cache_key = (tsdb_dir, resolved_hours, validated_peer)

	cached = _cache_get(cache, cache_key)
	if cached is not None:
		_log.debug("%s cache hit hours=%d peer_filter=%s", log_prefix, resolved_hours, validated_peer)
		return ok_response(data=cached)

	_log.info(
		"%s query by user=%s hours=%d peer_filter=%s",
		log_prefix,
		_get_user_identifier(current_user),
		resolved_hours,
		validated_peer,
	)

	t0 = time.monotonic()
	data = await run_in_threadpool(compute_fn, tsdb_dir, resolved_hours, validated_peer)
	elapsed_ms = (time.monotonic() - t0) * 1000
	if elapsed_ms > 1000:
		_log.warning("%s slow query: %.0fms hours=%d peer_filter=%s", log_prefix, elapsed_ms, resolved_hours, validated_peer)
	else:
		_log.debug("%s query: %.0fms hours=%d", log_prefix, elapsed_ms, resolved_hours)

	result = data.model_dump()
	_cache_set(cache, cache_key, result)
	return ok_response(data=result)


@router.get("/stats/traffic-by-country", response_model=None)
async def get_traffic_by_country(
	hours: int = Query(24, ge=1, le=8760, description="Hours of history (1-8760)"),
	range_key: str | None = Query(None, pattern="^(6h|24h|7d|30d|90d|180d|y1)$"),
	peer: str | None = Query(None, description="Filter by peer name", max_length=255),
	tsdb_dir: Path = Depends(get_tsdb_dir),
	current_user: sqlite3.Row = Depends(require_admin),
):
	"""Traffic aggregated by **destination** country (admin only).

	Analyses where WireGuard clients' internet traffic goes by summing
	per-country byte deltas from conntrack snapshots stored in TSDB.

	Query params:
		hours:     Number of hours (1-8760).
		range_key: Preset (6h|24h|7d|30d|90d|180d|y1), overrides *hours*.
		peer:      Optional peer name to filter by.

	Returns:
		``{countries: [{code, name, rx, tx, total, peers, peer_names}, ...],
		  display_unit, hours, total_countries}``
	"""
	resolved_hours = _resolve_hours(range_key, hours)
	return await _handle_traffic_request(
		cache=_country_cache,
		compute_fn=_compute_country_traffic,
		log_prefix="COUNTRY_TRAFFIC",
		tsdb_dir=tsdb_dir,
		hours=resolved_hours,
		peer=peer,
		current_user=current_user,
	)


# ---------------------------------------------------------------------------
# ASN Traffic
# ---------------------------------------------------------------------------

ASN_TRAFFIC_KEY = "__asn_traffic__"
ASN_TRAFFIC_METRIC = _TRAFFIC_SNAPSHOT_METRIC


class ASNEntry(BaseModel):
	asn: str
	name: str
	rx: float
	tx: float
	total: float
	peers: int
	peer_names: list[str]
	peer_names_truncated: bool


class ASNTrafficData(BaseModel):
	asns: list[ASNEntry]
	display_unit: str
	hours: int
	total_asns: int


def _compute_asn_traffic(
	tsdb_dir: Path,
	hours: int,
	peer_filter: str | None = None,
) -> ASNTrafficData:
	"""Sum TSDB ASN snapshots for the requested time window (blocking).

	Each TSDB point contains a JSON dict of per-ASN deltas::

	    {"13335": {"rx": 1234, "tx": 5678, "name": "Cloudflare", "peers": ["Alice"], "by_peer": {"Alice": {"rx": 1234, "tx": 5678}}}, ...}

	This function sums all such snapshots within ``[now - hours, now]``.

	Args:
		tsdb_dir: Path to TSDB directory.
		hours: Number of hours of history to query.
		peer_filter: Optional peer name to filter by. When set, only traffic
		             attributed to this specific peer is included.
	"""
	return _compute_traffic_generic(
		tsdb_dir,
		hours,
		peer_filter,
		traffic_key=ASN_TRAFFIC_KEY,
		traffic_metric=ASN_TRAFFIC_METRIC,
		log_prefix="ASN_TRAFFIC",
		build_entry_fn=_build_asn_entry,
		build_empty_result_fn=lambda h: ASNTrafficData(
			asns=[],
			display_unit="B",
			hours=h,
			total_asns=0,
		),
		build_result_fn=lambda asns, unit, h: ASNTrafficData(
			asns=asns,
			display_unit=unit,
			hours=h,
			total_asns=len(asns),
		),
	)


@router.get("/stats/traffic-by-asn", response_model=None)
async def get_traffic_by_asn(
	hours: int = Query(24, ge=1, le=8760, description="Hours of history (1-8760)"),
	range_key: str | None = Query(None, pattern="^(6h|24h|7d|30d|90d|180d|y1)$"),
	peer: str | None = Query(None, description="Filter by peer name", max_length=255),
	tsdb_dir: Path = Depends(get_tsdb_dir),
	current_user: sqlite3.Row = Depends(require_admin),
):
	"""Traffic aggregated by **destination** ASN (admin only).

	Analyses where WireGuard clients' internet traffic goes by summing
	per-ASN byte deltas from conntrack snapshots stored in TSDB.

	Query params:
		hours:     Number of hours (1-8760).
		range_key: Preset (6h|24h|7d|30d|90d|180d|y1), overrides *hours*.
		peer:      Optional peer name to filter by.

	Returns:
		``{asns: [{asn, name, rx, tx, total, peers, peer_names}, ...],
		  display_unit, hours, total_asns}``
	"""
	resolved_hours = _resolve_hours(range_key, hours)
	return await _handle_traffic_request(
		cache=_asn_cache,
		compute_fn=_compute_asn_traffic,
		log_prefix="ASN_TRAFFIC",
		tsdb_dir=tsdb_dir,
		hours=resolved_hours,
		peer=peer,
		current_user=current_user,
	)
