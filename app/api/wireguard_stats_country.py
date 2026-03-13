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
import sqlite3
from datetime import timedelta
from enum import Enum
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, validator
from starlette.concurrency import run_in_threadpool

from ..db import tsdb
from ..utils.deps import get_tsdb_dir
from ..utils.time import utcnow
from .auth import get_current_user
from .response import ok_response
from .wireguard_stats import TRAFFIC_RANGE_TO_HOURS
from .wireguard_utils import bytes_to_unit, select_display_unit

_log = logging.getLogger(__name__)

router = APIRouter(tags=["wireguard"])

__all__ = ["router"]

# Synthetic TSDB key for country traffic snapshots (written by scheduler)
GEO_TRAFFIC_KEY = "__geo_traffic__"
GEO_TRAFFIC_METRIC = "snapshot"

# Max data points to query (100 k ≈ 35 days at 30 s intervals)
_MAX_POINTS = 100_000

# Cap peer names per country in the response
_MAX_PEER_NAMES = 20


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
	flag: str | None


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


class TrafficType(Enum):
	"""Traffic aggregation type."""
	COUNTRY = "country"
	ASN = "asn"


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

	# Basic sanitization: allow alphanumeric, underscore, hyphen, dot
	if not all(c.isalnum() or c in "._- " for c in peer):
		raise HTTPException(
			status_code=400,
			detail="Peer name contains invalid characters (allowed: alphanumeric, '.', '_', '-', space)"
		)

	return peer


def _aggregate_snapshots(
	points: list,
	peer_filter: str | None,
	traffic_type: TrafficType,
) -> dict[str, dict[str, Any]]:
	"""Extract and aggregate traffic data from TSDB snapshots.

	Args:
		points: TSDB query results.
		peer_filter: Optional peer name to filter by.
		traffic_type: Type of traffic aggregation (country or ASN).

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
					"name": info.get("name", "Unknown"),  # For ASN; ignored for country
					"peers": set(),
					"peers_seen": 0,
				}

			agg[key]["rx"] += rx
			agg[key]["tx"] += tx

			# Collect peer names (capped at _MAX_PEER_NAMES)
			if peer_filter:
				agg[key]["peers_seen"] += 1
				agg[key]["peers"].add(peer_filter)
			else:
				for name in info.get("peers", []):
					agg[key]["peers_seen"] += 1
					if len(agg[key]["peers"]) < _MAX_PEER_NAMES:
						agg[key]["peers"].add(name)

	# Freeze sets into sorted lists for deterministic JSON serialization
	for info in agg.values():
		info["peers"] = sorted(info["peers"])

	return agg


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
		rx_display = round(bytes_to_unit(info["rx"], display_unit), 2)
		tx_display = round(bytes_to_unit(info["tx"], display_unit), 2)
		total_display = round(bytes_to_unit(info["rx"] + info["tx"], display_unit), 2)

		# Validate results are finite
		if not all(0 <= val < float('inf') for val in (rx_display, tx_display, total_display)):
			_log.warning("Invalid traffic values for country %s: rx=%s tx=%s", code, rx_display, tx_display)
			raise ValueError("Invalid traffic calculation")

		return CountryEntry(
			code=code,
			name=_country_name(code),
			rx=rx_display,
			tx=tx_display,
			total=total_display,
			peers=len(info["peers"]),
			peer_names=info["peers"],
			peer_names_truncated=info["peers_seen"] > _MAX_PEER_NAMES,
			flag=f"/static/vendor/images/flags/{code.lower()}.svg" if code != "XX" else None,
		)
	except (ValueError, ZeroDivisionError, OverflowError) as exc:
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
		rx_display = round(bytes_to_unit(info["rx"], display_unit), 2)
		tx_display = round(bytes_to_unit(info["tx"], display_unit), 2)
		total_display = round(bytes_to_unit(info["rx"] + info["tx"], display_unit), 2)

		# Validate results are finite
		if not all(0 <= val < float('inf') for val in (rx_display, tx_display, total_display)):
			_log.warning("Invalid traffic values for ASN %s: rx=%s tx=%s", asn_key, rx_display, tx_display)
			raise ValueError("Invalid traffic calculation")

		return ASNEntry(
			asn=asn_key,
			name=info["name"],
			rx=rx_display,
			tx=tx_display,
			total=total_display,
			peers=len(info["peers"]),
			peer_names=info["peers"],
			peer_names_truncated=info["peers_seen"] > _MAX_PEER_NAMES,
		)
	except (ValueError, ZeroDivisionError, OverflowError) as exc:
		_log.warning("Failed to build ASN entry for %s: %s", asn_key, exc)
		raise


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
	since = utcnow() - timedelta(hours=hours)

	try:
		points = tsdb.query(
			tsdb_dir,
			peer_key=GEO_TRAFFIC_KEY,
			metric=GEO_TRAFFIC_METRIC,
			since=since,
			limit=_MAX_POINTS,
		)
	except Exception as exc:
		_log.error("COUNTRY_TRAFFIC TSDB query failed: %s", exc, exc_info=True)
		# Return empty result on TSDB failure
		return CountryTrafficData(
			countries=[],
			display_unit="B",
			hours=hours,
			total_countries=0,
		)

	if len(points) >= _MAX_POINTS:
		_log.warning(
			"COUNTRY_TRAFFIC query hit %d-point cap for %dh window; results may be truncated",
			_MAX_POINTS, hours,
		)

	# Aggregate across all snapshot points using common logic
	country_agg = _aggregate_snapshots(points, peer_filter, TrafficType.COUNTRY)

	# Determine display unit from the max value (int 0 → "B", always valid)
	max_bytes = max(
		(max(info["rx"], info["tx"]) for info in country_agg.values()),
		default=0
	)
	display_unit = select_display_unit(max_bytes)

	# Build Pydantic models for validation and consistent serialisation
	countries: list[CountryEntry] = []
	for cc, info in sorted(
		country_agg.items(),
		key=lambda kv: kv[1]["rx"] + kv[1]["tx"],
		reverse=True,
	):
		try:
			entry = _build_country_entry(cc, info, display_unit)
			# Skip entries with negligible traffic (< 0.01 in display unit)
			if entry.total < 0.01:
				continue
			countries.append(entry)
		except (ValueError, ZeroDivisionError, OverflowError):
			# Skip entries with invalid values
			continue

	_log.debug(
		"COUNTRY_TRAFFIC hours=%d points=%d countries=%d display_unit=%s peer_filter=%s",
		hours, len(points), len(countries), display_unit, peer_filter,
	)

	return CountryTrafficData(
		countries=countries,
		display_unit=display_unit,
		hours=hours,
		total_countries=len(countries),
	)


@router.get("/stats/traffic-by-country", response_model=None)
async def get_traffic_by_country(
	hours: int = Query(24, ge=1, le=8760, description="Hours of history (1-8760)"),
	range_key: str | None = Query(None, pattern="^(6h|24h|7d|30d|90d|180d|y1)$"),
	peer: str | None = Query(None, description="Filter by peer name", max_length=255),
	tsdb_dir: Path = Depends(get_tsdb_dir),
	current_user: sqlite3.Row = Depends(get_current_user),
):
	"""Traffic aggregated by **destination** country (admin only).

	Analyses where WireGuard clients' internet traffic goes by summing
	per-country byte deltas from conntrack snapshots stored in TSDB.

	Query params:
		hours:     Number of hours (1-8760).
		range_key: Preset (6h|24h|7d|30d|90d|180d|y1), overrides *hours*.
		peer:      Optional peer name to filter by.

	Returns:
		``{countries: [{code, name, rx, tx, total, peers, peer_names, flag}, ...],
		  display_unit, hours, total_countries}``
	"""
	if range_key:
		hours = TRAFFIC_RANGE_TO_HOURS.get(range_key, hours)

	# Validate and log request
	validated_peer = _validate_peer_filter(peer)
	_log.info(
		"COUNTRY_TRAFFIC query by user=%s hours=%d peer_filter=%s",
		current_user["username"] if "username" in current_user.keys() else current_user.get("id", "unknown"),
		hours,
		validated_peer,
	)

	data: CountryTrafficData = await run_in_threadpool(
		_compute_country_traffic, tsdb_dir, hours, validated_peer
	)
	return ok_response(data=data.model_dump())


# ---------------------------------------------------------------------------
# ASN Traffic
# ---------------------------------------------------------------------------

ASN_TRAFFIC_KEY = "__asn_traffic__"
ASN_TRAFFIC_METRIC = "snapshot"


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
	since = utcnow() - timedelta(hours=hours)

	try:
		points = tsdb.query(
			tsdb_dir,
			peer_key=ASN_TRAFFIC_KEY,
			metric=ASN_TRAFFIC_METRIC,
			since=since,
			limit=_MAX_POINTS,
		)
	except Exception as exc:
		_log.error("ASN_TRAFFIC TSDB query failed: %s", exc, exc_info=True)
		# Return empty result on TSDB failure
		return ASNTrafficData(
			asns=[],
			display_unit="B",
			hours=hours,
			total_asns=0,
		)

	if len(points) >= _MAX_POINTS:
		_log.warning(
			"ASN_TRAFFIC query hit %d-point cap for %dh window; results may be truncated",
			_MAX_POINTS, hours,
		)

	# Aggregate across all snapshot points using common logic
	asn_agg = _aggregate_snapshots(points, peer_filter, TrafficType.ASN)

	# Determine display unit from the max value
	max_bytes = max(
		(max(info["rx"], info["tx"]) for info in asn_agg.values()),
		default=0
	)
	display_unit = select_display_unit(max_bytes)

	# Build Pydantic models
	asns: list[ASNEntry] = []
	for asn_key, info in sorted(
		asn_agg.items(),
		key=lambda kv: kv[1]["rx"] + kv[1]["tx"],
		reverse=True,
	):
		try:
			entry = _build_asn_entry(asn_key, info, display_unit)
			# Skip entries with negligible traffic (< 0.01 in display unit)
			if entry.total < 0.01:
				continue
			asns.append(entry)
		except (ValueError, ZeroDivisionError, OverflowError):
			# Skip entries with invalid values
			continue

	_log.debug(
		"ASN_TRAFFIC hours=%d points=%d asns=%d display_unit=%s peer_filter=%s",
		hours, len(points), len(asns), display_unit, peer_filter,
	)

	return ASNTrafficData(
		asns=asns,
		display_unit=display_unit,
		hours=hours,
		total_asns=len(asns),
	)


@router.get("/stats/traffic-by-asn", response_model=None)
async def get_traffic_by_asn(
	hours: int = Query(24, ge=1, le=8760, description="Hours of history (1-8760)"),
	range_key: str | None = Query(None, pattern="^(6h|24h|7d|30d|90d|180d|y1)$"),
	peer: str | None = Query(None, description="Filter by peer name", max_length=255),
	tsdb_dir: Path = Depends(get_tsdb_dir),
	current_user: sqlite3.Row = Depends(get_current_user),
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
	if range_key:
		hours = TRAFFIC_RANGE_TO_HOURS.get(range_key, hours)

	# Validate and log request
	validated_peer = _validate_peer_filter(peer)
	_log.info(
		"ASN_TRAFFIC query by user=%s hours=%d peer_filter=%s",
		current_user["username"] if "username" in current_user.keys() else current_user.get("id", "unknown"),
		hours,
		validated_peer,
	)

	data: ASNTrafficData = await run_in_threadpool(
		_compute_asn_traffic, tsdb_dir, hours, validated_peer
	)
	return ok_response(data=data.model_dump())
