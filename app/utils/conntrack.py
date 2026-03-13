#!/usr/bin/env python3
#
# app/utils/conntrack.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Lightweight conntrack-based country traffic analysis.

Reads the kernel connection tracking table to determine where WireGuard
VPN clients send their internet traffic.  Each destination IP is resolved
to a country via GeoLite2.

Data flow
~~~~~~~~~
1. ``/proc/net/nf_conntrack`` (primary) or ``conntrack -L`` (fallback)
2. Filter entries whose **source** is inside a WireGuard subnet
3. Resolve **destination** IPs → country via GeoIP (cached)
4. Compute byte deltas since last sample (per-connection tracking)
5. Return aggregated ``{country_code: {"rx": bytes, "tx": bytes}}``

The caller (scheduler task) stores the result in TSDB for historical
queries.

Requirements
~~~~~~~~~~~~
* ``nf_conntrack`` kernel module (loaded automatically by iptables/NAT)
* ``nf_conntrack_acct=1`` for byte counters (enabled at init)
* ``NET_ADMIN`` capability (already present in Docker compose)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from .geoip import geolocate_ip, lookup_asn

_log = logging.getLogger(__name__)

__all__ = [
	"init_conntrack_accounting",
	"sample_country_traffic",
	"reset_state",
	"GEO_TRAFFIC_KEY",
	"GEO_TRAFFIC_METRIC",
	"ASN_TRAFFIC_KEY",
	"ASN_TRAFFIC_METRIC",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CONNTRACK_PROC = Path("/proc/net/nf_conntrack")
_CONNTRACK_ACCT = Path("/proc/sys/net/netfilter/nf_conntrack_acct")


# Explicitly exclude ranges that may be treated inconsistently by
# ``ip.is_global`` across Python versions.
_EXTRA_NON_PUBLIC_V4 = (
	ipaddress.ip_network("100.64.0.0/10"),  # Shared / CGNAT
	ipaddress.ip_network("192.0.0.0/24"),   # IETF protocol assignments
)
# IPv6 has no known exclusions for this use case
_EXTRA_NON_PUBLIC_V6: tuple = ()

# Synthetic TSDB identifiers (re-exported for use by the scheduler task)
GEO_TRAFFIC_KEY = "__geo_traffic__"
GEO_TRAFFIC_METRIC = "snapshot"
ASN_TRAFFIC_KEY = "__asn_traffic__"
ASN_TRAFFIC_METRIC = "snapshot"

# ---------------------------------------------------------------------------
# Pre-compiled regexes (#8 — compile once, not per-line)
# ---------------------------------------------------------------------------

# Single-pass key=value parser — extracts all fields in one scan
_RE_KEYVAL = re.compile(r"(\w+)=(\S+)")
_RE_PROTO = re.compile(r"\b(tcp|udp|sctp|dccp|icmp|icmpv6)\b", re.I)

# ---------------------------------------------------------------------------
# Module state
# ---------------------------------------------------------------------------

_ct_prev: dict[tuple, tuple[int, int]] = {}   # conn_key → (bytes_orig, bytes_reply)
_ct_lock = threading.Lock()                    # serialises both conntrack state AND sampling
_ct_initialized = False
_acct_warned = False   # log "accounting disabled" only once per process

# Locking note:
# - Do not call _get_wireguard_subnets() while holding _ct_lock.
# - sample_country_traffic() resolves subnets before entering _ct_lock.
# Subnet cache — protected by its own lock to avoid blocking _ct_lock during I/O
_wg_lock = threading.Lock()
_wg_subnets_cache: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
_wg_subnets_ts = 0.0

_WG_SUBNET_TTL = 60.0  # re-detect subnets every 60 s


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def init_conntrack_accounting() -> bool:
	"""Enable conntrack byte accounting if not already active.

	Returns True if accounting is (now) enabled, False otherwise.
	Requires ``NET_ADMIN``; safe to call multiple times.
	"""
	try:
		current = _CONNTRACK_ACCT.read_text().strip()
		if current == "1":
			_log.debug("Conntrack byte accounting already enabled")
			return True

		_CONNTRACK_ACCT.write_text("1\n")
		_log.info("Enabled conntrack byte accounting (nf_conntrack_acct=1)")
		return True
	except FileNotFoundError:
		_log.warning(
			"CONNTRACK nf_conntrack module not loaded (nf_conntrack_acct missing) "
			"— country traffic analysis unavailable"
		)
		return False
	except PermissionError:
		_log.warning("CONNTRACK cannot enable byte accounting (no NET_ADMIN?)")
		return False
	except OSError as exc:
		_log.warning("CONNTRACK accounting init failed: %s", exc)
		return False


# ---------------------------------------------------------------------------
# WireGuard subnet detection
# ---------------------------------------------------------------------------

def _get_wireguard_subnets() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
	"""Detect IP subnets on active WireGuard interfaces.

	Tries three methods in order:
	1. ``ip -j addr show type wireguard`` (kernel WireGuard, modern iproute2)
	2. ``wg show interfaces`` + ``ip addr show dev <iface>`` (text fallback)
	3. SQLite database (always works — covers userspace WireGuard / Docker)

	Result is cached for ``_WG_SUBNET_TTL`` seconds and protected by
	``_wg_lock``.
	"""
	global _wg_subnets_cache, _wg_subnets_ts

	now = time.monotonic()
	with _wg_lock:
		if _wg_subnets_cache and (now - _wg_subnets_ts) < _WG_SUBNET_TTL:
			return list(_wg_subnets_cache)

		subnets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

		# Method 1: JSON output (iproute2 ≥ 4.14, kernel WireGuard only)
		try:
			result = subprocess.run(
				["ip", "-j", "addr", "show", "type", "wireguard"],
				capture_output=True, text=True, timeout=5,
			)
			if result.returncode == 0:
				if result.stdout.strip():
					for iface in json.loads(result.stdout):
						for ai in iface.get("addr_info", []):
							local = ai.get("local", "")
							prefixlen = ai.get("prefixlen")
							if local and prefixlen is not None:
								try:
									subnets.append(ipaddress.ip_network(f"{local}/{prefixlen}", strict=False))
								except ValueError:
									pass
			else:
				_log.debug(
					"COUNTRY_TRAFFIC 'ip -j addr show type wireguard' failed (rc=%d): %s",
					result.returncode,
					(result.stderr or "").strip(),
				)
		except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
			pass

		# Method 2: text fallback — get interface names, then addresses
		if not subnets:
			try:
				iface_result = subprocess.run(
					["wg", "show", "interfaces"],
					capture_output=True, text=True, timeout=5,
				)
				if iface_result.returncode == 0:
					for iface in iface_result.stdout.strip().split():
						addr_result = subprocess.run(
							["ip", "addr", "show", "dev", iface],
							capture_output=True, text=True, timeout=5,
						)
						if addr_result.returncode == 0:
							for m in re.finditer(r"inet6?\s+(\S+)", addr_result.stdout):
								try:
									subnets.append(ipaddress.ip_network(m.group(1), strict=False))
								except ValueError:
									pass
						else:
							_log.debug(
								"COUNTRY_TRAFFIC 'ip addr show dev %s' failed (rc=%d): %s",
								iface,
								addr_result.returncode,
								(addr_result.stderr or "").strip(),
							)
				else:
					_log.debug(
						"COUNTRY_TRAFFIC 'wg show interfaces' failed (rc=%d): %s",
						iface_result.returncode,
						(iface_result.stderr or "").strip(),
					)
			except (FileNotFoundError, subprocess.TimeoutExpired):
				pass

		# Method 3: read interface addresses from the application database.
		# This covers userspace WireGuard (wireguard-go / boringtun) inside
		# Docker where the kernel does not report type=wireguard and `wg`
		# may not be available or may return empty results.
		if not subnets:
			try:
				subnets = _get_subnets_from_db()
				if subnets:
					_log.debug(
						"COUNTRY_TRAFFIC subnet detection via DB fallback: %s",
						[str(s) for s in subnets],
					)
			except Exception as exc:
				_log.debug("COUNTRY_TRAFFIC DB subnet fallback failed: %s", exc)

		_wg_subnets_cache = subnets
		_wg_subnets_ts = now
		return list(subnets)


def _get_subnets_from_db() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
	"""Read WireGuard interface addresses from the SQLite database.

	Returns a list of IP networks derived from the ``address`` and
	``address6`` columns of the ``interfaces`` table.
	"""
	import sqlite3
	from .config import get_config

	cfg = get_config()
	if not cfg.db_path.exists():
		return []

	subnets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
	try:
		with sqlite3.connect(str(cfg.db_path), timeout=3) as conn:
			conn.row_factory = sqlite3.Row
			rows = conn.execute(
				"SELECT address, address6 FROM interfaces WHERE is_enabled = 1"
			).fetchall()
			for row in rows:
				for addr_field in ("address", "address6"):
					addr = row[addr_field]
					if addr:
						try:
							net = ipaddress.ip_network(addr, strict=False)
							if "/" not in addr and net.prefixlen in (32, 128):
								_log.debug(
									"COUNTRY_TRAFFIC DB address %r has no prefix length "
									"and is treated as a host route (%s)",
									addr,
									net,
								)
							subnets.append(net)
						except ValueError:
							pass
	except (sqlite3.Error, OSError) as exc:
		_log.debug("COUNTRY_TRAFFIC DB query failed: %s", exc)
		return []

	return subnets


# ---------------------------------------------------------------------------
# Conntrack parsing
# ---------------------------------------------------------------------------

def _read_conntrack_lines() -> list[str]:
	"""Read conntrack entries from /proc or the conntrack tool."""
	# Primary: /proc pseudo-file (no extra package needed)
	try:
		lines = _CONNTRACK_PROC.read_text().splitlines()
		if lines:
			return lines
	except (OSError, PermissionError) as exc:
		_log.debug("Cannot read %s: %s", _CONNTRACK_PROC, exc)

	# Fallback: conntrack tool
	try:
		result = subprocess.run(
			["conntrack", "-L", "-o", "extended"],
			capture_output=True, text=True, timeout=10,
		)
		if result.returncode == 0:
			return result.stdout.splitlines()
		_log.debug(
			"COUNTRY_TRAFFIC 'conntrack -L -o extended' failed (rc=%d): %s",
			result.returncode,
			(result.stderr or "").strip(),
		)
	except (FileNotFoundError, subprocess.TimeoutExpired):
		pass

	return []


def _parse_line(line: str) -> dict[str, Any] | None:
	"""Parse a single conntrack entry into structured data.

	Extracts the two direction blocks (original + reply) using a single-pass
	key=value parser instead of 5 separate regex scans.
	"""
	# Single scan: extract all key=value pairs
	kv_pairs = _RE_KEYVAL.findall(line)
	
	# Group values by key (conntrack repeats keys for orig + reply directions)
	srcs = []
	dsts = []
	sports = []
	dports = []
	bytes_vals = []
	
	for key, val in kv_pairs:
		if key == "src":
			srcs.append(val)
		elif key == "dst":
			dsts.append(val)
		elif key == "sport":
			sports.append(val)
		elif key == "dport":
			dports.append(val)
		elif key == "bytes":
			bytes_vals.append(val)

	# Need at least both direction blocks with byte counters
	if len(srcs) < 2 or len(dsts) < 2 or len(bytes_vals) < 2:
		return None

	proto_m = _RE_PROTO.search(line)
	proto = proto_m.group(1).lower() if proto_m else "other"

	try:
		return {
			"proto": proto,
			"src": srcs[0],              # original: WG client → internet
			"dst": dsts[0],              # original: internet destination
			"sport": int(sports[0]) if sports else 0,
			"dport": int(dports[0]) if dports else 0,
			"bytes_orig": int(bytes_vals[0]),   # client → internet (upload / tx)
			"bytes_reply": int(bytes_vals[1]),  # internet → client (download / rx)
		}
	except (ValueError, IndexError):
		return None


def _aggregate_traffic_by_country(
	deltas: list[tuple[str, str, int, int]],
	peer_ip_map: dict[str, str] | None,
) -> dict[str, dict[str, Any]]:
	"""Aggregate traffic deltas by destination country.

	Args:
		deltas: List of (dst_ip, src_ip, delta_tx, delta_rx) tuples.
		peer_ip_map: Optional mapping from WireGuard IP to peer name.

	Returns:
		Dict mapping country code to {"rx", "tx", "peers", "by_peer"}.
	"""
	country_agg: dict[str, dict[str, Any]] = {}

	for dst_ip, src_ip, delta_tx, delta_rx in deltas:
		peer_name = peer_ip_map.get(src_ip) if peer_ip_map else None

		# Country lookup
		try:
			geo = geolocate_ip(dst_ip)
			cc = (geo.get("country") if geo else None) or "XX"
		except Exception:
			_log.debug("COUNTRY_TRAFFIC GeoIP lookup failed for %s", dst_ip, exc_info=True)
			cc = "XX"

		if cc not in country_agg:
			country_agg[cc] = {"rx": 0, "tx": 0, "peers": set(), "by_peer": {}}

		country_agg[cc]["rx"] += delta_rx
		country_agg[cc]["tx"] += delta_tx

		# Per-peer traffic attribution
		if peer_name:
			country_agg[cc]["peers"].add(peer_name)
			if peer_name not in country_agg[cc]["by_peer"]:
				country_agg[cc]["by_peer"][peer_name] = {"rx": 0, "tx": 0}
			country_agg[cc]["by_peer"][peer_name]["rx"] += delta_rx
			country_agg[cc]["by_peer"][peer_name]["tx"] += delta_tx

	return country_agg


def _aggregate_traffic_by_asn(
	deltas: list[tuple[str, str, int, int]],
	peer_ip_map: dict[str, str] | None,
) -> dict[str, dict[str, Any]]:
	"""Aggregate traffic deltas by destination ASN.

	Args:
		deltas: List of (dst_ip, src_ip, delta_tx, delta_rx) tuples.
		peer_ip_map: Optional mapping from WireGuard IP to peer name.

	Returns:
		Dict mapping ASN number (as string) to {"rx", "tx", "name", "peers", "by_peer"}.
	"""
	asn_agg: dict[str, dict[str, Any]] = {}

	for dst_ip, src_ip, delta_tx, delta_rx in deltas:
		peer_name = peer_ip_map.get(src_ip) if peer_ip_map else None

		# ASN lookup
		try:
			asn_num, asn_org = lookup_asn(dst_ip)
			asn_key = str(asn_num) if asn_num else "0"
			asn_name = asn_org or "Unknown"
		except Exception:
			_log.debug("ASN_TRAFFIC ASN lookup failed for %s", dst_ip, exc_info=True)
			asn_key = "0"
			asn_name = "Unknown"

		if asn_key not in asn_agg:
			asn_agg[asn_key] = {"rx": 0, "tx": 0, "name": asn_name, "peers": set(), "by_peer": {}}

		asn_agg[asn_key]["rx"] += delta_rx
		asn_agg[asn_key]["tx"] += delta_tx

		# Per-peer traffic attribution
		if peer_name:
			asn_agg[asn_key]["peers"].add(peer_name)
			if peer_name not in asn_agg[asn_key]["by_peer"]:
				asn_agg[asn_key]["by_peer"][peer_name] = {"rx": 0, "tx": 0}
			asn_agg[asn_key]["by_peer"][peer_name]["rx"] += delta_rx
			asn_agg[asn_key]["by_peer"][peer_name]["tx"] += delta_tx

	return asn_agg


def _is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
	"""Return True if *ip* is a publicly routable address.

	Uses ``ip.is_global`` plus explicit exclusions for shared/assigned
	ranges with historically inconsistent handling across Python versions.
	Takes a pre-parsed ``ip_address`` object to avoid re-parsing strings.
	"""
	if not ip.is_global:
		return False
	
	# Fast path: IPv6 has no exclusions
	if isinstance(ip, ipaddress.IPv6Address):
		return True
	
	# IPv4: check exclusions
	return not any(ip in net for net in _EXTRA_NON_PUBLIC_V4)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def sample_country_traffic(
	peer_ip_map: dict[str, str] | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
	"""Sample the conntrack table and return **new** bytes by country and ASN.

	Args:
		peer_ip_map: Optional ``{wg_internal_ip: peer_name}`` mapping for
		             attribution.  If provided, ``peer_names`` lists are
		             included in the result.

	Returns:
		Tuple of (country_deltas, asn_deltas):
		- country_deltas: ``{country_code: {"rx": int, "tx": int, "peers": list[str]}}``
		- asn_deltas: ``{asn_number: {"rx": int, "tx": int, "name": str, "peers": list[str]}}``
		where *rx* = download (reply direction → to client) and
		*tx* = upload (original direction → from client).
		On the first call after startup the baseline is recorded and
		empty dicts are returned (no spike).

	Note:
		Connections that disappear between two samples lose their final
		delta — this is an inherent limitation of polling conntrack.
	"""
	global _ct_initialized, _ct_prev, _acct_warned

	# Warn if byte accounting appears to be off — log once, re-arm when it recovers
	acct_active: bool | None = None
	try:
		acct_active = _CONNTRACK_ACCT.read_text().strip() == "1"
	except OSError:
		pass

	if acct_active is not None:
		with _ct_lock:
			if not acct_active:
				if not _acct_warned:
					_acct_warned = True
					_log.warning(
						"COUNTRY_TRAFFIC conntrack byte accounting is disabled "
						"(nf_conntrack_acct=0) — run on the host: "
						"sysctl -w net.netfilter.nf_conntrack_acct=1"
					)
				return {}, {}
			if _acct_warned:
				# Accounting was just enabled (e.g. user ran sysctl on host)
				_acct_warned = False
				_log.info("COUNTRY_TRAFFIC conntrack byte accounting is now enabled — resuming sampling")

	# Subnet detection uses its own lock; must happen *before* _ct_lock
	# to keep lock ordering consistent and avoid holding _ct_lock during I/O.
	subnets = _get_wireguard_subnets()
	if not subnets:
		_log.debug("COUNTRY_TRAFFIC no WireGuard subnets detected")
		return {}, {}

	# _ct_lock serialises both conntrack state access and the sampling
	# itself, preventing two concurrent calls from corrupting _ct_prev.
	with _ct_lock:
		lines = _read_conntrack_lines()
		if not lines:
			_log.debug("COUNTRY_TRAFFIC no conntrack data available")
			return {}, {}

		# --- Parse + filter ----------------------------------------------
		current: dict[tuple, tuple[int, int]] = {}  # conn_key → (orig, reply)

		for line in lines:
			entry = _parse_line(line)
			if entry is None:
				continue

			# Parse IPs once; reuse objects for both subnet and public checks (#4)
			try:
				src_addr = ipaddress.ip_address(entry["src"])
				dst_addr = ipaddress.ip_address(entry["dst"])
			except ValueError:
				continue

			if not any(src_addr in net for net in subnets):
				continue
			if not _is_public_ip(dst_addr):
				continue

			key = (entry["proto"], entry["src"], entry["sport"], entry["dst"], entry["dport"])
			current[key] = (entry["bytes_orig"], entry["bytes_reply"])

		# --- First call: establish baseline, no deltas ------------------
		if not _ct_initialized:
			_ct_prev = current
			_ct_initialized = True
			_log.info("COUNTRY_TRAFFIC baseline recorded (%d conntrack entries)", len(current))
			return {}, {}

		# --- Compute deltas per connection ------------------------------
		deltas: list[tuple[str, str, int, int]] = []  # (dst_ip, src_ip, delta_tx, delta_rx)

		for key, (orig_now, reply_now) in current.items():
			orig_prev, reply_prev = _ct_prev.get(key, (0, 0))

			delta_tx = orig_now - orig_prev    # upload delta
			delta_rx = reply_now - reply_prev  # download delta

			# Negative delta: counter wrap or 5-tuple reuse; clamp and log (#10)
			if delta_tx < 0 or delta_rx < 0:
				_log.debug(
					"COUNTRY_TRAFFIC negative delta (counter wrap?) "
					"%s→%s tx=%d rx=%d",
					key[1], key[3], delta_tx, delta_rx,
				)
				delta_tx = max(delta_tx, 0)
				delta_rx = max(delta_rx, 0)

			if delta_tx == 0 and delta_rx == 0:
				continue

			deltas.append((key[3], key[1], delta_tx, delta_rx))

		# Update baseline for next sample (replaces entire dict to prevent unbounded growth)
		_ct_prev = current

	# GeoIP + ASN aggregation intentionally outside _ct_lock
	# to minimize lock hold time during potentially expensive lookups.
	country_agg = _aggregate_traffic_by_country(deltas, peer_ip_map)
	asn_agg = _aggregate_traffic_by_asn(deltas, peer_ip_map)

	# Convert sets to sorted lists for JSON serialisation (outside lock)
	country_result = {
		cc: {
			"rx": info["rx"],
			"tx": info["tx"],
			"peers": sorted(info["peers"]),
			"by_peer": info["by_peer"],
		}
		for cc, info in country_agg.items()
	}

	asn_result = {
		asn_key: {
			"rx": info["rx"],
			"tx": info["tx"],
			"name": info["name"],
			"peers": sorted(info["peers"]),
			"by_peer": info["by_peer"],
		}
		for asn_key, info in asn_agg.items()
	}

	return country_result, asn_result


def reset_state() -> None:
	"""Reset all internal state.

	Acquires both locks in consistent order to prevent race conditions.
	Intended for testing or startup paths where sampling is not running concurrently.
	"""
	global _ct_initialized, _ct_prev, _wg_subnets_cache, _wg_subnets_ts, _acct_warned

	# Acquire both locks in consistent order (wg_lock → ct_lock)
	with _wg_lock:
		with _ct_lock:
			_ct_prev.clear()
			_ct_initialized = False
			_acct_warned = False
			_wg_subnets_cache = []
			_wg_subnets_ts = 0.0
