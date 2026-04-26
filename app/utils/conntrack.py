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

Limitations
~~~~~~~~~~~
* **Connection key collisions**: Connections are tracked by 5-tuple
  (proto, src, sport, dst, dport). This can produce incorrect deltas if:
  - Multiple clients share the same tuple via NAT
  - Port reuse occurs over time
  - ICMP traffic (no ports) collides

* **Lost deltas on teardown**: Connections that disappear between samples
  lose their final delta. This affects short-lived flows (DNS, HTTP bursts).
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
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
# Pre-compiled regexes
# ---------------------------------------------------------------------------

# Single-pass key=value parser — extracts all fields in one scan
_RE_KEYVAL = re.compile(r"(\w+)=(\S+)")

# Known protocols (first token in conntrack line)
_KNOWN_PROTOS = frozenset({"tcp", "udp", "sctp", "dccp", "icmp", "icmpv6"})

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
_wg_gateway_ips_cache: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
_wg_subnets_ts = 0.0

_WG_SUBNET_TTL = 60.0  # re-detect subnets every 60 s


def _parse_interface_address(
	addr_str: str,
) -> tuple[
	ipaddress.IPv4Network | ipaddress.IPv6Network,
	ipaddress.IPv4Address | ipaddress.IPv6Address,
] | None:
	"""Parse an interface address into (network, gateway_ip)."""
	try:
		net = ipaddress.ip_network(addr_str, strict=False)
		if "/" not in addr_str and net.prefixlen in (32, 128):
			_log.debug(
				"COUNTRY_TRAFFIC address %r has no prefix length and is treated as a host route (%s)",
				addr_str,
				net,
			)
		return net, ipaddress.ip_address(addr_str.split("/")[0])
	except ValueError:
		return None


def _ensure_bucket(agg: dict, key: str, name: str | None = None) -> dict:
	"""Return an existing traffic bucket or initialise a new one."""
	if key not in agg:
		bucket = {"rx": 0, "tx": 0, "peers": set(), "by_peer": {}}
		if name is not None:
			bucket["name"] = name
		agg[key] = bucket
	return agg[key]


def _add_to_bucket(bucket: dict, delta_rx: int, delta_tx: int, peer_name: str | None) -> None:
	"""Add deltas to a traffic bucket and attribute them to a peer if present."""
	bucket["rx"] += delta_rx
	bucket["tx"] += delta_tx
	if not peer_name:
		return
	bucket["peers"].add(peer_name)
	peer = bucket["by_peer"].setdefault(peer_name, {"rx": 0, "tx": 0})
	peer["rx"] += delta_rx
	peer["tx"] += delta_tx


def _serialize_agg(agg: dict[str, dict]) -> dict[str, dict]:
	"""Convert aggregation buckets into JSON-safe dictionaries."""
	return {
		key: {
			**{k: v for k, v in info.items() if k not in ("peers", "by_peer")},
			"peers": sorted(info["peers"]),
			"by_peer": dict(sorted(info["by_peer"].items())),
		}
		for key, info in sorted(agg.items())
	}


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

def _get_wireguard_subnets() -> tuple[
	list[ipaddress.IPv4Network | ipaddress.IPv6Network],
	set[ipaddress.IPv4Address | ipaddress.IPv6Address],
]:
	"""Detect IP subnets and gateway IPs on active WireGuard interfaces.

	Tries three methods in order:
	1. ``ip -j addr show type wireguard`` (kernel WireGuard, modern iproute2)
	2. ``wg show interfaces`` + ``ip addr show dev <iface>`` (text fallback)
	3. SQLite database (always works — covers userspace WireGuard / Docker)

	Returns:
		Tuple of (subnets, gateway_ips). Gateway IPs are the server's own
		addresses on the WireGuard interfaces — these should be excluded
		from peer traffic counting.

	Result is cached for ``_WG_SUBNET_TTL`` seconds and protected by
	``_wg_lock``.
	"""
	global _wg_subnets_cache, _wg_gateway_ips_cache, _wg_subnets_ts

	now = time.monotonic()
	with _wg_lock:
		if _wg_subnets_cache and (now - _wg_subnets_ts) < _WG_SUBNET_TTL:
			return list(_wg_subnets_cache), set(_wg_gateway_ips_cache)

		subnets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
		gateway_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()

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
								parsed = _parse_interface_address(f"{local}/{prefixlen}")
								if parsed is not None:
									net, gateway_ip = parsed
									subnets.append(net)
									gateway_ips.add(gateway_ip)
			else:
				_log.debug(
					"COUNTRY_TRAFFIC 'ip -j addr show type wireguard' failed (rc=%d): %s",
					result.returncode,
					(result.stderr or "").strip(),
				)
		except FileNotFoundError:
			_log.debug("COUNTRY_TRAFFIC 'ip' command not found")
		except subprocess.TimeoutExpired:
			_log.debug("COUNTRY_TRAFFIC 'ip -j addr show' timed out")
		except json.JSONDecodeError as exc:
			_log.debug("COUNTRY_TRAFFIC 'ip -j addr show' returned invalid JSON: %s", exc)

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
								parsed = _parse_interface_address(m.group(1))
								if parsed is not None:
									net, gateway_ip = parsed
									subnets.append(net)
									gateway_ips.add(gateway_ip)
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
				subnets, gateway_ips = _get_subnets_from_db()
				if subnets:
					_log.debug(
						"COUNTRY_TRAFFIC subnet detection via DB fallback: %s",
						[str(s) for s in subnets],
					)
			except Exception as exc:
				_log.debug("COUNTRY_TRAFFIC DB subnet fallback failed: %s", exc)

		_wg_subnets_cache = subnets
		_wg_gateway_ips_cache = gateway_ips
		_wg_subnets_ts = now
		return list(subnets), set(gateway_ips)


def _get_subnets_from_db() -> tuple[
	list[ipaddress.IPv4Network | ipaddress.IPv6Network],
	set[ipaddress.IPv4Address | ipaddress.IPv6Address],
]:
	"""Read WireGuard interface addresses from the SQLite database.

	Returns:
		Tuple of (subnets, gateway_ips) derived from the ``address`` and
		``address6`` columns of the ``interfaces`` table.
	"""
	import sqlite3
	from .config import get_config

	cfg = get_config()
	if not cfg.db_path.exists():
		return [], set()

	subnets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
	gateway_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
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
						parsed = _parse_interface_address(addr)
						if parsed is not None:
							net, gateway_ip = parsed
							subnets.append(net)
							gateway_ips.add(gateway_ip)
	except (sqlite3.Error, OSError) as exc:
		_log.debug("COUNTRY_TRAFFIC DB query failed: %s", exc)
		return [], set()

	return subnets, gateway_ips


# ---------------------------------------------------------------------------
# Conntrack parsing
# ---------------------------------------------------------------------------

def _read_conntrack_lines() -> list[str]:
	"""Read conntrack entries from /proc or the conntrack tool.

	Streams /proc/net/nf_conntrack to avoid memory spikes on large systems.
	"""
	lines: list[str] = []

	# Primary: /proc pseudo-file (no extra package needed)
	try:
		with _CONNTRACK_PROC.open() as f:
			for line in f:
				stripped = line.rstrip("\n")
				if stripped:
					lines.append(stripped)
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
	except FileNotFoundError:
		_log.debug("COUNTRY_TRAFFIC conntrack tool not found")
	except subprocess.TimeoutExpired:
		_log.debug("COUNTRY_TRAFFIC conntrack command timed out")

	return []


def _parse_line(line: str) -> dict[str, Any] | None:
	"""Parse a single conntrack entry into structured data.

	Extracts the two direction blocks (original + reply) using a single-pass
	key=value parser instead of 5 separate regex scans.
	"""
	# Extract protocol from first token (faster than regex)
	tokens = line.split(None, 3)  # Split into max 4 parts
	proto = "other"
	for tok in tokens[:3]:  # Protocol is in first 3 tokens
		tok_lower = tok.lower()
		if tok_lower in _KNOWN_PROTOS:
			proto = tok_lower
			break

	# Single scan: extract all key=value pairs
	fields: dict[str, list[str]] = defaultdict(list)
	for key, val in _RE_KEYVAL.findall(line):
		fields[key].append(val)

	# Need at least both direction blocks with byte counters
	if len(fields["src"]) < 2 or len(fields["dst"]) < 2 or len(fields["bytes"]) < 2:
		return None

	try:
		return {
			"proto": proto,
			"src": fields["src"][0],              # original: WG client → internet
			"dst": fields["dst"][0],              # original: internet destination
			"sport": int(fields["sport"][0]) if fields["sport"] else 0,
			"dport": int(fields["dport"][0]) if fields["dport"] else 0,
			"bytes_orig": int(fields["bytes"][0]),   # client → internet (upload / tx)
			"bytes_reply": int(fields["bytes"][1]),  # internet → client (download / rx)
		}
	except (ValueError, IndexError):
		return None


def _aggregate_traffic(
	deltas: list[tuple[str, str, int, int]],
	peer_ip_map: dict[str, str] | None,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
	"""Aggregate traffic deltas by destination country and ASN in a single pass.

	Caches GeoIP and ASN lookups per destination IP to avoid redundant lookups
	when the same IP appears multiple times.

	Args:
		deltas: List of (dst_ip, src_ip, delta_tx, delta_rx) tuples.
		peer_ip_map: Optional mapping from WireGuard IP to peer name.

	Returns:
		Tuple of (country_agg, asn_agg).
	"""
	country_agg: dict[str, dict[str, Any]] = {}
	asn_agg: dict[str, dict[str, Any]] = {}

	# Per-sample caches to avoid redundant lookups
	geo_cache: dict[str, str] = {}  # dst_ip → country_code
	asn_cache: dict[str, tuple[str, str]] = {}  # dst_ip → (asn_key, asn_name)

	for dst_ip, src_ip, delta_tx, delta_rx in deltas:
		peer_name = peer_ip_map.get(src_ip) if peer_ip_map else None

		# Country lookup (cached)
		if dst_ip in geo_cache:
			cc = geo_cache[dst_ip]
		else:
			try:
				geo = geolocate_ip(dst_ip)
				cc = (geo.get("country") if geo else None) or "XX"
			except Exception:
				_log.debug("COUNTRY_TRAFFIC GeoIP lookup failed for %s", dst_ip, exc_info=True)
				cc = "XX"
			geo_cache[dst_ip] = cc

		# ASN lookup (cached)
		if dst_ip in asn_cache:
			asn_key, asn_name = asn_cache[dst_ip]
		else:
			try:
				asn_num, asn_org = lookup_asn(dst_ip)
				asn_key = str(asn_num) if asn_num else "0"
				asn_name = asn_org or "Unknown"
			except Exception:
				_log.debug("ASN_TRAFFIC ASN lookup failed for %s", dst_ip, exc_info=True)
				asn_key = "0"
				asn_name = "Unknown"
			asn_cache[dst_ip] = (asn_key, asn_name)

		_add_to_bucket(_ensure_bucket(country_agg, cc), delta_rx, delta_tx, peer_name)
		_add_to_bucket(_ensure_bucket(asn_agg, asn_key, name=asn_name), delta_rx, delta_tx, peer_name)

	return country_agg, asn_agg


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

	# IPv4: check exclusions (explicit loop avoids generator overhead)
	for net in _EXTRA_NON_PUBLIC_V4:
		if ip in net:
			return False
	return True


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
	subnets, gateway_ips = _get_wireguard_subnets()
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
			# Exclude server's own gateway IPs (e.g. 10.0.0.1) — only count peer traffic
			if src_addr in gateway_ips:
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
	# Uses per-sample caching to avoid redundant lookups for same destination IP.
	country_agg, asn_agg = _aggregate_traffic(deltas, peer_ip_map)

	# Convert sets to sorted lists for JSON serialisation (outside lock)
	# Also sort by_peer keys for consistent ordering in TSDB comparisons
	country_result = _serialize_agg(country_agg)
	asn_result = _serialize_agg(asn_agg)

	return country_result, asn_result


def reset_state() -> None:
	"""Reset all internal state.

	Acquires both locks in consistent order to prevent race conditions.
	Intended for testing or startup paths where sampling is not running concurrently.
	"""
	global _ct_initialized, _ct_prev, _wg_subnets_cache, _wg_gateway_ips_cache, _wg_subnets_ts, _acct_warned

	# Acquire both locks in consistent order (wg_lock → ct_lock)
	with _wg_lock:
		with _ct_lock:
			_ct_prev.clear()
			_ct_initialized = False
			_acct_warned = False
			_wg_subnets_cache = []
			_wg_gateway_ips_cache = set()
			_wg_subnets_ts = 0.0
