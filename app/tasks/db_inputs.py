#!/usr/bin/env python3
#
# app/tasks/db_inputs.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
# SPDX-License-Identifier: MIT
#

"""Startup and scheduled-task input readers, shared by app/main.py and app/tasks."""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

from ..api.wireguard_utils import safe_int
from ..db.sqlite_interfaces import list_interfaces
from ..db.sqlite_peers import get_all_peers
from ..db.sqlite_runtime import db_call, db_call_or
from ..db.sqlite_settings import (
	get_bool_setting,
	get_dns_blocklist_enabled,
	get_dns_custom_rules,
	get_dns_log_retention_days,
	get_dns_query_logging_enabled,
	get_dns_service_enabled,
	get_dns_upstream_servers,
	get_dnssec_enabled,
	get_enabled_blocklists,
	get_speedtest_retention_days,
	get_tsdb_retention_days,
)
from ..dns import unbound

_log = logging.getLogger(__name__)

__all__ = [
	"check_adblocker_timer_sync",
	"load_blocklist_update_inputs_sync",
	"load_peer_identity_map_sync",
	"parse_wg_dump_counters",
	"read_blocklist_enabled_sync",
	"read_country_traffic_inputs_sync",
	"read_dns_retention_days_sync",
	"read_speedtest_retention_days_sync",
	"read_tsdb_retention_days_sync",
	"reload_unbound_for_adblocker_async",
	"should_unbound_run_sync",
]


def parse_wg_dump_counters(stdout: str) -> dict[str, tuple[int, int, int]]:
	"""Parse `wg show all dump` and return counters per public key.

	Returns:
		Dict[public_key] -> (rx_bytes, tx_bytes, latest_handshake_ts)
	"""
	peers: dict[str, tuple[int, int, int]] = {}
	last_iface: str | None = None

	for line in stdout.strip().splitlines():
		if not line:
			continue
		parts = line.split("\t")

		# Interface header from `wg show all dump` has exactly 5 columns:
		# iface, private-key, public-key, listen-port, fwmark
		if len(parts) == 5:
			last_iface = parts[0] or last_iface
			continue

		public_key: str | None = None
		latest_handshake = 0
		rx = 0
		tx = 0

		# `wg show all dump` always emits 9-column peer lines:
		# iface, pubkey, psk, endpoint, allowed-ips, hs, rx, tx, keepalive
		# (issue #5: the old 8-column branch read wrong columns for rx/tx).
		if len(parts) >= 9:
			iface = parts[0] if parts[0] else last_iface
			if iface:
				last_iface = iface
			public_key = parts[1]
			latest_handshake = safe_int(parts[5])
			rx = safe_int(parts[6])
			tx = safe_int(parts[7])

		if not public_key:
			_log.debug("Malformed wg dump row ignored: %r", line)
			continue
		peers[public_key] = (rx, tx, latest_handshake)

	return peers


def load_blocklist_update_inputs_sync(db_path: Path) -> tuple[list[str], str]:
	"""Load blocklist URLs and custom DNS rules synchronously."""

	def _load(conn) -> tuple[list[str], str]:
		return get_enabled_blocklists(conn), get_dns_custom_rules(conn)

	return db_call(db_path, _load)


def read_dns_retention_days_sync(db_path: Path) -> int:
	"""Read DNS retention days synchronously."""
	return db_call(db_path, get_dns_log_retention_days)


def read_tsdb_retention_days_sync(db_path: Path) -> int:
	"""Read TSDB retention days synchronously."""
	return db_call(db_path, get_tsdb_retention_days)


def read_speedtest_retention_days_sync(db_path: Path) -> int:
	"""Read speedtest retention days synchronously."""
	return db_call(db_path, get_speedtest_retention_days)


def should_unbound_run_sync(db_path: Path) -> bool:
	"""Check if Unbound should be running (DNS enabled AND interfaces exist)."""

	def _check(conn) -> bool:
		if not get_dns_service_enabled(conn):
			return False
		# Unbound needs interface IPs to bind to
		return len(list_interfaces(conn)) > 0

	return db_call_or(db_path, _check, default=False)


def read_blocklist_enabled_sync(db_path: Path) -> bool:
	"""Read whether DNS blocklist is enabled synchronously."""
	return db_call_or(db_path, get_dns_blocklist_enabled, default=False)


def read_country_traffic_inputs_sync(db_path: Path) -> tuple[bool, dict[str, str]]:
	"""Load traffic-analysis enabled flag and peer IP map synchronously."""

	def _load(conn) -> tuple[bool, dict[str, str]]:
		# Factory default is off; accepts any truthy stored form, like the UI does.
		if not get_bool_setting(conn, "traffic_analysis_enabled"):
			return False, {}

		# peer_address can be dual-stack: "10.13.13.2/32, fd13:13:13::2/128"
		peer_ip_map: dict[str, str] = {}
		for peer in get_all_peers(conn):
			addr = peer["peer_address"]
			name = peer["name"]
			if addr and name:
				for raw_part in str(addr).split(","):
					part = raw_part.strip()
					if not part:
						continue
					# Strip CIDR suffix (e.g., 10.13.13.2/32 → 10.13.13.2)
					peer_ip_map[part.split("/")[0]] = name
		return True, peer_ip_map

	return db_call(db_path, _load)


def load_peer_identity_map_sync(db_path: Path, public_keys: list[str]) -> dict[str, tuple[str, str]]:
	"""Resolve peer name/interface by public key synchronously."""
	wanted = set(public_keys)

	def _resolve(conn) -> dict[str, tuple[str, str]]:
		result: dict[str, tuple[str, str]] = {}
		for peer_row in get_all_peers(conn):
			public_key = peer_row["public_key"]
			if public_key in wanted:
				result[public_key] = (peer_row["name"], peer_row["interface"])
		return result

	return db_call(db_path, _resolve)


def check_adblocker_timer_sync(db_path: Path) -> bool:
	"""Check and re-enable adblocker if timer expired. Returns True if re-enabled."""
	# Imported here because app.api.wireguard_peers pulls in the router layer,
	# which must not be a module-level dependency of the task inputs.
	from ..api.wireguard_peers import regenerate_all_peer_tags
	from ..db.sqlite_runtime import transaction
	from ..db.sqlite_settings import (
		clear_blocklist_disabled_until,
		get_blocklist_disabled_until,
		set_dns_blocklist_enabled,
	)

	def _check(conn) -> bool:
		# Read-only check first - avoid write lock if not needed
		disabled_until = get_blocklist_disabled_until(conn)
		enabled = get_dns_blocklist_enabled(conn)
		now = int(time.time())

		if disabled_until > 0 and disabled_until <= now and not enabled:
			# Timer expired and blocklist is still disabled - need to re-enable
			with transaction(conn, immediate=True):
				set_dns_blocklist_enabled(conn, True)
				clear_blocklist_disabled_until(conn)
				regenerate_all_peer_tags(conn)
			return True
		return False

	return db_call(db_path, _check)


async def reload_unbound_for_adblocker_async(db_path: Path) -> None:
	"""Reload Unbound config after adblocker state change.

	All DB access is done synchronously via to_thread to avoid
	sharing a connection across await boundaries.
	"""
	try:

		def _read(conn) -> tuple:
			return (
				get_dns_query_logging_enabled(conn),
				get_dns_blocklist_enabled(conn),
				get_dns_upstream_servers(conn),
				get_dnssec_enabled(conn),
				list_interfaces(conn),
			)

		enable_logging, enable_blocklist, upstream_dns, dnssec_enabled, interfaces = await asyncio.to_thread(db_call, db_path, _read)

		ipv6_gateways = unbound.get_interface_ipv6_gateways(interfaces)

		# Offload sync file I/O to thread
		await asyncio.to_thread(
			unbound.write_config,
			enable_logging=enable_logging,
			enable_blocklist=enable_blocklist,
			upstream_dns=upstream_dns,
			enable_dnssec=dnssec_enabled,
			listen_addrs_ipv4=unbound.get_interface_ipv4_gateways(interfaces),
			listen_addrs_ipv6=ipv6_gateways if ipv6_gateways else None,
		)
		await unbound.reload_config()
	except Exception:
		_log.warning("ADBLOCKER_TIMER failed to reload Unbound", exc_info=True)
