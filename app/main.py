#!/usr/bin/env python3
#
# app/main.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: AGPL-3.0
#

"""FastAPI application factory and startup lifecycle wiring."""

from __future__ import annotations
from typing import Any

from .db.sqlite_interfaces import (
	list_interfaces,
)
from .db.sqlite_peers import (
	get_peer_by_public_key,
	get_all_peers,
)
from .db.sqlite_runtime import (
	checkpoint_wal,
	close_all_connections,
	close_connection,
	connect,
)
from .db.sqlite_leader import try_acquire_leader_lock, release_leader_lock
from .db.sqlite_schema import ensure_default_admin, init_schema
from .db.sqlite_settings import (
	DEFAULT_DNS_LOG_RETENTION_DAYS,
	get_dns_blocklist_enabled,
	get_dns_custom_rules,
	get_dns_log_retention_days,
	get_dns_query_logging_enabled,
	get_dns_service_enabled,
	get_dns_upstream_servers,
	get_dnssec_enabled,
	get_enabled_blocklists,
	get_setting,
	get_tsdb_retention_days,
	recover_missing_global_settings,
	validate_secret_key,
)

import asyncio
import collections
import ipaddress
import logging
import os
import re
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from .utils.config import load_config, WG_CONFIG_PATH, Config
from .utils.rate_limit import limiter
from .utils.request_id import RequestIDMiddleware
from .utils.scheduler import Scheduler
from .utils.banner import print_banner_once
from .utils.version import VERSION

from .api import acme as acme_api
from .api import auth as auth_api
from .api import passkeys as passkeys_api
from .api import users as users_api
from .api import wireguard as wireguard_api
from .api import dns as dns_api
from .api import frontend_shared as frontend_ui
from .db import tsdb
from .dns import unbound
from .dns import ingestion as dns_ingestion
from .utils import migration

_log = logging.getLogger(__name__)

# Strict validation for interface names (prevents injection)
_IFACE_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,14}$")

# ANSI color codes for log levels (if TTY)
_LOG_COLORS = {
	"DEBUG": "\033[36m",    # Cyan
	"INFO": "\033[32m",     # Green
	"WARNING": "\033[33m",  # Yellow
	"ERROR": "\033[31m",    # Red
	"CRITICAL": "\033[35m", # Magenta
}
_RESET = "\033[0m"
_DOCKER_ENV_FILE = Path("/.dockerenv")
_WG_CHECK_TIMEOUT_SECONDS = 5.0
_WG_UP_TIMEOUT_SECONDS = 15.0
_WG_DOWN_TIMEOUT_SECONDS = 15.0
_TSDB_SAMPLE_INTERVAL_SECONDS = 30.0
_PEER_CONNECTION_THRESHOLD = 180  # seconds - peer is "connected" if handshake < 3 min ago
_BLOCKLIST_UPDATE_INTERVAL_SECONDS = 86400.0
_TSDB_MAINTENANCE_INTERVAL_SECONDS = 21600
_GEOIP_UPDATE_INTERVAL_SECONDS = 604800
_SQLITE_MAINTENANCE_INTERVAL_SECONDS = 21600
_SQLITE_INTEGRITY_INTERVAL_SECONDS = 604800
_TSDB_RETENTION_INTERVAL_SECONDS = 86400
_SESSION_CLEANUP_INTERVAL_SECONDS = 3600
_DNS_WATCHDOG_INTERVAL_SECONDS = 30
_ADBLOCKER_TIMER_CHECK_INTERVAL_SECONDS = 15
_DNS_INGESTION_RESTART_BASE_DELAY_SECONDS = 2.0
_DNS_INGESTION_RESTART_MAX_DELAY_SECONDS = 300.0

# Docker default bridge gateway ranges
_DOCKER_BRIDGE_NETWORKS = (
	ipaddress.ip_network("172.17.0.0/16"),
	ipaddress.ip_network("172.18.0.0/16"),
	ipaddress.ip_network("172.19.0.0/16"),
	ipaddress.ip_network("172.20.0.0/14"),
	ipaddress.ip_network("172.24.0.0/14"),
	ipaddress.ip_network("172.28.0.0/14"),
)


async def _verify_host_network_mode() -> None:
	"""Exit if running in Docker without network_mode: host.

	WireBuddy requires direct access to the host's network namespace
	for WireGuard interface management and conntrack statistics.

	Detection: In bridge mode, the default route goes through Docker's
	internal gateway (172.17.0.1, etc.). In host mode, the container
	shares the host's routing table with real gateway IPs.
	
	Can be bypassed with WIREBUDDY_SKIP_NETWORK_CHECK=1 for testing purposes.
	"""
	# Not in Docker container - OK (local development / bare-metal)
	if not _DOCKER_ENV_FILE.exists():
		return

	# Allow bypassing for CI/CD smoke tests
	if os.getenv("WIREBUDDY_SKIP_NETWORK_CHECK", "").lower() in ("1", "true", "yes"):
		_log.warning("Network mode check skipped (WIREBUDDY_SKIP_NETWORK_CHECK is set)")
		return

	try:
		proc = await asyncio.create_subprocess_exec(
			"ip", "route", "show", "default",
			stdout=asyncio.subprocess.PIPE,
			stderr=asyncio.subprocess.DEVNULL,
		)
		stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
		if proc.returncode not in (0, None):
			_log.warning("Could not verify network mode: 'ip route' exit code %s", proc.returncode)
			return

		routes = stdout.decode("utf-8", errors="replace")
		for line in routes.splitlines():
			parts = line.split()
			if len(parts) < 3 or parts[0] != "default" or "via" not in parts:
				continue
			via_idx = parts.index("via")
			if via_idx + 1 >= len(parts):
				continue
			gateway_raw = parts[via_idx + 1]
			try:
				gateway_ip = ipaddress.ip_address(gateway_raw)
			except ValueError:
				continue
			if any(gateway_ip in network for network in _DOCKER_BRIDGE_NETWORKS):
				_log.critical(
					"WireBuddy requires Docker host networking mode. "
					"Set 'network_mode: host' in your Docker configuration and try again."
				)
				sys.exit(1)

	except FileNotFoundError:
		_log.warning("'ip' command not found, cannot verify network mode")
	except asyncio.TimeoutError:
		_log.warning("Timeout checking network mode")
	except Exception as exc:
		_log.warning("Could not verify network mode: %s", exc)


async def _cleanup_stale_interfaces() -> list[str]:
	"""Remove WireGuard interfaces that are active in kernel but have no config file.

	This handles the case where the data directory was deleted but interfaces
	remain active (common in Docker host network mode). Returns list of removed
	interface names.
	"""
	removed: list[str] = []
	config_path = WG_CONFIG_PATH

	try:
		# Get list of active WireGuard interfaces from kernel
		proc = await asyncio.create_subprocess_exec(
			"wg", "show", "interfaces",
			stdout=asyncio.subprocess.PIPE,
			stderr=asyncio.subprocess.DEVNULL,
		)
		stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
		if proc.returncode != 0 or not stdout:
			return removed

		active_interfaces = stdout.decode("utf-8", errors="replace").strip().split()
		if not active_interfaces:
			return removed

		for iface_name in active_interfaces:
			# Validate interface name
			if not _IFACE_NAME_RE.match(iface_name):
				_log.warning("Skipping stale interface with invalid name: %r", iface_name)
				continue

			# Check if config file exists
			conf_file = config_path / f"{iface_name}.conf"
			if conf_file.exists():
				continue  # Has config, not orphaned

			# Orphaned interface: active but no config file
			_log.warning(
				"CLEANUP_STALE_INTERFACE name=%s (active in kernel but no config file)",
				iface_name,
			)
			try:
				# Bring interface down using ip commands (wg-quick needs config file)
				down_proc = await asyncio.create_subprocess_exec(
					"ip", "link", "set", iface_name, "down",
					stdout=asyncio.subprocess.DEVNULL,
					stderr=asyncio.subprocess.PIPE,
				)
				_, stderr = await asyncio.wait_for(down_proc.communicate(), timeout=5)
				if down_proc.returncode != 0:
					_log.warning(
						"Failed to set stale interface %s down: %s",
						iface_name,
						stderr.decode("utf-8", errors="replace"),
					)
					continue

				# Delete the interface
				del_proc = await asyncio.create_subprocess_exec(
					"ip", "link", "delete", iface_name,
					stdout=asyncio.subprocess.DEVNULL,
					stderr=asyncio.subprocess.PIPE,
				)
				_, stderr = await asyncio.wait_for(del_proc.communicate(), timeout=5)
				if del_proc.returncode == 0:
					_log.info("STALE_INTERFACE_REMOVED name=%s", iface_name)
					removed.append(iface_name)
				else:
					_log.warning(
						"Failed to delete stale interface %s: %s",
						iface_name,
						stderr.decode("utf-8", errors="replace"),
					)
			except asyncio.TimeoutError:
				_log.warning("Timeout cleaning up stale interface %s", iface_name)
			except Exception as exc:
				_log.warning("Failed to clean up stale interface %s: %s", iface_name, exc)

	except FileNotFoundError:
		_log.debug("'wg' command not found, skipping stale interface cleanup")
	except asyncio.TimeoutError:
		_log.warning("Timeout checking for stale interfaces")
	except Exception as exc:
		_log.warning("Could not check for stale interfaces: %s", exc)

	return removed


_PEER_STATE_MAX_SIZE = 100_000  # Evict oldest 10 % when full
# NOTE: _peer_connection_state OrderedDict is only accessed from the single
# event loop thread (in _sample_tsdb_metrics). Not thread-safe for concurrent access.


class _ColoredFormatter(logging.Formatter):
	"""Custom formatter that adds color to log levels in TTY."""

	def format(self, record: logging.LogRecord) -> str:
		# Work on a shallow copy so concurrent handlers see the unmodified record
		# (issue #16: modifying the shared LogRecord object is not thread-safe).
		record = logging.makeLogRecord(record.__dict__)
		if record.levelname in _LOG_COLORS:
			record.levelname = f"{_LOG_COLORS[record.levelname]}{record.levelname:<8}{_RESET}"
		else:
			record.levelname = f"{record.levelname:<8}"
		return super().format(record)


async def _communicate_with_timeout(
	proc: asyncio.subprocess.Process,
	*,
	timeout_seconds: float,
	grace_seconds: float = 3.0,
) -> tuple[bytes | None, bytes | None]:
	"""Wait for subprocess with timeout.

	On timeout, send SIGTERM first and wait ``grace_seconds`` for a clean
	exit (so wg-quick can run its PostDown iptables cleanup), then escalate
	to SIGKILL (issue #6).
	"""
	try:
		return await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
	except asyncio.TimeoutError:
		if proc.returncode is None:
			proc.terminate()  # SIGTERM – give the process a chance to clean up
			try:
				await asyncio.wait_for(proc.communicate(), timeout=grace_seconds)
			except asyncio.TimeoutError:
				proc.kill()  # SIGKILL – last resort
				await proc.communicate()
		raise


def _safe_int(value: str | None, default: int = 0) -> int:
	"""Safely parse integer values from wg dump columns."""
	try:
		return int(value) if value else default
	except (TypeError, ValueError):
		return default


def _parse_wg_dump_counters(stdout: str) -> dict[str, tuple[int, int, int]]:
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
			latest_handshake = _safe_int(parts[5])
			rx = _safe_int(parts[6])
			tx = _safe_int(parts[7])

		if not public_key:
			continue
		peers[public_key] = (rx, tx, latest_handshake)

	return peers


def _get_addr_field(iface: object, key: str) -> str | None:
	"""Safely get address field from dict, sqlite3.Row, or object."""
	try:
		return iface[key]  # type: ignore[index]
	except (KeyError, TypeError, IndexError):
		pass
	return getattr(iface, key, None)


def _bootstrap_sync(cfg: Config) -> tuple[bool, list[str], bool]:
	"""Run startup DB/bootstrap work synchronously (for asyncio.to_thread).
	
	Returns:
		Tuple of (is_leader, interfaces_to_start, key_mismatch).
	"""
	conn = connect(cfg.db_path)
	is_leader = False
	interfaces_to_start: list[str] = []
	key_mismatch = False
	try:
		init_schema(conn)

		# Validate secret key before any other operations
		if not validate_secret_key(conn, cfg.secret_key):
			key_mismatch = True
			_log.critical(
				"KEY_MISMATCH_DETECTED: WIREBUDDY_SECRET_KEY does not match the key used to encrypt this database. "
				"Please set the correct WIREBUDDY_SECRET_KEY environment variable."
			)
			# CRITICAL: Do not continue with wrong key — prevents data corruption
			return is_leader, interfaces_to_start, key_mismatch

		# Acquire leader lock first so one worker performs migration checks/logging.
		is_leader = try_acquire_leader_lock(conn)
		if is_leader:
			_log.info("This worker acquired leader lock (pid=%d)", os.getpid())
			migration.run_pending_migrations(conn)
		else:
			_log.info("Another worker is leader, skipping init tasks (pid=%d)", os.getpid())

		ensure_default_admin(conn)

		recovered = recover_missing_global_settings(
			conn,
			candidate_db_paths=[
				cfg.base_dir / "data" / "wirebuddy.db",
				Path("/app/data/wirebuddy.db"),
				Path("/opt/wirebuddy/data/wirebuddy.db"),
			],
		)
		if recovered > 0:
			_log.warning(
				"Recovered %d missing global setting(s) from alternate database path",
				recovered,
			)

		if is_leader:
			# Regenerate WireGuard configs from database (persistence across restarts)
			from .api.wireguard_config import regenerate_all_configs
			regen_result = regenerate_all_configs(WG_CONFIG_PATH, conn, pepper=cfg.secret_key)
			if regen_result.succeeded:
				_log.info("WireGuard configs regenerated: %d interfaces", len(regen_result.succeeded))
			if regen_result.failed:
				_log.warning(
					"WireGuard config regeneration failed for %d interfaces: %s",
					len(regen_result.failed),
					list(regen_result.failed.keys()),
				)
			if regen_result.key_mismatch:
				key_mismatch = True
				_log.critical(
					"KEY_MISMATCH_DETECTED: WIREBUDDY_SECRET_KEY does not match the key used to encrypt this database. "
					"WireGuard configs cannot be decrypted. Please set the correct WIREBUDDY_SECRET_KEY environment variable."
				)

			for iface in list_interfaces(conn):
				if iface["is_enabled"]:
					name = iface["name"]
					if _IFACE_NAME_RE.match(name):
						interfaces_to_start.append(name)
					else:
						_log.warning("Skipping interface with invalid name: %r", name)
	finally:
		close_connection(conn)

	return is_leader, interfaces_to_start, key_mismatch


def _load_dns_startup_data_sync(db_path: Path) -> dict[str, object]:
	"""Read DNS startup data from DB synchronously (for asyncio.to_thread)."""
	conn = connect(db_path)
	try:
		return {
			"dns_retention_days": get_dns_log_retention_days(conn),
			"dns_service_enabled": get_dns_service_enabled(conn),
			"enable_logging": get_dns_query_logging_enabled(conn),
			"enable_blocklist": get_dns_blocklist_enabled(conn),
			"upstream_dns": get_dns_upstream_servers(conn),
			"enable_dnssec": get_dnssec_enabled(conn),
			"interfaces": list_interfaces(conn),
			"wg_fqdn": get_setting(conn, "wg_fqdn"),
		}
	finally:
		close_connection(conn)


def _load_blocklist_update_inputs_sync(db_path: Path) -> tuple[list[str], str]:
	"""Load blocklist URLs and custom DNS rules synchronously."""
	conn = connect(db_path)
	try:
		return get_enabled_blocklists(conn), get_dns_custom_rules(conn)
	finally:
		close_connection(conn)


def _regenerate_peer_tags_sync(db_path: Path) -> int:
	"""Regenerate Unbound peer-tags.conf synchronously.
	
	Ensures peer tags are current at startup for ad-blocking to work.
	Returns the number of peers processed.
	"""
	from .api.wireguard_utils import (
		get_enabled_blocklist_ids,
		filter_peer_blocklist_ids,
		parse_blocklist_ids,
	)
	from .dns import unbound as _unbound
	
	conn = connect(db_path)
	try:
		enabled_blocklist_ids = get_enabled_blocklist_ids(conn)
		peers = get_all_peers(conn)
		peer_list = []
		
		for row in peers:
			blocklist_ids = parse_blocklist_ids(row["blocklist_ids"])
			if blocklist_ids is None:
				effective_ids = list(enabled_blocklist_ids)
			else:
				filtered = filter_peer_blocklist_ids(blocklist_ids, enabled_blocklist_ids)
				effective_ids = filtered or []
			
			peer_list.append({
				"peer_address": row["peer_address"],
				"use_adblocker": bool(row["use_adblocker"]),
				"blocklist_ids": effective_ids,
			})
		
		_unbound.write_peer_tags(peer_list)
		return len(peer_list)
	finally:
		close_connection(conn)


def _read_dns_retention_days_sync(db_path: Path) -> int:
	"""Read DNS retention days synchronously."""
	conn = connect(db_path)
	try:
		return get_dns_log_retention_days(conn)
	finally:
		close_connection(conn)


def _read_tsdb_retention_days_sync(db_path: Path) -> int:
	"""Read TSDB retention days synchronously."""
	conn = connect(db_path)
	try:
		return get_tsdb_retention_days(conn)
	finally:
		close_connection(conn)


def _read_dns_service_enabled_sync(db_path: Path) -> bool:
	"""Read whether DNS service should be running synchronously."""
	conn = connect(db_path)
	try:
		return get_dns_service_enabled(conn)
	except Exception:
		# default to "no action" on DB error to avoid watchdog restart loops
		_log.warning("_read_dns_service_enabled_sync failed, defaulting to no-op", exc_info=True)
		return False
	finally:
		close_connection(conn)


def _should_unbound_run_sync(db_path: Path) -> bool:
	"""Check if Unbound should be running (DNS enabled AND interfaces exist)."""
	conn = connect(db_path)
	try:
		if not get_dns_service_enabled(conn):
			return False
		# Check if any WireGuard interfaces exist (Unbound needs IPs to bind to)
		interfaces = list_interfaces(conn)
		return len(interfaces) > 0
	except Exception:
		# default to "no action" on DB error to avoid watchdog restart loops
		_log.warning("_should_unbound_run_sync failed, defaulting to no-op", exc_info=True)
		return False
	finally:
		close_connection(conn)


def _read_blocklist_enabled_sync(db_path: Path) -> bool:
	"""Read whether DNS blocklist is enabled synchronously."""
	conn = connect(db_path)
	try:
		return get_dns_blocklist_enabled(conn)
	except Exception:
		_log.warning("_read_blocklist_enabled_sync failed, defaulting to disabled", exc_info=True)
		return False
	finally:
		close_connection(conn)


def _read_country_traffic_inputs_sync(db_path: Path) -> tuple[bool, dict[str, str]]:
	"""Load traffic-analysis enabled flag and peer IP map synchronously."""
	from .db.sqlite_peers import get_all_peers

	conn = connect(db_path)
	try:
		enabled_str = get_setting(conn, "traffic_analysis_enabled")
		# Only enabled if explicitly set to "1" (default factory setting is "0")
		if enabled_str != "1":
			return False, {}

		all_peers = get_all_peers(conn)
		peer_ip_map: dict[str, str] = {}
		for peer in all_peers:
			addr = peer["peer_address"]
			name = peer["name"]
			if addr and name:
				peer_ip_map[addr.split("/")[0]] = name
		return True, peer_ip_map
	finally:
		close_connection(conn)


def _load_peer_identity_map_sync(db_path: Path, public_keys: list[str]) -> dict[str, tuple[str, str]]:
	"""Resolve peer name/interface by public key synchronously."""
	conn = connect(db_path)
	try:
		result: dict[str, tuple[str, str]] = {}
		for public_key in public_keys:
			peer_row = get_peer_by_public_key(conn, public_key)
			if peer_row:
				result[public_key] = (peer_row["name"], peer_row["interface"])
		return result
	finally:
		close_connection(conn)


def _release_leader_lock_sync(db_path: Path) -> None:
	"""Release leader lock synchronously."""
	conn = connect(db_path)
	try:
		release_leader_lock(conn)
	finally:
		close_connection(conn)


def _sqlite_shutdown_sync(db_path: Path) -> tuple[dict[str, int | str | None], int]:
	"""Run SQLite checkpoint + connection close synchronously."""
	checkpoint = checkpoint_wal(db_path, mode="TRUNCATE")
	closed_connections = close_all_connections()
	return checkpoint, closed_connections


def _setup_logging(log_level: str) -> None:
	"""Configure unified logging for the entire application."""
	level = getattr(logging, log_level, logging.INFO)
	is_tty = sys.stdout.isatty()

	# Choose formatter based on TTY detection
	if is_tty:
		formatter = _ColoredFormatter(
			fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
			datefmt="%Y-%m-%d %H:%M:%S",
		)
	else:
		formatter = logging.Formatter(
			fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
			datefmt="%Y-%m-%d %H:%M:%S",
		)

	# force=True removes any pre-existing handlers (e.g. from uvicorn)
	# so every logger inherits the same format.
	logging.basicConfig(
		level=level,
		handlers=[logging.StreamHandler(sys.stdout)],
		force=True,
	)
	
	# Apply the formatter to the root logger's handler
	for handler in logging.root.handlers:
		handler.setFormatter(formatter)

	# Make sure uvicorn loggers use the root handler & level
	for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
		logger = logging.getLogger(name)
		logger.handlers.clear()
		logger.setLevel(level)
		logger.propagate = True

	# Quiet down noisy third-party libraries
	for name in ("httpcore", "httpx", "hpack", "watchfiles"):
		logging.getLogger(name).setLevel(logging.WARNING)


@asynccontextmanager
async def _lifespan(app: FastAPI):
	"""Application lifespan manager."""
	# Verify host network mode before any initialization
	await _verify_host_network_mode()

	cfg = app.state.cfg
	is_leader = False
	started_interfaces: list[str] = []
	peer_connection_state: collections.OrderedDict[str, bool] = app.state.peer_connection_state
	
	# ─── BOOTSTRAP ───────────────────────────────────────────
	interfaces_to_start: list[str] = []
	is_leader, interfaces_to_start, key_mismatch = await asyncio.to_thread(_bootstrap_sync, cfg)
	app.state.key_mismatch = key_mismatch
	
	# Initialize TSDB (idempotent, safe for multi-worker)
	tsdb.init_tsdb(cfg.tsdb_dir)
	
	# ─── GeoIP databases ──────────────────────────────────────
	# Do not block startup on network-bound GeoIP checks/downloads.
	# GeoIP sync runs as scheduler background task (run_on_start + periodic).
	if is_leader:
		_log.info("GeoIP init scheduled in background (startup is non-blocking)")
	
	# Prepare Unbound DNS config - leader only
	# NOTE: Config is written BEFORE WireGuard starts, but Unbound is started
	# AFTER WireGuard to ensure interface IPs exist for binding.
	from .dns import unbound as _unbound
	_dns_service_enabled = False
	_dns_config_ready = False
	if is_leader and _unbound.is_unbound_installed():
		try:
			# Always write WireBuddy config (overwrites Debian default)
			# Bind Unbound ONLY to WireGuard interface IPs to avoid conflicts
			# with host DNS resolver when using network_mode: host.
			# Do NOT include 127.0.0.1 - host may already have DNS on localhost.
			dns_retention_days = DEFAULT_DNS_LOG_RETENTION_DAYS
			_dns_service_enabled = True
			listen_addrs_ipv4: list[str] = []
			listen_addrs_ipv6: list[str] = []
			dns_data = await asyncio.to_thread(_load_dns_startup_data_sync, cfg.db_path)
			dns_retention_days = _safe_int(dns_data.get("dns_retention_days"), DEFAULT_DNS_LOG_RETENTION_DAYS)
			_dns_service_enabled = bool(dns_data.get("dns_service_enabled", True))
			interfaces = dns_data.get("interfaces", [])

			# Extract WireGuard interface IPs (strip CIDR notation)
			for iface in interfaces:
				addr4 = _get_addr_field(iface, "address")
				if addr4:
					ip4 = addr4.split("/")[0]
					if ip4 not in listen_addrs_ipv4:
						listen_addrs_ipv4.append(ip4)
				addr6 = _get_addr_field(iface, "address6")
				if addr6:
					ip6 = addr6.split("/")[0]
					if ip6 not in listen_addrs_ipv6:
						listen_addrs_ipv6.append(ip6)

			# Skip DNS initialization if no WireGuard interfaces exist
			# (Unbound needs interface IPs to bind to)
			if not listen_addrs_ipv4:
				_log.info("DNS init skipped: no WireGuard interfaces configured yet")
			else:
				await asyncio.to_thread(
					_unbound.write_config,
					enable_logging=bool(dns_data.get("enable_logging", True)),
					enable_blocklist=bool(dns_data.get("enable_blocklist", True)),
					upstream_dns=dns_data.get("upstream_dns", []),
					enable_dnssec=bool(dns_data.get("enable_dnssec", True)),
					listen_addrs_ipv4=listen_addrs_ipv4,
					listen_addrs_ipv6=listen_addrs_ipv6 if listen_addrs_ipv6 else None,
				)
				# Generate split-DNS local-data (wg_fqdn -> interface IPs)
				await asyncio.to_thread(
					_unbound.write_local_data_overrides,
					interfaces,
					dns_data.get("wg_fqdn"),
				)
				
				# Regenerate peer tags for ad-blocking
				peer_count = await asyncio.to_thread(
					_regenerate_peer_tags_sync,
					cfg.db_path,
				)
				_log.debug("DNS peer tags regenerated for %d peers", peer_count)

				await asyncio.to_thread(
					dns_ingestion.enforce_dns_log_retention,
					cfg.dns_dir,
					dns_retention_days,
				)
				_log.info(
					"DNS config written (IPv4: %s, IPv6: %s)",
					", ".join(listen_addrs_ipv4) if listen_addrs_ipv4 else "none",
					", ".join(listen_addrs_ipv6) if listen_addrs_ipv6 else "none",
				)

				# Check for stale blocklist tags (e.g., after registry changes like easylist→hagezi)
				# This must run BEFORE Unbound starts to avoid config errors
				from .dns.unbound_blocklist import check_and_reset_stale_blocklist
				if check_and_reset_stale_blocklist():
					_log.info("Blocklist reset due to tag migration - triggering immediate update")
					try:
						bl_urls, bl_custom_rules = await asyncio.to_thread(
							_load_blocklist_update_inputs_sync,
							cfg.db_path,
						)
						count, msg = await _unbound.update_blocklists(bl_urls, custom_rules_text=bl_custom_rules)
						_log.info("BLOCKLIST_MIGRATION %s", msg)
					except Exception as exc:
						_log.warning("BLOCKLIST_MIGRATION update failed: %s", exc)

				_dns_config_ready = True
		except FileNotFoundError as exc:
			_log.warning("DNS init skipped: unbound tools not found! Use Docker Image for full experience! (%s)", exc)
		except Exception as exc:
			# Issue #10: use exception() so stack trace is always captured for
			# non-obvious errors (corrupted DB, key mismatch, permission failures).
			_log.exception("DNS config failed: %s", exc)
	
	# Clean up stale/orphaned WireGuard interfaces (leader only)
	# These are interfaces active in the kernel but without a config file,
	# typically left over after clearing the data directory in host network mode.
	if is_leader:
		removed_stale = await _cleanup_stale_interfaces()
		if removed_stale:
			_log.info("Cleaned up %d stale interface(s): %s", len(removed_stale), removed_stale)

	# Auto-start WireGuard interfaces (leader only)
	# Runs BEFORE Unbound so that interface IPs exist for DNS binding.
	# NOTE: DNS is not set in server-side configs, so wg-quick does not
	# rewrite /etc/resolv.conf. Unbound is started separately after WG.
		# KNOWN LIMITATION (Issue #17):
		# started_interfaces only tracks interfaces THIS process brought up.
		# If the leader crashes and a new worker becomes leader, old interfaces
		# remain active with no process tracking them for shutdown.
		# This is intentional to avoid bringing down interfaces we didn't create.
		if is_leader and interfaces_to_start:
			for iface_name in interfaces_to_start:
				try:
					# Check if interface is already up
					check_proc = await asyncio.create_subprocess_exec(
						"wg", "show", iface_name,
						stdout=asyncio.subprocess.DEVNULL,
						stderr=asyncio.subprocess.DEVNULL,
					)
					await _communicate_with_timeout(
						check_proc,
						timeout_seconds=_WG_CHECK_TIMEOUT_SECONDS,
					)
					
					if check_proc.returncode == 0:
						_log.info("WireGuard interface %s already running", iface_name)
						# Issue #17: do NOT append to started_interfaces here.
						# We only track interfaces that *we* started so that shutdown
						# only brings down what we brought up.
						continue

					# Start the interface
					proc = await asyncio.create_subprocess_exec(
						"wg-quick", "up", iface_name,
						stdout=asyncio.subprocess.PIPE,
						stderr=asyncio.subprocess.PIPE,
					)
					_, stderr = await _communicate_with_timeout(
						proc,
						timeout_seconds=_WG_UP_TIMEOUT_SECONDS,
					)
					if proc.returncode == 0:
						_log.info("WireGuard interface %s started", iface_name)
						started_interfaces.append(iface_name)
					else:
						_log.warning("Failed to start interface %s: %s", iface_name, stderr.decode("utf-8", errors="replace"))
				except asyncio.TimeoutError:
					_log.warning("Timeout while starting/checking interface %s", iface_name)
				except Exception as e:
					_log.warning("Failed to start interface %s: %s", iface_name, e)
	
	# ─── START UNBOUND DNS ─────────────────────────────────── (leader only)
	# Runs AFTER WireGuard interfaces are up to ensure bind addresses exist.
	# DNS config was written earlier, now we just start the resolver.
	if is_leader and _unbound.is_unbound_installed() and _dns_config_ready:
		try:
			unbound_running = await _unbound.is_running()
			if _dns_service_enabled:
				if not unbound_running:
					# Respect persisted user choice: start resolver after container restart
					# unless it was explicitly stopped by the user.
					ok, msg = await _unbound.start()
					if ok:
						_log.info("Unbound DNS started")
						# Give Unbound a moment to establish upstream TLS connections
						await asyncio.sleep(2)
					else:
						_log.warning("Failed to start Unbound: %s", msg)
			else:
				# Persisted manual stop: keep resolver down across restarts.
				if unbound_running:
					ok, msg = await _unbound.stop()
					if ok:
						_log.info("Unbound DNS kept stopped (persisted user preference)")
					else:
						_log.warning("Failed to keep Unbound stopped on startup: %s", msg)
				else:
					_log.info("Unbound autostart disabled; resolver remains stopped")
		except Exception as exc:
			_log.exception("DNS start failed: %s", exc)

	# ─── SCHEDULER ─────────────────────────────────────────── (leader only)
	scheduler: Scheduler | None = None
	if is_leader:
		scheduler = Scheduler()

		async def _update_blocklists() -> None:
			"""Scheduled task: download and apply blocklists."""
			if not _unbound.is_unbound_installed():
				return  # Skip if Unbound not installed
			# Skip if blocklist is disabled
			blocklist_enabled = await asyncio.to_thread(_read_blocklist_enabled_sync, cfg.db_path)
			if not blocklist_enabled:
				return
			try:
				urls, custom_rules_text = await asyncio.to_thread(
					_load_blocklist_update_inputs_sync,
					cfg.db_path,
				)
				
				count, msg = await _unbound.update_blocklists(urls, custom_rules_text=custom_rules_text)
				# Use restart instead of reload - reload crashes with large blocklists
				await _unbound.restart()
				_log.info("BLOCKLIST_UPDATE %s", msg)
			except Exception as exc:
				_log.error("BLOCKLIST_UPDATE failed: %s", exc)

		async def _maintain_tsdb() -> None:
			"""Scheduled task: prune/rotate/compress TSDB series."""
			try:
				tsdb_retention_days = await asyncio.to_thread(_read_tsdb_retention_days_sync, cfg.db_path)
				stats = await asyncio.to_thread(tsdb.run_maintenance, cfg.tsdb_dir, tsdb_retention_days)
				dns_retention_days = await asyncio.to_thread(_read_dns_retention_days_sync, cfg.db_path)
				dns_retention = await asyncio.to_thread(
					dns_ingestion.enforce_dns_log_retention,
					cfg.dns_dir,
					dns_retention_days,
				)
				_log.info(
					"TSDB_MAINTENANCE series=%d rotated=%d pruned=%d dns_deleted=%d dns_remaining=%d dns_days=%d",
					stats.get("series", 0),
					stats.get("rotated", 0),
					stats.get("pruned", 0),
					dns_retention.get("deleted_files", 0),
					dns_retention.get("remaining_files", 0),
					dns_retention_days,
				)
			except Exception as exc:
				_log.error("TSDB_MAINTENANCE failed: %s", exc)

		async def _sample_tsdb_metrics() -> None:
			"""Scheduled task: sample WireGuard transfer counters into TSDB."""
			try:
				proc = await asyncio.create_subprocess_exec(
					"wg", "show", "all", "dump",
					stdout=asyncio.subprocess.PIPE,
					stderr=asyncio.subprocess.PIPE,
				)
				stdout_raw, stderr_raw = await _communicate_with_timeout(
					proc,
					timeout_seconds=_WG_CHECK_TIMEOUT_SECONDS,
				)
			except asyncio.TimeoutError:
				_log.warning("TSDB_SAMPLE timed out while executing 'wg show all dump'")
				return
			except FileNotFoundError:
				_log.warning("TSDB_SAMPLE skipped: 'wg' binary not found")
				return
			except Exception as exc:
				_log.warning("TSDB_SAMPLE failed to execute wg dump: %s", exc)
				return

			if proc.returncode != 0:
				stderr = (stderr_raw or b"").decode("utf-8", errors="replace").strip()
				_log.info("TSDB_SAMPLE wg dump returned code=%s: %s", proc.returncode, stderr)
				return

			stdout = (stdout_raw or b"").decode("utf-8", errors="replace")
			if not stdout.strip():
				_log.debug("TSDB_SAMPLE wg dump returned empty output (no active interfaces?)")
				return

			peer_counters = _parse_wg_dump_counters(stdout)
			if not peer_counters:
				_log.debug("TSDB_SAMPLE no peers found in wg dump output")
				return

			# Track connection state changes for logging
			now = time.time()
			state_changes: list[tuple[str, bool]] = []  # (public_key, is_now_connected)

			points = 0
			for public_key, (rx, tx, latest_handshake) in peer_counters.items():
				tsdb.append_point(
					cfg.tsdb_dir,
					peer_key=public_key,
					metric="rx_bytes",
					value=rx,
				)
				tsdb.append_point(
					cfg.tsdb_dir,
					peer_key=public_key,
					metric="tx_bytes",
					value=tx,
				)
				points += 2
				if latest_handshake > 0:
					tsdb.append_point(
						cfg.tsdb_dir,
						peer_key=public_key,
						metric="latest_handshake",
						value=latest_handshake,
					)
					points += 1

					# Detect connection state changes
					is_connected = (now - latest_handshake) < _PEER_CONNECTION_THRESHOLD
					was_connected = peer_connection_state.get(public_key, False)

					# Log every active handshake at DEBUG level for visibility
					if is_connected:
						handshake_age = int(now - latest_handshake)
						_log.debug(
							"PEER_HANDSHAKE public_key=%s handshake_age=%ds rx=%d tx=%d",
							public_key[:16], handshake_age, rx, tx,
						)

					if is_connected != was_connected:
						# LRU eviction: drop oldest 10 % when near capacity (issue #3).
						# A full clear would cause every peer to appear as freshly
						# connected on the next sample, generating spurious log events.
						if len(peer_connection_state) >= _PEER_STATE_MAX_SIZE:
							evict = _PEER_STATE_MAX_SIZE // 10
							for _ in range(evict):
								peer_connection_state.popitem(last=False)
							_log.warning("PEER_STATE evicted %d oldest entries", evict)
						peer_connection_state[public_key] = is_connected
						peer_connection_state.move_to_end(public_key)
						state_changes.append((public_key, is_connected))

			_log.debug("TSDB_SAMPLE peers=%d points=%d", len(peer_counters), points)

			# Log connection state changes with peer names
			if state_changes:
				public_keys = [public_key for public_key, _ in state_changes]
				peer_identity_map = await asyncio.to_thread(
					_load_peer_identity_map_sync,
					cfg.db_path,
					public_keys,
				)
				for public_key, is_connected in state_changes:
					peer_identity = peer_identity_map.get(public_key)
					if peer_identity:
						peer_name, interface = peer_identity
						if is_connected:
							_log.info("PEER_CONNECTED name=%s interface=%s public_key=%s",
								peer_name, interface, public_key[:16])
						else:
							_log.info("PEER_DISCONNECTED name=%s interface=%s public_key=%s",
								peer_name, interface, public_key[:16])
					else:
						if is_connected:
							_log.info("PEER_CONNECTED public_key=%s (not in database)", public_key[:16])
						else:
							_log.info("PEER_DISCONNECTED public_key=%s (not in database)", public_key[:16])

		# Reuse existing blocklist after container restart.
		# Only do an immediate startup download if there is no local blocklist yet.
		# Skip all blocklist scheduling if blocklist is disabled.
		blocklist_enabled_startup = await asyncio.to_thread(_read_blocklist_enabled_sync, cfg.db_path)
		blocklist_interval_seconds = _BLOCKLIST_UPDATE_INTERVAL_SECONDS
		blocklist_jitter_pct = 0.1
		blocklist_run_on_start = False
		if blocklist_enabled_startup:
			try:
				blocklist_run_on_start = _unbound.get_blocklist_count() <= 0
			except Exception:
				_log.warning("BLOCKLIST_STARTUP could not inspect local blocklist; scheduling startup update")
				blocklist_run_on_start = True
			if blocklist_run_on_start:
				_log.info("BLOCKLIST_STARTUP no cached blocklist found - scheduling immediate update")
			else:
				min_delay_h = (blocklist_interval_seconds * (1.0 - blocklist_jitter_pct)) / 3600.0
				max_delay_h = (blocklist_interval_seconds * (1.0 + blocklist_jitter_pct)) / 3600.0
				_log.info(
					"BLOCKLIST_STARTUP cached blocklist found - deferring first update to %.1f-%.1f hours (interval=24h, jitter=±10%%)",
					min_delay_h,
					max_delay_h,
				)
		else:
			_log.info("BLOCKLIST_STARTUP skipped: ad-blocker is disabled")
		blocklist_initial_delay = 15.0 if blocklist_run_on_start else 0.0

		scheduler.add(
			"blocklist-update",
			interval_seconds=blocklist_interval_seconds,
			func=_update_blocklists,
			run_on_start=blocklist_run_on_start,
			initial_delay=blocklist_initial_delay,  # Delay only applies when run_on_start=True
			jitter_pct=blocklist_jitter_pct,  # ±10% jitter (±2.4h) to distribute load across instances
		)
		scheduler.add(
			"tsdb-maintenance",
			interval_seconds=_TSDB_MAINTENANCE_INTERVAL_SECONDS,  # 6 h
			func=_maintain_tsdb,
			run_on_start=True,
			initial_delay=30.0,
		)
		scheduler.add(
			"tsdb-sample",
			interval_seconds=_TSDB_SAMPLE_INTERVAL_SECONDS,
			func=_sample_tsdb_metrics,
			run_on_start=True,
			initial_delay=10.0,
		)

		# ─── COUNTRY TRAFFIC (CONNTRACK) ──────────────────────────────
		from .utils.conntrack import init_conntrack_accounting, sample_country_traffic
		from .utils.conntrack import ASN_TRAFFIC_KEY, ASN_TRAFFIC_METRIC
		from .api.wireguard_stats_country import GEO_TRAFFIC_KEY, GEO_TRAFFIC_METRIC

		# Enable byte accounting in the kernel conntrack table.
		# This is a no-op if already enabled or if /proc isn't writable.
		try:
			await asyncio.to_thread(init_conntrack_accounting)
		except Exception as exc:
			_log.warning("COUNTRY_TRAFFIC could not enable conntrack accounting: %s", exc)

		async def _sample_country_traffic() -> None:
			"""Scheduled task: sample conntrack → country + ASN traffic → TSDB."""
			try:
				enabled, peer_ip_map = await asyncio.to_thread(
					_read_country_traffic_inputs_sync,
					cfg.db_path,
				)
				if not enabled:
					return

				country_deltas, asn_deltas = await asyncio.to_thread(
					sample_country_traffic, peer_ip_map
				)

				if country_deltas:
					tsdb.append_point(
						cfg.tsdb_dir,
						peer_key=GEO_TRAFFIC_KEY,
						metric=GEO_TRAFFIC_METRIC,
						value=country_deltas,
					)
					total_rx = sum(v.get("rx", 0) for v in country_deltas.values())
					total_tx = sum(v.get("tx", 0) for v in country_deltas.values())
					_log.debug(
						"COUNTRY_TRAFFIC countries=%d rx=%.0f tx=%.0f",
						len(country_deltas), total_rx, total_tx,
					)

				if asn_deltas:
					tsdb.append_point(
						cfg.tsdb_dir,
						peer_key=ASN_TRAFFIC_KEY,
						metric=ASN_TRAFFIC_METRIC,
						value=asn_deltas,
					)
					_log.debug(
						"ASN_TRAFFIC asns=%d",
						len(asn_deltas),
					)
			except Exception as exc:
				_log.warning("COUNTRY_TRAFFIC sample failed: %s", exc)

		scheduler.add(
			"country-traffic",
			interval_seconds=_TSDB_SAMPLE_INTERVAL_SECONDS,
			func=_sample_country_traffic,
			run_on_start=True,
			initial_delay=15.0,  # after tsdb-sample (10 s) to stagger I/O
		)

		async def _update_geoip() -> None:
			"""Scheduled task: check for GeoIP database updates."""
			try:
				from .utils.geoip import ensure_geoip_databases, eager_init
				result = await asyncio.to_thread(ensure_geoip_databases, cfg.data_dir)
				_log.info("GEOIP_UPDATE city=%s asn=%s", result["city"], result["asn"])
				# Pre-load readers so first request is instant
				eager_init()
			except Exception as exc:
				_log.error("GEOIP_UPDATE failed: %s", exc)

		scheduler.add(
			"geoip-update",
			interval_seconds=_GEOIP_UPDATE_INTERVAL_SECONDS,  # 7 days
			func=_update_geoip,
			run_on_start=True,   # first check runs in background after startup
			initial_delay=20.0,  # wait for WireGuard + Unbound + DNS to be ready
		)
		
		# ─── DATABASE MAINTENANCE TASKS ───────────────────────────────
		# Periodic maintenance for SQLite and TSDB health
		from .tasks.maintenance import (
			sqlite_maintenance,
			sqlite_integrity_check,
			tsdb_retention_cleanup,
			cleanup_stale_sessions,
		)
		
		scheduler.add(
			"sqlite-maintenance",
			interval_seconds=_SQLITE_MAINTENANCE_INTERVAL_SECONDS,  # 6 hours
			func=sqlite_maintenance,
			run_on_start=True,
			initial_delay=60.0,  # Let app fully start first
			timeout=60.0,
		)
		
		scheduler.add(
			"sqlite-integrity",
			interval_seconds=_SQLITE_INTEGRITY_INTERVAL_SECONDS,  # 7 days (weekly)
			func=sqlite_integrity_check,
			run_on_start=False,  # Skip on every startup, only run weekly
			timeout=300.0,
		)
		
		scheduler.add(
			"tsdb-retention",
			interval_seconds=_TSDB_RETENTION_INTERVAL_SECONDS,  # 24 hours (daily)
			func=tsdb_retention_cleanup,
			run_on_start=True,
			initial_delay=90.0,
			timeout=120.0,
		)
		
		scheduler.add(
			"session-cleanup",
			interval_seconds=_SESSION_CLEANUP_INTERVAL_SECONDS,  # 1 hour
			func=cleanup_stale_sessions,
			run_on_start=True,
			initial_delay=120.0,
			timeout=30.0,
		)
		
		# ─── DNS WATCHDOG ─────────────────────────────────────────────
		# Periodically check if Unbound is running and restart if crashed
		async def _dns_watchdog() -> None:
			"""Scheduled task: restart Unbound if it crashed."""
			if not _unbound.is_unbound_installed():
				return  # Skip if Unbound not installed
			should_run = await asyncio.to_thread(_should_unbound_run_sync, cfg.db_path)
			await _unbound.watchdog(lambda: should_run)

		scheduler.add(
			"dns-watchdog",
			interval_seconds=_DNS_WATCHDOG_INTERVAL_SECONDS,  # Check every 30 seconds
			func=_dns_watchdog,
			run_on_start=True,  # Run first check after initial_delay
			initial_delay=60.0,  # Wait for initial startup to complete
			timeout=30.0,
		)

		# ─── ADBLOCKER TIMER CHECK ────────────────────────────────────
		# Periodically check if timed disable has expired and re-enable adblocker
		async def _check_adblocker_timer() -> None:
			"""Scheduled task: re-enable ad-blocker when timed disable expires."""
			import time as _time
			from .db.sqlite_settings import (
				get_blocklist_disabled_until,
				clear_blocklist_disabled_until,
				get_dns_blocklist_enabled,
				set_dns_blocklist_enabled,
			)
			conn = connect(cfg.db_path)
			try:
				# Use explicit transaction to prevent TOCTOU race with concurrent API requests
				conn.execute("BEGIN IMMEDIATE")
				try:
					disabled_until = get_blocklist_disabled_until(conn)
					enabled = get_dns_blocklist_enabled(conn)
					now = int(_time.time())

					# If timer has expired and blocker is still disabled, re-enable it
					if disabled_until > 0 and disabled_until <= now and not enabled:
						set_dns_blocklist_enabled(conn, True)
						clear_blocklist_disabled_until(conn)
						conn.commit()
						_log.info("ADBLOCKER_TIMER timer expired, re-enabling ad-blocker")

						# Regenerate peer tags and reload Unbound
						from .api.wireguard_peers import regenerate_all_peer_tags
						await asyncio.to_thread(regenerate_all_peer_tags, conn)
						await _reload_unbound_for_adblocker(conn)
					else:
						conn.rollback()
				except Exception:
					conn.rollback()
					raise
			except Exception as exc:
				_log.warning("ADBLOCKER_TIMER check failed: %s", exc)
			finally:
				close_connection(conn)

		async def _reload_unbound_for_adblocker(conn) -> None:
			"""Reload Unbound config after adblocker state change."""
			try:
				# Use module-level imports (already imported at top)
				enable_logging = get_dns_query_logging_enabled(conn)
				enable_blocklist = get_dns_blocklist_enabled(conn)
				upstream_dns = get_dns_upstream_servers(conn)
				dnssec_enabled = get_dnssec_enabled(conn)

				interfaces = list_interfaces(conn)
				ipv4_gateways = []
				for iface in interfaces:
					try:
						addr4 = iface["address"]
					except (KeyError, TypeError):
						addr4 = getattr(iface, "address", None)
					if addr4:
						ip4 = str(addr4).split("/")[0]
						if ip4 not in ipv4_gateways:
							ipv4_gateways.append(ip4)
				ipv6_gateways = _unbound.get_interface_ipv6_gateways(interfaces)
				_unbound.write_config(
					enable_logging=enable_logging,
					enable_blocklist=enable_blocklist,
					upstream_dns=upstream_dns,
					enable_dnssec=dnssec_enabled,
					listen_addrs_ipv4=ipv4_gateways,
					listen_addrs_ipv6=ipv6_gateways if ipv6_gateways else None,
				)
				await _unbound.reload_config()
			except Exception:
				_log.warning("ADBLOCKER_TIMER failed to reload Unbound", exc_info=True)

		scheduler.add(
			"adblocker-timer-check",
			interval_seconds=_ADBLOCKER_TIMER_CHECK_INTERVAL_SECONDS,  # Check every 15 seconds
			func=_check_adblocker_timer,
			run_on_start=False,  # No need to run immediately on start
			timeout=30.0,
		)
		
		await scheduler.start()
		
		# ─── DNS INGESTION DAEMON ─────────────────────────────────────
		# This is a long-running daemon task, not a periodic job.
		# Runs forever, managed separately from scheduler.
		async def _run_dns_ingestion() -> None:
			"""Daemon task: ingest DNS queries from Unbound log to TSDB."""
			# Skip entirely if Unbound is not installed
			if not _unbound.is_unbound_installed():
				_log.info("DNS_INGESTION skipped: Unbound not installed")
				return
			
			retry_count = 0
			dns_retention_days_cache = DEFAULT_DNS_LOG_RETENTION_DAYS
			while True:
				# Skip if no WireGuard interfaces configured (Unbound won't be running)
				should_run = await asyncio.to_thread(_should_unbound_run_sync, cfg.db_path)
				if not should_run:
					await asyncio.sleep(30.0)  # Check again in 30s
					continue
				
				# Wait for Unbound to be ready using a readiness probe instead of a
				# fixed sleep (issue #9: 25 s was fragile on slow/fast systems).
				for attempt in range(15):
					if await _unbound.is_running():
						break
					delay = min(2.0 ** attempt, 30.0)  # exponential back-off, cap 30 s
					_log.debug("DNS_INGESTION waiting for Unbound (attempt %d, retry in %.0fs)", attempt + 1, delay)
					await asyncio.sleep(delay)
				else:
					_log.warning("DNS_INGESTION Unbound not ready after probes; starting ingestion anyway")

				def _current_dns_retention_days() -> int:
					return dns_retention_days_cache
				
				try:
					dns_retention_days_cache = await asyncio.to_thread(
						_read_dns_retention_days_sync,
						cfg.db_path,
					)
					offset_path = cfg.data_dir / "dns" / "dns_tail.offset"
					offset_path.parent.mkdir(parents=True, exist_ok=True)

					# Backward compatibility: migrate legacy offset path if it exists.
					legacy_offset_path = cfg.data_dir / "runtime" / "dns_tail.offset"
					if not offset_path.exists() and legacy_offset_path.exists():
						try:
							offset_path.write_text(legacy_offset_path.read_text(encoding="utf-8"), encoding="utf-8")
							legacy_offset_path.unlink(missing_ok=True)
							legacy_runtime_dir = legacy_offset_path.parent
							if legacy_runtime_dir.exists() and not any(legacy_runtime_dir.iterdir()):
								legacy_runtime_dir.rmdir()
							_log.info("DNS_INGESTION migrated offset file from %s to %s", legacy_offset_path, offset_path)
						except Exception as exc:
							_log.warning("DNS_INGESTION failed to migrate legacy offset file: %s", exc)

					await dns_ingestion.run_dns_ingestion(
						log_path=unbound.QUERY_LOG,
						offset_path=offset_path,
						dns_dir=cfg.dns_dir,
						blocked_domains_func=unbound.get_blocked_domains,
						retention_days_func=_current_dns_retention_days,
					)
					retry_count = 0
					_log.warning("DNS_INGESTION stopped unexpectedly; restarting in 5s")
					await asyncio.sleep(5.0)
				except asyncio.CancelledError:
					_log.info("DNS_INGESTION shutdown requested")
					raise
				except Exception as exc:
					retry_count += 1
					delay = min(
						_DNS_INGESTION_RESTART_BASE_DELAY_SECONDS ** retry_count,
						_DNS_INGESTION_RESTART_MAX_DELAY_SECONDS,
					)
					_log.error(
						"DNS_INGESTION crashed (retry #%d in %.0fs): %s",
						retry_count,
						delay,
						exc,
					)
					await asyncio.sleep(delay)
		
		app.state.dns_task = asyncio.create_task(_run_dns_ingestion())
	
	app.state.scheduler = scheduler
	app.state.is_leader = is_leader
	app.state.started_interfaces = started_interfaces

	_log.info("WireBuddy started successfully (leader=%s, pid=%d)", is_leader, os.getpid())

	# ─── YIELD (app serving) + SHUTDOWN ──────────────────────────────────────
	# Issues #1 & #2: ALL cleanup is inside finally so it runs on:
	#   - normal shutdown
	#   - SIGTERM / SIGINT (CancelledError)
	#   - any unhandled exception during startup (after leader lock acquisition)
	try:
		yield
	finally:
		# 1. Cancel DNS ingestion daemon (fastest to stop)
		dns_task = getattr(app.state, "dns_task", None)
		if dns_task and not dns_task.done():
			dns_task.cancel()
			await asyncio.gather(dns_task, return_exceptions=True)
			_log.info("DNS_INGESTION stopped")

		# 2. Scheduler
		if scheduler:
			await scheduler.stop_graceful(timeout=5.0)

		# 3. Bring down WireGuard interfaces we started
		if is_leader and started_interfaces:
			for iface_name in started_interfaces:
				try:
					proc = await asyncio.create_subprocess_exec(
						"wg-quick", "down", iface_name,
						stdout=asyncio.subprocess.PIPE,
						stderr=asyncio.subprocess.PIPE,
					)
					_, stderr = await _communicate_with_timeout(
						proc,
						timeout_seconds=_WG_DOWN_TIMEOUT_SECONDS,
					)
					if proc.returncode == 0:
						_log.info("WireGuard interface %s stopped", iface_name)
					else:
						_log.warning("Failed to stop interface %s: %s", iface_name, stderr.decode("utf-8", errors="replace"))
				except asyncio.TimeoutError:
					_log.warning("Timeout while stopping interface %s", iface_name)
				except Exception as e:
					_log.warning("Failed to stop interface %s: %s", iface_name, e)

		# 4. Release leader lock (issue #2: always runs, even on startup crash)
		if is_leader:
			try:
				await asyncio.to_thread(_release_leader_lock_sync, cfg.db_path)
			except Exception:
				_log.exception("Failed to release leader lock")

		# 5. TSDB fsync
		try:
			tsdb_stats = tsdb.finalize_shutdown(cfg.tsdb_dir)
			_log.info(
				"TSDB_SHUTDOWN series=%d rotated=%d pruned=%d synced_files=%d synced_dirs=%d",
				tsdb_stats.get("series", 0),
				tsdb_stats.get("rotated", 0),
				tsdb_stats.get("pruned", 0),
				tsdb_stats.get("synced_files", 0),
				tsdb_stats.get("synced_dirs", 0),
			)
		except Exception as exc:
			_log.warning("TSDB_SHUTDOWN failed: %s", exc)

		# 6. SQLite WAL checkpoint + close all connections
		checkpoint, closed_connections = await asyncio.to_thread(
			_sqlite_shutdown_sync,
			cfg.db_path,
		)
		_log.info(
			"SQLITE_SHUTDOWN connections_closed=%d checkpoint_mode=%s busy=%s log_frames=%s checkpointed_frames=%s",
			closed_connections,
			checkpoint.get("mode"),
			checkpoint.get("busy"),
			checkpoint.get("log_frames"),
			checkpoint.get("checkpointed_frames"),
		)
		_log.info("WireBuddy shutdown complete")


def create_app() -> FastAPI:
	"""Application factory for WireBuddy."""
	# Print banner first (before any logs)
	print_banner_once()
	
	# Load configuration and setup logging
	cfg = load_config()
	_setup_logging(cfg.log_level)
	
	app = FastAPI(
		title="WireBuddy",
		description="Lightweight WireGuard Management WebUI",
		version=VERSION,
		lifespan=_lifespan,
		docs_url=None,
		redoc_url=None,
	)
	
	app.state.cfg = cfg
	app.state.db_path = cfg.db_path
	app.state.tsdb_dir = cfg.tsdb_dir
	app.state.dns_dir = cfg.dns_dir
	app.state.peer_connection_state = collections.OrderedDict()
	app.state.key_mismatch = False  # Set to True if SECRET_KEY doesn't match DB encryption
	
	# ─── MIDDLEWARE ──────────────────────────────────────────
	app.add_middleware(RequestIDMiddleware)

	from .middleware.csrf import CSRFMiddleware
	app.add_middleware(CSRFMiddleware)

	app.state.limiter = limiter

	from slowapi import _rate_limit_exceeded_handler
	from slowapi.errors import RateLimitExceeded
	app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
	app.add_exception_handler(frontend_ui.RedirectTo, frontend_ui.redirect_to_handler)

	# ─── STATIC FILES ────────────────────────────────────────
	from fastapi.staticfiles import StaticFiles
	static_path = Path(__file__).parent / "static"
	if static_path.exists():
		app.mount("/static", StaticFiles(directory=str(static_path)), name="static")
	else:
		_log.warning("Static files directory not found: %s", static_path)
	
	# ─── API ROUTES ──────────────────────────────────────────
	app.include_router(auth_api.router, prefix="/api")
	app.include_router(passkeys_api.router, prefix="/api/passkeys")
	app.include_router(users_api.router, prefix="/api/users")
	app.include_router(wireguard_api.router, prefix="/api/wireguard")
	app.include_router(dns_api.router, prefix="/api/dns")
	app.include_router(acme_api.router, prefix="/api/acme")
	
	# ─── FRONTEND ROUTES ─────────────────────────────────────
	app.include_router(frontend_ui.router)

	# ─── SWAGGER (admin-only) ────────────────────────────────
	_register_swagger_routes(app)

	return app


def _register_swagger_routes(app: FastAPI) -> None:
	"""Register admin-protected Swagger UI at /swagger."""
	import sqlite3
	from fastapi import Depends, HTTPException
	from fastapi.responses import HTMLResponse, JSONResponse
	from .api.auth import require_admin
	from .utils.deps import get_conn

	_SWAGGER_ENABLE_KEY = "enable_swagger"
	_SWAGGER_TRUTHY = {"1", "true", "yes", "on"}

	def _is_swagger_enabled(conn: sqlite3.Connection) -> bool:
		"""Return whether Swagger UI is enabled."""
		value = get_setting(conn, _SWAGGER_ENABLE_KEY, "0")
		return str(value or "").strip().lower() in _SWAGGER_TRUTHY

	@app.get("/swagger/openapi.json", include_in_schema=False)
	async def swagger_openapi_json(_=Depends(require_admin), conn: sqlite3.Connection = Depends(get_conn)):
		"""Serve OpenAPI schema (admin only, when enabled)."""
		if not _is_swagger_enabled(conn):
			raise HTTPException(status_code=404, detail="Swagger API disabled")
		return JSONResponse(content=app.openapi())

	@app.get("/swagger", include_in_schema=False)
	async def swagger_ui(_=Depends(require_admin), conn: sqlite3.Connection = Depends(get_conn)):
		"""Serve Swagger UI (admin only, when enabled)."""
		if not _is_swagger_enabled(conn):
			raise HTTPException(status_code=404, detail="Swagger API disabled")
		return HTMLResponse(_SWAGGER_HTML)


_SWAGGER_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>WireBuddy – API Docs</title>
  <!-- Pin exact version and use SRI to prevent CDN compromise / MITM attacks -->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.18.2/swagger-ui.css"
        integrity="sha384-OiJUz2Or7cLjcY1Eaw2xhMeUY3z5Csh2+HG9WXElrCqx45ddJCnYXN0a/HQQsJtz"
        crossorigin="anonymous">
  <style>
    html { box-sizing: border-box; overflow-y: scroll; }
    body { margin: 0; background: #fafafa; }
    .swagger-ui .topbar { display: none; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.18.2/swagger-ui-bundle.js"
          integrity="sha384-BxL6Z8PoHDrYi8O8M1NBMsFQH7sRaSmCF6y7iWMN6ijIc0+QfMwJ3ZqY5rkGNwmq"
          crossorigin="anonymous"></script>
  <script>
    SwaggerUIBundle({
      url: "/swagger/openapi.json",
      dom_id: "#swagger-ui",
      presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIBundle.SwaggerUIStandalonePreset,
      ],
      layout: "BaseLayout",
      deepLinking: true,
    });
  </script>
</body>
</html>
"""
