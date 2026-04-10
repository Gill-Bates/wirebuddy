#!/usr/bin/env python3
#
# app/main.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: AGPL-3.0
#

"""FastAPI application factory and startup lifecycle wiring."""

from __future__ import annotations

import typing

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
from .db.sqlite_schema import ensure_default_admin, init_schema, insert_default_settings
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
import signal
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
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
from .api import backup as backup_api
from .api import passkeys as passkeys_api
from .api import users as users_api
from .api import wireguard as wireguard_api
from .api import dns as dns_api
from .api import frontend_shared as frontend_ui
from .api import speedtest as speedtest_api
from .api import network_stats as network_stats_api
from .api import nodes as nodes_api
from .api import nodes_sync as nodes_sync_api
from .db import tsdb
from .dns import unbound
from .dns import ingestion as dns_ingestion
from .utils import migration
from .tasks import scheduled as scheduled_tasks

_log = logging.getLogger(__name__)


class StartupFatalError(RuntimeError):
	"""Raised when the application cannot start safely."""


@dataclass
class LifespanContext:
	"""State passed between lifespan phases for testability and clarity.
	
	This dataclass centralizes all state that needs to be shared between
	bootstrap, startup, and shutdown phases of the application lifecycle.
	"""
	cfg: Config
	app: FastAPI
	interfaces_to_start: list[str] = field(default_factory=list)
	started_interfaces: list[str] = field(default_factory=list)
	peer_connection_state: collections.OrderedDict = field(default_factory=collections.OrderedDict)
	dns_service_enabled: bool = False
	dns_config_ready: bool = False
	scheduler: Scheduler | None = None
	dns_task: asyncio.Task[None] | None = None


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
_WG_STARTUP_CONCURRENCY = 4  # Start up to 4 interfaces in parallel
_TSDB_SAMPLE_INTERVAL_SECONDS = 30.0
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


def _install_shutdown_signal_handlers(
	loop: asyncio.AbstractEventLoop,
	shutdown_event: asyncio.Event,
) -> list[tuple[int, object]]:
	"""Install signal handlers that also notify long-lived app connections.

	The wrapper preserves Uvicorn's existing SIGTERM/SIGINT handlers and only
	adds a side effect: setting ``shutdown_event`` as soon as the process is
	signalled. This lets streaming responses terminate before Uvicorn enters the
	application shutdown phase.
	"""
	installed: list[tuple[int, object]] = []

	for sig in (signal.SIGTERM, signal.SIGINT):
		try:
			previous_handler = signal.getsignal(sig)
		except Exception:
			continue

		def _handler(signum: int, frame: object, *, _previous=previous_handler) -> None:
			loop.call_soon_threadsafe(shutdown_event.set)
			if _previous in (None, signal.SIG_DFL, signal.SIG_IGN):
				return
			if _previous is signal.default_int_handler:
				_previous(signum, frame)
				return
			if callable(_previous):
				_previous(signum, frame)

		try:
			signal.signal(sig, _handler)
		except (ValueError, RuntimeError) as exc:
			_log.debug("Could not install shutdown signal hook for %s: %s", sig, exc)
			continue
		installed.append((sig, previous_handler))

	return installed


def _restore_signal_handlers(previous_handlers: list[tuple[int, object]]) -> None:
	"""Restore signal handlers replaced by _install_shutdown_signal_handlers."""
	for sig, previous_handler in previous_handlers:
		try:
			signal.signal(sig, previous_handler)
		except (ValueError, RuntimeError):
			continue


# Docker default bridge gateway ranges
_DOCKER_BRIDGE_NETWORKS = (
	ipaddress.ip_network("172.17.0.0/16"),
	ipaddress.ip_network("172.18.0.0/16"),
	ipaddress.ip_network("172.19.0.0/16"),
	ipaddress.ip_network("172.20.0.0/14"),
	ipaddress.ip_network("172.24.0.0/14"),
	ipaddress.ip_network("172.28.0.0/14"),
)

_BACKUP_INTERVAL_SECONDS = 86400  # 24 h (runs nightly)
_BACKUP_NIGHT_HOUR = 3  # Run backups at 03:00 local time

def _seconds_until_backup_time(tz: str = "UTC") -> float:
	"""Calculate seconds until next 03:00 in given timezone (default UTC)."""
	from datetime import datetime, timedelta, timezone
	try:
		from zoneinfo import ZoneInfo
		tzinfo = ZoneInfo(tz)
	except Exception as exc:
		_log.warning("Invalid timezone %r for scheduled backup; falling back to UTC: %s", tz, exc)
		tzinfo = timezone.utc

	now = datetime.now(tzinfo)
	target = now.replace(hour=_BACKUP_NIGHT_HOUR, minute=0, second=0, microsecond=0)
	if now >= target:
		target += timedelta(days=1)
	return max(0.0, (target - now).total_seconds())


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
		if proc.returncode != 0:
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
				raise SystemExit(1)

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
			_log.info(
				"CLEANUP_STALE_INTERFACE name=%s (active in kernel but no config file)",
				iface_name,
			)
			try:
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
						_decode_subprocess_output(stderr),
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


# NOTE: _peer_connection_state OrderedDict is only accessed from the single
# event loop thread (in _sample_tsdb_metrics). Not thread-safe for concurrent access.


def _humanize_aiosqlite_message(message: str) -> str:
	"""Rewrite low-signal aiosqlite debug messages into readable text."""
	def _describe_operation(operation: str) -> tuple[str, str]:
		known_operations = (
			("built-in method close of sqlite3.Connection", "closing SQLite connection", "SQLite connection closed"),
			("built-in method close of sqlite3.Cursor", "closing SQLite cursor", "SQLite cursor closed"),
			("built-in method commit of sqlite3.Connection", "committing SQLite transaction", "SQLite transaction committed"),
			("built-in method rollback of sqlite3.Connection", "rolling back SQLite transaction", "SQLite transaction rolled back"),
			("built-in method execute of sqlite3.Connection", "executing SQLite statement", "SQLite statement executed"),
			("built-in method execute of sqlite3.Cursor", "executing SQLite cursor statement", "SQLite cursor statement executed"),
			("built-in method fetchone of sqlite3.Cursor", "fetching one SQLite row", "SQLite row fetched"),
			("built-in method fetchall of sqlite3.Cursor", "fetching SQLite rows", "SQLite rows fetched"),
			("built-in method close of sqlite3.Blob", "closing SQLite blob handle", "SQLite blob handle closed"),
			("Connection.stop.<locals>.close_and_stop", "stopping SQLite worker thread", "SQLite worker thread stopped"),
			("connect.<locals>.connector", "opening SQLite connection", "SQLite connection opened"),
			("built-in method cursor of sqlite3.Connection", "creating SQLite cursor", "SQLite cursor created"),
		)
		for needle, active_text, done_text in known_operations:
			if needle in operation:
				return active_text, done_text
		return "running SQLite background operation", "SQLite background operation completed"

	if message.startswith("executing "):
		active_text, _ = _describe_operation(message[len("executing "):])
		return active_text
	if message.startswith("operation ") and message.endswith(" completed"):
		_, done_text = _describe_operation(message[len("operation "):-len(" completed")])
		return done_text
	if message.startswith("returning exception "):
		return f"SQLite background operation failed: {message[len('returning exception '):]}"
	return message


def _prepare_log_record(record: logging.LogRecord) -> logging.LogRecord:
	"""Clone and normalize a log record before formatting."""
	# Only copy records from loggers that need modification to reduce overhead
	# (issue #16: modifying the shared LogRecord object is not thread-safe).
	if record.name == "aiosqlite":
		record = logging.makeLogRecord(record.__dict__)
		record.msg = _humanize_aiosqlite_message(record.getMessage())
		record.args = ()
	return record


class _HumanizedFormatter(logging.Formatter):
	"""Formatter that normalizes noisy third-party log messages."""

	def _prepare(self, record: logging.LogRecord) -> logging.LogRecord:
		return _prepare_log_record(record)

	def format(self, record: logging.LogRecord) -> str:
		record = self._prepare(record)
		return super().format(record)


class _ColoredFormatter(_HumanizedFormatter):
	"""Custom formatter that adds color to log levels in TTY."""

	def format(self, record: logging.LogRecord) -> str:
		record = self._prepare(record)
		if record.levelname in _LOG_COLORS:
			record = logging.makeLogRecord(record.__dict__)
			record.levelname = f"{_LOG_COLORS[record.levelname]}{record.levelname:<8}{_RESET}"
		else:
			record = logging.makeLogRecord(record.__dict__)
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


def _decode_subprocess_output(data: bytes | None) -> str:
	"""Decode subprocess output safely for logs."""
	if not data:
		return ""
	return data.decode("utf-8", errors="replace")


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
	"""Get address from sqlite3.Row or dict.
	
	Needed because list_interfaces() returns sqlite3.Row objects which
	support both index and attribute access, but not all downstream code
	handles both consistently. Remove when data layer returns typed dicts.
	"""
	try:
		return iface[key]  # type: ignore[index]
	except (KeyError, TypeError, IndexError):
		pass
	return getattr(iface, key, None)


def _bootstrap_sync(cfg: Config) -> tuple[list[str], bool]:
	"""Run startup DB/bootstrap work synchronously (for asyncio.to_thread).
	
	Returns:
		Tuple of (interfaces_to_start, key_mismatch).
	"""
	conn = connect(cfg.db_path)
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
			return interfaces_to_start, key_mismatch

		# Insert default settings AFTER key validation (to avoid validation token conflicts)
		insert_default_settings(conn)

		migration.run_pending_migrations(conn)

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

	return interfaces_to_start, key_mismatch


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


def _with_conn(db_path: Path, fn: typing.Callable, *args, **kwargs):
	"""Run fn(conn, *args, **kwargs) with connect/close lifecycle.
	
	Eliminates boilerplate connect/try/finally/close_connection pattern.
	"""
	conn = connect(db_path)
	try:
		return fn(conn, *args, **kwargs)
	finally:
		close_connection(conn)


def _with_conn_or(db_path: Path, fn: typing.Callable, *args, default=None, **kwargs):
	"""Like _with_conn but returns default on any exception.
	
	Useful for watchdog/readiness checks where DB errors should fail safe
	instead of crashing.
	"""
	import sqlite3
	try:
		return _with_conn(db_path, fn, *args, **kwargs)
	except sqlite3.DatabaseError:
		raise
	except (OSError, RuntimeError, ValueError) as exc:
		_log.warning("%s failed, returning default: %s", fn.__name__, exc)
		return default


def _read_dns_retention_days_sync(db_path: Path) -> int:
	"""Read DNS retention days synchronously."""
	return _with_conn(db_path, get_dns_log_retention_days)


def _read_tsdb_retention_days_sync(db_path: Path) -> int:
	"""Read TSDB retention days synchronously."""
	return _with_conn(db_path, get_tsdb_retention_days)


def _read_speedtest_retention_days_sync(db_path: Path) -> int:
	"""Read speedtest retention days synchronously."""
	from .db.sqlite_settings import get_speedtest_retention_days
	return _with_conn(db_path, get_speedtest_retention_days)


def _read_dns_service_enabled_sync(db_path: Path) -> bool:
	"""Read whether DNS service should be running synchronously."""
	return _with_conn_or(db_path, get_dns_service_enabled, default=False)


def _should_unbound_run_sync(db_path: Path) -> bool:
	"""Check if Unbound should be running (DNS enabled AND interfaces exist)."""
	def _check(conn) -> bool:
		if not get_dns_service_enabled(conn):
			return False
		# Check if any WireGuard interfaces exist (Unbound needs IPs to bind to)
		interfaces = list_interfaces(conn)
		return len(interfaces) > 0
	return _with_conn_or(db_path, _check, default=False)


def _read_blocklist_enabled_sync(db_path: Path) -> bool:
	"""Read whether DNS blocklist is enabled synchronously."""
	return _with_conn_or(db_path, get_dns_blocklist_enabled, default=False)


def _read_country_traffic_inputs_sync(db_path: Path) -> tuple[bool, dict[str, str]]:
	"""Load traffic-analysis enabled flag and peer IP map synchronously."""
	from .db.sqlite_peers import get_all_peers

	def _load(conn) -> tuple[bool, dict[str, str]]:
		enabled_str = get_setting(conn, "traffic_analysis_enabled")
		# Only enabled if explicitly set to "1" (default factory setting is "0")
		if enabled_str != "1":
			return False, {}

		all_peers = get_all_peers(conn)
		# peer_address can be dual-stack: "10.13.13.2/32, fd13:13:13::2/128"
		peer_ip_map: dict[str, str] = {}
		for peer in all_peers:
			addr = peer["peer_address"]
			name = peer["name"]
			if addr and name:
				for part in str(addr).split(","):
					part = part.strip()
					if not part:
						continue
					# Strip CIDR suffix (e.g., 10.13.13.2/32 → 10.13.13.2)
					peer_ip_map[part.split("/")[0]] = name
		return True, peer_ip_map
	
	return _with_conn(db_path, _load)


def _load_peer_identity_map_sync(db_path: Path, public_keys: list[str]) -> dict[str, tuple[str, str]]:
	"""Resolve peer name/interface by public key synchronously."""
	def _resolve(conn) -> dict[str, tuple[str, str]]:
		result: dict[str, tuple[str, str]] = {}
		for public_key in public_keys:
			peer_row = get_peer_by_public_key(conn, public_key)
			if peer_row:
				result[public_key] = (peer_row["name"], peer_row["interface"])
		return result
	
	return _with_conn(db_path, _resolve)


def _check_adblocker_timer_sync(db_path: Path) -> bool:
	"""Check and re-enable adblocker if timer expired. Returns True if re-enabled."""
	from .db.sqlite_settings import (
		get_blocklist_disabled_until,
		clear_blocklist_disabled_until,
		get_dns_blocklist_enabled,
		set_dns_blocklist_enabled,
	)
	from .api.wireguard_peers import regenerate_all_peer_tags

	conn = connect(db_path)
	try:
		# Read-only check first - avoid write lock if not needed
		disabled_until = get_blocklist_disabled_until(conn)
		enabled = get_dns_blocklist_enabled(conn)
		now = int(time.time())

		if disabled_until > 0 and disabled_until <= now and not enabled:
			# Timer expired and blocklist is still disabled - need to re-enable
			from .db.sqlite_runtime import transaction
			with transaction(conn, immediate=True):
				set_dns_blocklist_enabled(conn, True)
				clear_blocklist_disabled_until(conn)
				regenerate_all_peer_tags(conn)
			return True
		return False
	finally:
		close_connection(conn)


async def _reload_unbound_for_adblocker_async(db_path: Path) -> None:
	"""Reload Unbound config after adblocker state change.
	
	All DB access is done synchronously via to_thread to avoid
	sharing a connection across await boundaries.
	"""
	from .dns import unbound as _unbound
	
	try:
		# Read all config values in one sync call
		def _read_unbound_config_sync() -> tuple:
			conn = connect(db_path)
			try:
				enable_logging = get_dns_query_logging_enabled(conn)
				enable_blocklist = get_dns_blocklist_enabled(conn)
				upstream_dns = get_dns_upstream_servers(conn)
				dnssec_enabled = get_dnssec_enabled(conn)
				interfaces = list_interfaces(conn)
				return (enable_logging, enable_blocklist, upstream_dns, dnssec_enabled, interfaces)
			finally:
				close_connection(conn)

		enable_logging, enable_blocklist, upstream_dns, dnssec_enabled, interfaces = await asyncio.to_thread(_read_unbound_config_sync)

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

		# Offload sync file I/O to thread
		await asyncio.to_thread(
			_unbound.write_config,
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
def _sqlite_shutdown_sync(db_path: Path) -> tuple[dict[str, int | str | None], int]:
	"""Run SQLite checkpoint + connection close synchronously."""
	closed_connections = close_all_connections()
	checkpoint: dict[str, int | str | None] = {
		"mode": "TRUNCATE",
		"busy": -1,
		"log_frames": -1,
		"checkpointed_frames": -1,
		"attempts": 0,
	}

	for attempt in range(1, 11):
		checkpoint = checkpoint_wal(db_path, mode="TRUNCATE")
		checkpoint["attempts"] = attempt
		if int(checkpoint.get("busy", -1)) == 0:
			break
		time.sleep(0.2)

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
		formatter = _HumanizedFormatter(
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


# ─── LIFESPAN HELPERS ────────────────────────────────────────────────────────
# These functions extract discrete phases of application lifecycle for testability.


async def _do_shutdown(ctx: LifespanContext) -> None:
	"""Shutdown in reverse order of startup.
	
	This function handles all cleanup:
	1. DNS ingestion daemon
	2. Scheduler
	3. SQLite checkpoint
	4. Unbound DNS
	5. WireGuard interfaces
	6. TSDB fsync
	"""

	# 1. Cancel DNS ingestion daemon (fastest to stop)
	if ctx.dns_task and not ctx.dns_task.done():
		ctx.dns_task.cancel()
		try:
			await asyncio.wait_for(ctx.dns_task, timeout=5.0)
		except (asyncio.CancelledError, asyncio.TimeoutError):
			pass
		_log.info("DNS_INGESTION stopped")

	# 1b. Cancel DNS API background tasks (rebuild worker, etc.)
	try:
		from .api import dns as dns_api
		await dns_api.shutdown_dns_tasks()
	except Exception as exc:
		_log.warning("DNS API tasks shutdown failed: %s", exc)

	# 2. Scheduler
	if ctx.scheduler:
		await ctx.scheduler.stop_graceful(timeout=5.0)

	# 3. SQLite WAL checkpoint + close all connections before longer teardown.
	checkpoint, closed_connections = await asyncio.to_thread(
		_sqlite_shutdown_sync,
		ctx.cfg.db_path,
	)
	_log.info(
		"SQLITE_SHUTDOWN connections_closed=%d checkpoint_mode=%s busy=%s log_frames=%s checkpointed_frames=%s attempts=%s",
		closed_connections,
		checkpoint.get("mode"),
		checkpoint.get("busy"),
		checkpoint.get("log_frames"),
		checkpoint.get("checkpointed_frames"),
		checkpoint.get("attempts"),
	)

	# 4. Stop Unbound DNS
	if unbound.is_unbound_installed():
		try:
			if await unbound.is_running():
				ok, msg = await unbound.stop()
				if ok:
					_log.info("Unbound DNS stopped")
				else:
					_log.warning("Failed to stop Unbound: %s", msg)
		except Exception as exc:
			_log.warning("Unbound shutdown failed: %s", exc)

	# 5. Bring down WireGuard interfaces we started
	if ctx.started_interfaces:
		for iface_name in ctx.started_interfaces:
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
					_log.warning("Failed to stop interface %s: %s", iface_name, _decode_subprocess_output(stderr))
			except asyncio.TimeoutError:
				_log.warning("Timeout while stopping interface %s", iface_name)
			except Exception as e:
				_log.warning("Failed to stop interface %s: %s", iface_name, e)

	# 6. TSDB fsync
	try:
		tsdb_stats = tsdb.finalize_shutdown(ctx.cfg.tsdb_dir)
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
	_log.info("WireBuddy shutdown complete")



async def _phase_bootstrap(ctx: LifespanContext) -> None:
	cfg, app = ctx.cfg, ctx.app
	interfaces_to_start, key_mismatch = await asyncio.to_thread(_bootstrap_sync, cfg)
	ctx.interfaces_to_start = interfaces_to_start
	app.state.key_mismatch = key_mismatch
	if key_mismatch:
		_log.critical("Aborting startup: WIREBUDDY_SECRET_KEY does not match database encryption key")
		await _do_shutdown(ctx)
		# Clean exit via SystemExit instead of os._exit to allow cleanup/logging
		print(
			"\n"
			"╔══════════════════════════════════════════════════════════════════════╗\n"
			"║  FATAL: WIREBUDDY_SECRET_KEY mismatch                                ║\n"
			"║                                                                      ║\n"
			"║  The configured secret key does not match the key used to encrypt   ║\n"
			"║  this database. Continuing would cause data corruption.             ║\n"
			"║                                                                      ║\n"
			"║  Solutions:                                                          ║\n"
			"║  1. Set the correct WIREBUDDY_SECRET_KEY in docker-compose.yml      ║\n"
			"║  2. Or delete data/wirebuddy.db to start fresh (loses all data)     ║\n"
			"╚══════════════════════════════════════════════════════════════════════╝\n",
			file=sys.stderr,
			flush=True,
		)
		raise SystemExit(1)
	from .db import tsdb
	tsdb.init_tsdb(cfg.tsdb_dir)
	_log.info("GeoIP init scheduled in background (startup is non-blocking)")

async def _phase_dns_config(ctx: LifespanContext) -> None:
	from .dns import unbound
	if not unbound.is_unbound_installed():
		return
	try:
		dns_data = await asyncio.to_thread(_load_dns_startup_data_sync, ctx.cfg.db_path)
		ctx.dns_service_enabled = bool(dns_data.get("dns_service_enabled", True))
		listen_addrs_ipv4, listen_addrs_ipv6 = [], []
		interfaces = dns_data.get("interfaces", [])
		for iface in interfaces:
			addr4 = _get_addr_field(iface, "address")
			if addr4 and addr4.split("/")[0] not in listen_addrs_ipv4:
				listen_addrs_ipv4.append(addr4.split("/")[0])
			addr6 = _get_addr_field(iface, "address6")
			if addr6 and addr6.split("/")[0] not in listen_addrs_ipv6:
				listen_addrs_ipv6.append(addr6.split("/")[0])
		if not listen_addrs_ipv4:
			_log.info("DNS init skipped: no WireGuard interfaces configured yet")
		else:
			await asyncio.to_thread(
				unbound.write_config,
				enable_logging=bool(dns_data.get("enable_logging", True)),
				enable_blocklist=bool(dns_data.get("enable_blocklist", True)),
				upstream_dns=dns_data.get("upstream_dns", []),
				enable_dnssec=bool(dns_data.get("enable_dnssec", True)),
				listen_addrs_ipv4=listen_addrs_ipv4,
				listen_addrs_ipv6=listen_addrs_ipv6 if listen_addrs_ipv6 else None,
			)
			await asyncio.to_thread(unbound.write_local_data_overrides, interfaces, dns_data.get("wg_fqdn"))
			peer_count = await asyncio.to_thread(_regenerate_peer_tags_sync, ctx.cfg.db_path)
			_log.debug("DNS peer tags regenerated for %d peers", peer_count)
			dns_retention_days = _safe_int(dns_data.get("dns_retention_days"), DEFAULT_DNS_LOG_RETENTION_DAYS)
			from .dns import ingestion as dns_ingestion
			await asyncio.to_thread(dns_ingestion.enforce_dns_log_retention, ctx.cfg.dns_dir, dns_retention_days)
			_log.info("DNS config written (IPv4: %s, IPv6: %s)", ", ".join(listen_addrs_ipv4) if listen_addrs_ipv4 else "none", ", ".join(listen_addrs_ipv6) if listen_addrs_ipv6 else "none")
			from .dns.unbound_blocklist import check_and_reset_stale_blocklist
			if check_and_reset_stale_blocklist():
				_log.info("Blocklist reset due to tag migration - triggering immediate update")
				try:
					bl_urls, bl_custom_rules = await asyncio.to_thread(_load_blocklist_update_inputs_sync, ctx.cfg.db_path)
					_, msg = await unbound.update_blocklists(bl_urls, custom_rules_text=bl_custom_rules)
					_log.info("BLOCKLIST_MIGRATION %s", msg)
				except Exception as exc:
					_log.warning("BLOCKLIST_MIGRATION update failed: %s", exc)
			ctx.dns_config_ready = True
	except FileNotFoundError as exc:
		_log.warning("DNS init skipped: unbound tools not found! Use Docker Image for full experience! (%s)", exc)
	except Exception:
		_log.exception("DNS config failed")

async def _phase_wireguard_start(ctx: LifespanContext) -> None:
	removed_stale = await _cleanup_stale_interfaces()
	if removed_stale:
		_log.info("Cleaned up %d stale interface(s): %s", len(removed_stale), removed_stale)
	if not ctx.interfaces_to_start:
		return
	async def _start_one(iface_name: str) -> str | None:
		try:
			check_proc = await asyncio.create_subprocess_exec("wg", "show", iface_name, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
			await _communicate_with_timeout(check_proc, timeout_seconds=_WG_CHECK_TIMEOUT_SECONDS)
			if check_proc.returncode == 0:
				_log.info("WireGuard interface %s already running", iface_name)
				return None
			proc = await asyncio.create_subprocess_exec("wg-quick", "up", iface_name, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
			_, stderr = await _communicate_with_timeout(proc, timeout_seconds=_WG_UP_TIMEOUT_SECONDS)
			if proc.returncode == 0:
				_log.info("WireGuard interface %s started", iface_name)
				return iface_name
			else:
				_log.warning("Failed to start interface %s: %s", iface_name, _decode_subprocess_output(stderr))
				return None
		except asyncio.TimeoutError:
			_log.warning("Timeout while starting/checking interface %s", iface_name)
			return None
		except Exception as e:
			_log.warning("Failed to start interface %s: %s", iface_name, e)
			return None
	sem = asyncio.Semaphore(_WG_STARTUP_CONCURRENCY)
	async def _start_guarded(iface_name: str) -> str | None:
		async with sem:
			return await _start_one(iface_name)
	results = await asyncio.gather(*[_start_guarded(name) for name in ctx.interfaces_to_start])
	ctx.started_interfaces = [r for r in results if r]

async def _phase_dns_start(ctx: LifespanContext) -> None:
	from .dns import unbound
	if unbound.is_unbound_installed() and ctx.dns_config_ready:
		try:
			unbound_running = await unbound.is_running()
			if ctx.dns_service_enabled:
				if not unbound_running:
					ok, msg = await unbound.start()
					if ok:
						_log.info("Unbound DNS started")
						await asyncio.sleep(2)
					else:
						_log.warning("Failed to start Unbound: %s", msg)
			else:
				if unbound_running:
					ok, msg = await unbound.stop()
					if ok:
						_log.info("Unbound DNS kept stopped (persisted user preference)")
					else:
						_log.warning("Failed to keep Unbound stopped on startup: %s", msg)
				else:
					_log.info("Unbound autostart disabled; resolver remains stopped")
		except Exception:
			_log.exception("DNS start failed")

async def _phase_scheduler(ctx: LifespanContext) -> None:
	scheduler = Scheduler()
	ctx.scheduler = scheduler
	ctx.app.state.scheduler = scheduler
	from .dns import unbound
	from .tasks import scheduled as scheduled_tasks
	import os
	unbound_installed = unbound.is_unbound_installed()
	blocklist_enabled_startup = unbound_installed and await asyncio.to_thread(_read_blocklist_enabled_sync, ctx.cfg.db_path)
	blocklist_interval_seconds = 86400.0
	blocklist_jitter_pct = 0.1
	blocklist_run_on_start = False
	if blocklist_enabled_startup:
		try:
			blocklist_run_on_start = unbound.get_blocklist_count() <= 0
		except Exception:
			_log.warning("BLOCKLIST_STARTUP could not inspect local blocklist; scheduling startup update")
			blocklist_run_on_start = True
		if blocklist_run_on_start:
			_log.info("BLOCKLIST_STARTUP no cached blocklist found - scheduling immediate update")
		else:
			min_delay_h = (blocklist_interval_seconds * (1.0 - blocklist_jitter_pct)) / 3600.0
			max_delay_h = (blocklist_interval_seconds * (1.0 + blocklist_jitter_pct)) / 3600.0
			_log.info("BLOCKLIST_STARTUP cached blocklist found - deferring first update to %.1f-%.1f hours (interval=24h, jitter=±10%%)", min_delay_h, max_delay_h)
	else:
		if unbound_installed:
			_log.info("BLOCKLIST_STARTUP skipped: ad-blocker is disabled")
		else:
			_log.info("BLOCKLIST_STARTUP skipped: Unbound not installed")
	if unbound_installed:
		blocklist_initial_delay = 15.0 if blocklist_run_on_start else 0.0
		async def _update_blocklists() -> None:
			await scheduled_tasks.update_blocklists(ctx)
		scheduler.add("blocklist-update", interval_seconds=blocklist_interval_seconds, func=_update_blocklists, run_on_start=blocklist_run_on_start, initial_delay=blocklist_initial_delay, jitter_pct=blocklist_jitter_pct)
	async def _maintain_tsdb() -> None:
		await scheduled_tasks.maintain_tsdb(ctx)
	scheduler.add("tsdb-maintenance", interval_seconds=21600, func=_maintain_tsdb, run_on_start=True, initial_delay=30.0)
	async def _sample_tsdb_metrics() -> None:
		await scheduled_tasks.sample_tsdb_metrics(ctx)
	scheduler.add("tsdb-sample", interval_seconds=30.0, func=_sample_tsdb_metrics, run_on_start=True, initial_delay=10.0)
	try:
		from .utils.conntrack import init_conntrack_accounting
		await asyncio.to_thread(init_conntrack_accounting)
	except Exception as exc:
		_log.warning("COUNTRY_TRAFFIC could not enable conntrack accounting: %s", exc)
	async def _sample_country_traffic() -> None:
		await scheduled_tasks.sample_country_traffic(ctx)
	scheduler.add("country-traffic", interval_seconds=30.0, func=_sample_country_traffic, run_on_start=True, initial_delay=15.0)
	async def _sample_network_stats() -> None:
		await scheduled_tasks.sample_network_stats(ctx)
	scheduler.add("network-stats", interval_seconds=30, func=_sample_network_stats, run_on_start=True, initial_delay=12.0)
	async def _update_geoip() -> None:
		await scheduled_tasks.update_geoip(ctx)
	scheduler.add("geoip-update", interval_seconds=604800, func=_update_geoip, run_on_start=True, initial_delay=20.0)
	from .tasks.maintenance import sqlite_maintenance, sqlite_integrity_check, tsdb_retention_cleanup, cleanup_stale_sessions
	scheduler.add("sqlite-maintenance", interval_seconds=21600, func=sqlite_maintenance, run_on_start=True, initial_delay=60.0, timeout=60.0)
	scheduler.add("sqlite-integrity", interval_seconds=604800, func=sqlite_integrity_check, run_on_start=False, timeout=300.0)
	scheduler.add("tsdb-retention", interval_seconds=86400, func=tsdb_retention_cleanup, run_on_start=True, initial_delay=90.0, timeout=120.0)
	scheduler.add("session-cleanup", interval_seconds=3600, func=cleanup_stale_sessions, run_on_start=True, initial_delay=120.0, timeout=30.0)
	if unbound_installed:
		async def _dns_watchdog() -> None:
			await scheduled_tasks.dns_watchdog(ctx)
		scheduler.add("dns-watchdog", interval_seconds=30, func=_dns_watchdog, run_on_start=True, initial_delay=60.0, timeout=30.0)
		async def _check_adblocker_timer() -> None:
			await scheduled_tasks.check_adblocker_timer(ctx)
		scheduler.add("adblocker-timer-check", interval_seconds=15, func=_check_adblocker_timer, run_on_start=False, timeout=30.0)
	initial_speedtest_delay, hours_since_last, speedtest_overdue = await scheduled_tasks.get_speedtest_initial_delay(ctx.cfg.db_path, ctx.cfg.tsdb_dir)
	if hours_since_last is not None:
		if speedtest_overdue:
			_log.warning("SPEEDTEST_SCHEDULER last run was %.1f hours ago (>36h) - missed tests detected!", hours_since_last)
		else:
			_log.info("SPEEDTEST_SCHEDULER last run was %.1f hours ago", hours_since_last)
	else:
		_log.info("SPEEDTEST_SCHEDULER no previous run recorded")
	if initial_speedtest_delay > 0:
		from datetime import datetime as dt, timedelta
		scheduled_time = dt.now() + timedelta(seconds=initial_speedtest_delay)
		_log.info("SPEEDTEST_SCHEDULER first run in %.1f hours (at ~%s)", initial_speedtest_delay / 3600, scheduled_time.strftime("%H:%M"))
	async def _run_scheduled_speedtest() -> None:
		await scheduled_tasks.run_scheduled_speedtest(ctx)
	scheduler.add("speedtest", interval_seconds=86400, func=_run_scheduled_speedtest, run_on_start=True, initial_delay=initial_speedtest_delay, timeout=7500.0, jitter_pct=0.0)
	initial_backup_delay = _seconds_until_backup_time(os.environ.get("TZ", "UTC"))
	_log.info("SCHEDULED_BACKUP first run in %.1f hours (at ~%02d:00)", initial_backup_delay / 3600, _BACKUP_NIGHT_HOUR)
	async def _run_scheduled_backup() -> None:
		await scheduled_tasks.run_scheduled_backup(ctx)
	scheduler.add("scheduled-backup", interval_seconds=86400, func=_run_scheduled_backup, run_on_start=True, initial_delay=initial_backup_delay, timeout=300.0, jitter_pct=0.05)
	async def _run_node_health() -> None:
		await scheduled_tasks.monitor_node_health(ctx)
	scheduler.add("node-health", interval_seconds=60, func=_run_node_health, run_on_start=False, timeout=15.0)
	await scheduler.start()

async def _sleep_interruptible(seconds: float, chunk_size: float = 60.0) -> None:
	"""Sleep for total seconds with periodic cancellation checks.
	
	Breaks long sleeps into chunks to enable responsive shutdown.
	"""
	remaining = seconds
	while remaining > 0:
		await asyncio.sleep(min(chunk_size, remaining))
		remaining -= chunk_size


async def _phase_dns_ingestion(ctx: LifespanContext) -> None:
	from .dns import unbound
	from .dns import ingestion as dns_ingestion
	if not unbound.is_unbound_installed():
		_log.info("DNS_INGESTION skipped: Unbound not installed")
		return
	retry_count = 0
	dns_retention_days_cache = DEFAULT_DNS_LOG_RETENTION_DAYS
	while True:
		should_run = await asyncio.to_thread(_should_unbound_run_sync, ctx.cfg.db_path)
		if not should_run:
			await _sleep_interruptible(30.0)
			continue
		for attempt in range(15):
			if await unbound.is_running():
				break
			delay = min(2.0 ** attempt, 30.0)
			_log.debug("DNS_INGESTION waiting for Unbound (attempt %d, retry in %.0fs)", attempt + 1, delay)
			await asyncio.sleep(delay)
		else:
			_log.warning("DNS_INGESTION Unbound not ready after probes; starting ingestion anyway")
		def _current_dns_retention_days() -> int:
			return dns_retention_days_cache
		try:
			dns_retention_days_cache = await asyncio.to_thread(_read_dns_retention_days_sync, ctx.cfg.db_path)
			offset_path = ctx.cfg.data_dir / "dns" / "dns_tail.offset"
			offset_path.parent.mkdir(parents=True, exist_ok=True)
			legacy_offset_path = ctx.cfg.data_dir / "runtime" / "dns_tail.offset"
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
				dns_dir=ctx.cfg.dns_dir,
				blocked_domains_func=unbound.get_blocked_domains,
				retention_days_func=_current_dns_retention_days,
				tsdb_dir=ctx.cfg.tsdb_dir,
			)
			retry_count = 0
			_log.warning("DNS_INGESTION stopped unexpectedly; restarting in 5s")
			await _sleep_interruptible(5.0)
		except asyncio.CancelledError:
			_log.info("DNS_INGESTION shutdown requested")
			raise
		except Exception as exc:
			retry_count += 1
			# Exponential backoff with jitter to prevent thundering herd
			import random
			jitter = random.uniform(0.8, 1.2)
			delay = min(
				(2 ** retry_count * _DNS_INGESTION_RESTART_BASE_DELAY_SECONDS * jitter),
				_DNS_INGESTION_RESTART_MAX_DELAY_SECONDS
			)
			_log.error("DNS_INGESTION crashed (retry #%d in %.0fs): %s", retry_count, delay, exc)
			await _sleep_interruptible(delay)

@asynccontextmanager
async def _lifespan(app: FastAPI):
	"""Application lifespan manager."""
	import os
	await _verify_host_network_mode()
	loop = asyncio.get_running_loop()
	shutdown_signal_event = asyncio.Event()
	app.state.shutdown_signal_event = shutdown_signal_event
	previous_signal_handlers = _install_shutdown_signal_handlers(loop, shutdown_signal_event)
	cfg = app.state.cfg
	ctx = LifespanContext(
		cfg=cfg,
		app=app,
		peer_connection_state=app.state.peer_connection_state,
	)
	try:
		await _phase_bootstrap(ctx)
		await _phase_dns_config(ctx)
		await _phase_wireguard_start(ctx)
		await _phase_dns_start(ctx)
		await _phase_scheduler(ctx)
		# Create DNS ingestion task with defensive handling
		dns_task = asyncio.create_task(_phase_dns_ingestion(ctx))
		ctx.dns_task = dns_task
		app.state.dns_task = dns_task
		app.state.started_interfaces = ctx.started_interfaces
		_log.info("WireBuddy started successfully (pid=%d)", os.getpid())
		yield
	finally:
		shutdown_signal_event.set()
		_restore_signal_handlers(previous_signal_handlers)
		await _do_shutdown(ctx)

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
	app.state.shutdown_signal_event = None
	app.state.key_mismatch = False  # Set to True if SECRET_KEY doesn't match DB encryption
	
	# ─── MIDDLEWARE ──────────────────────────────────────────
	app.add_middleware(RequestIDMiddleware)

	from .middleware.csrf import CSRFMiddleware
	app.add_middleware(CSRFMiddleware)

	app.state.limiter = limiter

	from slowapi.errors import RateLimitExceeded
	from starlette.requests import Request
	from starlette.responses import JSONResponse

	async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
		"""Custom rate limit handler that uses 'detail' for API consistency."""
		response = JSONResponse(
			status_code=429,
			content={"detail": "Too many requests. Please try again later."},
		)

		limiter_instance = getattr(request.app.state, "limiter", None)
		view_rate_limit = getattr(request.state, "view_rate_limit", None)
		if limiter_instance is not None and view_rate_limit is not None:
			try:
				retry_after = getattr(exc, "retry_after", 60)
				response.headers["Retry-After"] = str(retry_after)
				response.headers["X-RateLimit-Limit"] = str(getattr(exc, "limit", ""))
			except Exception as header_exc:
				_log.debug("Rate limit header injection failed: %s", header_exc)

		response.headers.setdefault("Retry-After", "60")
		return response

	app.add_exception_handler(RateLimitExceeded, rate_limit_handler)
	app.add_exception_handler(frontend_ui.RedirectTo, frontend_ui.redirect_to_handler)

	@app.get("/health", include_in_schema=False)
	async def healthcheck() -> JSONResponse:
		"""Lightweight unauthenticated health endpoint for container probes."""
		return JSONResponse(content={"status": "ok", "version": VERSION})

	@app.get("/ready", include_in_schema=False)
	@limiter.limit("30/minute")
	async def readiness(request: Request) -> JSONResponse:
		"""Readiness probe that verifies database connectivity.
		
		Use this for Kubernetes/Docker readiness probes instead of /health.
		Returns 503 if any critical component is unavailable.
		"""
		cfg: Config = app.state.cfg
		errors = []
		
		# Check database connectivity (offload to thread to avoid blocking event loop)
		try:
			await asyncio.to_thread(
				_with_conn,
				cfg.db_path,
				lambda conn: conn.execute("SELECT 1").fetchone()
			)
		except Exception as exc:
			errors.append("database unavailable")
			_log.warning("Readiness check failed: database: %s", exc)
		
		# Check for key mismatch (critical security error)
		if getattr(app.state, "key_mismatch", False):
			errors.append("encryption key mismatch")
		
		if errors:
			return JSONResponse(
				status_code=503,
				content={"status": "unavailable", "errors": errors, "version": VERSION}
			)
		
		return JSONResponse(content={"status": "ready", "version": VERSION})

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
	app.include_router(speedtest_api.router, prefix="/api/wireguard")
	app.include_router(network_stats_api.router, prefix="/api")
	app.include_router(backup_api.router, prefix="/api")
	app.include_router(nodes_sync_api.router, prefix="/api/nodes")
	app.include_router(nodes_api.router, prefix="/api/nodes")
	
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
		
		# Generate nonce for inline script/style (CSP security)
		import secrets
		nonce = secrets.token_urlsafe(16)
		html = _SWAGGER_HTML.replace("%%NONCE%%", nonce)
		response = HTMLResponse(html)
		response.headers["Content-Security-Policy"] = (
			"default-src 'none'; "
			f"script-src https://cdn.jsdelivr.net 'nonce-{nonce}'; "
			f"style-src https://cdn.jsdelivr.net 'nonce-{nonce}'; "
			"connect-src 'self'"
		)
		return response


_SWAGGER_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>WireBuddy - API Docs</title>
  <!-- Pin exact version and use SRI to prevent CDN compromise / MITM attacks -->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.18.2/swagger-ui.css"
        integrity="sha384-OiJUz2Or7cLjcY1Eaw2xhMeUY3z5Csh2+HG9WXElrCqx45ddJCnYXN0a/HQQsJtz"
        crossorigin="anonymous">
  <style nonce="%%NONCE%%">
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
  <script nonce="%%NONCE%%">
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
