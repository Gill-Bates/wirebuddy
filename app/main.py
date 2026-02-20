#!/usr/bin/env python3
#
# app/main.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""FastAPI application factory and startup lifecycle wiring."""

from __future__ import annotations

from .db.sqlite_interfaces import (
	list_interfaces,
)
from .db.sqlite_peers import (
	get_peer_by_public_key,
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
	get_dns_log_retention_days,
	get_dns_query_logging_enabled,
	get_dns_service_enabled,
	get_dns_upstream_servers,
	get_dnssec_enabled,
	get_enabled_blocklists,
)

import asyncio
import logging
import os
import re
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .utils.config import load_config, WG_CONFIG_PATH
from .utils.rate_limit import limiter
from .utils.request_id import RequestIDMiddleware
from .utils.scheduler import Scheduler
from .middleware.csrf import CSRFMiddleware
from .utils.banner import print_banner_once

from .api import acme as acme_api
from .api import auth as auth_api
from .api import users as users_api
from .api import wireguard as wireguard_api
from .api import dns as dns_api
from .api import frontend as frontend_ui
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
_WG_CHECK_TIMEOUT_SECONDS = 5.0
_WG_UP_TIMEOUT_SECONDS = 15.0
_WG_DOWN_TIMEOUT_SECONDS = 15.0
_TSDB_SAMPLE_INTERVAL_SECONDS = 30.0
_PEER_CONNECTION_THRESHOLD = 180  # seconds - peer is "connected" if handshake < 3 min ago

# Track peer connection state for logging connect/disconnect events
_peer_connection_state: dict[str, bool] = {}  # public_key -> is_connected
_PEER_STATE_MAX_SIZE = 100_000  # Prevent unbounded memory growth


class _ColoredFormatter(logging.Formatter):
	"""Custom formatter that adds color to log levels in TTY."""
	
	def format(self, record):
		orig_levelname = record.levelname
		levelname = orig_levelname
		if levelname in _LOG_COLORS:
			record.levelname = f"{_LOG_COLORS[levelname]}{orig_levelname:<8}{_RESET}"
		else:
			record.levelname = f"{orig_levelname:<8}"
		try:
			return super().format(record)
		finally:
			record.levelname = orig_levelname


async def _communicate_with_timeout(
	proc: asyncio.subprocess.Process,
	*,
	timeout_seconds: float,
) -> tuple[bytes | None, bytes | None]:
	"""Wait for subprocess with timeout; kill on timeout and re-raise."""
	try:
		return await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
	except asyncio.TimeoutError:
		if proc.returncode is None:
			proc.kill()
			await proc.communicate()
		raise


def _safe_int(value: str, default: int = 0) -> int:
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

		# Interface header: iface, private-key, public-key, listen-port, fwmark
		if len(parts) >= 5 and len(parts) < 8:
			last_iface = parts[0] or last_iface
			continue

		public_key: str | None = None
		latest_handshake = 0
		rx = 0
		tx = 0

		# Peer line format A: iface, pubkey, psk, endpoint, allowed-ips, hs, rx, tx, keepalive
		if len(parts) >= 9:
			iface = parts[0] if parts[0] else last_iface
			if iface:
				last_iface = iface
			public_key = parts[1]
			latest_handshake = _safe_int(parts[5])
			rx = _safe_int(parts[6])
			tx = _safe_int(parts[7])
		# Peer line format B: pubkey, psk, endpoint, allowed-ips, hs, rx, tx, keepalive
		elif len(parts) >= 8:
			public_key = parts[0]
			latest_handshake = _safe_int(parts[4])
			rx = _safe_int(parts[5])
			tx = _safe_int(parts[6])

		if not public_key:
			continue
		peers[public_key] = (rx, tx, latest_handshake)

	return peers


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
	cfg = app.state.cfg
	is_leader = False
	started_interfaces: list[str] = []
	
	# ─── BOOTSTRAP ───────────────────────────────────────────
	# Initialize database
	conn = connect(cfg.db_path)
	interfaces_to_start: list[str] = []
	try:
		init_schema(conn)
		migration.run_pending_migrations(conn)
		ensure_default_admin(conn)
		
		# Acquire leader lock (multi-worker safety)
		is_leader = try_acquire_leader_lock(conn)
		if is_leader:
			_log.info("This worker acquired leader lock (pid=%d)", os.getpid())
		else:
			_log.info("Another worker is leader, skipping init tasks (pid=%d)", os.getpid())
		
		if is_leader:
			# Regenerate WireGuard configs from database (persistence across container restarts)
			from .api import wireguard as wg_api
			config_path = WG_CONFIG_PATH
			regen_result = wg_api.regenerate_all_configs(config_path, conn, pepper=cfg.secret_key)
			if regen_result.succeeded:
				_log.info("WireGuard configs regenerated: %d interfaces", len(regen_result.succeeded))
			if regen_result.failed:
				_log.warning(
					"WireGuard config regeneration failed for %d interfaces: %s",
					len(regen_result.failed),
					list(regen_result.failed.keys()),
				)
			
			# Get list of enabled interfaces to auto-start
			for iface in list_interfaces(conn):
				if iface["is_enabled"]:
					name = iface["name"]
					# Validate interface name before passing to subprocess
					if _IFACE_NAME_RE.match(name):
						interfaces_to_start.append(name)
					else:
						_log.warning("Skipping interface with invalid name: %r", name)
	finally:
		close_connection(conn)
	
	# Initialize TSDB (idempotent, safe for multi-worker)
	tsdb.init_tsdb(cfg.tsdb_dir)
	
	# ─── GeoIP databases ──────────────────────────────────────
	# Do not block startup on network-bound GeoIP checks/downloads.
	# GeoIP sync runs as scheduler background task (run_on_start + periodic).
	if is_leader:
		_log.info("GeoIP init scheduled in background (startup is non-blocking)")
	
	# Initialize and start Unbound DNS - leader only
	# MUST happen BEFORE WireGuard start: wg-quick rewrites /etc/resolv.conf
	# to point to Unbound, so Unbound must be running first.
	from .dns import unbound as _unbound
	if is_leader:
		try:
			# Always write WireBuddy config (overwrites Debian default)
			# This ensures 0.0.0.0 binding so WireGuard clients can reach DNS
			dns_retention_days = DEFAULT_DNS_LOG_RETENTION_DAYS
			dns_service_enabled = True
			dns_cfg_conn = connect(cfg.db_path)
			try:
				dns_retention_days = get_dns_log_retention_days(dns_cfg_conn)
				dns_service_enabled = get_dns_service_enabled(dns_cfg_conn)
				# Collect IPv6 gateway addresses from all interfaces for dual-stack DNS
				interfaces = list_interfaces(dns_cfg_conn)
				ipv6_gateways = _unbound.get_interface_ipv6_gateways(interfaces)
				_unbound.write_config(
					enable_logging=get_dns_query_logging_enabled(dns_cfg_conn),
					enable_blocklist=get_dns_blocklist_enabled(dns_cfg_conn),
					upstream_dns=get_dns_upstream_servers(dns_cfg_conn),
					enable_dnssec=get_dnssec_enabled(dns_cfg_conn),
					listen_addrs_ipv6=ipv6_gateways if ipv6_gateways else None,
				)
			finally:
				close_connection(dns_cfg_conn)

			await asyncio.to_thread(
				dns_ingestion.enforce_dns_log_retention,
				cfg.tsdb_dir,
				dns_retention_days,
			)
			if ipv6_gateways:
				_log.info("DNS config written (IPv4: 0.0.0.0, IPv6: %s)", ", ".join(ipv6_gateways))
			else:
				_log.info("DNS config written (interface: 0.0.0.0)")

			unbound_running = await _unbound.is_running()
			if dns_service_enabled:
				# Respect persisted user choice: start resolver after container restart
				# unless it was explicitly stopped by the user.
				if not unbound_running:
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
		except FileNotFoundError as exc:
			_log.warning("DNS init skipped: unbound tools not found! Use Docker Image for full experience! (%s)", exc)
		except Exception as exc:
			_log.warning("DNS init skipped: %s", exc)
	
	# Auto-start WireGuard interfaces (leader only)
	# Runs AFTER Unbound because wg-quick rewrites /etc/resolv.conf to use
	# the interface DNS (often Unbound), which must already be listening.
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
					started_interfaces.append(iface_name)
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
					_log.warning("Failed to start interface %s: %s", iface_name, stderr.decode())
			except asyncio.TimeoutError:
				_log.warning("Timeout while starting/checking interface %s", iface_name)
			except Exception as e:
				_log.warning("Failed to start interface %s: %s", iface_name, e)
	
	# ─── SCHEDULER ─────────────────────────────────────────── (leader only)
	scheduler: Scheduler | None = None
	if is_leader:
		scheduler = Scheduler()

		async def _update_blocklists() -> None:
			"""Scheduled task: download and apply blocklists."""
			try:
				# Load enabled blocklists from database
				conn = connect(cfg.db_path)
				try:
					urls = get_enabled_blocklists(conn)
				finally:
					close_connection(conn)
				
				count, msg = await _unbound.update_blocklists(urls)
				await _unbound.reload_config()
				_log.info("BLOCKLIST_UPDATE %s", msg)
			except Exception as exc:
				_log.error("BLOCKLIST_UPDATE failed: %s", exc)

		async def _maintain_tsdb() -> None:
			"""Scheduled task: prune/rotate/compress TSDB series."""
			try:
				stats = tsdb.run_maintenance(cfg.tsdb_dir)
				dns_cfg_conn = connect(cfg.db_path)
				try:
					dns_retention_days = get_dns_log_retention_days(dns_cfg_conn)
				finally:
					close_connection(dns_cfg_conn)
				dns_retention = await asyncio.to_thread(
					dns_ingestion.enforce_dns_log_retention,
					cfg.tsdb_dir,
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
			import time as _time
			now = _time.time()
			state_changes: list[tuple[str, bool, str]] = []  # (public_key, is_now_connected, peer_name)

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
					was_connected = _peer_connection_state.get(public_key, False)

					if is_connected != was_connected:
						# Prevent unbounded memory growth
						if len(_peer_connection_state) >= _PEER_STATE_MAX_SIZE:
							_log.warning("PEER_STATE clearing %d stale entries", len(_peer_connection_state))
							_peer_connection_state.clear()
						_peer_connection_state[public_key] = is_connected
						state_changes.append((public_key, is_connected, ""))

			_log.debug("TSDB_SAMPLE peers=%d points=%d", len(peer_counters), points)

			# Log connection state changes with peer names
			if state_changes:
				conn = connect(cfg.db_path)
				try:
					for public_key, is_connected, _ in state_changes:
						peer_row = get_peer_by_public_key(conn, public_key)
						if peer_row:
							peer_name = peer_row["name"]
							interface = peer_row["interface"]
							if is_connected:
								_log.info("PEER_CONNECTED name=%s interface=%s public_key=%s", 
										  peer_name, interface, public_key[:16])
							else:
								_log.info("PEER_DISCONNECTED name=%s interface=%s public_key=%s", 
										  peer_name, interface, public_key[:16])
						else:
							# Peer not in DB (orphaned WireGuard config?)
							if is_connected:
								_log.info("PEER_CONNECTED public_key=%s (not in database)", public_key[:16])
							else:
								_log.info("PEER_DISCONNECTED public_key=%s (not in database)", public_key[:16])
				finally:
					close_connection(conn)

		scheduler.add(
			"blocklist-update",
			interval_seconds=86400,  # 24 h
			func=_update_blocklists,
			run_on_start=True,
			initial_delay=15.0,  # Wait for WireGuard + Unbound + network to be ready
			jitter_pct=0.1,  # ±10% jitter (±2.4h) to distribute load across instances
		)
		scheduler.add(
			"tsdb-maintenance",
			interval_seconds=21600,  # 6 h
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
			interval_seconds=604800,  # 7 days
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
			interval_seconds=21600,  # 6 hours
			func=sqlite_maintenance,
			run_on_start=True,
			initial_delay=60.0,  # Let app fully start first
			timeout=60.0,
		)
		
		scheduler.add(
			"sqlite-integrity",
			interval_seconds=604800,  # 7 days (weekly)
			func=sqlite_integrity_check,
			run_on_start=False,  # Skip on every startup, only run weekly
			timeout=300.0,
		)
		
		scheduler.add(
			"tsdb-retention",
			interval_seconds=86400,  # 24 hours (daily)
			func=tsdb_retention_cleanup,
			run_on_start=True,
			initial_delay=90.0,
			timeout=120.0,
		)
		
		scheduler.add(
			"session-cleanup",
			interval_seconds=3600,  # 1 hour
			func=cleanup_stale_sessions,
			run_on_start=True,
			initial_delay=120.0,
			timeout=30.0,
		)
		
		await scheduler.start()
		
		# ─── DNS INGESTION DAEMON ─────────────────────────────────────
		# This is a long-running daemon task, not a periodic job.
		# Runs forever, managed separately from scheduler.
		async def _run_dns_ingestion() -> None:
			"""Daemon task: ingest DNS queries from Unbound log to TSDB."""
			# Wait for Unbound to be fully ready
			await asyncio.sleep(25.0)

			def _current_dns_retention_days() -> int:
				conn = connect(cfg.db_path)
				try:
					return get_dns_log_retention_days(conn)
				except Exception:
					return DEFAULT_DNS_LOG_RETENTION_DAYS
				finally:
					close_connection(conn)
			
			try:
				offset_path = cfg.data_dir / "runtime" / "dns_tail.offset"
				await dns_ingestion.run_dns_ingestion(
					log_path=unbound.QUERY_LOG,
					offset_path=offset_path,
					tsdb_dir=cfg.tsdb_dir,
					blocked_domains_func=unbound.get_blocked_domains,
					retention_days_func=_current_dns_retention_days,
				)
			except asyncio.CancelledError:
				_log.info("DNS_INGESTION shutdown requested")
				raise
			except Exception as exc:
				_log.error("DNS_INGESTION crashed: %s", exc)
		
		app.state.dns_task = asyncio.create_task(_run_dns_ingestion())
	
	app.state.scheduler = scheduler
	app.state.is_leader = is_leader
	app.state.started_interfaces = started_interfaces
	
	_log.info("WireBuddy started successfully (leader=%s, pid=%d)", is_leader, os.getpid())
	
	yield
	
	# ─── SHUTDOWN ────────────────────────────────────────────
	# Cancel DNS ingestion daemon first (cleanest shutdown order)
	dns_task = getattr(app.state, "dns_task", None)
	if dns_task and not dns_task.done():
		dns_task.cancel()
		await asyncio.gather(dns_task, return_exceptions=True)
		_log.info("DNS_INGESTION stopped")
	
	if scheduler:
		await scheduler.stop_graceful(timeout=5.0)
	
	# Shutdown WireGuard interfaces we started (leader only)
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
					_log.warning("Failed to stop interface %s: %s", iface_name, stderr.decode())
			except asyncio.TimeoutError:
				_log.warning("Timeout while stopping interface %s", iface_name)
			except Exception as e:
				_log.warning("Failed to stop interface %s: %s", iface_name, e)
	
	# Release leader lock
	if is_leader:
		conn = connect(cfg.db_path)
		try:
			release_leader_lock(conn)
		finally:
			close_connection(conn)

	# Final TSDB maintenance + fsync to avoid partial writes on stop/restart.
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

	closed_connections = close_all_connections()
	checkpoint = checkpoint_wal(cfg.db_path, mode="TRUNCATE")
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
		version="0.1.0",
		lifespan=_lifespan,
		docs_url="/api/docs",
		redoc_url="/api/redoc",
	)
	
	# Store config in app state
	app.state.cfg = cfg
	app.state.db_path = cfg.db_path
	app.state.tsdb_dir = cfg.tsdb_dir
	
	# ─── MIDDLEWARE ──────────────────────────────────────────
	app.add_middleware(RequestIDMiddleware)
	app.add_middleware(CSRFMiddleware)
	
	# Rate limiting
	app.state.limiter = limiter
	app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
	
	# ─── STATIC FILES ────────────────────────────────────────
	static_path = Path(__file__).parent / "static"
	if static_path.exists():
		app.mount("/static", StaticFiles(directory=str(static_path)), name="static")
	else:
		_log.warning("Static files directory not found: %s", static_path)
	
	# ─── API ROUTES ──────────────────────────────────────────
	app.include_router(auth_api.router, prefix="/api")
	app.include_router(users_api.router, prefix="/api/users")
	app.include_router(wireguard_api.router, prefix="/api/wireguard")
	app.include_router(dns_api.router, prefix="/api/dns")
	app.include_router(acme_api.router, prefix="/api/acme")
	
	# ─── FRONTEND ROUTES ─────────────────────────────────────
	app.include_router(frontend_ui.router)
	
	return app
