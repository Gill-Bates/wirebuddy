#!/usr/bin/env python3
#
# app/runtime/services/dns.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: AGPL-3.0
#

"""DNS service lifecycle management.

Manages:
- Unbound DNS resolver configuration and process
- DNS query log ingestion
- Blocklist updates
- Peer tag generation for ad-blocking
"""

from __future__ import annotations

import asyncio
import logging
import random
from pathlib import Path
from typing import TYPE_CHECKING

from ..service import RuntimeService, ServiceHealth

if TYPE_CHECKING:
    from ...utils.config import Config

_log = logging.getLogger(__name__)

# Ingestion restart configuration
_INGESTION_RESTART_BASE_DELAY = 2.0
_INGESTION_RESTART_MAX_DELAY = 300.0
_UNBOUND_WAIT_MAX_ATTEMPTS = 15


class DNSService(RuntimeService):
    """DNS resolver and query logging service.

    Manages Unbound configuration, process supervision, and DNS query
    ingestion for analytics.
    """

    name = "dns"
    dependencies = ["sqlite", "wireguard"]  # Needs DB and interfaces to bind to
    start_timeout = 60.0
    stop_timeout = 15.0

    def __init__(self, config: Config) -> None:
        super().__init__()
        self._config = config
        self._service_enabled = False
        self._config_ready = False
        self._ingestion_task: asyncio.Task | None = None
        self._reload_lock = asyncio.Lock()

    @property
    def service_enabled(self) -> bool:
        """Whether DNS service is enabled in settings."""
        return self._service_enabled

    @property
    def config_ready(self) -> bool:
        """Whether DNS configuration was written successfully."""
        return self._config_ready

    async def _do_start(self) -> None:
        """Configure and start Unbound DNS resolver."""
        from ...dns import unbound

        if not unbound.is_unbound_installed():
            _log.info("DNS_SKIPPED: Unbound not installed")
            return

        try:
            await self._write_config()

            if self._shutdown_event.is_set():
                raise asyncio.CancelledError

            if not self._config_ready:
                _log.info("DNS_SKIPPED: No interfaces to bind to")
                return

            async with self._reload_lock:
                # Start or stop Unbound based on enabled setting
                await self._sync_unbound_state()

            # Start ingestion in background
            if self._service_enabled:
                self._ingestion_task = self.create_background_task(
                    self._run_ingestion_loop(),
                    name="dns-ingestion",
                )

        except asyncio.CancelledError:
            _log.info("DNS_STARTUP_CANCELLED")
            raise
        except FileNotFoundError as exc:
            _log.warning("DNS_INIT_SKIPPED: Unbound tools not found (%s)", exc)
        except Exception:
            _log.exception("DNS_CONFIG_FAILED")
            raise

    async def _do_stop(self) -> None:
        """Stop Unbound DNS resolver."""
        from ...dns import unbound

        # Ingestion task is cancelled by base class

        if not unbound.is_unbound_installed():
            self._ingestion_task = None
            return

        try:
            async with self._reload_lock:
                if await unbound.is_running():
                    ok, msg = await unbound.stop()
                    if ok:
                        _log.info("DNS_UNBOUND_STOPPED")
                    else:
                        _log.warning("DNS_UNBOUND_STOP_FAILED: %s", msg)
        except Exception:
            _log.exception("DNS_SHUTDOWN_ERROR")
        finally:
            self._ingestion_task = None

    async def check_health(self) -> ServiceHealth:
        """Check DNS service health."""
        health = await super().check_health()
        health.details = dict(health.details)

        if not self.is_running:
            return health

        from ...dns import unbound

        if not unbound.is_unbound_installed():
            health.details["installed"] = False
            return health

        service_enabled = self._service_enabled
        config_ready = self._config_ready
        ingestion_task = self._ingestion_task
        if ingestion_task and ingestion_task.done():
            self._ingestion_task = None
            ingestion_task = None

        health.details["installed"] = True
        health.details["enabled"] = service_enabled
        health.details["config_ready"] = config_ready

        try:
            running = await unbound.is_running()
            health.details["unbound_running"] = running

            if service_enabled and config_ready and not running:
                health.healthy = False
                health.error = "Unbound not running but should be"

            if ingestion_task:
                health.details["ingestion_running"] = not ingestion_task.done()
        except Exception:
            _log.exception("DNS_HEALTH_CHECK_FAILED")
            health.healthy = False
            health.error = "DNS health check failed"

        return health

    async def _write_config(self) -> None:
        """Write Unbound configuration files."""
        from ...dns import unbound
        from ...dns import ingestion as dns_ingestion
        from ...dns.unbound_blocklist import check_and_reset_stale_blocklist
        from ...api.wireguard_utils import safe_int

        self._config_ready = False

        # Load DNS config from DB
        dns_data = await asyncio.to_thread(self._load_dns_config_sync)

        self._service_enabled = bool(dns_data.get("dns_service_enabled", True))
        interfaces = dns_data.get("interfaces", [])

        # Extract gateway addresses
        listen_addrs_ipv4, listen_addrs_ipv6 = self._extract_gateways(interfaces)

        if not listen_addrs_ipv4:
            _log.info("DNS_CONFIG_SKIPPED: No WireGuard interfaces configured")
            return

        # Write Unbound config
        await asyncio.to_thread(
            unbound.write_config,
            enable_logging=bool(dns_data.get("enable_logging", True)),
            enable_blocklist=bool(dns_data.get("enable_blocklist", True)),
            upstream_dns=dns_data.get("upstream_dns", []),
            enable_dnssec=bool(dns_data.get("enable_dnssec", True)),
            listen_addrs_ipv4=listen_addrs_ipv4,
            listen_addrs_ipv6=listen_addrs_ipv6 if listen_addrs_ipv6 else None,
        )

        # Write local data overrides
        await asyncio.to_thread(
            unbound.write_local_data_overrides,
            interfaces,
            dns_data.get("wg_fqdn"),
        )

        # Regenerate peer tags for ad-blocking
        peer_count = await asyncio.to_thread(self._regenerate_peer_tags_sync)
        _log.debug("DNS peer tags regenerated for %d peers", peer_count)

        # Enforce retention
        dns_retention_days = safe_int(
            dns_data.get("dns_retention_days"),
            DEFAULT_DNS_LOG_RETENTION_DAYS,
        )
        await asyncio.to_thread(
            dns_ingestion.enforce_dns_log_retention,
            self._config.dns_dir,
            dns_retention_days,
        )

        _log.info(
            "DNS_CONFIG_WRITTEN ipv4=%s ipv6=%s",
            ", ".join(listen_addrs_ipv4) if listen_addrs_ipv4 else "none",
            ", ".join(listen_addrs_ipv6) if listen_addrs_ipv6 else "none",
        )

        # Check for stale blocklist migration
        if await asyncio.to_thread(check_and_reset_stale_blocklist):
            _log.info("Blocklist reset due to tag migration - triggering immediate update")
            try:
                bl_urls, bl_custom_rules = await asyncio.to_thread(
                    self._load_blocklist_config_sync
                )
                _, msg = await unbound.update_blocklists(bl_urls, custom_rules_text=bl_custom_rules)
                _log.info("BLOCKLIST_MIGRATION %s", msg)
            except Exception:
                _log.exception("BLOCKLIST_MIGRATION update failed")

        self._config_ready = True

    async def _sync_unbound_state(self) -> None:
        """Start or stop Unbound based on enabled setting."""
        from ...dns import unbound

        unbound_running = await unbound.is_running()

        if self._service_enabled:
            if not unbound_running:
                ok, msg = await unbound.start()
                if ok:
                    _log.info("DNS_UNBOUND_STARTED")
                    if await self.wait_for_shutdown(timeout=2.0):
                        raise asyncio.CancelledError
                else:
                    raise RuntimeError(f"Failed to start Unbound: {msg}")
        else:
            if unbound_running:
                ok, msg = await unbound.stop()
                if ok:
                    _log.info("DNS_UNBOUND_STOPPED (disabled by user)")
                else:
                    _log.warning("DNS_UNBOUND_STOP_FAILED: %s", msg)
            else:
                _log.info("DNS_AUTOSTART_DISABLED: Resolver remains stopped")

    async def _run_ingestion_loop(self) -> None:
        """Run DNS query log ingestion with restart on failure."""
        from ...dns import unbound
        from ...dns import ingestion as dns_ingestion
        from ...db.sqlite_settings import DEFAULT_DNS_LOG_RETENTION_DAYS
        from ...tasks import scheduled as scheduled_tasks

        retry_count = 0
        dns_retention_days_cache = DEFAULT_DNS_LOG_RETENTION_DAYS

        while True:
            # Check if DNS should be running
            should_run, dns_retention_days_cache = await asyncio.to_thread(
                self._read_runtime_settings_sync
            )
            if not should_run:
                await scheduled_tasks._sleep_with_cancellation_check(30.0)
                continue

            # Wait for Unbound to be ready
            for attempt in range(_UNBOUND_WAIT_MAX_ATTEMPTS):
                if await unbound.is_running():
                    break
                delay = min(2.0 ** attempt, 30.0)
                _log.debug(
                    "DNS_INGESTION waiting for Unbound (attempt %d, delay %.0fs)",
                    attempt + 1,
                    delay,
                )
                if await self.wait_for_shutdown(timeout=delay):
                    raise asyncio.CancelledError
            else:
                _log.warning("DNS_INGESTION Unbound not ready; starting anyway")

            def _current_retention_days() -> int:
                return dns_retention_days_cache

            try:
                # Ensure offset path exists
                offset_path = await asyncio.to_thread(
                    self._ensure_offset_path_sync
                )

                # Run ingestion (blocks until error/shutdown)
                await dns_ingestion.run_dns_ingestion(
                    log_path=unbound.QUERY_LOG,
                    offset_path=offset_path,
                    dns_dir=self._config.dns_dir,
                    blocked_domains_func=unbound.get_blocked_domains,
                    retention_days_func=_current_retention_days,
                    tsdb_dir=self._config.tsdb_dir,
                )

                # Unexpected exit - restart
                retry_count = 0
                if self._shutdown_event.is_set():
                    return
                _log.warning("DNS_INGESTION stopped unexpectedly; restarting in 5s")
                await scheduled_tasks._sleep_with_cancellation_check(5.0)

            except asyncio.CancelledError:
                _log.info("DNS_INGESTION shutdown requested")
                raise

            except Exception:
                retry_count = min(retry_count + 1, 32)
                jitter = random.uniform(0.8, 1.2)
                delay = min(
                    (2 ** retry_count * _INGESTION_RESTART_BASE_DELAY * jitter),
                    _INGESTION_RESTART_MAX_DELAY,
                )
                if retry_count <= 3:
                    _log.exception(
                        "DNS_INGESTION crashed (retry #%d in %.0fs)",
                        retry_count,
                        delay,
                    )
                else:
                    _log.error(
                        "DNS_INGESTION crashed (retry #%d in %.0fs)",
                        retry_count,
                        delay,
                    )
                await scheduled_tasks._sleep_with_cancellation_check(delay)

    def _load_dns_config_sync(self) -> dict[str, object]:
        """Load DNS configuration from DB (sync, runs in thread)."""
        from ...db.sqlite_runtime import connect, close_connection
        from ...db.sqlite_interfaces import list_interfaces
        from ...db.sqlite_settings import (
            get_dns_blocklist_enabled,
            get_dns_log_retention_days,
            get_dns_query_logging_enabled,
            get_dns_service_enabled,
            get_dns_upstream_servers,
            get_dnssec_enabled,
            get_setting,
        )

        conn = connect(self._config.db_path)
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

    def _load_blocklist_config_sync(self) -> tuple[list[str], str]:
        """Load blocklist URLs and custom rules (sync, runs in thread)."""
        from ...db.sqlite_runtime import connect, close_connection
        from ...db.sqlite_settings import get_enabled_blocklists, get_dns_custom_rules

        conn = connect(self._config.db_path)
        try:
            return get_enabled_blocklists(conn), get_dns_custom_rules(conn)
        finally:
            close_connection(conn)

    def _regenerate_peer_tags_sync(self) -> int:
        """Regenerate peer tags for ad-blocking (sync, runs in thread)."""
        from ...db.sqlite_runtime import connect, close_connection
        from ...db.sqlite_peers import get_all_peers
        from ...api.wireguard_peers import regenerate_all_peer_tags

        conn = connect(self._config.db_path)
        try:
            regenerate_all_peer_tags(conn)
            return len(get_all_peers(conn))
        finally:
            close_connection(conn)

    def _read_runtime_settings_sync(self) -> tuple[bool, int]:
        """Read DNS runtime settings (sync, runs in thread)."""
        from ...db.sqlite_runtime import connect, close_connection
        from ...db.sqlite_interfaces import list_interfaces
        from ...db.sqlite_settings import get_dns_log_retention_days
        from ...db.sqlite_settings import get_dns_service_enabled

        conn = connect(self._config.db_path)
        try:
            service_enabled = get_dns_service_enabled(conn)
            interfaces = list_interfaces(conn)
            return service_enabled and len(interfaces) > 0, get_dns_log_retention_days(conn)
        finally:
            close_connection(conn)

    def _ensure_offset_path_sync(self) -> Path:
        """Ensure DNS ingestion offset path exists (sync, runs in thread)."""
        offset_path = self._config.data_dir / "dns" / "dns_tail.offset"
        offset_path.parent.mkdir(parents=True, exist_ok=True)

        # Migrate legacy path
        legacy_path = self._config.data_dir / "runtime" / "dns_tail.offset"
        if not offset_path.exists() and legacy_path.exists():
            try:
                max_size = 64 * 1024
                if legacy_path.stat().st_size > max_size:
                    raise ValueError("Legacy offset file is unexpectedly large")

                offset_path.write_text(
                    legacy_path.read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
                legacy_path.unlink(missing_ok=True)
                legacy_dir = legacy_path.parent
                if legacy_dir.exists() and not any(legacy_dir.iterdir()):
                    legacy_dir.rmdir()
                _log.info(
                    "DNS_INGESTION migrated offset file from %s to %s",
                    legacy_path,
                    offset_path,
                )
            except Exception:
                _log.exception("DNS_INGESTION failed to migrate offset file")

        return offset_path

    def _extract_gateways(self, interfaces: list) -> tuple[list[str], list[str]]:
        """Extract IPv4 and IPv6 gateway addresses from interfaces."""
        from ...dns import unbound

        listen_addrs_ipv4 = []
        seen_ipv4: set[str] = set()
        for iface in interfaces:
            addr4 = self._get_addr_field(iface, "address")
            if addr4:
                ip4 = str(addr4).split("/")[0]
                if ip4 not in seen_ipv4:
                    seen_ipv4.add(ip4)
                    listen_addrs_ipv4.append(ip4)

        return listen_addrs_ipv4, unbound.get_interface_ipv6_gateways(interfaces)

    @staticmethod
    def _get_addr_field(iface: object, key: str) -> str | None:
        """Get address field from interface row."""
        try:
            return iface[key]  # type: ignore[index]
        except (KeyError, IndexError):
            pass
        return getattr(iface, key, None)

    async def reload_config(self) -> bool:
        """Reload DNS configuration without restart.

        Returns:
            True if reload succeeded.
        """
        from ...dns import unbound

        await self._write_config()
        if not self._config_ready or self._shutdown_event.is_set():
            return False

        async with self._reload_lock:
            try:
                await unbound.reload_config()
                _log.info("DNS_CONFIG_RELOADED")
                return True
            except Exception:
                _log.exception("DNS_RELOAD_FAILED runtime state may not match written config")
                return False
