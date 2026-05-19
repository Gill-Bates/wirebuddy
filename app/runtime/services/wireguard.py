#!/usr/bin/env python3
#
# app/runtime/services/wireguard.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: AGPL-3.0
#

"""WireGuard interface lifecycle service.

Manages:
- Interface startup (wg-quick up)
- Interface shutdown (wg-quick down)
- Stale interface cleanup
- Concurrent startup with bounded parallelism
- Health monitoring via wg show
"""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

from ..service import RuntimeService, ServiceHealth

if TYPE_CHECKING:
    from ...utils.config import Config

_log = logging.getLogger(__name__)

# Strict validation for interface names (prevents injection)
_IFACE_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,14}$")

# Timeouts
_WG_CHECK_TIMEOUT = 5.0
_WG_UP_TIMEOUT = 15.0
_WG_DOWN_TIMEOUT = 15.0
_WG_STARTUP_CONCURRENCY = 4


class WireGuardService(RuntimeService):
    """WireGuard interface lifecycle management.

    Handles starting enabled interfaces at startup and graceful
    shutdown of all managed interfaces.
    """

    name = "wireguard"
    dependencies = ["sqlite"]  # Needs DB to read interface config
    start_timeout = 60.0  # Multiple interfaces may need to start
    stop_timeout = 30.0

    def __init__(self, config: Config, interfaces_to_start: list[str] | None = None) -> None:
        super().__init__()
        self._config = config
        self._config_path = config.wg_config_path
        self._interfaces_to_start = interfaces_to_start or []
        self._started_interfaces: list[str] = []
        self._stale_removed: list[str] = []

    @property
    def started_interfaces(self) -> list[str]:
        """List of interface names that were started by this service."""
        return self._started_interfaces.copy()

    @property
    def stale_removed(self) -> list[str]:
        """List of stale interfaces that were cleaned up."""
        return self._stale_removed.copy()

    def set_interfaces_to_start(self, interfaces: list[str]) -> None:
        """Set interfaces to start (called after bootstrap determines enabled interfaces)."""
        self._interfaces_to_start = interfaces

    async def _do_start(self) -> None:
        """Clean stale interfaces and start enabled ones."""
        from ...utils.subprocess import run_command

        # Clean up stale interfaces first
        self._stale_removed = await self._cleanup_stale_interfaces()
        if self._stale_removed:
            _log.info(
                "WIREGUARD_STALE_CLEANUP removed=%d interfaces=%s",
                len(self._stale_removed),
                self._stale_removed,
            )

        if not self._interfaces_to_start:
            _log.info("WIREGUARD_NO_INTERFACES_TO_START")
            return

        # Start interfaces with bounded concurrency
        sem = asyncio.Semaphore(_WG_STARTUP_CONCURRENCY)

        async def _start_one(iface_name: str) -> str | None:
            async with sem:
                return await self._start_interface(iface_name)

        results = await asyncio.gather(
            *[_start_one(name) for name in self._interfaces_to_start]
        )
        self._started_interfaces = [r for r in results if r]

        _log.info(
            "WIREGUARD_STARTED requested=%d started=%d interfaces=%s",
            len(self._interfaces_to_start),
            len(self._started_interfaces),
            self._started_interfaces,
        )

    async def _do_stop(self) -> None:
        """Stop all interfaces that we started."""
        from ...utils.subprocess import run_command

        if not self._started_interfaces:
            return

        for iface_name in self._started_interfaces:
            try:
                res = await run_command(
                    "wg-quick", "down", iface_name,
                    timeout=_WG_DOWN_TIMEOUT,
                )
                if res.returncode == 0:
                    _log.info("WIREGUARD_INTERFACE_STOPPED name=%s", iface_name)
                else:
                    _log.warning(
                        "WIREGUARD_STOP_FAILED name=%s stderr=%s",
                        iface_name,
                        res.stderr,
                    )
            except asyncio.TimeoutError:
                _log.warning("WIREGUARD_STOP_TIMEOUT name=%s", iface_name)
            except Exception as exc:
                _log.warning("WIREGUARD_STOP_ERROR name=%s error=%s", iface_name, exc)

        self._started_interfaces.clear()

    async def check_health(self) -> ServiceHealth:
        """Check WireGuard interface health via wg show."""
        health = await super().check_health()

        if not self.is_running:
            return health

        try:
            from ...utils.subprocess import run_command

            res = await run_command("wg", "show", "interfaces", timeout=_WG_CHECK_TIMEOUT)
            if res.returncode == 0:
                active = res.stdout.strip().split() if res.stdout.strip() else []
                health.details["active_interfaces"] = active
                health.details["managed_interfaces"] = self._started_interfaces

                # Check if all started interfaces are still active
                missing = set(self._started_interfaces) - set(active)
                if missing:
                    health.healthy = False
                    health.error = f"Interfaces not active: {list(missing)}"
            else:
                health.healthy = False
                health.error = "wg show failed"
        except Exception as exc:
            health.healthy = False
            health.error = str(exc)

        return health

    async def _start_interface(self, iface_name: str) -> str | None:
        """Start a single WireGuard interface.

        Returns:
            Interface name if started successfully, None otherwise.
        """
        from ...utils.subprocess import run_command

        try:
            # Check if already running
            check_res = await run_command(
                "wg", "show", iface_name,
                timeout=_WG_CHECK_TIMEOUT,
            )
            if check_res.returncode == 0:
                _log.info("WIREGUARD_INTERFACE_ALREADY_RUNNING name=%s", iface_name)
                return None  # Already running, don't track as "started by us"

            # Start the interface
            up_res = await run_command(
                "wg-quick", "up", iface_name,
                timeout=_WG_UP_TIMEOUT,
            )
            if up_res.returncode == 0:
                _log.info("WIREGUARD_INTERFACE_STARTED name=%s", iface_name)
                return iface_name
            else:
                _log.warning(
                    "WIREGUARD_START_FAILED name=%s stderr=%s",
                    iface_name,
                    up_res.stderr,
                )
                return None

        except asyncio.TimeoutError:
            _log.warning("WIREGUARD_START_TIMEOUT name=%s", iface_name)
            return None
        except Exception as exc:
            _log.warning("WIREGUARD_START_ERROR name=%s error=%s", iface_name, exc)
            return None

    async def _cleanup_stale_interfaces(self) -> list[str]:
        """Remove WireGuard interfaces active in kernel but without config file.

        Returns:
            List of removed interface names.
        """
        from ...utils.subprocess import run_command

        removed: list[str] = []

        try:
            # Get active interfaces from kernel
            res = await run_command("wg", "show", "interfaces", timeout=5.0)
            if res.returncode != 0 or not res.stdout:
                return removed

            active_interfaces = res.stdout.strip().split()
            if not active_interfaces:
                return removed

            for iface_name in active_interfaces:
                # Validate interface name
                if not _IFACE_NAME_RE.match(iface_name):
                    _log.warning(
                        "WIREGUARD_STALE_INVALID_NAME name=%r",
                        iface_name,
                    )
                    continue

                # Check if config file exists
                conf_file = self._config_path / f"{iface_name}.conf"
                if conf_file.exists():
                    continue  # Has config, not orphaned

                # Orphaned interface: active but no config
                _log.info(
                    "WIREGUARD_STALE_INTERFACE name=%s (active but no config)",
                    iface_name,
                )

                try:
                    del_res = await run_command(
                        "ip", "link", "delete", iface_name,
                        timeout=5.0,
                    )
                    if del_res.returncode == 0:
                        _log.info("WIREGUARD_STALE_REMOVED name=%s", iface_name)
                        removed.append(iface_name)
                    else:
                        _log.warning(
                            "WIREGUARD_STALE_DELETE_FAILED name=%s stderr=%s",
                            iface_name,
                            del_res.stderr,
                        )
                except asyncio.TimeoutError:
                    _log.warning("WIREGUARD_STALE_DELETE_TIMEOUT name=%s", iface_name)
                except Exception as exc:
                    _log.warning(
                        "WIREGUARD_STALE_DELETE_ERROR name=%s error=%s",
                        iface_name,
                        exc,
                    )

        except FileNotFoundError:
            _log.debug("wg command not found, skipping stale cleanup")
        except asyncio.TimeoutError:
            _log.warning("Timeout checking for stale interfaces")
        except Exception as exc:
            _log.warning("Could not check stale interfaces: %s", exc)

        return removed

    async def restart_interface(self, iface_name: str) -> bool:
        """Restart a specific interface.

        Returns:
            True if restart succeeded.
        """
        from ...utils.subprocess import run_command

        try:
            # Stop
            down_res = await run_command(
                "wg-quick", "down", iface_name,
                timeout=_WG_DOWN_TIMEOUT,
            )
            if down_res.returncode != 0:
                _log.warning(
                    "WIREGUARD_RESTART_DOWN_FAILED name=%s stderr=%s",
                    iface_name,
                    down_res.stderr,
                )

            # Start
            up_res = await run_command(
                "wg-quick", "up", iface_name,
                timeout=_WG_UP_TIMEOUT,
            )
            if up_res.returncode == 0:
                _log.info("WIREGUARD_INTERFACE_RESTARTED name=%s", iface_name)
                return True
            else:
                _log.warning(
                    "WIREGUARD_RESTART_UP_FAILED name=%s stderr=%s",
                    iface_name,
                    up_res.stderr,
                )
                return False

        except Exception as exc:
            _log.warning("WIREGUARD_RESTART_ERROR name=%s error=%s", iface_name, exc)
            return False
