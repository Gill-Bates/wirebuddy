#!/usr/bin/env python3
#
# app/api/wireguard.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard management API - main router aggregating all modules."""

from __future__ import annotations

import logging

from fastapi import APIRouter

from . import (
    wireguard_interfaces,
    wireguard_interfaces_crud,
    wireguard_peers,
    wireguard_peers_config,
    wireguard_settings,
    wireguard_stats,
    wireguard_stats_country,
    wireguard_stats_geo,
)

_log = logging.getLogger(__name__)

router = APIRouter(tags=["wireguard"])


router.include_router(wireguard_settings.router)
router.include_router(wireguard_interfaces_crud.router)  # Must be before wireguard_interfaces for route priority
router.include_router(wireguard_interfaces.router)
router.include_router(wireguard_peers.router)
router.include_router(wireguard_peers_config.router)
router.include_router(wireguard_stats.router)
router.include_router(wireguard_stats_country.router)
router.include_router(wireguard_stats_geo.router)

__all__ = ["router"]

_log.info("WireGuard API router initialized with %d endpoints", len(router.routes))
