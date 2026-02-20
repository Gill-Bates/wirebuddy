#!/usr/bin/env python3
#
# app/api/wireguard.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireGuard management API - main router aggregating all modules."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter

# Import all wireguard sub-routers
from . import wireguard_settings
from . import wireguard_interfaces
from . import wireguard_interfaces_crud
from . import wireguard_peers
from . import wireguard_peers_config
from . import wireguard_stats
from . import wireguard_stats_geo

# Import shared utilities
from . import wireguard_utils
from . import wireguard_isolation
from . import wireguard_config

_log = logging.getLogger(__name__)

# Main router that combines all sub-routers
router = APIRouter(tags=["wireguard"])

# Include all sub-routers
router.include_router(wireguard_settings.router)
router.include_router(wireguard_interfaces.router)
router.include_router(wireguard_interfaces_crud.router)
router.include_router(wireguard_peers.router)
router.include_router(wireguard_peers_config.router)
router.include_router(wireguard_stats.router)
router.include_router(wireguard_stats_geo.router)

# Re-export commonly used utilities for backwards compatibility
validate_interface_name = wireguard_utils.validate_interface_name
select_display_unit = wireguard_utils.select_display_unit
bytes_to_unit = wireguard_utils.bytes_to_unit
safe_int = wireguard_utils.safe_int
get_enabled_blocklist_ids = wireguard_utils.get_enabled_blocklist_ids
filter_peer_blocklist_ids = wireguard_utils.filter_peer_blocklist_ids
effective_peer_blocklist_ids = wireguard_utils.effective_peer_blocklist_ids
validate_post_script = wireguard_utils.validate_post_script
row_to_public = wireguard_utils.row_to_public
run_wg_command = wireguard_utils.run_wg_command
run_wg_command_stdin = wireguard_utils.run_wg_command_stdin
wg_set_peer_with_psk = wireguard_utils.wg_set_peer_with_psk
generate_keypair = wireguard_utils.generate_keypair
generate_preshared_key = wireguard_utils.generate_preshared_key

client_iso_chain_name = wireguard_isolation.client_iso_chain_name
extract_peer_ips = wireguard_isolation.extract_peer_ips
build_client_isolation_post_rules = wireguard_isolation.build_client_isolation_post_rules
apply_client_isolation_runtime = wireguard_isolation.apply_client_isolation_runtime

write_interface_config = wireguard_config.write_interface_config
regenerate_all_configs = wireguard_config.regenerate_all_configs
sync_interface_config = wireguard_config.sync_interface_config
allowed_ips_with_dns_routes = wireguard_config.allowed_ips_with_dns_routes

get_server_endpoint = wireguard_settings.get_server_endpoint
get_dns_for_peer = wireguard_settings.get_dns_for_peer
WgSettingsPayload = wireguard_settings.WgSettingsPayload
WG_SETTING_KEYS = wireguard_settings.WG_SETTING_KEYS

InterfaceCreate = wireguard_interfaces_crud.InterfaceCreate
InterfaceUpdate = wireguard_interfaces_crud.InterfaceUpdate

__all__ = [
	"router",
	# Utils
	"validate_interface_name",
	"select_display_unit",
	"bytes_to_unit",
	"safe_int",
	"get_enabled_blocklist_ids",
	"filter_peer_blocklist_ids",
	"effective_peer_blocklist_ids",
	"validate_post_script",
	"row_to_public",
	"run_wg_command",
	"run_wg_command_stdin",
	"wg_set_peer_with_psk",
	"generate_keypair",
	"generate_preshared_key",
	# Isolation
	"client_iso_chain_name",
	"extract_peer_ips",
	"build_client_isolation_post_rules",
	"apply_client_isolation_runtime",
	# Config
	"write_interface_config",
	"regenerate_all_configs",
	"sync_interface_config",
	"allowed_ips_with_dns_routes",
	# Settings
	"get_server_endpoint",
	"get_dns_for_peer",
	"WgSettingsPayload",
	"WG_SETTING_KEYS",
	# Schemas
	"InterfaceCreate",
	"InterfaceUpdate",
]

_log.info("WireGuard API router initialized with %d endpoints", len(router.routes))
