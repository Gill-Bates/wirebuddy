#!/usr/bin/env python3
#
# app/dns/__init__.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""DNS ad-blocking module powered by Unbound."""

# Re-export public API from submodules for backwards compatibility
# This ensures `from app.dns import unbound` still works

from . import unbound_blocklist as blocklist
from . import unbound_config as config
from . import unbound_constants as constants
from . import unbound_process as process

# Create a unified 'unbound' namespace with all public functions
class _UnboundNamespace:
	"""Unified namespace for backwards compatibility with app.dns.unbound."""
	
	# Process management
	invalidate_running_cache = staticmethod(process.invalidate_running_cache)
	is_running = staticmethod(process.is_running)
	start = staticmethod(process.start)
	stop = staticmethod(process.stop)
	restart = staticmethod(process.restart)
	reload_config = staticmethod(process.reload_config)
	watchdog = staticmethod(process.watchdog)
	reset_watchdog_failures = staticmethod(process.reset_watchdog_failures)
	
	# Config generation
	is_dnssec_available = staticmethod(config.is_dnssec_available)
	generate_config = staticmethod(config.generate_config)
	get_interface_ipv6_gateways = staticmethod(config.get_interface_ipv6_gateways)
	write_config = staticmethod(config.write_config)
	write_peer_tags = staticmethod(config.write_peer_tags)
	
	# Blocklist management
	update_blocklists = staticmethod(blocklist.update_blocklists)
	get_blocklist_count = staticmethod(blocklist.get_blocklist_count)
	get_blocklist_source_counts = staticmethod(blocklist.get_blocklist_source_counts)
	get_blocked_domains = staticmethod(blocklist.get_blocked_domains)
	is_domain_blocked = staticmethod(blocklist.is_domain_blocked)
	
	# Constants (for easy access)
	BLOCKLIST_REGISTRY = constants.BLOCKLIST_REGISTRY
	QUERY_LOG = constants.QUERY_LOG
	get_blocklist_file = staticmethod(constants.get_blocklist_file)


unbound = _UnboundNamespace()

__all__ = [
	"unbound",
	"blocklist",
	"config",
	"constants",
	"process",
]
