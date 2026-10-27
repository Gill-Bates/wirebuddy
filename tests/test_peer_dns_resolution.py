#!/usr/bin/env python3
#
# tests/test_peer_dns_resolution.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Per-interface DNS precedence when building peer client configs.

With the ad-blocker off, a generated .conf/QR config must use the
interface's configured ``dns`` value when set, falling back to the global
default only when the column is NULL/empty. With the ad-blocker on, the
internal resolver (interface gateway IP) is returned unchanged.
"""

from __future__ import annotations

import sqlite3

from app.api.wireguard_settings import get_dns_for_peer
from app.db.sqlite_interfaces import create_interface

_DEFAULT_DNS = "1.1.1.1,9.9.9.9"


def _make_iface(conn: sqlite3.Connection, dns: str | None) -> str:
	create_interface(
		conn,
		name="wg0",
		private_key="a" * 44,
		public_key="b" * 44,
		address="10.13.13.1/24",
		dns=dns,
	)
	return "wg0"


def test_adblocker_off_uses_interface_dns_when_set(conn: sqlite3.Connection):
	iface = _make_iface(conn, dns="192.0.2.53")
	assert get_dns_for_peer(conn, iface, use_adblocker=False, default_dns=_DEFAULT_DNS) == "192.0.2.53"


def test_adblocker_off_falls_back_to_default_when_dns_null(conn: sqlite3.Connection):
	iface = _make_iface(conn, dns=None)
	assert get_dns_for_peer(conn, iface, use_adblocker=False, default_dns=_DEFAULT_DNS) == _DEFAULT_DNS


def test_adblocker_off_falls_back_to_default_when_dns_blank(conn: sqlite3.Connection):
	iface = _make_iface(conn, dns="   ")
	assert get_dns_for_peer(conn, iface, use_adblocker=False, default_dns=_DEFAULT_DNS) == _DEFAULT_DNS


def test_adblocker_on_returns_internal_resolver_unchanged(conn: sqlite3.Connection):
	iface = _make_iface(conn, dns="192.0.2.53")
	# Ad-blocker on ignores the interface dns column and returns the gateway IP.
	assert get_dns_for_peer(conn, iface, use_adblocker=True, default_dns=_DEFAULT_DNS) == "10.13.13.1"
