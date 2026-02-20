#!/usr/bin/env python3
#
# app/db/sqlite_peers.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Peer read/query and allocation helpers."""

from __future__ import annotations

import logging
import sqlite3
from typing import Optional

from .sqlite_interfaces import get_interface
from .sqlite_runtime import transaction

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Peer operations (read/query)
# ---------------------------------------------------------------------------

def get_all_peers(conn: sqlite3.Connection, interface: Optional[str] = None) -> list[sqlite3.Row]:
	"""Get all peers, optionally filtered by interface."""
	if interface:
		cur = conn.execute(
			"SELECT * FROM peers WHERE interface = ? ORDER BY name",
			(interface,),
		)
	else:
		cur = conn.execute("SELECT * FROM peers ORDER BY interface, name")
	return cur.fetchall()


def count_peers(conn: sqlite3.Connection, interface: Optional[str] = None) -> int:
	"""Count peers, optionally filtered by interface."""
	if interface:
		cur = conn.execute("SELECT COUNT(*) FROM peers WHERE interface = ?", (interface,))
	else:
		cur = conn.execute("SELECT COUNT(*) FROM peers")
	row = cur.fetchone()
	return int(row[0]) if row else 0


def get_peers_paginated(
	conn: sqlite3.Connection,
	*,
	page: int = 1,
	page_size: int = 50,
	interface: Optional[str] = None,
) -> list[sqlite3.Row]:
	"""Get peers paginated, optionally filtered by interface."""
	page = max(1, page)
	page_size = max(1, page_size)
	offset = (page - 1) * page_size
	if interface:
		cur = conn.execute(
			"SELECT * FROM peers WHERE interface = ? ORDER BY interface, name LIMIT ? OFFSET ?",
			(interface, page_size, offset),
		)
	else:
		cur = conn.execute(
			"SELECT * FROM peers ORDER BY interface, name LIMIT ? OFFSET ?",
			(page_size, offset),
		)
	return cur.fetchall()


def get_peer_by_public_key(conn: sqlite3.Connection, public_key: str) -> Optional[sqlite3.Row]:
	"""Get a peer by public key."""
	cur = conn.execute("SELECT * FROM peers WHERE public_key = ?", (public_key,))
	return cur.fetchone()


def get_peer_by_id(conn: sqlite3.Connection, peer_id: int) -> Optional[sqlite3.Row]:
	"""Get a peer by ID."""
	cur = conn.execute("SELECT * FROM peers WHERE id = ?", (peer_id,))
	return cur.fetchone()


def update_peer_last_seen(
	conn: sqlite3.Connection,
	public_key: str,
	client_ip: str,
	handshake_at: int,
) -> None:
	"""Persist the client's last observed public IP and handshake timestamp."""
	with transaction(conn):
		conn.execute(
			"UPDATE peers SET last_client_ip = ?, last_handshake_at = ? WHERE public_key = ?",
			(client_ip, handshake_at, public_key),
		)


def update_peers_last_seen_batch(
	conn: sqlite3.Connection,
	updates: list[tuple[str, int, str]],
) -> None:
	"""Batch-persist last_client_ip and last_handshake_at for multiple peers.

	*updates* is a list of ``(client_ip, handshake_at, public_key)`` tuples.
	"""
	if not updates:
		return
	with transaction(conn):
		conn.executemany(
			"UPDATE peers SET last_client_ip = ?, last_handshake_at = ? WHERE public_key = ?",
			updates,
		)


def allocate_peer_ip(conn: sqlite3.Connection, interface_name: str) -> Optional[str]:
	"""Allocate the next available dual-stack IP address for a peer.

	Returns:
		The address string (e.g. "10.13.13.2/32, fd13:13:13::2/128"),
		or None if the pool is exhausted.

	Note:
		Allocation is optimistic and NOT atomic. A concurrent writer may reserve
		the same address between this read and the subsequent peer insert, causing
		sqlite3.IntegrityError due to the unique index on (peer_address, interface).
		Callers SHOULD catch IntegrityError and retry allocation + insert.
	"""
	import ipaddress

	iface = get_interface(conn, interface_name)
	if not iface:
		return None

	# Parse IPv4 subnet
	try:
		ipv4_iface = ipaddress.ip_interface(iface["address"].strip())
		ipv4_network = ipv4_iface.network
		ipv4_server = ipv4_iface.ip
	except ValueError as e:
		_log.error("Invalid interface IPv4 address %s: %s", iface["address"], e)
		return None

	# Parse IPv6 subnet (optional)
	ipv6_network = None
	ipv6_server = None
	if iface["address6"]:
		try:
			ipv6_iface = ipaddress.ip_interface(iface["address6"].strip())
			ipv6_network = ipv6_iface.network
			ipv6_server = ipv6_iface.ip
		except ValueError:
			_log.warning("Invalid interface IPv6 address %s, skipping", iface["address6"])

	# Collect already-used IPs from existing peers
	cur = conn.execute(
		"SELECT peer_address FROM peers WHERE interface = ? AND peer_address IS NOT NULL",
		(interface_name,),
	)
	used_v4: set[ipaddress.IPv4Address] = {ipv4_server}
	used_v6: set[ipaddress.IPv6Address] = set()
	if ipv6_server:
		used_v6.add(ipv6_server)

	for row in cur.fetchall():
		for part in row[0].split(","):
			part = part.strip()
			if not part:
				continue
			try:
				used_ip = ipaddress.ip_interface(part).ip
				if isinstance(used_ip, ipaddress.IPv4Address):
					used_v4.add(used_ip)
				else:
					used_v6.add(used_ip)
			except ValueError:
				pass

	# Find next free IPv4
	next_v4 = None
	for ip in ipv4_network.hosts():
		if ip not in used_v4:
			next_v4 = ip
			break

	if next_v4 is None:
		return None  # Pool exhausted

	# Find matching IPv6 (mirror host part from IPv4)
	result = f"{next_v4}/32"
	if ipv6_network:
		# Use same host offset for IPv6
		v4_offset = int(next_v4) - int(ipv4_network.network_address)
		next_v6 = ipv6_network.network_address + v4_offset
		if next_v6 not in used_v6 and next_v6 in ipv6_network:
			result += f", {next_v6}/128"

	return result
