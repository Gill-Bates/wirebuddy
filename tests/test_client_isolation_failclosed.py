#!/usr/bin/env python3
#
# tests/test_client_isolation_failclosed.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Client isolation must classify iptables failures per operation.

A failed rule-install (-I/-A), such as the DROP rules that enforce
peer-to-peer isolation, is never benign: counting it as success would let
isolation fail open. Conversely, a pre-existing chain on -N or a missing
chain/rule on cleanup (-F/-X/-D) stays benign. The synchronous input loader
must also return the seeded isolated-peer IPs so the apply path can run off
the event loop.
"""

from __future__ import annotations

import asyncio
import sqlite3

from app.api.wireguard_isolation import (
	_benign_phrases_for_op,
	_load_isolation_inputs,
	apply_client_isolation_runtime,
)
from app.db.sqlite_interfaces import create_interface
from app.db.sqlite_peers_mutations import create_peer

_PUBKEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI="


def _seed(conn: sqlite3.Connection) -> str:
	create_interface(
		conn,
		name="wg0",
		private_key="a" * 44,
		public_key="b" * 44,
		address="10.13.13.1/24",
	)
	create_peer(
		conn,
		public_key=_PUBKEY,
		allowed_ips="10.0.0.0/8",
		allowed_ips_mode="split",
		peer_address="10.13.13.2/32",
		interface="wg0",
		client_isolation=True,
	)
	return "wg0"


def _runner(fail_on):
	"""Build a fake run_wg_command failing on a given (op) with a stderr phrase."""

	async def _run(*args: str) -> tuple[int, str, str]:
		if args[:2] == ("wg", "show"):
			return 0, "", ""
		op = args[1] if len(args) > 1 else ""
		if op in fail_on:
			return 1, "", fail_on[op]
		return 0, "", ""

	return _run


def test_benign_phrases_depend_on_operation():
	assert "Chain already exists" in _benign_phrases_for_op("-N")
	# A pre-existing chain is NOT a benign outcome for a rule append.
	assert "Chain already exists" not in _benign_phrases_for_op("-A")
	assert _benign_phrases_for_op("-A") == ()
	assert _benign_phrases_for_op("-I") == ()


def test_failed_drop_rule_counts_as_failure(threadsafe_conn: sqlite3.Connection):
	_seed(threadsafe_conn)
	# A benign-looking stderr on an -A DROP must still be counted as failure.
	run = _runner({"-A": "No chain/target/match by name"})
	result = asyncio.run(apply_client_isolation_runtime("wg0", threadsafe_conn, run_wg_command=run))
	assert result.rules_failed >= 1
	assert result.errors


def test_chain_exists_on_create_stays_benign(threadsafe_conn: sqlite3.Connection):
	_seed(threadsafe_conn)
	run = _runner({"-N": "iptables: Chain already exists."})
	result = asyncio.run(apply_client_isolation_runtime("wg0", threadsafe_conn, run_wg_command=run))
	assert result.rules_failed == 0
	assert not result.errors
	assert result.applied is True


def test_all_rules_ok_is_clean(threadsafe_conn: sqlite3.Connection):
	_seed(threadsafe_conn)
	run = _runner({})
	result = asyncio.run(apply_client_isolation_runtime("wg0", threadsafe_conn, run_wg_command=run))
	assert result.rules_failed == 0
	assert not result.errors
	assert result.applied is True


def test_load_isolation_inputs_returns_seeded_peer(conn: sqlite3.Connection):
	_seed(conn)
	loaded = _load_isolation_inputs(conn, "wg0")
	assert loaded is not None
	v4_subnet, _v6_subnet, isolated_v4, isolated_v6 = loaded
	assert v4_subnet == "10.13.13.0/24"
	assert isolated_v4 == ["10.13.13.2"]
	assert isolated_v6 == []


def test_load_isolation_inputs_missing_interface(conn: sqlite3.Connection):
	assert _load_isolation_inputs(conn, "wg9") is None
