#!/usr/bin/env python3
#
# tests/test_client_isolation_failclosed.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
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
	cleanup_client_isolation,
	client_iso_chain_name,
	shutdown_interface_fail_closed,
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


class _FakeIptables:
	"""Minimal stateful iptables: chains, FORWARD jumps, injectable failures."""

	def __init__(self, fail=None):
		self.chains: dict[str, list[tuple[str, ...]]] = {}
		self.forward: list[str] = []
		self.fail = fail  # callable(args) -> stderr | None
		self.down_ok = True
		self.down_calls = 0

	async def __call__(self, *args: str) -> tuple[int, str, str]:
		if args[:2] == ("wg", "show"):
			return 0, "", ""
		if args[0] == "wg-quick":
			self.down_calls += 1
			return (0, "", "") if self.down_ok else (1, "", "down failed")
		if self.fail and (err := self.fail(args)):
			return 1, "", err
		op = args[1]
		if op == "-N":
			if args[2] in self.chains:
				return 1, "", "Chain already exists"
			self.chains[args[2]] = []
		elif op == "-F":
			if args[2] not in self.chains:
				return 1, "", "No chain/target/match by name"
			self.chains[args[2]] = []
		elif op == "-X":
			if args[2] not in self.chains:
				return 1, "", "No chain/target/match by name"
			del self.chains[args[2]]
		elif op == "-D":
			target = args[-1]
			if target not in self.forward:
				return 1, "", "does a matching rule exist"
			self.forward.remove(target)
		elif op == "-I":
			self.forward.insert(0, args[-1])
		elif op == "-A":
			self.chains[args[2]].append(args[3:])
		elif op == "-E":
			self.chains[args[3]] = self.chains.pop(args[2])
			self.forward = [args[3] if t == args[2] else t for t in self.forward]
		return 0, "", ""


def _add_second_peer(conn: sqlite3.Connection) -> None:
	create_peer(
		conn,
		public_key="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
		allowed_ips="10.0.0.0/8",
		allowed_ips_mode="split",
		peer_address="10.13.13.3/32",
		interface="wg0",
		client_isolation=True,
	)


def _apply(conn, fake):
	return asyncio.run(apply_client_isolation_runtime("wg0", conn, run_wg_command=fake))


def test_apply_replaces_chain_atomically_on_success(threadsafe_conn: sqlite3.Connection):
	_seed(threadsafe_conn)
	fake = _FakeIptables()
	assert not _apply(threadsafe_conn, fake).errors
	_add_second_peer(threadsafe_conn)
	result = _apply(threadsafe_conn, fake)
	live = client_iso_chain_name("wg0")
	assert not result.errors
	assert fake.forward == [live]
	assert len(fake.chains[live]) == 4
	assert set(fake.chains) == {live}


def _inject(op: str, nth: int):
	"""Fail the nth call of an operation (1-based) after the live chain exists."""
	counter = {"n": 0}

	def _fail(args):
		if args[1] == op and (op != "-A" or args[2].startswith("WBIST")):
			counter["n"] += 1
			if counter["n"] == nth:
				return "injected failure"
		return None

	return _fail


def test_failure_during_rebuild_keeps_existing_isolation(threadsafe_conn: sqlite3.Connection):
	_seed(threadsafe_conn)
	live = client_iso_chain_name("wg0")
	for op, nth in (("-A", 1), ("-A", 3), ("-I", 1)):
		fake = _FakeIptables()
		assert not _apply(threadsafe_conn, fake).errors
		before = (list(fake.chains[live]), list(fake.forward))
		_add_second_peer_once(threadsafe_conn)
		fake.fail = _inject(op, nth)
		result = _apply(threadsafe_conn, fake)
		assert result.errors, (op, nth)
		assert (fake.chains[live], fake.forward) == before, (op, nth)
		assert set(fake.chains) == {live}, (op, nth)


def _add_second_peer_once(conn: sqlite3.Connection) -> None:
	if conn.execute("SELECT 1 FROM peers WHERE peer_address = '10.13.13.3/32'").fetchone() is None:
		_add_second_peer(conn)


def test_failed_rename_keeps_new_chain_live_and_reports(threadsafe_conn: sqlite3.Connection):
	_seed(threadsafe_conn)
	fake = _FakeIptables(fail=lambda a: "rename failed" if a[1] == "-E" else None)
	result = _apply(threadsafe_conn, fake)
	assert result.errors
	assert len(fake.forward) == 1
	assert fake.forward[0] in fake.chains
	asyncio.run(cleanup_client_isolation("wg0", run_wg_command=fake))
	assert fake.chains == {}
	assert fake.forward == []


def test_fail_closed_shutdown_reports_outcome():
	fake = _FakeIptables()
	assert asyncio.run(shutdown_interface_fail_closed("wg0", run_wg_command=fake)) is True
	fake.down_ok = False
	assert asyncio.run(shutdown_interface_fail_closed("wg0", run_wg_command=fake)) is False
	assert asyncio.run(shutdown_interface_fail_closed("bad name!", run_wg_command=fake)) is False


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


def test_isolation_applies_serialize_per_interface(monkeypatch):
	"""Concurrent applies share one staging chain: same interface runs one at a time, others in parallel."""
	import app.api.wireguard_isolation as iso

	active: dict[str, int] = {}
	peak: dict[str, int] = {}

	async def _fake(interface_name, conn, run_wg_command=None):
		active[interface_name] = active.get(interface_name, 0) + 1
		peak[interface_name] = max(peak.get(interface_name, 0), active[interface_name])
		await asyncio.sleep(0.01)
		active[interface_name] -= 1
		return iso.IsolationResult(applied=True)

	monkeypatch.setattr(iso, "_apply_client_isolation_unlocked", _fake)

	async def _run():
		await asyncio.gather(
			*(apply_client_isolation_runtime("wg0", None) for _ in range(4)),
			apply_client_isolation_runtime("wg1", None),
		)

	asyncio.run(_run())
	assert peak == {"wg0": 1, "wg1": 1}
