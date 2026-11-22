#!/usr/bin/env python3
#
# tests/test_peer_runtime_consistency.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""A peer runtime mutation that fails must not be reported as success.

_wg_add_peer_runtime() must raise HTTPException(503) when the underlying
`wg set` returns a non-zero exit code, so an enable/migration cannot claim
success while the peer never reached the running interface. The happy path
(exit 0) must return normally.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api import wireguard_peers as wp
from app.api.wireguard_config import ConfigWriteError
from app.api.wireguard_isolation import IsolationResult
from app.db.sqlite_interfaces import create_interface
from app.db.sqlite_peers_mutations import PeerPoolExhaustedError, create_peer
from app.db.sqlite_settings import set_setting
from app.models.peers import PeerCreate, PeerUpdate

_PUBKEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI="


def test_wg_add_peer_runtime_raises_503_on_nonzero(monkeypatch):
	async def _fail(*args, **kwargs):
		return 1, "", "wg set failed"

	monkeypatch.setattr(wp, "run_wg_command", _fail)

	with pytest.raises(HTTPException) as exc:
		asyncio.run(
			wp._wg_add_peer_runtime(
				"wg0",
				_PUBKEY,
				"10.13.13.2/32",
				None,
				"secret",
			)
		)
	assert exc.value.status_code == 503
	assert "runtime" in exc.value.detail.lower()


def test_wg_add_peer_runtime_ok_on_success(monkeypatch):
	async def _ok(*args, **kwargs):
		return 0, "", ""

	monkeypatch.setattr(wp, "run_wg_command", _ok)

	# Returns None without raising when the runtime mutation succeeds.
	assert (
		asyncio.run(
			wp._wg_add_peer_runtime(
				"wg0",
				_PUBKEY,
				"10.13.13.2/32",
				None,
				"secret",
			)
		)
		is None
	)


def test_failed_disable_remove_restores_enabled_state(monkeypatch, threadsafe_conn: sqlite3.Connection):
	"""Revocation must not fail open: a failed runtime removal leaves the peer enabled in the DB."""
	create_interface(
		threadsafe_conn,
		name="wg0",
		private_key="a" * 44,
		public_key="b" * 44,
		address="10.13.13.1/24",
	)
	peer_id = create_peer(
		threadsafe_conn,
		public_key=_PUBKEY,
		allowed_ips="10.0.0.0/8",
		allowed_ips_mode="split",
		peer_address="10.13.13.2/32",
		interface="wg0",
	)

	async def _fail(*args, **kwargs):
		return 1, "", "wg set failed"

	monkeypatch.setattr(wp, "run_wg_command", _fail)
	monkeypatch.setattr(wp, "get_config", lambda request: SimpleNamespace(secret_key="secret"))
	assert threadsafe_conn.execute("SELECT is_enabled FROM peers WHERE id = ?", (peer_id,)).fetchone()[0] == 1

	with pytest.raises(HTTPException) as exc:
		asyncio.run(wp.update_peer(None, peer_id, PeerUpdate(is_enabled=False), threadsafe_conn, None))

	assert exc.value.status_code == 503
	assert threadsafe_conn.execute("SELECT is_enabled FROM peers WHERE id = ?", (peer_id,)).fetchone()[0] == 1


def test_create_peer_rolls_back_when_config_write_fails(monkeypatch, threadsafe_conn: sqlite3.Connection):
	"""ConfigWriteError after the DB insert must remove the peer from WG and the DB (no half-created peer)."""
	create_interface(
		threadsafe_conn,
		name="wg0",
		private_key="a" * 44,
		public_key="b" * 44,
		address="10.13.13.1/24",
	)
	set_setting(threadsafe_conn, "wg_fqdn", "vpn.test.invalid")
	wg_calls: list[tuple] = []

	async def _wg(*args, **kwargs):
		wg_calls.append(args)
		return 0, "", ""

	async def _keypair():
		return "k" * 43 + "=", _PUBKEY

	def _boom(*args, **kwargs):
		raise ConfigWriteError("Failed to write config for wg0")

	monkeypatch.setattr(wp, "run_wg_command", _wg)
	monkeypatch.setattr(wp, "wg_set_peer_with_psk", lambda *a, **k: _wg())
	monkeypatch.setattr(wp, "generate_keypair", _keypair)
	monkeypatch.setattr(wp, "sync_interface_config", _boom)
	monkeypatch.setattr(wp, "get_config", lambda request: SimpleNamespace(secret_key="s" * 40))

	payload = PeerCreate(name="p1", allowed_ips="10.0.0.0/8", allowed_ips_mode="split", interface="wg0")
	with pytest.raises(HTTPException) as exc:
		asyncio.run(wp.create_peer(None, payload, threadsafe_conn, Path("/nonexistent-tsdb"), None))

	assert exc.value.status_code == 500
	assert threadsafe_conn.execute("SELECT COUNT(*) FROM peers").fetchone()[0] == 0
	assert any(call[:1] == ("remove",) or "remove" in call for call in wg_calls)


def test_create_peer_aborts_when_global_psk_cannot_be_decrypted(monkeypatch, threadsafe_conn: sqlite3.Connection):
	"""An undecryptable stored PSK must not silently downgrade the peer to no PSK."""
	create_interface(
		threadsafe_conn,
		name="wg0",
		private_key="a" * 44,
		public_key="b" * 44,
		address="10.13.13.1/24",
	)
	set_setting(threadsafe_conn, "wg_fqdn", "vpn.test.invalid")
	set_setting(threadsafe_conn, "wg_use_psk", "1")
	set_setting(threadsafe_conn, "wg_global_psk", "not-a-valid-vault-token")
	wg_calls: list[tuple] = []

	async def _wg(*args, **kwargs):
		wg_calls.append(args)
		return 0, "", ""

	async def _keypair():
		return "k" * 43 + "=", _PUBKEY

	monkeypatch.setattr(wp, "run_wg_command", _wg)
	monkeypatch.setattr(wp, "wg_set_peer_with_psk", lambda *a, **k: _wg())
	monkeypatch.setattr(wp, "generate_keypair", _keypair)
	monkeypatch.setattr(wp, "get_config", lambda request: SimpleNamespace(secret_key="s" * 40))
	payload = PeerCreate(name="p1", allowed_ips="10.0.0.0/8", allowed_ips_mode="split", interface="wg0")
	with pytest.raises(HTTPException) as exc:
		asyncio.run(wp.create_peer(None, payload, threadsafe_conn, Path("/nonexistent-tsdb"), None))
	assert exc.value.status_code == 500
	assert not any("set" in call for call in wg_calls)
	assert threadsafe_conn.execute("SELECT COUNT(*) FROM peers").fetchone()[0] == 0


def test_concurrent_create_with_same_key_keeps_stored_peer_in_runtime(monkeypatch, threadsafe_conn: sqlite3.Connection):
	"""The losing request's rollback must not remove the peer the winner stored."""
	create_interface(
		threadsafe_conn,
		name="wg0",
		private_key="a" * 44,
		public_key="b" * 44,
		address="10.13.13.1/24",
	)
	set_setting(threadsafe_conn, "wg_fqdn", "vpn.test.invalid")
	runtime: set[str] = set()

	async def _wg(*args, **kwargs):
		await asyncio.sleep(0)
		if "remove" in args:
			runtime.discard(args[4])
		elif "allowed-ips" in args:
			runtime.add(args[4])
		return 0, "", ""

	async def _noop(*args, **kwargs):
		return None

	async def _isolation(*args, **kwargs):
		return IsolationResult(applied=True)

	monkeypatch.setattr(wp, "run_wg_command", _wg)
	monkeypatch.setattr(wp, "validate_keypair", _noop)
	monkeypatch.setattr(wp, "sync_interface_config", lambda *a, **k: None)
	monkeypatch.setattr(wp, "apply_client_isolation_runtime", _isolation)
	monkeypatch.setattr(wp, "_safe_regenerate_peer_tags", _noop)
	monkeypatch.setattr(wp, "get_config", lambda request: SimpleNamespace(secret_key="s" * 40))
	payload = PeerCreate(
		name="p1",
		allowed_ips="10.0.0.0/8",
		allowed_ips_mode="split",
		interface="wg0",
		public_key=_PUBKEY,
		private_key="k" * 43 + "=",
	)

	async def _both():
		return await asyncio.gather(
			wp.create_peer(None, payload, threadsafe_conn, Path("/nonexistent-tsdb"), None),
			wp.create_peer(None, payload, threadsafe_conn, Path("/nonexistent-tsdb"), None),
			return_exceptions=True,
		)

	results = asyncio.run(_both())
	assert sum(isinstance(r, HTTPException) and r.status_code == 409 for r in results) == 1
	assert threadsafe_conn.execute("SELECT COUNT(*) FROM peers").fetchone()[0] == 1
	assert runtime == {_PUBKEY}


def _pubkey(i: int) -> str:
	import base64

	return base64.b64encode(bytes([i + 1]) * 32).decode()


def test_parallel_connections_get_unique_addresses_in_one_transaction(tmp_path):
	"""Allocation and insert share one BEGIN IMMEDIATE, so racing writers never pick the same address."""
	import threading

	from app.db.sqlite_runtime import connect
	from app.db.sqlite_schema import init_schema

	first = connect(tmp_path / "peers.db")
	init_schema(first)
	create_interface(
		first,
		name="wg0",
		private_key="a" * 44,
		public_key="b" * 44,
		address="10.13.13.1/24",
		address6="fd13:13:13::1/64",
	)
	conns = [first, connect(tmp_path / "peers.db"), connect(tmp_path / "peers.db")]
	barrier = threading.Barrier(len(conns))
	errors: list[BaseException] = []

	def _worker(n: int) -> None:
		barrier.wait()
		for i in range(8):
			try:
				create_peer(
					conns[n],
					_pubkey(n * 8 + i),
					"10.0.0.0/8",
					allowed_ips_mode="split",
					interface="wg0",
					allocate_address=True,
				)
			except BaseException as exc:
				errors.append(exc)

	threads = [threading.Thread(target=_worker, args=(n,)) for n in range(len(conns))]
	for t in threads:
		t.start()
	for t in threads:
		t.join(60)
	assert not errors
	addresses = [r[0] for r in first.execute("SELECT peer_address FROM peers")]
	assert len(addresses) == 24
	assert len(set(addresses)) == 24
	v4 = {a.split("/")[0] for a in addresses}
	v6 = {a.split(",")[1].strip().split("/")[0] for a in addresses}
	assert len(v4) == len(v6) == 24
	for c in conns:
		c.close()


def test_create_peer_allocate_address_reports_exhausted_pool(threadsafe_conn):
	create_interface(
		threadsafe_conn,
		name="wg0",
		private_key="a" * 44,
		public_key="b" * 44,
		address="10.13.13.1/30",
	)
	create_peer(
		threadsafe_conn,
		_pubkey(0),
		"10.0.0.0/8",
		allowed_ips_mode="split",
		interface="wg0",
		allocate_address=True,
	)
	with pytest.raises(PeerPoolExhaustedError):
		create_peer(
			threadsafe_conn,
			_pubkey(1),
			"10.0.0.0/8",
			allowed_ips_mode="split",
			interface="wg0",
			allocate_address=True,
		)
	assert threadsafe_conn.execute("SELECT COUNT(*) FROM peers").fetchone()[0] == 1


def _patch_create_env(monkeypatch, conn, runtime: set[str], *, wg_fail: bool = False):
	set_setting(conn, "wg_fqdn", "vpn.test.invalid")
	keys = iter(range(100))

	async def _wg(*args, **kwargs):
		await asyncio.sleep(0)
		if "remove" in args:
			runtime.discard(args[4])
		elif "allowed-ips" in args:
			if wg_fail:
				return 1, "", "boom"
			runtime.add(args[4])
		return 0, "", ""

	async def _keypair():
		return "k" * 43 + "=", _pubkey(next(keys))

	async def _noop(*args, **kwargs):
		return None

	async def _isolation(*args, **kwargs):
		return IsolationResult(applied=True)

	monkeypatch.setattr(wp, "run_wg_command", _wg)
	monkeypatch.setattr(wp, "generate_keypair", _keypair)
	monkeypatch.setattr(wp, "sync_interface_config", lambda *a, **k: None)
	monkeypatch.setattr(wp, "apply_client_isolation_runtime", _isolation)
	monkeypatch.setattr(wp, "_safe_regenerate_peer_tags", _noop)
	monkeypatch.setattr(wp, "get_config", lambda request: SimpleNamespace(secret_key="s" * 40))


def test_concurrent_creates_get_distinct_addresses_and_runtime_matches_db(monkeypatch, threadsafe_conn):
	create_interface(
		threadsafe_conn,
		name="wg0",
		private_key="a" * 44,
		public_key="b" * 44,
		address="10.13.13.1/24",
	)
	runtime: set[str] = set()
	_patch_create_env(monkeypatch, threadsafe_conn, runtime)
	payload = PeerCreate(name="p", allowed_ips="10.0.0.0/8", allowed_ips_mode="split", interface="wg0")

	async def _many():
		return await asyncio.gather(*(wp.create_peer(None, payload, threadsafe_conn, Path("/nonexistent-tsdb"), None) for _ in range(5)))

	asyncio.run(_many())
	rows = threadsafe_conn.execute("SELECT public_key, peer_address FROM peers").fetchall()
	assert len({r["peer_address"] for r in rows}) == 5
	assert runtime == {r["public_key"] for r in rows}


def test_failed_wg_set_removes_reserved_row(monkeypatch, threadsafe_conn):
	create_interface(
		threadsafe_conn,
		name="wg0",
		private_key="a" * 44,
		public_key="b" * 44,
		address="10.13.13.1/24",
	)
	runtime: set[str] = set()
	_patch_create_env(monkeypatch, threadsafe_conn, runtime, wg_fail=True)
	payload = PeerCreate(name="p", allowed_ips="10.0.0.0/8", allowed_ips_mode="split", interface="wg0")
	with pytest.raises(HTTPException) as exc:
		asyncio.run(wp.create_peer(None, payload, threadsafe_conn, Path("/nonexistent-tsdb"), None))
	assert exc.value.status_code == 500
	assert threadsafe_conn.execute("SELECT COUNT(*) FROM peers").fetchone()[0] == 0
	assert not runtime


def test_create_peer_exhausted_pool_returns_409(monkeypatch, threadsafe_conn):
	create_interface(
		threadsafe_conn,
		name="wg0",
		private_key="a" * 44,
		public_key="b" * 44,
		address="10.13.13.1/30",
	)
	runtime: set[str] = set()
	_patch_create_env(monkeypatch, threadsafe_conn, runtime)
	payload = PeerCreate(name="p", allowed_ips="10.0.0.0/8", allowed_ips_mode="split", interface="wg0")
	asyncio.run(wp.create_peer(None, payload, threadsafe_conn, Path("/nonexistent-tsdb"), None))
	with pytest.raises(HTTPException) as exc:
		asyncio.run(wp.create_peer(None, payload, threadsafe_conn, Path("/nonexistent-tsdb"), None))
	assert exc.value.status_code == 409
	assert exc.value.detail == "No free peer address available on this interface"
	assert threadsafe_conn.execute("SELECT COUNT(*) FROM peers").fetchone()[0] == 1


def test_failed_wg_set_does_not_leak_wg_stderr(monkeypatch, threadsafe_conn):
	create_interface(
		threadsafe_conn,
		name="wg0",
		private_key="a" * 44,
		public_key="b" * 44,
		address="10.13.13.1/24",
	)
	_patch_create_env(monkeypatch, threadsafe_conn, set(), wg_fail=True)
	payload = PeerCreate(name="p", allowed_ips="10.0.0.0/8", allowed_ips_mode="split", interface="wg0")
	with pytest.raises(HTTPException) as exc:
		asyncio.run(wp.create_peer(None, payload, threadsafe_conn, Path("/nonexistent-tsdb"), None))
	assert exc.value.status_code == 500
	assert exc.value.detail == "Failed to add peer to WireGuard; see server log"


def _failing_remove_env(monkeypatch, conn, *, set_fails: bool, runtime_state: str):
	"""Remove always fails; runtime_state is one of absent-interface, absent-peer, present, unknown."""
	_patch_create_env(monkeypatch, conn, set(), wg_fail=set_fails)

	async def _wg(*args, **kwargs):
		if "remove" in args:
			return 1, "", "secret-internal-stderr"
		if "allowed-ips" in args and set_fails:
			return 1, "", "boom"
		if args[1:3] == ("show", "interfaces"):
			if runtime_state == "unknown":
				return 1, "", "timeout"
			return 0, ("" if runtime_state == "absent-interface" else "wg0"), ""
		if args[1] == "show" and args[-1] == "peers":
			return 0, (_pubkey(0) if runtime_state == "present" else ""), ""
		return 0, "", ""

	monkeypatch.setattr(wp, "run_wg_command", _wg)


@pytest.mark.parametrize("runtime_state", ["absent-interface", "absent-peer", "present", "unknown"])
@pytest.mark.parametrize("set_fails", [True, False])
def test_failed_rollback_remove_keeps_row_only_when_runtime_not_provably_clean(monkeypatch, threadsafe_conn, set_fails, runtime_state):
	"""A failed runtime remove deletes the row if the peer is provably absent, else keeps it; stderr never leaks."""
	create_interface(
		threadsafe_conn,
		name="wg0",
		private_key="a" * 44,
		public_key="b" * 44,
		address="10.13.13.1/24",
	)
	_failing_remove_env(monkeypatch, threadsafe_conn, set_fails=set_fails, runtime_state=runtime_state)
	if not set_fails:

		def _boom(*args, **kwargs):
			raise ConfigWriteError("Failed to write config for wg0")

		monkeypatch.setattr(wp, "sync_interface_config", _boom)
	payload = PeerCreate(name="p", allowed_ips="10.0.0.0/8", allowed_ips_mode="split", interface="wg0")
	with pytest.raises(HTTPException) as exc:
		asyncio.run(wp.create_peer(None, payload, threadsafe_conn, Path("/nonexistent-tsdb"), None))
	assert exc.value.status_code == 500
	assert "secret-internal-stderr" not in str(exc.value.detail)
	clean = runtime_state.startswith("absent")
	if set_fails:
		assert exc.value.detail == "Failed to add peer to WireGuard; see server log"
	elif clean:
		assert exc.value.detail == "Peer created but config sync failed; rolled back"
	else:
		assert exc.value.detail == "Peer creation failed; cleanup incomplete, see server log"
	assert threadsafe_conn.execute("SELECT COUNT(*) FROM peers").fetchone()[0] == (0 if clean else 1)
