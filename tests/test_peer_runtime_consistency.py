#!/usr/bin/env python3
#
# tests/test_peer_runtime_consistency.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
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
from app.db.sqlite_interfaces import create_interface
from app.db.sqlite_peers_mutations import create_peer
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
	create_interface(threadsafe_conn, name="wg0", private_key="a" * 44, public_key="b" * 44, address="10.13.13.1/24")
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
	create_interface(threadsafe_conn, name="wg0", private_key="a" * 44, public_key="b" * 44, address="10.13.13.1/24")
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
