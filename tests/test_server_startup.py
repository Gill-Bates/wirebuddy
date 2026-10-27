#!/usr/bin/env python3
#
# tests/test_server_startup.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Tests for the shared start path in ``app.server``.

Covers the two pieces the Docker health check and the HTTPS listener rely on:
the runtime listener state the probe reads, and the validation that keeps the
optional plaintext ACME listener from colliding with the GUI port.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.server import _record_listener_state, _resolve_acme_http_port


@pytest.mark.parametrize(
	("raw", "gui_port", "expected"),
	[
		("80", 8000, 80),
		(None, 8000, 80),
		("", 8000, 80),
		("0", 8000, 0),
		("8080", 443, 8080),
		("80", 80, 0),
		("65536", 8000, 0),
		("-1", 8000, 0),
		("eighty", 8000, 0),
		("²", 8000, 0),
	],
)
def test_acme_port_is_validated_against_range_and_gui_port(raw, gui_port, expected):
	assert _resolve_acme_http_port(raw, gui_port) == expected


@pytest.mark.parametrize(
	("scheme", "host", "port", "expected"),
	[
		("http", "0.0.0.0", 8000, "SCHEME=http\nHOST=127.0.0.1\nPORT=8000\n"),  # noqa: S104 - wildcard bind under test
		("https", "::", 8443, "SCHEME=https\nHOST=[::1]\nPORT=8443\n"),
		("https", "::1", 8443, "SCHEME=https\nHOST=[::1]\nPORT=8443\n"),
		("http", "192.0.2.10", 80, "SCHEME=http\nHOST=192.0.2.10\nPORT=80\n"),
	],
)
def test_listener_state_records_a_reachable_probe_address(monkeypatch, tmp_path: Path, scheme, host, port, expected):
	state = tmp_path / "run" / "listener.env"
	monkeypatch.setenv("WIREBUDDY_LISTENER_STATE", str(state))

	_record_listener_state(scheme, host, port)

	assert state.read_text(encoding="utf-8") == expected
	assert not state.with_name("listener.env.tmp").exists()


def test_listener_state_is_not_written_outside_docker(monkeypatch, tmp_path: Path):
	monkeypatch.delenv("WIREBUDDY_LISTENER_STATE", raising=False)

	_record_listener_state("https", "0.0.0.0", 8443)  # noqa: S104 - wildcard bind under test

	assert list(tmp_path.iterdir()) == []


def test_acme_challenge_written_to_disk_is_served_by_the_plaintext_listener(tmp_path: Path):
	"""The HTTP-01 path end to end, minus Let's Encrypt.

	Regression: ``_atomic_write_bytes`` called FastAPI's ``Path`` marker instead
	of ``pathlib.Path``, so every ACME write (account key, certificate,
	challenge) raised and certificate issuance could not work.
	"""
	import asyncio

	from app.api.acme import _save_challenge
	from app.utils.acme_http import build_acme_http_app

	token = "abcdefghijklmnopqrstuvwxyz012345"
	_save_challenge(tmp_path, token, f"{token}.keyauth")
	assert (tmp_path / ".challenges.json").stat().st_mode & 0o777 == 0o600

	app = build_acme_http_app(tmp_path, 8443, public_origin="https://wb.example.test:8443")
	sent: list[dict] = []

	async def send(message: dict) -> None:
		sent.append(message)

	asyncio.run(app({"type": "http", "path": f"/.well-known/acme-challenge/{token}"}, None, send))

	assert sent[0]["status"] == 200
	assert sent[1]["body"] == f"{token}.keyauth".encode()


def test_bootstrap_does_not_start_interface_with_failed_regeneration(monkeypatch, tmp_path: Path):
	"""Fail closed: an enabled interface whose config regeneration failed must not be started from a stale file."""
	from types import SimpleNamespace

	from app import main
	from app.api import wireguard_config
	from app.db import sqlite_interfaces
	from app.db.sqlite_runtime import close_connection, connect

	key = "k" * 40
	monkeypatch.setenv("WIREBUDDY_SECRET_KEY", key)
	db_path = tmp_path / "wirebuddy.db"
	conn = connect(db_path)
	main.init_schema(conn)
	for name, port in (("wg0", 51820), ("wg1", 51821)):
		sqlite_interfaces.create_interface(conn, name, "a" * 44, "b" * 44, f"10.{port - 51820 + 10}.0.1/24", listen_port=port)
	close_connection(conn)

	def _fake_regen(config_path, conn, pepper=""):
		return wireguard_config.RegenResult(succeeded=["wg1"], failed={"wg0": "disk full"})

	monkeypatch.setattr(wireguard_config, "regenerate_all_configs", _fake_regen)
	monkeypatch.setattr(main, "_purge_staged_interface_configs", lambda path: None)
	# The bootstrap also probes hard-coded real DB paths (e.g. /opt/wirebuddy/data) for missing settings.
	monkeypatch.setattr(main, "recover_missing_global_settings", lambda *_args, **_kwargs: 0)
	cfg = SimpleNamespace(db_path=db_path, secret_key=key, base_dir=tmp_path)

	interfaces, key_mismatch, _ = main._bootstrap_sync(cfg)

	assert not key_mismatch
	assert interfaces == ["wg1"]
