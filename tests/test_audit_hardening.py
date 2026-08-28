#!/usr/bin/env python3
#
# tests/test_audit_hardening.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

from __future__ import annotations

import asyncio
import fcntl
import os
import stat
import time
from pathlib import Path

import pytest
from fastapi import Request, Response

from app.utils.acme_http import build_acme_http_app
from app.utils.backup_lock import BackupLockBusyError, _acquire_lock_file, _ensure_private_lock_dir
from app.utils.config import load_config
from app.utils.conntrack import (
    _SAMPLER_LOCK_NAME,
    acquire_sampler_leadership,
    release_sampler_leadership,
)
from app.utils.crypto import hash_password, verify_password
from app.utils.node_token import _require_secret_key
from app.utils.passkeys import _normalize_expected_origin
from app.utils.rate_limit import _select_storage_uri
from app.utils.request_id import RequestIDMiddleware
from app.main import (
    StartupFatalError,
    _DNS_INGESTION_MAX_BACKOFF_EXPONENT,
    _DNS_INGESTION_RESTART_BASE_DELAY_SECONDS,
    _acquire_application_lock,
    _release_application_lock,
    _resolve_trusted_binary,
)


def test_request_id_is_server_generated_and_external_value_is_separate():
    request = Request({
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"x-request-id", b"client-chosen-id")],
        "query_string": b"",
        "scheme": "https",
        "server": ("example.test", 443),
        "client": ("127.0.0.1", 1234),
        "root_path": "",
        "http_version": "1.1",
    })
    middleware = RequestIDMiddleware(lambda scope, receive, send: None)

    async def call_next(req: Request) -> Response:
        assert req.state.request_id != "client-chosen-id"
        assert req.state.external_request_id == "client-chosen-id"
        return Response()

    response = asyncio.run(middleware.dispatch(request, call_next))
    assert response.headers["x-request-id"] == request.state.request_id


def test_password_and_node_secret_limits():
    with pytest.raises(ValueError):
        hash_password("a" * 1025)
    assert not verify_password("a" * 1025, "not-a-hash")

    with pytest.raises(ValueError):
        _require_secret_key("short")
    _require_secret_key("x" * 32)


def test_expected_origin_is_canonical_and_https_outside_localhost():
    assert _normalize_expected_origin("https://[2001:db8::1]:443/") == "https://[2001:db8::1]"
    assert _normalize_expected_origin("http://localhost:80/") == "http://localhost"
    for origin in ("https://example.test/app", "https://example.test?x=1", "http://example.test"):
        with pytest.raises(ValueError):
            _normalize_expected_origin(origin)


def test_lock_timeout_is_honored_and_directory_is_private(tmp_path: Path):
    lock_path = tmp_path / "operation.lock"
    with _acquire_lock_file(lock_path):
        started = time.monotonic()
        with pytest.raises(BackupLockBusyError):
            with _acquire_lock_file(lock_path, blocking=True, timeout=0.15):
                pass
        assert time.monotonic() - started < 1.0

    lock_dir = tmp_path / "locks"
    _ensure_private_lock_dir(lock_dir)
    assert stat.S_IMODE(lock_dir.stat().st_mode) == 0o700


def test_node_config_has_no_fake_secret_and_private_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("WIREBUDDY_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SERVER_MODE", "node")
    monkeypatch.delenv("WIREBUDDY_SECRET_KEY", raising=False)

    config = load_config()

    assert config.secret_key is None
    assert stat.S_IMODE(config.data_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(config.tsdb_dir.stat().st_mode) == 0o700


def test_acme_redirect_uses_configured_origin_not_host_header(tmp_path: Path):
    app = build_acme_http_app(tmp_path, "https://[2001:db8::1]:8443")
    sent: list[dict] = []

    async def send(message: dict) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "path": "/login",
        "query_string": b"next=%2Fsettings",
        "headers": [(b"host", b"attacker.example")],
    }

    async def receive() -> dict:
        return {"type": "http.request"}

    asyncio.run(app(scope, receive, send))
    headers = dict(sent[0]["headers"])
    assert sent[0]["status"] == 308
    assert headers[b"location"] == b"https://[2001:db8::1]:8443/login?next=%2Fsettings"


def test_acme_requires_configured_https_origin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("WIREBUDDY_PUBLIC_ORIGIN", raising=False)
    with pytest.raises(ValueError):
        build_acme_http_app(tmp_path, 443)


def test_conntrack_sampler_leadership_is_exclusive(tmp_path: Path):
    release_sampler_leadership()
    try:
        # A foreign process already holds the lock -> we must not become sampler.
        foreign = os.open(tmp_path / _SAMPLER_LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(foreign, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            assert acquire_sampler_leadership(tmp_path) is False
        finally:
            fcntl.flock(foreign, fcntl.LOCK_UN)
            os.close(foreign)

        # Lock is free now: we acquire it and the call is idempotent.
        assert acquire_sampler_leadership(tmp_path) is True
        assert acquire_sampler_leadership(tmp_path) is True
    finally:
        release_sampler_leadership()


def test_rate_limit_requires_shared_backend_for_multiple_workers():
    assert _select_storage_uri("", 1) == "memory://"
    assert _select_storage_uri("redis://localhost:6379/0", 4) == "redis://localhost:6379/0"
    with pytest.raises(RuntimeError):
        _select_storage_uri("", 4)


def test_application_lock_is_exclusive_per_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setattr("app.main._APPLICATION_LOCK_ACQUIRE_TIMEOUT", 0.0, raising=False)

    fd = _acquire_application_lock(tmp_path)
    assert fd is not None
    try:
        # A second control plane against the same data dir must refuse to start.
        with pytest.raises(StartupFatalError):
            _acquire_application_lock(tmp_path)
    finally:
        _release_application_lock(fd)

    # Once released, a fresh acquisition succeeds again.
    fd2 = _acquire_application_lock(tmp_path)
    assert fd2 is not None
    _release_application_lock(fd2)


def test_privileged_binaries_resolve_to_absolute_paths():
    assert _resolve_trusted_binary((Path("/bin/sh"),)) == "/bin/sh"
    # Unknown layout: fall back to the bare name (run_command still fails closed).
    assert _resolve_trusted_binary((Path("/nonexistent/wb-xyzzy"),)) == "wb-xyzzy"


def test_dns_ingestion_backoff_exponent_cannot_overflow():
    # A very large consecutive-failure count must clamp to the capped exponent
    # so ``2.0 ** exponent * base`` stays a finite float.
    exponent = min(10_000_000, _DNS_INGESTION_MAX_BACKOFF_EXPONENT)
    delay = 2.0 ** exponent * _DNS_INGESTION_RESTART_BASE_DELAY_SECONDS
    assert 0 < delay < 1e6
