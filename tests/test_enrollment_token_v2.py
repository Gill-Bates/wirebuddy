#!/usr/bin/env python3
#
# tests/test_enrollment_token_v2.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Enrollment-token protocol: legacy v1 (HMAC) and v2 (Ed25519), migration and key custody."""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
import logging
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api import nodes as nodes_api
from app.api import nodes_sync
from app.db.sqlite_nodes import create_node, enroll_node, get_node
from app.utils import enrollment_keys, enrollment_signing
from app.utils.node_token import (
	generate_enrollment_token,
	generate_enrollment_token_v2,
	token_version,
	verify_enrollment_token,
	verify_enrollment_token_v2,
)

# daemon imports wg_manager, which resolves wg/ip/iptables at import time and raises on a
# host without them (CI runner). The same fake-path import as in test_node_db.py.
if "app.node.wg_manager" not in sys.modules:
	with pytest.MonkeyPatch.context() as _patch:
		_patch.setattr("app.utils.binaries.first_executable", lambda candidates: f"/fake-bin/{Path(next(iter(candidates))).name}")
		importlib.import_module("app.node.wg_manager")
from app.node import daemon

SECRET = "unit-test-master-secret-0123456789abcdef"
OTHER_SECRET = "another-master-secret-0123456789abcdef"
MASTER_URL = "https://master.example.com"
NODE_ID = "node1"


def _v2(key=None):
	key = key or enrollment_signing.generate_private_key()
	token, secret = generate_enrollment_token_v2(MASTER_URL, NODE_ID, "Node One", key)
	return key, token, secret


def _v1(secret_key=SECRET):
	return generate_enrollment_token(MASTER_URL, NODE_ID, "Node One", secret_key)


def _signed_v2(key, **overrides):
	"""Hand-build a signed v2 token so schema and lifetime checks can be exercised."""
	payload = {
		"v": 2,
		"kid": enrollment_signing.key_id(key.public_key()),
		"master_url": MASTER_URL,
		"node_id": NODE_ID,
		"node_name": "Node One",
		"api_secret": "a" * 43,
		"created_at": datetime.now(UTC).isoformat(),
	}
	payload.update(overrides)
	payload = {k: v for k, v in payload.items() if v is not None}
	raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
	return enrollment_signing.encode_token_v2(raw, enrollment_signing.sign(raw, key))


# ── Protocol v1 (regression) ────────────────────────────────────────────────


def test_v1_roundtrip_and_prefix_is_not_v2():
	token, api_secret = _v1()
	assert token_version(token) == 1
	payload = verify_enrollment_token(token, SECRET)
	assert payload["api_secret"] == api_secret
	assert payload["node_id"] == NODE_ID


def test_v1_rejects_wrong_secret_tamper_and_v2_token():
	token, _ = _v1()
	with pytest.raises(ValueError):
		verify_enrollment_token(token, OTHER_SECRET)
	tampered = base64.urlsafe_b64decode(token).replace(b"Node One", b"Node Two")
	with pytest.raises(ValueError):
		verify_enrollment_token(base64.urlsafe_b64encode(tampered).decode(), SECRET)
	_, v2_token, _ = _v2()
	with pytest.raises(ValueError, match="not a legacy"):
		verify_enrollment_token(v2_token, SECRET)


def test_v1_rejects_expired():
	token, _ = _v1()
	with pytest.raises(ValueError, match="expired"):
		verify_enrollment_token(token, SECRET, max_age=timedelta(seconds=-1))


# ── Protocol v2 ─────────────────────────────────────────────────────────────


def test_v2_roundtrip_normalizes_like_v1():
	key, token, api_secret = _v2()
	assert token_version(token) == 2
	assert token.startswith("wb2.")
	payload = verify_enrollment_token_v2(token, key.public_key())
	assert payload["api_secret"] == api_secret
	assert payload["master_url"] == MASTER_URL
	assert payload["node_id"] == NODE_ID


def test_v2_rejects_wrong_key_and_foreign_kid():
	_, token, _ = _v2()
	other = enrollment_signing.generate_private_key()
	with pytest.raises(ValueError):
		verify_enrollment_token_v2(token, other.public_key())
	# Valid signature of the other key, but the token claims the first key's id.
	key = enrollment_signing.generate_private_key()
	forged = _signed_v2(other, kid=enrollment_signing.key_id(key.public_key()))
	with pytest.raises(ValueError, match="different master key"):
		verify_enrollment_token_v2(forged, other.public_key())


def test_v2_rejects_tampered_payload_signature_and_truncation():
	key, token, _ = _v2()
	head, payload_b64, sig_b64 = token.split(".")
	raw = bytearray(enrollment_signing.b64u_decode(payload_b64))
	raw[-3] ^= 0x01
	bad_payload = ".".join([head, enrollment_signing.b64u_encode(bytes(raw)), sig_b64])
	sig = bytearray(enrollment_signing.b64u_decode(sig_b64))
	sig[0] ^= 0x01
	bad_sig = ".".join([head, payload_b64, enrollment_signing.b64u_encode(bytes(sig))])
	for bad in (bad_payload, bad_sig, token[:-6], token + "A", "wb2.", "wb2.a.b.c", "wb2.!!!.???"):
		with pytest.raises(ValueError):
			verify_enrollment_token_v2(bad, key.public_key())


def test_v2_rejects_schema_violations():
	key = enrollment_signing.generate_private_key()
	pub = key.public_key()
	for overrides in ({"v": 1}, {"v": True}, {"v": "2"}, {"extra": "x"}, {"api_secret": None}, {"kid": None}):
		with pytest.raises(ValueError):
			verify_enrollment_token_v2(_signed_v2(key, **overrides), pub)


def test_v2_rejects_expired_and_future():
	key = enrollment_signing.generate_private_key()
	old = (datetime.now(UTC) - timedelta(hours=25)).isoformat()
	future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
	with pytest.raises(ValueError, match="expired"):
		verify_enrollment_token_v2(_signed_v2(key, created_at=old), key.public_key())
	with pytest.raises(ValueError, match="future"):
		verify_enrollment_token_v2(_signed_v2(key, created_at=future), key.public_key())


def test_signature_is_bound_to_signing_context():
	key = enrollment_signing.generate_private_key()
	token = _signed_v2(key)
	payload, _ = enrollment_signing.decode_token_v2(token)
	context_free = key.sign(payload)
	forged = enrollment_signing.encode_token_v2(payload, context_free)
	with pytest.raises(ValueError):
		verify_enrollment_token_v2(forged, key.public_key())


def test_public_key_string_roundtrip_and_bad_values():
	key = enrollment_signing.generate_private_key().public_key()
	text = enrollment_signing.encode_public_key(key)
	assert text.startswith("wbpk2:")
	assert enrollment_signing.key_id(enrollment_signing.parse_public_key(text)) == enrollment_signing.key_id(key)
	for bad in ("", "wbpk2:", "wbpk2:AAAA", "wbpk2:" + "A" * 200, "wbpk1:" + text[6:], SECRET):
		with pytest.raises(ValueError):
			enrollment_signing.parse_public_key(bad)


# ── Cross-version / downgrade ───────────────────────────────────────────────


def test_v2_string_never_reaches_lenient_v1_decoder():
	key, token, _ = _v2()
	with pytest.raises(ValueError):
		verify_enrollment_token(token, SECRET)
	v1_token, _ = _v1()
	with pytest.raises(ValueError):
		verify_enrollment_token_v2(v1_token, key.public_key())


def test_node_pinned_to_public_key_rejects_v1_and_unverified_fallback(monkeypatch):
	key, v2_token, _ = _v2()
	pub = enrollment_signing.encode_public_key(key.public_key())
	assert daemon._parse_enrollment_token(v2_token, pub)["node_id"] == NODE_ID
	v1_token, _ = _v1()
	monkeypatch.setenv("WIREBUDDY_ALLOW_UNVERIFIED_ENROLLMENT_TOKEN", "1")
	with pytest.raises(ValueError, match="pinned"):
		daemon._parse_enrollment_token(v1_token, pub)
	# A pinned key that does not match must not fall back to the unverified override.
	other = enrollment_signing.encode_public_key(enrollment_signing.generate_private_key().public_key())
	with pytest.raises(ValueError):
		daemon._parse_enrollment_token(v2_token, other)


def test_node_with_legacy_secret_rejects_v2_and_honours_allow_v1(monkeypatch):
	_, v2_token, _ = _v2()
	with pytest.raises(ValueError, match="wbpk2"):
		daemon._parse_enrollment_token(v2_token, SECRET)
	v1_token, _ = _v1()
	assert daemon._parse_enrollment_token(v1_token, SECRET)["node_id"] == NODE_ID
	monkeypatch.setenv("WIREBUDDY_ENROLLMENT_ALLOW_V1", "0")
	with pytest.raises(ValueError, match="disabled"):
		daemon._parse_enrollment_token(v1_token, SECRET)
	with pytest.raises(ValueError, match="required"):
		daemon._parse_enrollment_token(v1_token, None)


def test_node_dev_override_decodes_both_versions_only_without_key(monkeypatch):
	monkeypatch.setenv("WIREBUDDY_ALLOW_UNVERIFIED_ENROLLMENT_TOKEN", "1")
	_, v2_token, _ = _v2()
	v1_token, _ = _v1()
	assert daemon._parse_enrollment_token(v2_token, None)["node_id"] == NODE_ID
	assert daemon._parse_enrollment_token(v1_token, None)["node_id"] == NODE_ID


# ── Master key custody ──────────────────────────────────────────────────────


def test_signing_key_created_once_and_stored_encrypted(conn):
	first = enrollment_keys.get_signing_key(conn, SECRET)
	second = enrollment_keys.get_signing_key(conn, SECRET)
	assert enrollment_signing.private_key_seed(first) == enrollment_signing.private_key_seed(second)
	stored = conn.execute("SELECT value FROM settings WHERE key = ?", (enrollment_keys.SIGNING_KEY_SETTING,)).fetchone()[0]
	seed_b64 = enrollment_signing.b64u_encode(enrollment_signing.private_key_seed(first))
	assert seed_b64 not in stored
	dump = "".join(str(tuple(row)) for row in conn.execute("SELECT key, value FROM settings"))
	assert seed_b64 not in dump


def test_unreadable_key_fails_closed_without_regenerating(conn):
	enrollment_keys.get_signing_key(conn, SECRET)
	before = conn.execute("SELECT value FROM settings WHERE key = ?", (enrollment_keys.SIGNING_KEY_SETTING,)).fetchone()[0]
	with pytest.raises(enrollment_keys.EnrollmentKeyError):
		enrollment_keys.get_signing_key(conn, OTHER_SECRET)
	after = conn.execute("SELECT value FROM settings WHERE key = ?", (enrollment_keys.SIGNING_KEY_SETTING,)).fetchone()[0]
	assert before == after


def test_rotation_invalidates_pending_tokens_and_keeps_nodes(conn):
	create_node(conn, "n1", "N1", "n1.example.com", 51820, "hash")
	enroll_node(conn, "n1", "f" * 64)
	token, _ = enrollment_keys.issue_token(conn, SECRET, version=2, master_url=MASTER_URL, node_id=NODE_ID, node_name="N")
	_, v = enrollment_keys.verify_any(conn, token, SECRET, accept_v1=False)
	assert v == 2
	old_info = enrollment_keys.get_public_key_info(conn, SECRET)
	enrollment_keys.rotate_signing_key(conn, SECRET)
	assert enrollment_keys.get_public_key_info(conn, SECRET)["kid"] != old_info["kid"]
	with pytest.raises(ValueError):
		enrollment_keys.verify_any(conn, token, SECRET, accept_v1=False)
	assert get_node(conn, "n1")["status"] == "online"


def test_verify_any_policy_for_v1(conn, caplog):
	v1_token, _ = _v1()
	payload, version = enrollment_keys.verify_any(conn, v1_token, SECRET, accept_v1=True)
	assert (version, payload["node_id"]) == (1, NODE_ID)
	with pytest.raises(ValueError, match="no longer accepted"):
		enrollment_keys.verify_any(conn, v1_token, SECRET, accept_v1=False)
	v2_token, _ = enrollment_keys.issue_token(conn, SECRET, version=2, master_url=MASTER_URL, node_id=NODE_ID, node_name="N")
	assert enrollment_keys.verify_any(conn, v2_token, SECRET, accept_v1=False)[1] == 2
	with caplog.at_level(logging.WARNING):
		enrollment_keys.record_v1_use(conn, NODE_ID)
	assert "deprecated v1" in caplog.text
	assert v1_token not in caplog.text
	assert conn.execute("SELECT 1 FROM settings WHERE key = ?", (enrollment_keys.V1_LAST_USED_SETTING,)).fetchone()


def test_issue_token_version_switch(conn):
	t1, _ = enrollment_keys.issue_token(conn, SECRET, version=1, master_url=MASTER_URL, node_id=NODE_ID, node_name="N")
	t2, _ = enrollment_keys.issue_token(conn, SECRET, version=2, master_url=MASTER_URL, node_id=NODE_ID, node_name="N")
	assert (token_version(t1), token_version(t2)) == (1, 2)
	with pytest.raises(ValueError):
		enrollment_keys.issue_token(conn, SECRET, version=3, master_url=MASTER_URL, node_id=NODE_ID, node_name="N")


# ── API ─────────────────────────────────────────────────────────────────────


def _cfg(**kw):
	base = {"secret_key": SECRET, "enrollment_accept_v1": True, "enrollment_token_version": 2}
	return SimpleNamespace(**(base | kw))


def test_enroll_endpoint_rejects_v1_when_not_accepted(threadsafe_conn, monkeypatch):
	monkeypatch.setattr(nodes_sync, "get_config", lambda: _cfg(enrollment_accept_v1=False))
	v1_token, _ = _v1()
	body = SimpleNamespace(enrollment_token=v1_token, cert_pem="")
	with pytest.raises(HTTPException) as exc:
		asyncio.run(nodes_sync.enroll_node_endpoint(None, body, threadsafe_conn))
	assert exc.value.status_code == 401
	assert "no longer accepted" in exc.value.detail


def test_enroll_endpoint_fails_closed_on_unreadable_key(threadsafe_conn, monkeypatch):
	enrollment_keys.get_signing_key(threadsafe_conn, SECRET)
	monkeypatch.setattr(nodes_sync, "get_config", lambda: _cfg(secret_key=OTHER_SECRET))
	v2_token, _ = _v2()[1:]
	body = SimpleNamespace(enrollment_token=v2_token, cert_pem="")
	with pytest.raises(HTTPException) as exc:
		asyncio.run(nodes_sync.enroll_node_endpoint(None, body, threadsafe_conn))
	assert exc.value.status_code == 500
	assert "unreadable" not in exc.value.detail


def test_create_node_returns_verify_key_never_the_seed(conn, monkeypatch):
	monkeypatch.setattr(nodes_api, "get_config", _cfg)
	monkeypatch.setattr(nodes_api, "_get_master_url", lambda _c: MASTER_URL)
	body = SimpleNamespace(name="N1", fqdn="n1.example.com", wg_port=51820)
	user = {"id": 1, "username": "admin"}
	result = nodes_api.create_node_endpoint(body, conn=conn, user=user)
	data = result["data"] if isinstance(result, dict) else result.data
	assert token_version(data["enrollment_token"]) == 2
	assert data["enrollment_verify_key"].startswith("wbpk2:")
	verify_enrollment_token_v2(data["enrollment_token"], enrollment_signing.parse_public_key(data["enrollment_verify_key"]))
	seed = enrollment_signing.b64u_encode(enrollment_signing.private_key_seed(enrollment_keys.get_signing_key(conn, SECRET)))
	assert seed not in json.dumps(data)


def test_create_node_in_legacy_mode_issues_v1_without_key(conn, monkeypatch):
	monkeypatch.setattr(nodes_api, "get_config", lambda: _cfg(enrollment_token_version=1))
	monkeypatch.setattr(nodes_api, "_get_master_url", lambda _c: MASTER_URL)
	body = SimpleNamespace(name="N1", fqdn="n1.example.com", wg_port=51820)
	result = nodes_api.create_node_endpoint(body, conn=conn, user={"id": 1, "username": "admin"})
	data = result["data"] if isinstance(result, dict) else result.data
	assert token_version(data["enrollment_token"]) == 1
	assert data["enrollment_verify_key"] is None


def test_key_endpoints_are_admin_only():
	for route in nodes_api.router.routes:
		if route.path in ("/enrollment-key", "/enrollment-key/rotate"):
			flat = [d.call for d in route.dependant.dependencies]
			assert nodes_api.require_admin in flat


def test_enrollment_key_routes_precede_node_id_route():
	paths = [r.path for r in nodes_api.router.routes if "GET" in getattr(r, "methods", ())]
	assert paths.index("/enrollment-key") < paths.index("/{node_id}")


def test_verify_any_never_creates_the_signing_key(conn):
	"""An anonymous verify (POST /enroll) must not write: a missing key rejects like an invalid token."""
	token, _ = enrollment_keys.issue_token(conn, SECRET, version=2, master_url=MASTER_URL, node_id=NODE_ID, node_name="N")
	conn.execute("DELETE FROM settings WHERE key IN (?, ?)", (enrollment_keys.SIGNING_KEY_SETTING, enrollment_keys.SIGNING_KID_SETTING))
	with pytest.raises(ValueError):
		enrollment_keys.verify_any(conn, token, SECRET, accept_v1=False)
	assert conn.execute("SELECT COUNT(*) FROM settings WHERE key = ?", (enrollment_keys.SIGNING_KEY_SETTING,)).fetchone()[0] == 0
