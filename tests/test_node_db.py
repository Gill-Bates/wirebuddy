#!/usr/bin/env python3
#
# tests/test_node_db.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Unit tests for node/auth DB-helper boundaries.

Locks the security/reliability behaviors hardened after review: heartbeat must
not enliven pending nodes, command payloads must be finite JSON, the command
claim limit is clamped and returns the fresh delivered_at, and the stale-node /
token-refresh helpers reject non-positive durations.
"""

from __future__ import annotations

import importlib
import sqlite3
import sys
from pathlib import Path

import pytest

from app.db import sqlite_runtime as rt
from app.db.sqlite_auth import refresh_auth_token
from app.db.sqlite_nodes import (
	_MAX_COMMAND_CLAIM_LIMIT,
	STATUS_ERROR,
	STATUS_OFFLINE,
	STATUS_ONLINE,
	STATUS_PENDING,
	VALID_NODE_COMMANDS,
	_serialize_command_payload,
	ack_node_command,
	claim_pending_node_commands,
	create_node,
	enqueue_node_command,
	enroll_node,
	mark_stale_nodes_offline,
	set_node_tunnel_peer,
	update_node_api_secret,
	update_node_heartbeat,
)
from app.db.sqlite_schema import init_schema
from app.utils.time import utcnow

_A_COMMAND = next(iter(VALID_NODE_COMMANDS))


def _status(conn: sqlite3.Connection, node_id: str) -> str:
	return conn.execute("SELECT status FROM nodes WHERE id = ?", (node_id,)).fetchone()["status"]


# ─── _serialize_command_payload (Finding 3) ──────────────────────────────────


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_serialize_command_payload_rejects_non_finite(bad):
	with pytest.raises(ValueError):
		_serialize_command_payload({"value": bad})


def test_serialize_command_payload_accepts_finite_and_sorts_keys():
	assert _serialize_command_payload({"b": 1, "a": 2}) == '{"a":2,"b":1}'
	assert _serialize_command_payload(None) == "{}"


# ─── update_node_heartbeat status transitions (Finding 2) ─────────────────────


def test_heartbeat_does_not_enliven_pending(conn):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	assert _status(conn, "n1") == STATUS_PENDING

	assert update_node_heartbeat(conn, "n1") is True
	# Enrollment, not heartbeat, owns the pending -> online transition.
	assert _status(conn, "n1") == STATUS_PENDING


def test_heartbeat_re_enlivens_offline(conn):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	enroll_node(conn, "n1", "f" * 64)
	conn.execute("UPDATE nodes SET status = ? WHERE id = ?", (STATUS_OFFLINE, "n1"))

	update_node_heartbeat(conn, "n1")
	assert _status(conn, "n1") == STATUS_ONLINE


def test_heartbeat_leaves_error_untouched(conn):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	conn.execute("UPDATE nodes SET status = ? WHERE id = ?", (STATUS_ERROR, "n1"))

	update_node_heartbeat(conn, "n1")
	assert _status(conn, "n1") == STATUS_ERROR


def test_enroll_then_heartbeat_keeps_online(conn):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	assert enroll_node(conn, "n1", "a" * 64) is True
	assert _status(conn, "n1") == STATUS_ONLINE

	update_node_heartbeat(conn, "n1")
	assert _status(conn, "n1") == STATUS_ONLINE


# ─── claim_pending_node_commands (Findings 4 & 10) ────────────────────────────


def test_claim_clamps_limit_and_returns_fresh_delivered_at(conn):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	for _ in range(_MAX_COMMAND_CLAIM_LIMIT + 25):
		enqueue_node_command(conn, "n1", _A_COMMAND)

	claimed = claim_pending_node_commands(conn, "n1", limit=10_000)

	assert len(claimed) == _MAX_COMMAND_CLAIM_LIMIT
	# Returned delivered_at must reflect the in-transaction update, not the
	# stale pre-update NULL.
	assert all(cmd["delivered_at"] is not None for cmd in claimed)


@pytest.mark.parametrize("bad_limit", [0, -1, -100])
def test_claim_non_positive_limit_returns_empty(conn, bad_limit):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	enqueue_node_command(conn, "n1", _A_COMMAND)
	assert claim_pending_node_commands(conn, "n1", limit=bad_limit) == []


def test_claim_is_exclusive_across_concurrent_connections(tmp_path):
	"""Two workers racing to claim must never be handed the same command.

	`:memory:` databases are private per connection, so this needs a real file
	on disk to exercise the BEGIN IMMEDIATE exclusion `claim_pending_node_commands`
	relies on for its claim guarantee.
	"""
	db_path = tmp_path / "nodes.db"

	def _open() -> sqlite3.Connection:
		rt._ensure_sqlite_adapters()
		connection = sqlite3.connect(str(db_path), detect_types=sqlite3.PARSE_DECLTYPES)
		connection.row_factory = sqlite3.Row
		connection.execute("PRAGMA journal_mode=WAL")
		return connection

	conn_a = _open()
	init_schema(conn_a)
	create_node(conn_a, "n1", "N1", "example.com", 51820, "hash")
	for _ in range(10):
		enqueue_node_command(conn_a, "n1", _A_COMMAND)

	conn_b = _open()
	try:
		claimed_a = claim_pending_node_commands(conn_a, "n1", limit=10)
		# conn_a's BEGIN IMMEDIATE transaction has already committed by the time
		# claim_pending_node_commands() returns, so this must not block forever.
		claimed_b = claim_pending_node_commands(conn_b, "n1", limit=10)

		ids_a = {cmd["id"] for cmd in claimed_a}
		ids_b = {cmd["id"] for cmd in claimed_b}
		assert ids_a, "first claim should have found the freshly enqueued commands"
		assert ids_a.isdisjoint(ids_b), "the same command must not be claimed twice"
	finally:
		conn_a.close()
		conn_b.close()


# ─── input validation (Findings 6 & 9) ───────────────────────────────────────


@pytest.mark.parametrize("bad", [0, -1, -90])
def test_mark_stale_nodes_offline_rejects_non_positive(conn, bad):
	with pytest.raises(ValueError):
		mark_stale_nodes_offline(conn, stale_seconds=bad)


@pytest.mark.parametrize("bad", [0, -1])
def test_refresh_auth_token_rejects_non_positive_hours(conn, bad):
	with pytest.raises(ValueError):
		refresh_auth_token(conn, "some-token", hours=bad)


# ─── update_node_api_secret re-enrollment boundary (P2.2) ─────────────────────


def _make_tunnel_peer(conn: sqlite3.Connection, node_id: str) -> int:
	"""Create an enabled peer and bind it as the node's tunnel peer."""
	now = utcnow()
	cur = conn.execute(
		"""
		INSERT INTO peers (public_key, allowed_ips, is_enabled, created_at, updated_at)
		VALUES (?, ?, 1, ?, ?)
		""",
		(f"pk-{node_id}", "10.0.0.2/32", now, now),
	)
	peer_id = cur.lastrowid
	assert set_node_tunnel_peer(conn, node_id, peer_id) is True
	return peer_id


def _peer_enabled(conn: sqlite3.Connection, peer_id: int) -> int:
	return conn.execute("SELECT is_enabled FROM peers WHERE id = ?", (peer_id,)).fetchone()["is_enabled"]


def test_token_regen_disables_tunnel_peer(conn):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	enroll_node(conn, "n1", "f" * 64)
	peer_id = _make_tunnel_peer(conn, "n1")
	assert _peer_enabled(conn, peer_id) == 1

	assert update_node_api_secret(conn, "n1", "new-hash") is True

	# Boundary: old WireGuard key is disabled in the DB; node is pending again.
	assert _peer_enabled(conn, peer_id) == 0
	assert _status(conn, "n1") == STATUS_PENDING


def test_token_regen_purges_unacked_commands_but_keeps_acked(conn):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	# One command that will be delivered + acked, one left unacked.
	enqueue_node_command(conn, "n1", _A_COMMAND)
	enqueue_node_command(conn, "n1", _A_COMMAND)
	claimed = claim_pending_node_commands(conn, "n1", limit=1)
	assert len(claimed) == 1
	assert ack_node_command(conn, "n1", claimed[0]["id"]) is True

	update_node_api_secret(conn, "n1", "new-hash")

	rows = conn.execute("SELECT id, acked_at FROM node_commands WHERE node_id = ?", ("n1",)).fetchall()
	# Unacked command is purged; the acked one survives (audit trail).
	assert len(rows) == 1
	assert rows[0]["acked_at"] is not None


def test_enroll_re_enables_tunnel_peer_after_regen(conn):
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	enroll_node(conn, "n1", "f" * 64)
	peer_id = _make_tunnel_peer(conn, "n1")

	update_node_api_secret(conn, "n1", "new-hash")
	assert _peer_enabled(conn, peer_id) == 0

	# Successful re-enrollment re-enables the reused tunnel peer.
	assert enroll_node(conn, "n1", "a" * 64) is True
	assert _peer_enabled(conn, peer_id) == 1


# ─── SSE session validity across token regeneration ───────────────────────────


def test_node_session_is_current_ends_after_token_regeneration(conn):
	from app.api.nodes_sync import node_session_is_current

	create_node(conn, "n1", "N1", "example.com", 51820, "hash-old")
	enroll_node(conn, "n1", "a" * 64)
	assert node_session_is_current(conn, "n1", "hash-old") is True

	# Regeneration swaps the secret and resets the node to pending: the SSE
	# stream that authenticated with the old secret must be told to close.
	assert update_node_api_secret(conn, "n1", "hash-new") is True
	assert node_session_is_current(conn, "n1", "hash-old") is False
	assert node_session_is_current(conn, "n1", "hash-new") is False  # still pending
	enroll_node(conn, "n1", "b" * 64)
	assert node_session_is_current(conn, "n1", "hash-new") is True
	assert node_session_is_current(conn, "n1", "hash-old") is False


def test_node_session_is_current_false_for_deleted_node(conn):
	from app.api.nodes_sync import node_session_is_current

	assert node_session_is_current(conn, "missing", "x") is False


# ─── schema upgrade / token refresh contracts (DB-layer review) ───────────────


def test_init_schema_upgrades_peers_table_without_node_id():
	"""A pre-node database must reach the migration instead of failing on the node_id index."""
	rt._ensure_sqlite_adapters()
	old = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
	old.row_factory = sqlite3.Row
	try:
		old.execute(
			"""
			CREATE TABLE peers (
				id INTEGER PRIMARY KEY AUTOINCREMENT, public_key TEXT NOT NULL UNIQUE, allowed_ips TEXT NOT NULL,
				interface TEXT NOT NULL DEFAULT 'wg0', peer_address TEXT, created_at timestamp NOT NULL, updated_at timestamp NOT NULL
			)
			"""
		)
		old.execute("INSERT INTO peers (public_key, allowed_ips, created_at, updated_at) VALUES ('pk-old', '10.0.0.2/32', ?, ?)", (utcnow(), utcnow()))
		old.commit()
		init_schema(old)
		assert "node_id" in {r["name"] for r in old.execute("PRAGMA table_info(peers)")}
		assert old.execute("SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'idx_peers_node_id'").fetchone() is not None
		assert old.execute("SELECT public_key FROM peers").fetchall()[0]["public_key"] == "pk-old"
	finally:
		old.close()


def test_refresh_auth_token_never_shortens_a_session(conn):
	from datetime import timedelta

	from app.db.sqlite_auth import create_auth_token, get_user_by_token
	from app.db.sqlite_users import create_user

	user_id = create_user(conn, "refresh-user", "hash")
	now = utcnow()
	create_auth_token(conn, user_id, "long", now + timedelta(hours=4), now + timedelta(hours=24))
	create_auth_token(conn, user_id, "short", now + timedelta(minutes=10), now + timedelta(minutes=30))

	def _expiry(token: str):
		from app.utils.crypto import hash_token

		return conn.execute("SELECT expires_at FROM auth_tokens WHERE token_hash = ?", (hash_token(token),)).fetchone()["expires_at"]

	before = _expiry("long")
	assert refresh_auth_token(conn, "long", hours=1) is True
	assert _expiry("long") == before  # 4 h left stays 4 h, not ~1 h
	assert get_user_by_token(conn, "long") is not None

	assert refresh_auth_token(conn, "short", hours=1) is True
	assert _expiry("short") <= now + timedelta(minutes=30, seconds=1)  # still capped by max_expires_at
	assert _expiry("short") > now + timedelta(minutes=10)


def test_redact_keys_shortens_keys_embedded_in_messages():
	_redact_keys = _import_wg_manager()._redact_keys

	key = "A" * 43 + "="
	out = _redact_keys(f"wg set wg0 peer {key} allowed-ips 10.0.0.2/32 failed")
	assert key not in out and "AAAAAAAA..." in out and out.endswith("failed")


def test_init_queue_closes_connection_when_initialisation_fails(tmp_path, monkeypatch):
	from app.node import metrics_queue

	opened: list[sqlite3.Connection] = []
	real_connect = sqlite3.connect

	def tracking_connect(*args, **kwargs):
		conn = real_connect(*args, **kwargs)
		opened.append(conn)
		return conn

	monkeypatch.setattr(metrics_queue.sqlite3, "connect", tracking_connect)
	monkeypatch.setattr(metrics_queue, "_init_schema", lambda _c: (_ for _ in ()).throw(sqlite3.OperationalError("boom")))
	with pytest.raises(sqlite3.OperationalError):
		metrics_queue.init_queue(tmp_path)
	with pytest.raises(sqlite3.ProgrammingError):
		opened[0].execute("SELECT 1")  # closed


def test_connect_refuses_group_writable_data_dir_when_chmod_fails(tmp_path, monkeypatch):
	data = tmp_path / "data"
	data.mkdir()
	data.chmod(0o770)
	real_chmod = type(data).chmod

	def chmod_denied(self, mode, *args, **kwargs):
		if self == data:
			raise PermissionError("denied")
		return real_chmod(self, mode, *args, **kwargs)

	monkeypatch.setattr(type(data), "chmod", chmod_denied)
	with pytest.raises(RuntimeError, match="group/other writable"):
		rt.connect(data / "wirebuddy.db")


def test_connect_tolerates_unchangeable_but_not_writable_data_dir(tmp_path, monkeypatch):
	data = tmp_path / "data"
	data.mkdir()
	data.chmod(0o750)
	real_chmod = type(data).chmod

	def chmod_denied(self, mode, *args, **kwargs):
		if self == data:
			raise PermissionError("denied")
		return real_chmod(self, mode, *args, **kwargs)

	monkeypatch.setattr(type(data), "chmod", chmod_denied)
	conn = rt.connect(data / "wirebuddy.db")
	rt.close_connection(conn)


def test_connect_tightens_group_writable_data_dir(tmp_path):
	data = tmp_path / "data"
	data.mkdir()
	data.chmod(0o777)
	rt.close_connection(rt.connect(data / "wirebuddy.db"))
	assert (data.stat().st_mode & 0o777) == 0o700


# --- wg_manager: all-or-nothing interface apply (fake wg/wg-quick/ip, no root needed) ---


class _FakeWireGuardHost:
	"""In-memory stand-in for wg, wg-quick and ip, tracking files, peers and routes."""

	def __init__(self, wg, conf_dir, *, fail_up: dict[str, int], show_interfaces_fails: bool = False):
		self.wg = wg
		self.conf_dir = conf_dir
		self.fail_up = fail_up
		self.show_interfaces_fails = show_interfaces_fails
		self.running: set[str] = set()
		self.runtime_conf: dict[str, str] = {}
		self.peers: dict[str, dict[str, tuple[str, str, str]]] = {}
		self.routes: set[tuple[str, str]] = set()
		self.quick_calls: list[tuple[str, str]] = []

	def start(self, name: str, peers: dict[str, str]) -> None:
		self.running.add(name)
		self.runtime_conf[name] = (self.conf_dir / f"{name}.conf").read_text()
		self.peers[name] = {key: (ip, "(none)", "0") for key, ip in peers.items()}
		self.routes |= {(name, ip) for ip in peers.values()}

	def files(self) -> dict[str, str]:
		return {p.name: p.read_text() for p in sorted(self.conf_dir.glob("*.conf"))}

	def state(self):
		return self.files(), {k: dict(v) for k, v in self.peers.items()}, set(self.routes), set(self.running)

	def run(self, cmd, timeout=30):
		binary, args = cmd[0], cmd[1:]
		if binary == self.wg._WG_QUICK_BIN:
			return self._quick(args[0], args[1])
		if binary == self.wg._WG_BIN:
			return self._wg(args)
		if binary == self.wg._IP_BIN:
			return self._ip(args)
		raise AssertionError(f"unexpected command {cmd}")

	def _quick(self, verb, name):
		self.quick_calls.append((verb, name))
		if verb == "up":
			if self.fail_up.get(name, 0) > 0:
				self.fail_up[name] -= 1
				return 1, "", "wg-quick: simulated failure"
			self.running.add(name)
			self.runtime_conf[name] = (self.conf_dir / f"{name}.conf").read_text()
			return 0, "", ""
		self.running.discard(name)
		self.runtime_conf.pop(name, None)
		self.peers.pop(name, None)
		self.routes = {r for r in self.routes if r[0] != name}
		return 0, "", ""

	def _wg(self, args):
		if args[:2] == ["show", "interfaces"]:
			if self.show_interfaces_fails:
				return 1, "", "simulated wg failure"
			return 0, " ".join(sorted(self.running)), ""
		if args[0] == "show" and args[2] == "dump":
			rows = ["priv\tpub\t51820\toff"]
			for key, (ip, endpoint, keepalive) in self.peers.get(args[1], {}).items():
				rows.append("\t".join([key, "(none)", endpoint, ip, "0", "0", "0", keepalive]))
			return 0, "\n".join(rows), ""
		if args[0] == "set":
			iface, key = args[1], args[3]
			if args[4] == "remove":
				self.peers.get(iface, {}).pop(key, None)
			else:
				ip = args[5]
				endpoint = args[args.index("endpoint") + 1] if "endpoint" in args else "(none)"
				keepalive = args[args.index("persistent-keepalive") + 1]
				self.peers.setdefault(iface, {})[key] = (ip, endpoint, keepalive)
			return 0, "", ""
		raise AssertionError(f"unexpected wg command {args}")

	def _ip(self, args):
		verb, target, iface = args[2], args[3], args[5]
		if verb == "replace":
			self.routes.add((iface, target))
		elif verb == "delete":
			self.routes.discard((iface, target))
		return 0, "", ""


def _wg_key(n: int) -> str:
	import base64

	return base64.b64encode(bytes([n]) * 32).decode()


def _wg_iface(wg, name: str, n: int, port: int):
	return wg.InterfaceConfig(name, _wg_key(n), f"10.{n}.0.1/24", None, port)


def _wg_iface_payload(name: str, n: int, port: int) -> dict:
	return {"name": name, "private_key": _wg_key(n), "address": f"10.{n}.0.1/24", "listen_port": port}


def _import_wg_manager():
	"""Import wg_manager on hosts without wireguard-tools (CI runner); it resolves its binaries at import time."""
	if "app.node.wg_manager" not in sys.modules:
		with pytest.MonkeyPatch.context() as patch:
			# One distinct fake path per tool: the fake host dispatches on it.
			patch.setattr("app.utils.binaries.first_executable", lambda candidates: f"/fake-bin/{Path(next(iter(candidates))).name}")
			importlib.import_module("app.node.wg_manager")
	return sys.modules["app.node.wg_manager"]


@pytest.fixture
def wg_host(tmp_path, monkeypatch):
	wg = _import_wg_manager()

	conf_dir = tmp_path / "wireguard"
	monkeypatch.setattr(wg, "WG_CONFIG_DIR", conf_dir)
	monkeypatch.setattr(wg, "_get_default_route_iface", lambda: "eth0")

	def make(**kwargs):
		host = _FakeWireGuardHost(wg, conf_dir, **kwargs)
		monkeypatch.setattr(wg, "_run", host.run)
		return host

	return wg, conf_dir, make


@pytest.mark.parametrize("scenario", ["reload-fails-mid-way", "second-new-interface-fails"])
def test_apply_config_failure_restores_files_peers_and_routes_of_three_interfaces(wg_host, scenario):
	wg, _conf_dir, make = wg_host
	peers = {"wg0": {_wg_key(100): "10.1.0.2/32"}, "wg1": {_wg_key(101): "10.2.0.2/32"}, "wg2": {_wg_key(102): "10.3.0.2/32"}}
	old = {"wg0": (1, 51820), "wg1": (2, 51821), "wg2": (3, 51822)}
	if scenario == "reload-fails-mid-way":
		# wg0 unchanged, wg1 reload fails after wg-quick down, wg2 changed but never reached.
		host = make(fail_up={"wg1": 1})  # only the reload fails, the rollback up works
		new = {"wg0": (1, 51820), "wg1": (2, 51999), "wg2": (3, 51998)}
		seeded = ["wg0", "wg1", "wg2"]
	else:
		# wg0 running and unchanged, wg1 and wg2 are new; starting wg2 fails after wg1 came up.
		host = make(fail_up={"wg2": 99})
		new = old
		seeded = ["wg0"]
	for name in seeded:
		wg._write_interface_config(name, _wg_iface(wg, name, *old[name][:1], old[name][1]), "eth0")
		host.start(name, peers[name])
	payload = {
		"config_version": "v2",
		"interfaces": [_wg_iface_payload(n, new[n][0], new[n][1]) for n in ("wg0", "wg1", "wg2")],
		"peers": [{"interface": n, "public_key": next(iter(peers[n])), "peer_address": next(iter(peers[n].values()))} for n in peers],
	}
	before = host.state()

	with pytest.raises(RuntimeError, match="wg-quick"):
		wg._apply_config_locked(payload)

	assert host.state() == before
	assert ("down", "wg0") not in host.quick_calls and ("up", "wg0") not in host.quick_calls
	for name in host.running:
		assert host.runtime_conf[name] == host.files()[f"{name}.conf"]


def test_apply_config_aborts_untouched_when_running_interfaces_cannot_be_queried(wg_host):
	wg, _conf_dir, make = wg_host
	host = make(fail_up={}, show_interfaces_fails=True)
	wg._write_interface_config("wg0", _wg_iface(wg, "wg0", 1, 51820), "eth0")
	host.start("wg0", {_wg_key(100): "10.1.0.2/32"})
	before = host.state()
	payload = {"config_version": "v2", "interfaces": [_wg_iface_payload("wg0", 1, 51999)], "peers": []}

	with pytest.raises(RuntimeError, match="query running WireGuard interfaces"):
		wg._apply_config_locked(payload)

	assert host.state() == before
	assert host.quick_calls == []


@pytest.mark.parametrize(
	("peers", "master"),
	[
		([("wg0", 100, "10.1.0.2/32"), ("wg0", 101, "10.1.0.2/32")], None),
		([("wg0", 100, "10.1.0.2/32"), ("wg1", 101, "10.1.0.2")], None),
		([("wg0", 100, "10.1.0.2/32")], ("wg1", 102, "10.1.0.2/32")),
		([("wg0", 100, "fd00::2/128, 10.1.0.3/32"), ("wg1", 101, "fd00::2/128")], None),
	],
)
def test_apply_config_rejects_duplicate_peer_host_routes_before_any_change(wg_host, peers, master):
	wg, conf_dir, make = wg_host
	host = make(fail_up={})
	payload = {
		"config_version": "v1",
		"interfaces": [_wg_iface_payload("wg0", 1, 51820), _wg_iface_payload("wg1", 2, 51821)],
		"peers": [{"interface": i, "public_key": _wg_key(n), "peer_address": addr} for i, n, addr in peers],
	}
	if master:
		payload["master_peer"] = {"interface": master[0], "public_key": _wg_key(master[1]), "peer_address": master[2]}
	with pytest.raises(ValueError, match="Duplicate peer host route"):
		wg._apply_config_locked(payload)
	assert host.quick_calls == []
	assert not conf_dir.exists() or not list(conf_dir.iterdir())


def test_apply_config_manages_no_dns_firewall_rules(wg_host, monkeypatch):
	"""Remote-peer DNS reaches the master through the tunnel (forwarded), so a node opens no port 53 and runs no resolver."""
	wg, _conf_dir, make = wg_host
	host = make(fail_up={})
	commands: list[list[str]] = []
	run = host.run

	def recording_run(cmd, timeout=30):
		commands.append(list(cmd))
		return run(cmd, timeout=timeout)

	monkeypatch.setattr(wg, "_run", recording_run)
	key = _wg_key(100)
	payload = {
		"config_version": "v1",
		"interfaces": [_wg_iface_payload("wg0", 1, 51820)],
		"peers": [{"interface": "wg0", "public_key": key, "peer_address": "10.1.0.2/32"}],
	}
	wg._apply_config_locked(payload)
	assert commands, "expected the node to apply the config through wg tooling"
	assert all(Path(cmd[0]).name in {"wg", "wg-quick", "ip"} for cmd in commands)
	assert not any("53" in cmd or "iptables" in Path(cmd[0]).name for cmd in commands)


def test_node_speedtest_passes_no_geoip_country_resolver(monkeypatch):
	"""A node loads no GeoIP data, so the speedtest must not ask for a DNS-based country lookup."""
	import asyncio
	from types import SimpleNamespace

	import gillbates_speedtest

	_import_wg_manager()
	from app.node import daemon

	seen: dict = {}

	class _Lease:
		async def __aenter__(self):
			return self

		async def __aexit__(self, *_exc):
			return False

		def mark_success(self):
			pass

	async def acquire(*_args, **_kwargs):
		return _Lease()

	async def run(**kwargs):
		seen.update(kwargs)
		return {"status": "ok", "download_mbit": 1.0, "upload_mbit": 1.0}

	class _Client:
		async def post(self, *_args, **_kwargs):
			return SimpleNamespace(raise_for_status=lambda: None)

	monkeypatch.setattr(gillbates_speedtest, "acquire_speedtest_run_lease_async", acquire)
	monkeypatch.setattr(gillbates_speedtest, "run_speedtest", run)
	assert asyncio.run(daemon._run_node_speedtest(_Client(), "https://master.example", "secret", "")) is True
	assert "country_resolver" not in seen
