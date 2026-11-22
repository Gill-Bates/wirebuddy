#!/usr/bin/env python3
#
# tests/test_utils_hardening.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Regression tests for assorted utility-layer correctness fixes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest

from app.utils import version as version_mod
from app.utils.scheduler import Scheduler
from app.utils.tsdb_helpers import build_latest_by_node
from app.utils.vault import decrypt, encrypt, is_encrypted


@dataclass
class _Point:
	"""Stand-in for a tsdb MetricPoint."""

	ts: datetime
	value: Any


# ─── build_latest_by_node ────────────────────────────────────────────────────


def test_point_timestamp_wins_over_node_reported_ts():
	"""Nodes report their own 'ts' in the value; their clock is not authoritative."""
	recorded = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
	points = [_Point(ts=recorded, value={"node_id": "n1", "ts": "1999-01-01T00:00:00+00:00"})]

	assert build_latest_by_node(points)["n1"]["ts"] == recorded.isoformat()


def test_latest_point_per_node_wins():
	older = datetime(2026, 6, 15, 10, 0, tzinfo=UTC)
	newer = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
	points = [
		_Point(ts=older, value={"node_id": "n1", "download_mbit": 10}),
		_Point(ts=newer, value={"node_id": "n1", "download_mbit": 90}),
	]

	latest = build_latest_by_node(points)
	assert latest["n1"]["download_mbit"] == 90
	assert latest["n1"]["ts"] == newer.isoformat()


def test_master_points_key_on_none_and_junk_is_skipped():
	ts = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
	points = [
		_Point(ts=ts, value={"download_mbit": 50}),
		_Point(ts=ts, value="not-a-dict"),
		_Point(ts=None, value={"node_id": "n2"}),
	]

	latest = build_latest_by_node(points)
	assert set(latest) == {None}
	assert latest[None]["download_mbit"] == 50


# ─── vault payload parsing ───────────────────────────────────────────────────


_PEPPER = "x" * 40


def test_roundtrip_encrypt_decrypt():
	assert decrypt(encrypt("s3cret", _PEPPER), _PEPPER) == "s3cret"


def test_non_ascii_token_is_reported_as_a_corrupt_payload():
	"""Must not surface as a bare UnicodeEncodeError from the .encode() call."""
	payload = f"vault:2:{'ab' * 16}:tökén"
	with pytest.raises(ValueError, match="Corrupt vault payload"):
		decrypt(payload, _PEPPER)
	assert is_encrypted(payload) is False


def test_wrong_pepper_is_rejected():
	stored = encrypt("s3cret", _PEPPER)
	with pytest.raises(ValueError, match="Cannot decrypt secret"):
		decrypt(stored, "y" * 40)


# ─── version comparison and update cache ─────────────────────────────────────


@pytest.mark.parametrize(
	"current,latest,expected",
	[
		("1.6.0", "1.7.0", True),
		("1.6.0", "1.6.0", False),
		("1.7.0", "1.6.0", False),
		("1.2", "1.2.0", False),  # same release, differently written
		("1.2.0", "1.2", False),
		("dev", "9.9.9", False),
		("1.8.0-rc.1", "1.8.0", True),  # the final release supersedes its prerelease
		("1.8.0", "1.8.0-rc.1", False),
		("1.6.0", "", False),  # unparseable release tag is never an update
		("1.6.0", "garbage", False),
	],
)
def test_version_comparison(current, latest, expected):
	assert version_mod._is_newer_version(current, latest) is expected


def test_update_check_cache_is_not_mutable_by_callers(monkeypatch):
	"""A caller editing the returned dict must not poison later cache hits."""
	monkeypatch.setattr(version_mod, "_UPDATE_CHECK_CACHE", None)
	monkeypatch.setattr(version_mod, "_UPDATE_CHECK_TIME", 0.0)
	monkeypatch.setattr(version_mod, "get_version", lambda: "dev")

	first = version_mod.check_for_updates()
	first["latest_version"] = "9.9.9-tampered"

	assert version_mod.check_for_updates()["latest_version"] != "9.9.9-tampered"


# ─── scheduler job validation ────────────────────────────────────────────────


async def _noop() -> None:
	return None


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 0.5, -1.0])
def test_rejects_invalid_interval(bad):
	with pytest.raises(ValueError, match="interval_seconds"):
		Scheduler().add("job", bad, _noop)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1.0])
def test_rejects_invalid_initial_delay(bad):
	with pytest.raises(ValueError, match="initial_delay"):
		Scheduler().add("job", 60.0, _noop, initial_delay=bad)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 0.0, -1.0])
def test_rejects_invalid_timeout(bad):
	with pytest.raises(ValueError, match="timeout"):
		Scheduler().add("job", 60.0, _noop, timeout=bad)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf"), -0.01, 0.51, 1.0])
def test_rejects_invalid_jitter_pct(bad):
	"""An out-of-range jitter_pct must not reach random.uniform(-range, range)."""
	with pytest.raises(ValueError, match="jitter_pct"):
		Scheduler().add("job", 60.0, _noop, jitter_pct=bad)


@pytest.mark.parametrize("ok", [0.0, 0.1, 0.5])
def test_accepts_boundary_jitter_pct(ok):
	scheduler = Scheduler()
	scheduler.add("job", 60.0, _noop, jitter_pct=ok)
	assert scheduler.get_status()[0]["name"] == "job"


def test_accepts_a_valid_job():
	scheduler = Scheduler()
	scheduler.add("job", 60.0, _noop, initial_delay=5.0, timeout=30.0, jitter_pct=0.1)
	assert [s["name"] for s in scheduler.get_status()] == ["job"]


def test_timeout_none_means_no_limit():
	scheduler = Scheduler()
	scheduler.add("job", 60.0, _noop, timeout=None)
	assert scheduler.get_status()[0]["name"] == "job"


def test_domain_lock_release_closes_fd_even_when_unlock_fails(tmp_path, monkeypatch):
	from app.api import acme

	fd = acme._acquire_domain_lock(tmp_path, "vpn.example.com")
	assert fd is not None
	fd_obj, _ = acme._domain_lock_fds[fd]

	def failing_flock(fileno, operation):
		raise OSError("unlock failed")

	monkeypatch.setattr(acme.fcntl, "flock", failing_flock)
	acme._release_domain_lock(fd)

	assert fd_obj.closed
	assert fd not in acme._domain_lock_fds


@pytest.mark.parametrize(
	("key", "valid"),
	[
		("A" * 43 + "=", True),
		("A" * 44, False),  # no padding
		("A" * 42 + "==", False),  # decodes to 31 bytes
		("not a key", False),
		("  " + "A" * 43 + "=  ", True),
	],
)
def test_is_valid_wg_key(key, valid):
	from app.api.wireguard_utils import is_valid_wg_key

	assert is_valid_wg_key(key) is valid


# --- SSRF address classes shared by the node host, DoT upstream and blocklist checks ---

_BLOCKED_ADDRESSES = [
	"127.0.0.1",
	"10.0.0.1",
	"169.254.169.254",
	"::1",
	"fc00::1",  # ULA fc00::/7
	"fd00::1",  # ULA fd00::/8
	"fe80::1",
	"::ffff:127.0.0.1",  # IPv4-mapped loopback
	"::ffff:10.0.0.1",
	"::ffff:169.254.169.254",
	"2002:7f00:1::1",  # 6to4 embedding 127.0.0.1
	"2002:0a00:0001::1",  # 6to4 embedding 10.0.0.1
	"2001:0:4136:e378:8000:63bf:f5ff:fffe",  # Teredo
	"64:ff9b:1::1",  # local-use NAT64
]
_ALLOWED_ADDRESSES = ["8.8.8.8", "::ffff:8.8.8.8", "2606:4700::1111"]


@pytest.mark.parametrize("text", _BLOCKED_ADDRESSES)
def test_ssrf_address_checks_block_internal_classes(text):
	import ipaddress

	from app.api.nodes import _is_private_ip
	from app.utils.network import is_unsafe_outbound_address as _is_ip_unsafe

	addr = ipaddress.ip_address(text)
	assert _is_private_ip(addr)
	assert _is_ip_unsafe(addr)


@pytest.mark.parametrize("text", ["::ffff:224.0.0.1", "ff02::1", "64:ff9b::7f00:1", "0.0.0.0", "::"])  # noqa: S104  (SSRF fixtures, not a bind)
def test_ssrf_address_check_blocks_multicast_and_unspecified(text):
	import ipaddress

	from app.utils.network import is_unsafe_outbound_address as _is_ip_unsafe

	assert _is_ip_unsafe(ipaddress.ip_address(text))


@pytest.mark.parametrize("text", ["100.64.0.1", "100.127.255.254", "::ffff:100.64.0.1", "64:ff9b::6440:1"])
def test_ssrf_guard_blocks_cgnat_but_node_host_check_allows_it(text):
	import ipaddress

	from app.api.nodes import _is_private_ip
	from app.utils.network import is_unsafe_outbound_address as _is_ip_unsafe

	addr = ipaddress.ip_address(text)
	assert _is_ip_unsafe(addr)
	# nodes.py only builds the master URL (Tailscale masters); NAT64 stays blocked there.
	assert _is_private_ip(addr) is text.startswith("64:ff9b")


def test_ssrf_guard_allows_public_neighbours_of_cgnat():
	import ipaddress

	from app.utils.network import is_unsafe_outbound_address as _is_ip_unsafe

	assert not _is_ip_unsafe(ipaddress.ip_address("100.128.0.1"))
	assert not _is_ip_unsafe(ipaddress.ip_address("100.63.255.255"))


@pytest.mark.parametrize("text", _ALLOWED_ADDRESSES)
def test_ssrf_address_checks_allow_public_addresses(text):
	import ipaddress

	from app.api.nodes import _is_private_ip
	from app.utils.network import is_unsafe_outbound_address as _is_ip_unsafe

	addr = ipaddress.ip_address(text)
	assert not _is_private_ip(addr)
	assert not _is_ip_unsafe(addr)


@pytest.mark.parametrize("text", [*_BLOCKED_ADDRESSES, "::ffff:224.0.0.1", "ff02::1", "64:ff9b::7f00:1"])
def test_dot_upstream_rejects_internal_addresses(text):
	from app.api.dns import _test_dot_server

	host = f"[{text}]" if ":" in text else text
	result = _test_dot_server(f"{host}@853#dns.example")
	assert result["error"] == "Private/reserved addresses not allowed"


def test_secret_temp_file_is_private_and_complete(tmp_path):
	import stat
	from pathlib import Path

	from app.api.wireguard_utils import write_secret_temp_file

	path = Path(write_secret_temp_file(tmp_path, b"k" * 100_000, suffix=".tmp"))
	assert path.read_bytes() == b"k" * 100_000
	assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_secret_temp_file_removed_on_write_failure(tmp_path, monkeypatch):
	import os

	from app.api.wireguard_utils import write_secret_temp_file

	def _boom(*_a, **_k):
		raise OSError("disk full")

	monkeypatch.setattr(os, "fchmod", _boom)
	with pytest.raises(OSError):
		write_secret_temp_file(tmp_path, b"secret")
	assert list(tmp_path.iterdir()) == []


def test_psk_temp_file_removed_when_runner_fails(tmp_path, monkeypatch):
	import asyncio
	import tempfile

	from app.api import wireguard_utils

	seen: list[str] = []

	async def _run(*args, **_k):
		seen.append(next(a for a in args if str(a).endswith(".key")))
		raise RuntimeError("wg crashed")

	monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
	monkeypatch.setattr(wireguard_utils, "run_wg_command", _run)
	with pytest.raises(RuntimeError):
		asyncio.run(wireguard_utils.wg_set_peer_with_psk("wg0", "pub", "10.0.0.2/32", "psk"))
	assert seen
	assert list(tmp_path.iterdir()) == []


def test_banner_text_links_to_the_release_repository(monkeypatch):
	from app.utils import banner, version

	captured: list[tuple[str, list[str]]] = []
	monkeypatch.setattr(banner, "print_banner_drawing", lambda art, title, lines: captured.append((title, list(lines))))
	banner.print_banner()
	assert captured[0][1] == [f"(C) 2026 by Gill-Bates (https://github.com/{version.GITHUB_REPO})"]


def test_next_delay_replaces_the_fixed_interval_and_keeps_failure_backoff(monkeypatch):
	"""A calendar rule decides the next run (no 24 h drift); a failure still waits for its backoff."""
	import asyncio

	from app.utils import scheduler as scheduler_mod

	monkeypatch.setattr(scheduler_mod, "_MIN_INTERVAL", 0.01)
	runs = {"ok": 0, "bad": 0}

	async def ok_job() -> None:
		runs["ok"] += 1

	async def bad_job() -> None:
		runs["bad"] += 1
		raise RuntimeError("boom")

	async def scenario() -> None:
		scheduler = Scheduler()
		scheduler.add("ok", 3600.0, ok_job, run_on_start=True, next_delay=lambda: 0.02)
		scheduler.add("bad", 3600.0, bad_job, run_on_start=True, next_delay=lambda: 0.02)
		await scheduler.start()
		await asyncio.sleep(0.4)
		await scheduler.stop_graceful()

	asyncio.run(scenario())

	assert runs["ok"] >= 3
	assert runs["bad"] == 1  # the 2 s failure backoff is a lower bound for the calendar delay


@pytest.mark.parametrize("task_name", ["update_blocklists", "maintain_tsdb", "run_scheduled_backup"])
def test_failed_scheduled_task_is_recorded_as_failure(task_name, monkeypatch, tmp_path):
	"""A task whose work raises must reach the scheduler as a failure, not as a success."""
	import asyncio
	from types import SimpleNamespace

	from app.api import backup as backup_api
	from app.dns import ingestion as dns_ingestion
	from app.dns import unbound as unbound_mod
	from app.tasks import scheduled

	def boom(*_args: Any, **_kwargs: Any) -> Any:
		raise RuntimeError("boom")

	async def failed_blocklist_update(*_args: Any, **_kwargs: Any) -> tuple[bool, str]:
		return False, "download failed"

	ctx = SimpleNamespace(cfg=SimpleNamespace(db_path=str(tmp_path / "x.db"), tsdb_dir=tmp_path, dns_dir=tmp_path, data_dir=tmp_path, secret_key="k"))
	monkeypatch.setattr(unbound_mod, "is_unbound_installed", lambda **_: True)
	monkeypatch.setattr(unbound_mod, "update_blocklists", failed_blocklist_update)
	monkeypatch.setattr(scheduled, "read_blocklist_enabled_sync", lambda _db: True)
	monkeypatch.setattr(scheduled, "load_blocklist_update_inputs_sync", lambda _db: (["https://example.invalid/l"], ""))
	monkeypatch.setattr(scheduled, "read_tsdb_retention_plan_sync", boom)
	monkeypatch.setattr(dns_ingestion, "enforce_dns_log_retention", boom)
	monkeypatch.setattr(backup_api, "is_scheduled_backup_enabled", lambda _db: True)
	monkeypatch.setattr(backup_api, "run_scheduled_backup", boom)

	task = getattr(scheduled, task_name)

	async def job() -> None:
		await task(ctx)

	async def scenario() -> dict[str, Any]:
		scheduler = Scheduler()
		scheduler.add("job", 3600.0, job, run_on_start=True)
		await scheduler.start()
		await asyncio.sleep(0.2)
		status = scheduler.get_status()[0]
		await scheduler.stop_graceful()
		return dict(status)

	status = asyncio.run(scenario())

	assert status["fail_count"] == 1
	assert status["run_count"] == 0
	assert status["last_success"] is None


def test_stop_graceful_is_bounded_when_a_job_ignores_cancellation():
	"""A job that suppresses the first cancellation must not block shutdown."""
	import asyncio

	async def stubborn() -> None:
		try:
			await asyncio.sleep(3600)
		except asyncio.CancelledError:
			await asyncio.sleep(1.0)  # swallow the first cancellation, finish later

	async def scenario() -> float:
		scheduler = Scheduler()
		scheduler.add("stubborn", 3600.0, stubborn, run_on_start=True)
		await scheduler.start()
		await asyncio.sleep(0.1)
		loop = asyncio.get_running_loop()
		began = loop.time()
		await scheduler.stop_graceful(timeout=0.2)
		took = loop.time() - began
		assert scheduler._abandoned_tasks
		return took

	assert asyncio.run(scenario()) < 0.8


@pytest.mark.parametrize("text", ["224.0.0.1", "ff02::1", "240.0.0.1", "0.0.0.0", "::"])  # noqa: S104  (SSRF fixtures, not a bind)
def test_node_host_check_matches_shared_ssrf_guard(text):
	import ipaddress

	from app.api.nodes import _format_host_for_url, _is_private_ip

	addr = ipaddress.ip_address(text)
	assert _is_private_ip(addr)
	with pytest.raises(ValueError, match="not allowed"):
		_format_host_for_url(f"[{text}]" if ":" in text else text)
