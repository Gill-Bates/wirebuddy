#!/usr/bin/env python3
#
# tests/test_config_derivation.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Regression tests for environment-variable consolidation in app/utils/config.py.

Covers the WIREBUDDY_PUBLIC_ORIGIN / WIREBUDDY_TRUSTED_PROXIES derivation
introduced to reduce the number of separately configured settings: trusted
proxy CIDRs, public-origin hostname/scheme derivation, and the resulting
force_https flag.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.main import _bind_is_loopback, _resolve_allowed_hosts
from app.utils.config import load_config


def _base_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
	monkeypatch.setenv("WIREBUDDY_DATA_DIR", str(tmp_path / "data"))
	monkeypatch.setenv("WIREBUDDY_SECRET_KEY", "x" * 32)
	monkeypatch.delenv("WIREBUDDY_PUBLIC_ORIGIN", raising=False)
	monkeypatch.delenv("WIREBUDDY_TRUSTED_PROXIES", raising=False)


def test_trusted_proxies_default_to_loopback_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
	_base_env(monkeypatch, tmp_path)

	cfg = load_config()

	assert cfg.is_trusted_proxy_ip("127.0.0.1")
	assert cfg.is_trusted_proxy_ip("::1")
	assert not cfg.is_trusted_proxy_ip("203.0.113.5")


def test_trusted_proxies_explicit_value_replaces_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
	_base_env(monkeypatch, tmp_path)
	monkeypatch.setenv("WIREBUDDY_TRUSTED_PROXIES", "192.168.1.10/32")

	cfg = load_config()

	assert cfg.is_trusted_proxy_ip("192.168.1.10")
	# Loopback is no longer implicitly trusted once an explicit value is set.
	assert not cfg.is_trusted_proxy_ip("127.0.0.1")


def test_trusted_proxies_ignores_invalid_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
	_base_env(monkeypatch, tmp_path)
	monkeypatch.setenv("WIREBUDDY_TRUSTED_PROXIES", "not-a-cidr,192.168.1.10/32")

	cfg = load_config()

	assert cfg.is_trusted_proxy_ip("192.168.1.10")
	assert len(cfg.trusted_proxies) == 1


def test_public_origin_hostname_and_force_https_derivation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
	_base_env(monkeypatch, tmp_path)
	monkeypatch.setenv("WIREBUDDY_PUBLIC_ORIGIN", "https://vpn.example.com")

	cfg = load_config()

	assert cfg.public_origin_hostname == "vpn.example.com"
	assert cfg.force_https is True


def test_public_origin_http_does_not_force_https(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
	_base_env(monkeypatch, tmp_path)
	monkeypatch.setenv("WIREBUDDY_PUBLIC_ORIGIN", "http://vpn.example.com")

	cfg = load_config()

	assert cfg.public_origin_hostname == "vpn.example.com"
	assert cfg.force_https is False


def test_no_public_origin_means_no_hostname_and_no_force_https(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
	_base_env(monkeypatch, tmp_path)

	cfg = load_config()

	assert cfg.public_origin_hostname is None
	assert cfg.force_https is False


def test_allowed_hosts_explicit_value_wins_over_derivation():
	hosts, derived = _resolve_allowed_hosts("vpn.example.com,localhost", "other.example.com")
	assert hosts == ["vpn.example.com", "localhost"]
	assert derived is False


def test_allowed_hosts_derived_from_public_origin_when_unset():
	hosts, derived = _resolve_allowed_hosts("", "vpn.example.com")
	assert hosts == ["vpn.example.com"]
	assert derived is True


def test_allowed_hosts_empty_when_neither_configured():
	hosts, derived = _resolve_allowed_hosts("", None)
	assert hosts == []
	assert derived is False


@pytest.mark.parametrize(
	("raw", "expected"),
	[
		("127.0.0.1", True),
		("::1", True),
		("[::1]", True),
		("localhost", True),
		("0.0.0.0", False),  # noqa: S104 - wildcard bind under test
		("::", False),
		("192.168.1.10", False),
		("", False),
		(None, False),
		("not-a-host", False),
	],
)
def test_bind_is_loopback_only_for_known_loopback_hosts(raw, expected):
	"""An unknown or wildcard bind must keep the missing-Host-validation warning."""
	assert _bind_is_loopback(raw) is expected


def test_symlinked_data_dir_is_rejected_and_target_permissions_untouched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
	_base_env(monkeypatch, tmp_path)
	target = tmp_path / "foreign"
	target.mkdir()
	target.chmod(0o755)
	(tmp_path / "data").symlink_to(target)
	with pytest.raises(SystemExit):
		load_config()
	assert target.stat().st_mode & 0o777 == 0o755


def test_symlinked_tsdb_dir_is_rejected_and_target_permissions_untouched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
	_base_env(monkeypatch, tmp_path)
	target = tmp_path / "foreign"
	target.mkdir()
	target.chmod(0o755)
	(tmp_path / "data").mkdir()
	(tmp_path / "data" / "tsdb").symlink_to(target)
	with pytest.raises(SystemExit):
		load_config()
	assert target.stat().st_mode & 0o777 == 0o755


def test_data_dir_is_tightened_to_0700(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
	_base_env(monkeypatch, tmp_path)
	(tmp_path / "data").mkdir()
	(tmp_path / "data").chmod(0o777)
	cfg = load_config()
	assert cfg.data_dir.stat().st_mode & 0o777 == 0o700


def test_data_dir_group_writable_after_failed_chmod_refuses_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
	_base_env(monkeypatch, tmp_path)
	(tmp_path / "data").mkdir()
	(tmp_path / "data").chmod(0o770)
	monkeypatch.setattr("app.utils.config.os.fchmod", lambda *_a: (_ for _ in ()).throw(PermissionError("denied")))
	with pytest.raises(SystemExit):
		load_config()


def test_data_dir_read_only_group_access_survives_failed_chmod(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
	_base_env(monkeypatch, tmp_path)
	(tmp_path / "data").mkdir()
	(tmp_path / "data").chmod(0o750)
	monkeypatch.setattr("app.utils.config.os.fchmod", lambda *_a: (_ for _ in ()).throw(PermissionError("denied")))
	assert load_config().data_dir == (tmp_path / "data").resolve()
