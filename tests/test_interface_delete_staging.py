#!/usr/bin/env python3
#
# tests/test_interface_delete_staging.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

# SPDX-License-Identifier: MIT
#

"""Interface delete keeps the config file until the DB transaction committed."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.api import wireguard_interfaces_crud as crud
from app.db.sqlite_interfaces import create_interface, get_interface
from app.db.sqlite_nodes import create_node, create_node_interface, enroll_node, get_node_interface_public_key


def _setup(conn, tmp_path):
	create_interface(conn, name="wg7", private_key="enc", public_key="pub", address="10.7.0.1/24")
	conf = tmp_path / "wg7.conf"
	conf.write_text("[Interface]\n")
	return conf


def test_delete_removes_row_and_file_after_commit(conn, tmp_path):
	conf = _setup(conn, tmp_path)
	crud._delete_interface_sync(conn, name="wg7", conf_file=conf, db_exists=True, file_exists=True)
	assert get_interface(conn, "wg7") is None
	assert not conf.exists()
	assert list(tmp_path.iterdir()) == []


def test_db_failure_restores_config_file(conn, tmp_path, monkeypatch):
	conf = _setup(conn, tmp_path)

	def boom(*_args, **_kwargs):
		raise RuntimeError("db down")

	monkeypatch.setattr(crud, "db_delete_interface", boom)
	with pytest.raises(HTTPException) as exc:
		crud._delete_interface_sync(conn, name="wg7", conf_file=conf, db_exists=True, file_exists=True)
	assert exc.value.status_code == 500
	assert conf.read_text() == "[Interface]\n"
	assert get_interface(conn, "wg7") is not None
	assert [p.name for p in tmp_path.iterdir()] == ["wg7.conf"]


def test_orphaned_file_without_db_row_is_removed(conn, tmp_path):
	conf = tmp_path / "wg8.conf"
	conf.write_text("x")
	crud._delete_interface_sync(conn, name="wg8", conf_file=conf, db_exists=False, file_exists=True)
	assert list(tmp_path.iterdir()) == []


def test_delete_clears_node_keypairs_and_reports_versions(conn, tmp_path):
	"""An interface a node was provisioned for must stay deletable.

	``delete_interface`` refuses to drop a row that ``node_interfaces`` still
	references, so without clearing them the delete failed *after* the interface
	had already been shut down.
	"""
	conf = _setup(conn, tmp_path)
	create_node(conn, "n1", "N1", "example.com", 51820, "hash")
	enroll_node(conn, "n1", "a" * 64)
	create_node_interface(conn, "n1", "wg7", "node-priv", "node-pub", pepper="x" * 32)
	assert get_node_interface_public_key(conn, "n1", "wg7") == "node-pub"

	_peers, node_versions, warning = crud._delete_interface_sync(conn, name="wg7", conf_file=conf, db_exists=True, file_exists=True)

	assert get_interface(conn, "wg7") is None
	assert get_node_interface_public_key(conn, "n1", "wg7") is None
	# The node must be told to pull a new config.
	assert list(node_versions) == ["n1"]
	assert node_versions["n1"]
	assert warning is None


def test_failed_unlink_is_reported_instead_of_silent_success(conn, tmp_path, monkeypatch):
	"""The staged file holds the decrypted private key, so a leftover is surfaced."""
	conf = _setup(conn, tmp_path)

	def refuse(self, **_kwargs):
		raise OSError("read-only filesystem")

	monkeypatch.setattr(crud.Path, "unlink", refuse)
	_peers, _versions, warning = crud._delete_interface_sync(conn, name="wg7", conf_file=conf, db_exists=True, file_exists=True)

	# The DB commit stands, but the caller learns the key file is still there.
	assert get_interface(conn, "wg7") is None
	assert warning is not None
	assert "private-key" in warning
	assert [p.name for p in tmp_path.iterdir()] == [".wg7.conf.deleting"]


def test_startup_purges_leftover_staged_configs(tmp_path):
	from app.main import _purge_staged_interface_configs

	(tmp_path / ".wg7.conf.deleting").write_text("[Interface]\nPrivateKey = secret\n")
	(tmp_path / "wg9.conf").write_text("[Interface]\n")

	_purge_staged_interface_configs(tmp_path)

	# Leftovers go, live configs stay.
	assert [p.name for p in tmp_path.iterdir()] == ["wg9.conf"]
