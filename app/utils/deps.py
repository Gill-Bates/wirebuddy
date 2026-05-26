#!/usr/bin/env python3
#
# app/utils/deps.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""FastAPI dependency helpers."""

from __future__ import annotations

import logging
from collections.abc import Generator
from pathlib import Path
from sqlite3 import Connection
from typing import Protocol, cast

from fastapi import HTTPException, Request

from ..utils.config import Config
from ..utils.backup_lock import is_restore_in_progress
from ..db.sqlite_runtime import (
	close_connection,
	connect,
)

_log = logging.getLogger(__name__)


class AppState(Protocol):
	"""Typed subset of app.state used by request dependencies."""
	cfg: Config
	db_path: Path
	tsdb_dir: Path
	dns_dir: Path
	maintenance: bool


def _get_app_state(request: Request) -> AppState:
	"""Return validated application state with clear startup diagnostics."""
	state = request.app.state
	missing = [
		name
		for name in ("cfg", "db_path", "tsdb_dir", "dns_dir")
		if not hasattr(state, name)
	]
	if missing:
		raise RuntimeError(
			"Application state not initialized: missing " + ", ".join(sorted(missing))
		)
	return cast(AppState, state)


def _restore_in_progress(state: AppState) -> bool:
	"""Check in-memory restore state first, then fall back to lock probing."""
	if getattr(state, "maintenance", False):
		return True
	if getattr(state, "restore_in_progress", False):
		return True
	data_dir = getattr(state, "data_dir", state.cfg.data_dir)
	return is_restore_in_progress(data_dir)



def get_conn(request: Request) -> Generator[Connection, None, None]:
	"""Yield a per-request SQLite connection.

	This dependency exposes a synchronous sqlite3 connection and is intended for
	synchronous handlers or narrowly scoped request work. It does not make raw
	SQLite access async-safe by itself.

	Returns *503 Service Unavailable* while a backup restore is in progress
	(``app.state.maintenance`` flag) to prevent queries against a database
	that is about to be replaced.
	"""
	state = _get_app_state(request)
	if _restore_in_progress(state):
		raise HTTPException(
			status_code=503,
			detail="Service restarting — backup restore in progress",
			headers={"Retry-After": "30"},
		)
	conn = connect(state.db_path)
	try:
		yield conn
	finally:
		try:
			close_connection(conn)
		except Exception:
			_log.exception("Failed to close SQLite connection")


def get_tsdb_dir(request: Request) -> Path:
	"""Central helper to get TSDB directory from app state."""
	return _get_app_state(request).tsdb_dir


def get_dns_dir(request: Request) -> Path:
	"""Central helper to get DNS directory from app state."""
	return _get_app_state(request).dns_dir


def get_config(request: Request) -> Config:
	"""Get the application configuration from app state."""
	return _get_app_state(request).cfg
