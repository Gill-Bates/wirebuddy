#!/usr/bin/env python3
#
# app/utils/deps.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""FastAPI dependency helpers."""

from __future__ import annotations

from ..db.sqlite_runtime import (
	close_connection,
	connect,
)

from collections.abc import Generator
from pathlib import Path

from fastapi import HTTPException, Request



def get_conn(request: Request) -> Generator:
	"""Yield a per-request SQLite connection.

	Returns *503 Service Unavailable* while a backup restore is in progress
	(``app.state.maintenance`` flag) to prevent queries against a database
	that is about to be replaced.
	"""
	if getattr(request.app.state, "maintenance", False):
		raise HTTPException(status_code=503, detail="Service restarting — backup restore in progress")
	conn = connect(request.app.state.db_path)
	try:
		yield conn
	finally:
		close_connection(conn)


def get_tsdb_dir(request: Request) -> Path:
	"""Central helper to get TSDB directory from app state."""
	return request.app.state.tsdb_dir


def get_dns_dir(request: Request) -> Path:
	"""Central helper to get DNS directory from app state."""
	return request.app.state.dns_dir


def get_config(request: Request):
	"""Get the application configuration from app state."""
	return request.app.state.cfg
