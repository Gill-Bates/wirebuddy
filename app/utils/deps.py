#!/usr/bin/env python3
#
# app/utils/deps.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""FastAPI dependency helpers."""

from __future__ import annotations

from ..db.sqlite_runtime import (
	close_connection,
	connect,
)

from collections.abc import Generator
from pathlib import Path

from fastapi import Request



def get_conn(request: Request) -> Generator:
	"""Yield a per-request SQLite connection."""
	conn = connect(request.app.state.db_path)
	try:
		yield conn
	finally:
		close_connection(conn)


def get_tsdb_dir(request: Request) -> Path:
	"""Central helper to get TSDB directory from app state."""
	return request.app.state.tsdb_dir


def get_config(request: Request):
	"""Get the application configuration from app state."""
	return request.app.state.cfg
