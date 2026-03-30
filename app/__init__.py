#!/usr/bin/env python3
#
# app/__init__.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""WireBuddy – Lightweight WireGuard Management WebUI."""

from __future__ import annotations

from typing import Any

__all__ = ["create_app"]


def create_app(*args: Any, **kwargs: Any):
	"""Lazily import the FastAPI app factory.

	This keeps lightweight modules importable in tests and utility scripts
	without pulling in the full application dependency graph.
	"""
	from .main import create_app as _create_app

	return _create_app(*args, **kwargs)
