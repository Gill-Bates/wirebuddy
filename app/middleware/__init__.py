#!/usr/bin/env python3
#
# app/middleware/__init__.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Middleware modules for WireBuddy."""

from .csrf import CSRFMiddleware

__all__ = ["CSRFMiddleware"]
