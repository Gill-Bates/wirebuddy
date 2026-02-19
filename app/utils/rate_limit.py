#!/usr/bin/env python3
#
# app/utils/rate_limit.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Rate limiting configuration using slowapi."""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

# Rate limit presets
RATE_LIMIT_DEFAULT = "60/minute"
RATE_LIMIT_AUTH = "5/minute"       # Strict limit for login attempts
RATE_LIMIT_HEAVY = "10/minute"     # For expensive operations
RATE_LIMIT_API = "120/minute"      # General API operations

# Global limiter instance
limiter = Limiter(key_func=get_remote_address)

__all__ = [
	"RATE_LIMIT_AUTH",
	"RATE_LIMIT_DEFAULT",
	"RATE_LIMIT_HEAVY",
	"RATE_LIMIT_API",
	"limiter",
]
