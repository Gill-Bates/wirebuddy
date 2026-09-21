#!/usr/bin/env python3
#
# app/utils/rate_limit.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Rate limiting configuration using slowapi.

Storage backend
~~~~~~~~~~~~~~~~
WireBuddy web mode is single-worker only (``docker/entrypoint.sh`` hardcodes
``--workers 1``; the in-process job/session state would not survive a second
worker anyway). The in-memory limiter counter is therefore always
authoritative and no shared backend is needed.
"""

from __future__ import annotations

import os

from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

# Rate limit presets
RATE_LIMIT_DEFAULT = "60/minute"
RATE_LIMIT_AUTH = "5/minute"       # Strict limit for login attempts
RATE_LIMIT_HEAVY = "10/minute"     # For expensive operations
RATE_LIMIT_API = "120/minute"      # General API operations
RATE_LIMIT_CRITICAL = "3/minute"   # For sensitive operations like PSK reveal
RATE_LIMIT_UI_HEAVY = os.getenv("WIREBUDDY_RATE_LIMIT_UI_HEAVY", "60/minute")


def rate_limit_key(request: Request) -> str:
	"""Key rate limits by client address.

	``get_remote_address`` reads ``request.client.host``. Behind a reverse
	proxy this is only the real client when the ASGI server is started with
	``--proxy-headers`` and ``--forwarded-allow-ips`` restricted to the trusted
	proxy IPs (see ``docker/entrypoint.sh``); otherwise it is the proxy address
	and all clients share one bucket.

	Authenticated per-user keying would require identity resolution before the
	SlowAPI limiter runs. The current request pipeline does not populate a user
	identity that early, so using the client address keeps runtime behavior
	consistent with the configured limiter.
	"""
	return get_remote_address(request)


# Global limiter instance. Single-worker deployment (see module docstring) —
# the in-memory backend is always correct here.
limiter = Limiter(key_func=rate_limit_key, storage_uri="memory://")

__all__ = [
	"RATE_LIMIT_API",
	"RATE_LIMIT_AUTH",
	"RATE_LIMIT_CRITICAL",
	"RATE_LIMIT_DEFAULT",
	"RATE_LIMIT_HEAVY",
	"RATE_LIMIT_UI_HEAVY",
	"limiter",
	"rate_limit_key",
]
