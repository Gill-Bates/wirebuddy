#!/usr/bin/env python3
#
# app/utils/rate_limit.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Rate limiting configuration using slowapi.

Storage backend
~~~~~~~~~~~~~~~~
By default the limiter counts requests in process memory. WireBuddy web mode
runs single-worker (``docker/entrypoint.sh`` forces ``--workers 1``), so the
in-memory counter is authoritative.

If the deployment is ever scaled to multiple worker processes, per-process
counters diverge and every worker grants the full quota (e.g. ``5/minute``
with 4 workers becomes up to ``20/minute``). Set
``WIREBUDDY_RATE_LIMIT_STORAGE_URI`` to a shared backend such as
``redis://host:6379/0`` or ``memcached://host:11211`` so all workers share one
counter. A multi-worker configuration without that variable is refused at
import time rather than silently under-enforcing.
"""

from __future__ import annotations

import os
import sys

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


def _configured_worker_count() -> int:
	"""Best-effort read of an explicit multi-worker configuration."""
	raw = os.getenv("UVICORN_WORKERS") or os.getenv("WEB_CONCURRENCY") or "1"
	try:
		return int(raw)
	except ValueError:
		return 1


def _select_storage_uri(configured: str, worker_count: int) -> str:
	"""Resolve the limiter storage URI; a shared backend is mandatory for >1 worker."""
	if configured:
		return configured
	if worker_count > 1:
		raise RuntimeError(
			"Multiple workers are configured but WIREBUDDY_RATE_LIMIT_STORAGE_URI "
			"is not set. In-memory rate limits are per-process and would let each "
			"worker grant the full quota. Configure a shared redis:// or "
			"memcached:// backend."
		)
	return "memory://"


def _resolve_storage_uri() -> str:
	"""Return the limiter storage URI for the current environment."""
	running_tests = "pytest" in sys.modules or "PYTEST_CURRENT_TEST" in os.environ
	worker_count = 1 if running_tests else _configured_worker_count()
	return _select_storage_uri(
		os.getenv("WIREBUDDY_RATE_LIMIT_STORAGE_URI", "").strip(),
		worker_count,
	)


# Global limiter instance
limiter = Limiter(key_func=rate_limit_key, storage_uri=_resolve_storage_uri())

__all__ = [
	"RATE_LIMIT_AUTH",
	"RATE_LIMIT_CRITICAL",
	"RATE_LIMIT_DEFAULT",
	"RATE_LIMIT_HEAVY",
	"RATE_LIMIT_UI_HEAVY",
	"RATE_LIMIT_API",
	"limiter",
	"rate_limit_key",
]
