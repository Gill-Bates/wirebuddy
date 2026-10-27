#!/usr/bin/env python3
#
# app/utils/rate_limit.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Dependency-free in-memory rate limiting for FastAPI routes.

Usage::

	@router.post("/login", dependencies=[Depends(rate_limit(RATE_LIMIT_AUTH))])

Every ``rate_limit(...)`` call creates its own sliding window, so two routes
that share a limit string still count separately. Route-level dependencies run
before parameter dependencies, so the limiter counts a request before the
authentication dependency can reject it (401/403/422 attempts are counted too).

Storage backend
~~~~~~~~~~~~~~~
WireBuddy web mode is single-worker only (``docker/entrypoint.sh`` hardcodes
``--workers 1``; the in-process job/session state would not survive a second
worker anyway). The in-process counters are therefore always authoritative and
no shared backend is needed.

Any internal failure rejects the request instead of admitting it.
"""

from __future__ import annotations

import logging
import math
import os
import re
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable
from ipaddress import IPv6Network, ip_address

from starlette.requests import Request

from .network import resolve_client_ip

__all__ = [
	"MAX_KEYS",
	"RATE_LIMIT_API",
	"RATE_LIMIT_AUTH",
	"RATE_LIMIT_CRITICAL",
	"RATE_LIMIT_DEFAULT",
	"RATE_LIMIT_HEAVY",
	"RATE_LIMIT_UI_HEAVY",
	"RateLimitExceededError",
	"SlidingWindow",
	"parse_limit",
	"rate_limit",
	"rate_limit_key",
]

_log = logging.getLogger(__name__)

# Rate limit presets
RATE_LIMIT_DEFAULT = "60/minute"
RATE_LIMIT_AUTH = "5/minute"  # Strict limit for login attempts
RATE_LIMIT_HEAVY = "10/minute"  # For expensive operations
RATE_LIMIT_API = "120/minute"  # General API operations
RATE_LIMIT_CRITICAL = "3/minute"  # For sensitive operations like PSK reveal
RATE_LIMIT_UI_HEAVY = os.getenv("WIREBUDDY_RATE_LIMIT_UI_HEAVY", "60/minute")

# Upper bound of tracked client keys per window; a full table rejects new keys.
MAX_KEYS = 10_000

# Shared key for requests without a usable client address. Counting them
# together is conservative: they can never bypass the limit, and the 400 that
# the login lockout raises for such requests stays limited to the routes that
# actually need an address.
_UNKNOWN_CLIENT_KEY = "unknown"

_UNIT_SECONDS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
_LIMIT_RE = re.compile(r"^\s*(\d+)\s*/\s*(second|minute|hour|day)s?\s*$")


class RateLimitExceededError(Exception):
	"""Raised by a rate-limit dependency when the caller exceeded its budget."""

	def __init__(self, retry_after: int, limit: str) -> None:
		super().__init__(f"Rate limit exceeded ({limit})")
		self.retry_after = retry_after
		self.limit = limit


def parse_limit(limit: str) -> tuple[int, int]:
	"""Parse ``"N/second|minute|hour|day"`` into ``(count, window_seconds)``.

	Raises ValueError for anything else, including a zero count.
	"""
	match = _LIMIT_RE.match(limit) if isinstance(limit, str) else None
	if match is None:
		raise ValueError(f"Invalid rate limit {limit!r}; expected 'N/second|minute|hour|day'")
	count = int(match.group(1))
	if count < 1:
		raise ValueError(f"Invalid rate limit {limit!r}; count must be at least 1")
	return count, _UNIT_SECONDS[match.group(2)]


def _bucket(key: str) -> str:
	"""IPv6 callers share one counter per /64 so address rotation inside a prefix does not help."""
	try:
		ip = ip_address(key)
	except ValueError:
		return key
	if ip.version == 6:
		return str(IPv6Network(f"{ip}/64", strict=False))
	return key


class SlidingWindow:
	"""Per-key request counter over a sliding window.

	Rejected requests are not recorded, so a caller that backs off is admitted
	again once the oldest admitted request leaves the window.
	"""

	def __init__(self, limit: int, window_seconds: float, clock: Callable[[], float] = time.monotonic) -> None:
		self._limit = limit
		self._window = window_seconds
		self._clock = clock
		self._hits: dict[str, deque[float]] = {}
		# Shared by the event loop and threadpool handlers.
		self._lock = threading.Lock()

	def _make_room(self, now: float) -> None:
		"""Drop expired keys only; dropping an active one would reset a live limit."""
		for key in [k for k, s in self._hits.items() if not s or s[-1] <= now - self._window]:
			del self._hits[key]
		if len(self._hits) >= MAX_KEYS:
			raise RuntimeError("rate limiter capacity exhausted")

	def hit(self, key: str) -> float | None:
		"""Count one request; None when allowed, else the seconds until a slot frees up."""
		key = _bucket(key)
		with self._lock:
			now = self._clock()
			stamps = self._hits.get(key)
			if stamps is None:
				if len(self._hits) >= MAX_KEYS:
					self._make_room(now)
				stamps = self._hits[key] = deque()
			while stamps and stamps[0] <= now - self._window:
				stamps.popleft()
			if len(stamps) >= self._limit:
				return max(0.0, stamps[0] + self._window - now)
			stamps.append(now)
			return None


def rate_limit_key(request: Request) -> str:
	"""Key rate limits by client address (same resolution as the login lockout).

	Trusted-proxy handling is shared with ``api.auth`` through
	``resolve_client_ip``. Authenticated per-user keying is not possible here:
	the limiter must run before authentication.
	"""
	return resolve_client_ip(request) or _UNKNOWN_CLIENT_KEY


def rate_limit(limit: str, *, clock: Callable[[], float] = time.monotonic) -> Callable[[Request], Awaitable[None]]:
	"""Build a FastAPI dependency enforcing ``limit`` (e.g. ``"5/minute"``) per client.

	Each call owns a separate window, so counters are per route. An invalid
	limit string raises ValueError immediately, at route registration.
	"""
	count, window = parse_limit(limit)
	window_label = next(name for name, seconds in _UNIT_SECONDS.items() if seconds == window)
	label = f"{count} per 1 {window_label}"
	counter = SlidingWindow(count, window, clock)

	async def _enforce(request: Request) -> None:
		try:
			wait = counter.hit(rate_limit_key(request))
		except Exception:  # unreadable limiter state means rejection, not admission
			_log.exception("Rate limiter state unreadable; rejecting the request")
			raise RateLimitExceededError(retry_after=window, limit=label) from None
		if wait is not None:
			raise RateLimitExceededError(retry_after=max(1, math.ceil(wait)), limit=label)

	return _enforce
