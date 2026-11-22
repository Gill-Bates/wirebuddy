#!/usr/bin/env python3
#
# app/utils/socket_peer.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Preserve the real TCP peer address before forwarded headers are applied.

uvicorn's proxy-header handling overwrites ``scope["client"]`` with the
``X-Forwarded-For`` address for trusted proxies. Trust decisions that must
name the actual connecting host (the node mTLS fingerprint header) read the
copy stored here instead.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Any

from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

SOCKET_PEER_SCOPE_KEY = "wb.socket_peer"


def socket_peer_ip(scope: Mapping[str, Any]) -> str | None:
	"""Return the normalized TCP peer IP captured by ``SocketPeerMiddleware``.

	Fails closed (None) when the key is absent, for example when the app runs
	without ``wrap_with_proxy_headers``; ``scope["client"]`` is never a fallback
	because uvicorn rewrites it from ``X-Forwarded-For``.
	"""
	peer = scope.get(SOCKET_PEER_SCOPE_KEY)
	if not peer:
		return None
	try:
		parsed = ipaddress.ip_address(str(peer).strip())
	except ValueError:
		return None
	if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
		parsed = parsed.ipv4_mapped
	return str(parsed)


class SocketPeerMiddleware:
	"""Store the server-reported peer IP under ``SOCKET_PEER_SCOPE_KEY``."""

	def __init__(self, app) -> None:
		self.app = app

	async def __call__(self, scope, receive, send) -> None:
		if scope["type"] in ("http", "websocket"):
			client = scope.get("client")
			# Always overwritten: the key is never taken from the request.
			scope[SOCKET_PEER_SCOPE_KEY] = client[0] if client and client[0] else None
		await self.app(scope, receive, send)


def wrap_with_proxy_headers(app, trusted_hosts: str):
	"""Apply uvicorn's forwarded-header handling after capturing the socket peer."""
	return SocketPeerMiddleware(ProxyHeadersMiddleware(app, trusted_hosts=trusted_hosts))
