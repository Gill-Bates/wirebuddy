#!/usr/bin/env python3
#
# app/utils/acme_http.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Minimal plaintext HTTP listener used alongside the HTTPS GUI listener.

ACME HTTP-01 validation always connects to port 80 over plain HTTP. Once the
GUI port terminates TLS, a validation request would hit a TLS socket and fail,
so certificate issue and renewal would break exactly when HTTPS is switched on.

This listener keeps that path open. It answers only ACME challenge lookups and
redirects everything else to HTTPS, so no authenticated surface is exposed in
clear text.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from urllib.parse import quote, urlsplit

_log = logging.getLogger(__name__)

__all__ = ["build_acme_http_app"]

_ACME_PREFIX = "/.well-known/acme-challenge/"
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,256}$")


async def _send(send, status: int, body: bytes, headers: list[tuple[bytes, bytes]]) -> None:
	await send({"type": "http.response.start", "status": status, "headers": headers})
	await send({"type": "http.response.body", "body": body})


def _canonical_https_origin(public_origin: str | None) -> str:
	raw = (public_origin or os.environ.get("WIREBUDDY_PUBLIC_ORIGIN", "")).strip()
	parsed = urlsplit(raw)
	if parsed.scheme.lower() != "https" or not parsed.hostname:
		raise ValueError("ACME redirect requires a configured HTTPS public origin")
	if parsed.username or parsed.password or parsed.query or parsed.fragment:
		raise ValueError("ACME public origin must not contain credentials, query, or fragment")
	if parsed.path not in ("", "/"):
		raise ValueError("ACME public origin must not contain a path")
	host = parsed.hostname.rstrip(".").lower()
	port = parsed.port
	if port == 443:
		port = None
	if ":" in host:
		host = f"[{host}]"
	netloc = host if port is None else f"{host}:{port}"
	return f"https://{netloc}"


def build_acme_http_app(
	certs_dir: Path,
	https_port: int | str,
	*,
	public_origin: str | None = None,
):
	"""Return an ASGI app serving ACME challenges and redirecting to HTTPS.

	The redirect destination is deliberately taken from the configured public
	origin.  The HTTP Host header is request input and must not select it.
	"""
	# Imported lazily so this module stays cheap for non-HTTPS startups.
	from ..api.acme import get_challenge_response

	# Also accept the safer ``build_acme_http_app(certs_dir, public_origin)``
	# form.  The integer form is retained for existing callers, but it can no
	# longer select a redirect host from request input.
	if isinstance(https_port, str):
		if public_origin is not None:
			raise ValueError("public_origin was supplied twice")
		public_origin = https_port
		https_port = 443
	_ = https_port
	redirect_origin = _canonical_https_origin(public_origin)

	async def app(scope, receive, send) -> None:
		if scope["type"] != "http":
			return

		path: str = scope.get("path", "/")

		if path.startswith(_ACME_PREFIX):
			token = path[len(_ACME_PREFIX):]
			if not _TOKEN_RE.fullmatch(token):
				await _send(send, 404, b"Challenge not found",
				            [(b"content-type", b"text/plain; charset=utf-8")])
				return
			key_auth = get_challenge_response(token, certs_dir)
			if not key_auth:
				_log.info("ACME_HTTP challenge token not found (len=%d)", len(token))
				await _send(send, 404, b"Challenge not found",
				            [(b"content-type", b"text/plain; charset=utf-8")])
				return
			_log.info("ACME_HTTP served challenge over plaintext listener")
			await _send(send, 200, key_auth.encode("utf-8"),
			            [(b"content-type", b"text/plain; charset=utf-8")])
			return

		# Everything else: point the client at the configured HTTPS origin.
		query = scope.get("query_string", b"").decode("latin-1")
		target = f"{redirect_origin}{quote(path)}"
		if query:
			if "\r" in query or "\n" in query:
				await _send(send, 400, b"Invalid query string",
				            [(b"content-type", b"text/plain; charset=utf-8")])
				return
			target = f"{target}?{query}"
		await _send(send, 308, b"", [
			(b"location", target.encode("latin-1")),
			(b"content-length", b"0"),
		])

	return app
