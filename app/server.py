#!/usr/bin/env python3
#
# app/server.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Start the web server, including the built-in HTTPS listener.

The single start path for ``run.py`` (local runs) and the Docker entrypoint
(``python -m app.server --host ... --port ...``). Only ``gui_https_enabled``
decides whether the GUI port itself speaks TLS; a reverse proxy terminating
HTTPS in front keeps it off. The entrypoint passes the bind address it already
validated, so the database values are only the fallback here.
"""

import argparse
import logging
import os
from pathlib import Path

import uvicorn

from app.db.sqlite_runtime import connect
from app.db.sqlite_schema import init_schema
from app.db.sqlite_settings import get_gui_https_enabled, get_setting
from app.utils.config import load_config

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


class UvicornMessageFilter(logging.Filter):
	"""Filter to downgrade specific uvicorn messages from INFO to DEBUG."""

	def filter(self, record: logging.LogRecord) -> bool:
		# Drop the noisy shutdown message instead of mutating the shared record.
		return not (record.levelno == logging.INFO and "Finished server process" in record.getMessage())


_UVICORN_LOG_CONFIG: dict = {
	"version": 1,
	"disable_existing_loggers": False,
	"formatters": {
		"default": {
			"format": _LOG_FORMAT,
			"datefmt": _DATE_FORMAT,
		},
		"access": {
			"format": _LOG_FORMAT,
			"datefmt": _DATE_FORMAT,
		},
	},
	"filters": {
		"uvicorn_filter": {
			"()": "app.server.UvicornMessageFilter",
		},
	},
	"handlers": {
		"default": {
			"formatter": "default",
			"class": "logging.StreamHandler",
			"stream": "ext://sys.stderr",
			"filters": ["uvicorn_filter"],
		},
		"access": {
			"formatter": "access",
			"class": "logging.StreamHandler",
			"stream": "ext://sys.stdout",
		},
	},
	"loggers": {
		"uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
		"uvicorn.error": {"level": "INFO"},
		"uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
	},
}


def _log_https_startup(material, gui_port: int, wg_fqdn: str) -> None:
	"""Report which certificate is served and warn about ACME interaction."""
	log = logging.getLogger("wirebuddy")
	expiry = material.expires_at.isoformat() if material.expires_at else "unknown"
	log.info(
		"HTTPS enabled on port %s using %s certificate for %s (expires %s)",
		gui_port,
		material.source,
		material.domain,
		expiry,
	)
	if material.is_self_signed:
		log.warning(
			"Serving a self-signed certificate: browsers will show a trust warning. Request a Let's Encrypt certificate for %s in Settings to replace it.",
			wg_fqdn or "your FQDN",
		)
	# HTTP-01 validation always connects to port 80 in plaintext. Once the GUI
	# port speaks TLS, any existing :80 -> gui_port mapping breaks the challenge.
	log.warning(
		"ACME HTTP-01 note: Let's Encrypt validates over PLAIN HTTP on port 80. "
		"Ensure port 80 still reaches this app unencrypted (e.g. map host :80 to "
		"the container's HTTP port), otherwise certificate issue/renewal will fail."
	)
	log.warning("Certificates are read at startup: restart WireBuddy after issuing or renewing a certificate for the new one to be served.")


def _run_https_with_acme_listener(
	*,
	host: str,
	gui_port: int,
	ssl_certfile: str,
	ssl_keyfile: str,
	proxy_allow_ips: str,
	certs_dir: Path,
	acme_http_port: int,
	public_origin: str,
	graceful_timeout: int | None,
) -> None:
	"""Serve the app over TLS while keeping a plaintext ACME/redirect listener."""
	import asyncio

	from app import create_app
	from app.utils.acme_http import build_acme_http_app

	log = logging.getLogger("wirebuddy")

	https_server = uvicorn.Server(
		uvicorn.Config(
			create_app(),
			host=host,
			port=gui_port,
			log_config=_UVICORN_LOG_CONFIG,
			proxy_headers=True,
			forwarded_allow_ips=proxy_allow_ips,
			ssl_certfile=ssl_certfile,
			ssl_keyfile=ssl_keyfile,
			timeout_graceful_shutdown=graceful_timeout,
		)
	)
	acme_server = uvicorn.Server(
		uvicorn.Config(
			build_acme_http_app(certs_dir, gui_port, public_origin=public_origin),
			host=host,
			port=acme_http_port,
			log_config=_UVICORN_LOG_CONFIG,
			# This listener is reached directly by ACME validation servers.
			proxy_headers=False,
		)
	)

	async def _serve_acme() -> None:
		try:
			await acme_server.serve()
		except (OSError, SystemExit) as exc:
			# Port 80 may be privileged or already taken. HTTPS must still come
			# up; only ACME HTTP-01 is affected. uvicorn reports a failed bind
			# with sys.exit(STARTUP_FAILURE), not OSError, so SystemExit has to
			# be caught here or it takes the HTTPS listener down with it.
			log.warning(
				"Could not bind plaintext ACME listener on port %s (%s). "
				"HTTPS is running, but Let's Encrypt HTTP-01 validation will "
				"fail until port 80 reaches this app unencrypted.",
				acme_http_port,
				exc,
			)

	async def _serve_both() -> None:
		log.info(
			"Plaintext ACME/redirect listener on port %s -> HTTPS on port %s",
			acme_http_port,
			gui_port,
		)
		await asyncio.gather(https_server.serve(), _serve_acme())

	asyncio.run(_serve_both())


def _record_listener_state(scheme: str, host: str, port: int) -> None:
	"""Record the transport this start is configured to serve, for the Docker health check.

	Written atomically to the file named by ``WIREBUDDY_LISTENER_STATE`` (set by
	the Docker entrypoint; unset elsewhere) once the start configuration,
	including the certificate, is fully resolved, just before the socket is
	bound. That is safe: the probe still has to reach the real listener, so the
	file alone never reports healthy. The health check reads this file instead
	of the database, so switching HTTPS on in the UI does not flip the probe
	before the restart that actually changes the listener.
	"""
	path = os.environ.get("WIREBUDDY_LISTENER_STATE")
	if not path:
		return
	if host in ("0.0.0.0", "localhost"):  # noqa: S104 - wildcard binds are probed via loopback
		probe_host = "127.0.0.1"
	elif host == "::":
		# IPv6 wildcard: probe IPv6 loopback, which also works on IPv6-only hosts.
		probe_host = "[::1]"
	elif ":" in host:
		probe_host = f"[{host}]"
	else:
		probe_host = host
	target = Path(path)
	target.parent.mkdir(parents=True, exist_ok=True)
	tmp = target.with_name(target.name + ".tmp")
	tmp.write_text(f"SCHEME={scheme}\nHOST={probe_host}\nPORT={port}\n", encoding="utf-8")
	tmp.replace(target)


def _resolve_acme_http_port(raw: str | None, gui_port: int) -> int:
	"""Validate ``gui_acme_http_port``; 0 means the plaintext listener stays off.

	The listener is optional, so a bad value disables it with an error instead
	of keeping the HTTPS GUI from starting.
	"""
	log = logging.getLogger("wirebuddy")
	text = "80" if raw in (None, "") else str(raw).strip()
	if not (text.isascii() and text.isdigit()):
		log.error("Ignoring invalid gui_acme_http_port %r; plaintext ACME listener disabled", raw)
		return 0
	port = int(text)
	if port == 0:
		return 0
	if not 1 <= port <= 65535:
		log.error("gui_acme_http_port %s is outside 1-65535; plaintext ACME listener disabled", port)
		return 0
	if port == gui_port:
		log.error(
			"gui_acme_http_port %s equals the HTTPS GUI port; plaintext ACME listener disabled. Use a different port (normally 80) for Let's Encrypt HTTP-01.",
			port,
		)
		return 0
	return port


def main(host: str | None = None, port: int | None = None, graceful_timeout: int | None = None) -> None:
	"""Start WireBuddy; ``host``/``port`` override the database bind settings."""
	server_mode = os.environ.get("SERVER_MODE", "master").lower()

	if server_mode == "node":
		# Node mode: run minimal daemon, no web server
		from app.node.daemon import run as run_node_daemon

		run_node_daemon()
		return

	cfg = load_config()

	level = cfg.log_level.upper()

	for logger in _UVICORN_LOG_CONFIG["loggers"].values():
		logger["level"] = level

	conn = connect(cfg.db_path)

	try:
		init_schema(conn)

		gui_port_str = get_setting(conn, "gui_port", "8000")
		gui_localhost_only_str = get_setting(conn, "gui_localhost_only", "true")
		gui_https_enabled = get_gui_https_enabled(conn)
		wg_fqdn = (get_setting(conn, "wg_fqdn") or "").strip()
		acme_http_port_raw = get_setting(conn, "gui_acme_http_port", "80")

		try:
			gui_port = int(gui_port_str)
		except (ValueError, TypeError):
			gui_port = 8000

		gui_localhost_only = gui_localhost_only_str.lower() not in ("false", "0", "no")
		# Binding all interfaces is the documented default; gui_localhost_only narrows it.
		bind_host = "127.0.0.1" if gui_localhost_only else "0.0.0.0"  # noqa: S104

	finally:
		conn.close()

	if host is not None:
		bind_host = host
	if port is not None:
		gui_port = port
	# Validated against the final GUI port, after any --port override.
	acme_http_port = _resolve_acme_http_port(acme_http_port_raw, gui_port)

	ssl_certfile: str | None = None
	ssl_keyfile: str | None = None
	if gui_https_enabled:
		from app.utils.tls import resolve_gui_certificate

		try:
			material = resolve_gui_certificate(cfg.data_dir / "certs", wg_fqdn)
		except Exception as exc:
			# Fail closed: with HTTPS enabled, logins reject plain HTTP, so an
			# HTTP fallback would only lock everyone out over a clear-text port.
			logging.getLogger("wirebuddy").critical("HTTPS is enabled but no certificate could be prepared; refusing to start over plain HTTP", exc_info=True)
			raise SystemExit(1) from exc
		ssl_certfile = str(material.certfile)
		ssl_keyfile = str(material.keyfile)
		_log_https_startup(material, gui_port, wg_fqdn)

	reload_enabled = os.environ.get("WIREBUDDY_DEV_RELOAD", "").lower() in (
		"1",
		"true",
		"yes",
	)
	proxy_allow_ips = os.environ.get("WIREBUDDY_TRUSTED_PROXIES", "127.0.0.1,::1").strip() or "127.0.0.1,::1"
	public_origin = os.environ.get("WIREBUDDY_PUBLIC_ORIGIN", "").strip()
	if not public_origin and wg_fqdn:
		# The database FQDN is an explicit administrator setting and is safe to
		# use as a fallback.  The request Host header is never used here.
		port_suffix = "" if gui_port == 443 else f":{gui_port}"
		public_origin = f"https://{wg_fqdn}{port_suffix}"
	if ssl_certfile and acme_http_port > 0 and not public_origin:
		logging.getLogger("wirebuddy").warning(
			"Disabling plaintext ACME listener: configure WIREBUDDY_PUBLIC_ORIGIN or Server FQDN before enabling HTTP-01 redirects"
		)
		acme_http_port = 0

	_record_listener_state("https" if ssl_certfile else "http", bind_host, gui_port)

	if ssl_certfile and not reload_enabled and acme_http_port > 0:
		# HTTPS mode: run the TLS listener plus a plaintext ACME/redirect
		# listener so Let's Encrypt validation keeps working (see acme_http).
		_run_https_with_acme_listener(
			host=bind_host,
			gui_port=gui_port,
			ssl_certfile=ssl_certfile,
			ssl_keyfile=ssl_keyfile,
			proxy_allow_ips=proxy_allow_ips,
			certs_dir=cfg.data_dir / "certs",
			acme_http_port=acme_http_port,
			public_origin=public_origin,
			graceful_timeout=graceful_timeout,
		)
		return

	uvicorn.run(
		"app:create_app",
		host=bind_host,
		port=gui_port,
		reload=reload_enabled,
		factory=True,
		log_config=_UVICORN_LOG_CONFIG,
		proxy_headers=True,
		forwarded_allow_ips=proxy_allow_ips,
		ssl_certfile=ssl_certfile,
		ssl_keyfile=ssl_keyfile,
		timeout_graceful_shutdown=graceful_timeout,
	)


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Start the WireBuddy web server")
	parser.add_argument("--host", help="bind address (overrides gui_localhost_only)")
	parser.add_argument("--port", type=int, help="GUI port (overrides gui_port)")
	parser.add_argument("--timeout-graceful-shutdown", type=int, dest="graceful_timeout")
	args = parser.parse_args()
	main(host=args.host, port=args.port, graceful_timeout=args.graceful_timeout)
