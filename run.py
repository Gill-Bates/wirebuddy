#!/usr/bin/env python3
#
# run.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import logging
import os
from pathlib import Path

import uvicorn
from dotenv import load_dotenv

# ---------------------------------------------------------
# Load environment early (before config is read)
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"

if ENV_FILE.exists():
	load_dotenv(ENV_FILE)

# ---------------------------------------------------------

from app.utils.config import load_config
from app.db.sqlite_runtime import connect
from app.db.sqlite_schema import init_schema
from app.db.sqlite_settings import get_setting


_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


class UvicornMessageFilter(logging.Filter):
	"""Filter to downgrade specific uvicorn messages from INFO to DEBUG."""
	
	def filter(self, record: logging.LogRecord) -> bool:
		# Drop the noisy shutdown message instead of mutating the shared record.
		if record.levelno == logging.INFO and "Finished server process" in record.getMessage():
			return False
		return True


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
			"()": "run.UvicornMessageFilter",
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
		gui_port, material.source, material.domain, expiry,
	)
	if material.is_self_signed:
		log.warning(
			"Serving a self-signed certificate: browsers will show a trust warning. "
			"Request a Let's Encrypt certificate for %s in Settings to replace it.",
			wg_fqdn or "your FQDN",
		)
	# HTTP-01 validation always connects to port 80 in plaintext. Once the GUI
	# port speaks TLS, any existing :80 -> gui_port mapping breaks the challenge.
	log.warning(
		"ACME HTTP-01 note: Let's Encrypt validates over PLAIN HTTP on port 80. "
		"Ensure port 80 still reaches this app unencrypted (e.g. map host :80 to "
		"the container's HTTP port), otherwise certificate issue/renewal will fail."
	)
	log.warning(
		"Certificates are read at startup: restart WireBuddy after issuing or "
		"renewing a certificate for the new one to be served."
	)


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
) -> None:
	"""Serve the app over TLS while keeping a plaintext ACME/redirect listener."""
	import asyncio

	from app import create_app
	from app.utils.acme_http import build_acme_http_app

	log = logging.getLogger("wirebuddy")

	https_server = uvicorn.Server(uvicorn.Config(
		create_app(),
		host=host,
		port=gui_port,
		log_config=_UVICORN_LOG_CONFIG,
		proxy_headers=True,
		forwarded_allow_ips=proxy_allow_ips,
		ssl_certfile=ssl_certfile,
		ssl_keyfile=ssl_keyfile,
	))
	acme_server = uvicorn.Server(uvicorn.Config(
		build_acme_http_app(certs_dir, gui_port, public_origin=public_origin),
		host=host,
		port=acme_http_port,
		log_config=_UVICORN_LOG_CONFIG,
		# This listener is reached directly by ACME validation servers.
		proxy_headers=False,
	))

	async def _serve_acme() -> None:
		try:
			await acme_server.serve()
		except OSError as exc:
			# Port 80 may be privileged or already taken. HTTPS must still come
			# up; only ACME HTTP-01 is affected.
			log.warning(
				"Could not bind plaintext ACME listener on port %s (%s). "
				"HTTPS is running, but Let's Encrypt HTTP-01 validation will "
				"fail until port 80 reaches this app unencrypted.",
				acme_http_port, exc,
			)

	async def _serve_both() -> None:
		log.info(
			"Plaintext ACME/redirect listener on port %s -> HTTPS on port %s",
			acme_http_port, gui_port,
		)
		await asyncio.gather(https_server.serve(), _serve_acme())

	asyncio.run(_serve_both())


def main() -> None:
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
		gui_https_enabled = (get_setting(conn, "gui_https_enabled", "0") or "0").lower() in (
			"1", "true", "yes",
		)
		wg_fqdn = (get_setting(conn, "wg_fqdn") or "").strip()
		try:
			# 0 disables the plaintext listener entirely.
			acme_http_port = int(get_setting(conn, "gui_acme_http_port", "80") or 80)
		except (ValueError, TypeError):
			acme_http_port = 80

		try:
			gui_port = int(gui_port_str)
		except (ValueError, TypeError):
			gui_port = 8000

		gui_localhost_only = gui_localhost_only_str.lower() not in ("false", "0", "no")
		host = "127.0.0.1" if gui_localhost_only else "0.0.0.0"

	finally:
		conn.close()

	ssl_certfile: str | None = None
	ssl_keyfile: str | None = None
	if gui_https_enabled:
		from app.utils.tls import resolve_gui_certificate

		try:
			material = resolve_gui_certificate(cfg.data_dir / "certs", wg_fqdn)
		except Exception:
			logging.getLogger("wirebuddy").exception(
				"HTTPS is enabled but no certificate could be prepared; "
				"starting over plain HTTP instead"
			)
		else:
			ssl_certfile = str(material.certfile)
			ssl_keyfile = str(material.keyfile)
			_log_https_startup(material, gui_port, wg_fqdn)

	reload_enabled = os.environ.get("WIREBUDDY_DEV_RELOAD", "").lower() in (
		"1",
		"true",
		"yes",
	)
	proxy_allow_ips = os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1").strip() or "127.0.0.1"
	public_origin = os.environ.get("WIREBUDDY_PUBLIC_ORIGIN", "").strip()
	if not public_origin and wg_fqdn:
		# The database FQDN is an explicit administrator setting and is safe to
		# use as a fallback.  The request Host header is never used here.
		port_suffix = "" if gui_port == 443 else f":{gui_port}"
		public_origin = f"https://{wg_fqdn}{port_suffix}"
	if ssl_certfile and acme_http_port > 0 and not public_origin:
		logging.getLogger("wirebuddy").warning(
			"Disabling plaintext ACME listener: configure WIREBUDDY_PUBLIC_ORIGIN "
			"or Server FQDN before enabling HTTP-01 redirects"
		)
		acme_http_port = 0

	if ssl_certfile and not reload_enabled and acme_http_port > 0:
		# HTTPS mode: run the TLS listener plus a plaintext ACME/redirect
		# listener so Let's Encrypt validation keeps working (see acme_http).
		_run_https_with_acme_listener(
			host=host,
			gui_port=gui_port,
			ssl_certfile=ssl_certfile,
			ssl_keyfile=ssl_keyfile,
			proxy_allow_ips=proxy_allow_ips,
			certs_dir=cfg.data_dir / "certs",
			acme_http_port=acme_http_port,
			public_origin=public_origin,
		)
		return

	uvicorn.run(
		"app:create_app",
		host=host,
		port=gui_port,
		reload=reload_enabled,
		factory=True,
		log_config=_UVICORN_LOG_CONFIG,
		proxy_headers=True,
		forwarded_allow_ips=proxy_allow_ips,
		ssl_certfile=ssl_certfile,
		ssl_keyfile=ssl_keyfile,
	)


if __name__ == "__main__":
	main()
