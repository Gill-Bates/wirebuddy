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
		# Downgrade "Finished server process" from INFO to DEBUG
		if record.levelno == logging.INFO and "Finished server process" in record.getMessage():
			record.levelno = logging.DEBUG
			record.levelname = "DEBUG"
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


def main():
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
		gui_localhost_only_str = get_setting(conn, "gui_localhost_only", "false")

		try:
			gui_port = int(gui_port_str)
		except (ValueError, TypeError):
			gui_port = 8000

		gui_localhost_only = gui_localhost_only_str.lower() in ("true", "1", "yes")
		host = "127.0.0.1" if gui_localhost_only else "0.0.0.0"

	finally:
		conn.close()

	reload_enabled = os.environ.get("WIREBUDDY_DEV_RELOAD", "").lower() in (
		"1",
		"true",
		"yes",
	)

	uvicorn.run(
		"app:create_app",
		host=host,
		port=gui_port,
		reload=reload_enabled,
		factory=True,
		log_config=_UVICORN_LOG_CONFIG,
		proxy_headers=True,
		forwarded_allow_ips="*",
	)


if __name__ == "__main__":
	main()