#!/usr/bin/env python3
#
# main.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

# WireBuddy - WireGuard Management WebUI
# Local development entry point
#

import logging
import os

import uvicorn
from app.utils.config import load_config
from app.db.sqlite_runtime import connect
from app.db.sqlite_schema import init_schema
from app.db.sqlite_settings import get_setting

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Uvicorn logging dict-config that reuses the same format as the app
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
	"handlers": {
		"default": {
			"formatter": "default",
			"class": "logging.StreamHandler",
			"stream": "ext://sys.stderr",
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

if __name__ == "__main__":
	cfg = load_config()

	# Set levels in the uvicorn log-config to match the app
	_level = cfg.log_level.upper()
	for _logger in _UVICORN_LOG_CONFIG["loggers"].values():
		_logger["level"] = _level

	# Read GUI server settings from database
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

	uvicorn.run(
		"app:create_app",
		host=host,
		port=gui_port,
		reload=os.environ.get("WIREBUDDY_DEV_RELOAD", "").lower() in ("1", "true", "yes"),
		factory=True,
		log_config=_UVICORN_LOG_CONFIG,
	)
