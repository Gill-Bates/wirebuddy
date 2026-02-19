#!/usr/bin/env python3
#
# app/utils/banner.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Startup banner for WireBuddy."""

from __future__ import annotations

import fcntl
import os
import sys
import tempfile

from .version import VERSION, BUILD_INFO

_BANNER_LOCK_FILE = os.path.join(tempfile.gettempdir(), "wirebuddy_banner.lock")


def print_banner() -> None:
	"""Print the WireBuddy startup banner."""
	build_short = BUILD_INFO[:7] if BUILD_INFO else "dev"
	banner = rf"""
          _            _               _     _       
__      _(_)_ __ ___  | |__  _   _  __| | __| |_   _ 
\ \ /\ / / | '__/ _ \ | '_ \| | | |/ _` |/ _` | | | |
 \ V  V /| | | |  __/ | |_) | |_| | (_| | (_| | |_| |
  \_/\_/ |_|_|  \___| |_.__/ \__,_|\__,_|\__,_|\__, |
                                               |___/ 
    Use WireGuard with ease!  v{VERSION} ({build_short})
                (C) 2026 by Gill-Bates
"""
	# Colorize banner in cyan if running in a TTY
	if sys.stdout.isatty():
		cyan = "\033[96m"
		reset = "\033[0m"
		sys.stdout.write(cyan + banner + reset + "\n")
	else:
		sys.stdout.write(banner + "\n")
	sys.stdout.flush()


def print_banner_once() -> None:
	"""Print startup banner at most once per process tree.
	
	Uses a file lock so that only one worker prints the banner,
	even when running with multiple uvicorn workers.
	"""
	# Use parent PID to detect new startup (all workers share same parent)
	ppid = str(os.getppid())
	
	try:
		fd = os.open(_BANNER_LOCK_FILE, os.O_CREAT | os.O_RDWR)
		try:
			# Get exclusive lock (blocking is fine, will be fast)
			fcntl.flock(fd, fcntl.LOCK_EX)
			
			# Read current content
			content = os.read(fd, 32).decode("utf-8", errors="ignore").strip()
			
			if content == ppid:
				# Same parent already printed banner
				return
			
			# New startup or first worker - print banner
			print_banner()
			
			# Write our parent PID to mark completion
			os.lseek(fd, 0, os.SEEK_SET)
			os.ftruncate(fd, 0)
			os.write(fd, ppid.encode())
		finally:
			fcntl.flock(fd, fcntl.LOCK_UN)
			os.close(fd)
	except OSError:
		# Fallback: just print (better than crashing)
		print_banner()
