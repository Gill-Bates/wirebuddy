#!/usr/bin/env python3
#
# app/utils/banner.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Startup banner for WireBuddy."""

from __future__ import annotations

import fcntl
import logging
import os
import stat
import sys
from pathlib import Path

from .version import BUILD_INFO, VERSION

logger = logging.getLogger(__name__)

_BANNER_RUNTIME_DIR = Path(os.environ.get("WIREBUDDY_RUNTIME_DIR", "/run/wirebuddy"))
_BANNER_LOCK_FILE = _BANNER_RUNTIME_DIR / "banner.lock"


def _ensure_runtime_dir(path: Path) -> None:
	"""Ensure the banner runtime directory exists and is not symlinked."""
	try:
		st = path.lstat()
	except FileNotFoundError:
		path.mkdir(mode=0o750, parents=True)
		st = path.lstat()

	if path.is_symlink() or not stat.S_ISDIR(st.st_mode):
		raise RuntimeError(f"Banner runtime path is not a safe directory: {path}")

	path.chmod(0o750)


def _open_banner_lock() -> int:
	_ensure_runtime_dir(_BANNER_RUNTIME_DIR)

	flags = os.O_CREAT | os.O_RDWR
	if hasattr(os, "O_CLOEXEC"):
		flags |= os.O_CLOEXEC
	if hasattr(os, "O_NOFOLLOW"):
		flags |= os.O_NOFOLLOW

	fd = os.open(_BANNER_LOCK_FILE, flags, 0o600)
	file_stat = os.fstat(fd)
	if not stat.S_ISREG(file_stat.st_mode):
		os.close(fd)
		raise OSError("Banner lock path is not a regular file")

	return fd


def _process_start_key(pid: int) -> str:
	try:
		stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
		stat_tail = stat_text.rsplit(") ", 1)[1]
		start_time = stat_tail.split()[19]
	except (IndexError, OSError):
		start_time = "unknown"
	return f"{pid}:{start_time}"


def _banner_startup_key() -> str:
	return _process_start_key(os.getppid())


def print_banner() -> None:
    """Print the WireBuddy startup banner."""
    build_short = BUILD_INFO[:7] if BUILD_INFO else "dev"

    ascii_art = r"""
          _          _               _     _       
__      _(_)_ __ ___| |__  _   _  __| | __| |_   _ 
\ \ /\ / / | '__/ _ \ '_ \| | | |/ _` |/ _` | | | |
 \ V  V /| | | |  __/ |_) | |_| | (_| | (_| | |_| |
  \_/\_/ |_|_|  \___|_.__/ \__,_|\__,_|\__,_|\__, |
                                             |___/ 
""".strip("\n")

    text_lines = [
        f"Use WireGuard with ease! v{VERSION} ({build_short})",
        "(C) 2026 by Gill-Bates (https://github.com/Gill-Bates/wirebuddy)",
    ]

    ascii_lines = ascii_art.splitlines()
    ascii_width = max((len(l) for l in ascii_lines), default=0)
    text_width = max((len(t) for t in text_lines), default=0)

    master_width = max(ascii_width, text_width)

    left_pad = max((master_width - ascii_width) // 2, 0)
    pad = " " * left_pad
    ascii_centered = "\n".join(pad + line for line in ascii_lines)

    text_centered = [t.center(master_width) for t in text_lines]

    banner = "\n" + "\n".join([ascii_centered, *text_centered]) + "\n"

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
	    startup_key = _banner_startup_key()

	    try:
	        fd = _open_banner_lock()
	        try:
	            try:
	                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
	            except BlockingIOError:
	                return

	            content = os.read(fd, 128).decode("utf-8", errors="ignore").strip()
	            if content == startup_key:
	                return

	            print_banner()

	            os.lseek(fd, 0, os.SEEK_SET)
	            os.ftruncate(fd, 0)
	            os.write(fd, startup_key.encode("utf-8"))
	            os.fsync(fd)
	        finally:
	            fcntl.flock(fd, fcntl.LOCK_UN)
	            os.close(fd)
	    except OSError:
	        logger.warning("Could not coordinate startup banner printing.", exc_info=True)
	        print_banner()
