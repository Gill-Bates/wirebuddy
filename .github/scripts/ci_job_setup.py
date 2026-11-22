#!/usr/bin/env python3
#
# .github/scripts/ci_job_setup.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Print the agent banner and point the temp variables at the job temp directory.

First step of every job in every workflow of this repository.
"""

import ipaddress
import os
import platform
import shutil
import socket
import subprocess
import sys
from pathlib import Path

from ci_output import REPO_URL, format_line
from ci_output import print_header as print_script_header

__author__ = "Gill-Bates"
SCRIPT = Path(__file__).resolve()
HELP_URL = f"{REPO_URL}/blob/main/.github/scripts/{SCRIPT.name}"
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
MASKED = "masked (not an RFC 1918 address)"
TEMP_VARIABLES = ("TMPDIR", "TMP", "TEMP")


def log(level: str, message: str) -> None:
	"""Print one line to stdout, unlike ci_output.log; level is info, warning or error."""
	github = os.environ.get("GITHUB_ACTIONS") == "true"
	print(format_line(level, message, github=github), flush=True)


def print_header() -> None:
	"""Print the script header; the output routine itself reads only GITHUB_ACTIONS."""
	summary = (__doc__ or "").strip().splitlines()
	print_script_header(SCRIPT, summary[0] if summary else "", __author__, HELP_URL, emit=log)


def in_rfc1918(address: str) -> bool:
	return any(ipaddress.ip_address(address) in net for net in RFC1918)


def private_ipv4() -> list[str] | None:
	"""Private IPv4 addresses of all interfaces, or None without a preinstalled psutil."""
	try:
		import psutil  # third-party; the standard library cannot list interface addresses
	except ImportError:
		return None
	found = {nic.address for nics in psutil.net_if_addrs().values() for nic in nics if nic.family == socket.AF_INET}
	return sorted((a for a in found if in_rfc1918(a)), key=ipaddress.ip_address)


def powershell_version() -> str | None:
	pwsh = shutil.which("pwsh")
	if pwsh is None:
		return None
	query = '$PSVersionTable.PSVersion.ToString() + " (" + $PSVersionTable.PSEdition + ")"'
	try:
		result = subprocess.run(  # noqa: S603 - fixed query for a resolved binary, no shell
			[pwsh, "-NoProfile", "-NonInteractive", "-Command", query],
			capture_output=True,
			text=True,
			timeout=30,
			check=True,
		)
	except OSError, subprocess.SubprocessError:
		return None
	return result.stdout.strip() or None


def outbound_ipv4() -> str | None:
	"""Local address the OS picks for the default route; a UDP connect sends no datagram."""
	try:
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
			probe.connect(("192.0.2.1", 9))  # RFC 5737 documentation address, never contacted
			address = probe.getsockname()[0]
	except OSError:
		return None
	return None if address == "0.0.0.0" else address  # noqa: S104 compares, does not bind


def print_banner() -> None:
	log("info", "========== Agent Network Information ==========")
	log("info", f"Hostname: {socket.gethostname()}")
	log("info", f"OS: {platform.platform()}")
	log(
		"info",
		f"Python: {platform.python_version()} ({platform.python_implementation()})",
	)
	pwsh_version = powershell_version()
	if pwsh_version:
		log("info", f"PowerShell: {pwsh_version}")
	addresses = private_ipv4()
	if addresses is None:
		log("info", "Agent Private IP: not available (psutil is not preinstalled)")
	for address in addresses or []:
		log("info", f"Agent Private IP: {address}")
	outbound = outbound_ipv4()
	if outbound is None:
		outbound = "not available"
	elif not in_rfc1918(outbound):
		outbound = MASKED
	log("info", f"Agent Outbound IP: {outbound}")


def point_temp_at_runner_temp() -> int:
	"""Append TMPDIR, TMP and TEMP to GITHUB_ENV; only a validated single-line path is written."""
	env_file = os.environ.get("GITHUB_ENV")
	runner_temp = os.environ.get("RUNNER_TEMP", "")
	if not env_file:
		log("info", "GITHUB_ENV is not set: temp variables stay unchanged (local run).")
		return 0
	if not runner_temp or any(c in runner_temp for c in "\r\n\0") or not Path(runner_temp).is_dir():
		log(
			"error",
			"RUNNER_TEMP is empty, multi-line or not a directory; refusing to write GITHUB_ENV.",
		)
		return 1
	with Path(env_file).open("a", encoding="utf-8") as handle:
		handle.writelines(f"{name}={runner_temp}\n" for name in TEMP_VARIABLES)
	log("info", f"Temp variables {', '.join(TEMP_VARIABLES)} point at RUNNER_TEMP.")
	return 0


def main() -> int:
	sys.stdout.reconfigure(line_buffering=True)
	print_header()
	print_banner()
	return point_temp_at_runner_temp()


if __name__ == "__main__":
	sys.exit(main())
