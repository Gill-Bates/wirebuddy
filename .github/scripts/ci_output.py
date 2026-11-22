#!/usr/bin/env python3
#
# .github/scripts/ci_output.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Shared header and level output for the CI tools in this directory."""

import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

REPO_URL = "https://github.com/Gill-Bates/wirebuddy"
COMMIT_VARIABLES = ("GITHUB_SHA",)


def neutralize(text: str) -> str:
	"""Keep untrusted text on one line and break workflow command tokens."""
	text = " ".join(str(text).splitlines())
	text = text.replace("##[", "## [")
	return re.sub(r"^(\s*)::", r"\1: :", text)


def format_line(level: str, message: str, *, github: bool) -> str:
	"""Return one log line that carries its level once."""
	text = neutralize(message)
	if level == "info":
		return text
	if github:
		return f"::{level}::{text}"
	return f"{level.upper()}: {text}"


def log(level: str, message: str) -> None:
	"""Print one line to stderr; stdout stays reserved for the tool's data."""
	github = os.environ.get("GITHUB_ACTIONS") == "true"
	print(format_line(level, message, github=github), file=sys.stderr, flush=True)


def write_outputs(values: dict[str, str]) -> None:
	"""Print key=value lines and append them to GITHUB_OUTPUT when it is set.

	A value with a line break would start a second assignment, so it is refused.
	"""
	for key, value in values.items():
		if "\n" in value or "\r" in value or "=" in key or not key:
			raise ValueError(f"Refusing to write output '{key}': not a single line")
	lines = [f"{key}={value}" for key, value in values.items()]
	target = os.environ.get("GITHUB_OUTPUT")
	if target:
		with Path(target).open("a", encoding="utf-8") as handle:
			handle.write("\n".join(lines) + "\n")
	for line in lines:
		print(line)


def git(script: Path, *args: str) -> str | None:
	"""Return git's answer for the script's directory, or None without git or a checkout."""
	git_bin = shutil.which("git")
	if git_bin is None:
		return None
	try:
		result = subprocess.run(  # noqa: S603 - fixed argument list, resolved binary, no shell
			[git_bin, "-C", str(script.parent), *args],
			capture_output=True,
			text=True,
			timeout=30,
			check=False,
		)
	except OSError, subprocess.SubprocessError:
		return None
	if result.returncode != 0:
		return None
	return result.stdout.strip() or None


def commit(script: Path) -> str:
	sha = git(script, "rev-parse", "HEAD")
	if sha:
		return sha
	for name in COMMIT_VARIABLES:
		if os.environ.get(name):
			return f"{os.environ[name]} (from {name})"
	return "unknown"


def print_header(
	script: Path,
	description: str,
	author: str,
	help_url: str,
	emit: Callable[[str, str], None] = log,
) -> None:
	"""Print the script header (to stderr unless `emit` says otherwise) before argument parsing.

	It reads only git metadata and the commit variables in COMMIT_VARIABLES; the default
	`emit` (log) also reads GITHUB_ACTIONS to pick the line format.
	"""
	source = git(script, "ls-files", "--full-name", "--", script.name) or "unknown"
	emit("info", f"Script: {script.name}")
	emit("info", f"Description: {description}")
	emit("info", f"Version: {commit(script)}")
	emit("info", f"Source: {source}")
	emit("info", f"Author: {author}")
	emit("info", f"Help: {help_url}")
