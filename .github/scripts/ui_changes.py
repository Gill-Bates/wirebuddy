#!/usr/bin/env python3
#
# .github/scripts/ui_changes.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Decide whether the Playwright layout job has to run (output `ui=true|false`).

Reads EVENT_NAME, REF, BEFORE and AFTER (push) or BASE and HEAD (pull request) from the
environment. Anything unclear (no comparison base, failed git diff) answers true.
"""

import os
import subprocess
import sys
from pathlib import Path

from ci_output import REPO_URL, log, write_outputs
from ci_output import print_header as print_script_header

__author__ = "Gill-Bates"
SCRIPT = Path(__file__).resolve()
HELP_URL = f"{REPO_URL}/blob/main/.github/scripts/{SCRIPT.name}"
NO_BASE = "0" * 40

# The suite starts the real app, so any app/ file can change a page or the login; only
# AGENTS.md files and bytecode are exempt (IGNORED_SUFFIXES). When in doubt a path is listed.
PREFIXES = (
	"app/",
	"tests/layout/",
	"tests/e2e/run_server.py",
	"tools/ci-seed-admin.py",
	"tools/pyproject-deps.py",
	"package.json",
	"package-lock.json",
	"pyproject.toml",
	".github/workflows/ci.yml",
	".github/scripts/ci_job_setup.py",
	".github/scripts/ci_output.py",
	".github/scripts/ui_changes.py",
)
IGNORED_SUFFIXES = ("/AGENTS.md", ".pyc")


def is_ui_relevant(path: str) -> bool:
	"""Return True when a changed file can affect the layout suite."""
	return path.startswith(PREFIXES) and not path.endswith(IGNORED_SUFFIXES)


def decide(event: str, ref: str, files: list[str] | None) -> tuple[bool, str]:
	"""Return (run, reason); `files` is None when the change list is unknown."""
	if event == "workflow_dispatch":
		return True, "manual run"
	if ref.startswith("refs/tags/v"):
		return True, "release tag"
	if files is None:
		return True, "change list unknown (fail-open)"
	hits = [path for path in files if is_ui_relevant(path)]
	if hits:
		return True, f"UI-relevant change: {', '.join(hits[:5])}"
	return False, f"no UI-relevant change in {len(files)} file(s)"


def changed_files(event: str, env: dict[str, str]) -> list[str] | None:
	"""List the changed paths, or None when no reliable comparison exists."""
	if event == "pull_request":
		base, head, separator = env.get("BASE", ""), env.get("HEAD", ""), "..."
	else:
		base, head, separator = env.get("BEFORE", ""), env.get("AFTER", ""), ".."
	if not base or not head or base == NO_BASE:
		return None
	try:
		result = subprocess.run(  # noqa: S603 - fixed argument vector, git resolved from PATH
			# --no-renames reports a move as delete + add, so the old (UI) path is seen too.
			["git", "diff", "--no-renames", "--name-only", "-z", f"{base}{separator}{head}", "--"],  # noqa: S607
			cwd=SCRIPT.parents[2],
			capture_output=True,
			check=False,
			timeout=30,
		)
	except (OSError, subprocess.TimeoutExpired) as exc:
		log("warning", f"git diff unavailable: {exc}; running the layout job")
		return None
	if result.returncode != 0:
		log("warning", f"git diff failed ({result.returncode}); running the layout job")
		return None
	return [p for p in result.stdout.decode("utf-8", "replace").split("\0") if p]


def main() -> int:
	print_script_header(SCRIPT, "Decide whether the layout job runs", __author__, HELP_URL)
	event = os.environ.get("EVENT_NAME", "")
	run, reason = decide(event, os.environ.get("REF", ""), None if event in ("workflow_dispatch", "") else changed_files(event, dict(os.environ)))
	log("info", f"layout job: {'run' if run else 'skip'} - {reason}")
	write_outputs({"ui": "true" if run else "false"})
	return 0


if __name__ == "__main__":
	sys.exit(main())
