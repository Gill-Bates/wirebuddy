#!/usr/bin/env python3
#
# .github/scripts/failure_issue.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Open or update the one tracking issue of a failed workflow run.

Runs inside GitHub Actions with GH_TOKEN set; the issue is found by its exact title.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from ci_output import REPO_URL, log, print_header

__author__ = "Gill-Bates"
SCRIPT = Path(__file__).resolve()
HELP_URL = f"{REPO_URL}/blob/main/.github/scripts/{SCRIPT.name}"
REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
NUMBER_RE = re.compile(r"^[0-9]{1,12}$")
SERVER_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:[0-9]+)?$")
RUN_URL_RE = re.compile(
	r"https://[A-Za-z0-9.-]+(?::[0-9]+)?/"
	r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*/"
	r"actions/runs/[0-9]{1,12}/attempts/[0-9]{1,12}(?![A-Za-z0-9/_-])"
)
TITLE_MAX = 120
GH_TIMEOUT_SECONDS = 60
SEARCH_LIMIT = 100
LIST_LIMIT = 1000


class IssueError(Exception):
	"""A failure that ends the run with exit code 1."""


def gh(*args: str) -> str:
	"""Run the GitHub CLI and return stdout; a failure carries gh's own message."""
	gh_bin = shutil.which("gh")
	if gh_bin is None:
		raise IssueError("the GitHub CLI (gh) is not installed on this runner")
	try:
		result = subprocess.run(  # noqa: S603 - argument list for a resolved binary, no shell
			[gh_bin, *args],
			capture_output=True,
			text=True,
			timeout=GH_TIMEOUT_SECONDS,
			check=False,
		)
	except (OSError, subprocess.SubprocessError) as exc:
		raise IssueError(f"gh {args[0]} failed: {exc}") from exc
	if result.returncode != 0:
		raise IssueError(f"gh {' '.join(args[:2])} failed: {result.stderr.strip()}")
	return result.stdout


def env_value(name: str, pattern: re.Pattern[str]) -> str:
	value = os.environ.get(name, "")
	if not pattern.match(value):
		raise IssueError(f"{name} is missing or malformed")
	return value


def run_url() -> str:
	"""Build the URL of the failed run attempt from the Actions environment."""
	server = env_value("GITHUB_SERVER_URL", SERVER_RE)
	repo = env_value("GITHUB_REPOSITORY", REPO_RE)
	run_id = env_value("GITHUB_RUN_ID", NUMBER_RE)
	attempt = env_value("GITHUB_RUN_ATTEMPT", NUMBER_RE)
	return f"{server}/{repo}/actions/runs/{run_id}/attempts/{attempt}"


def _list_issues(repo: str, limit: int, search: str | None = None) -> list[dict]:
	args = ["issue", "list", "--repo", repo, "--state", "open", "--limit", str(limit)]
	if search is not None:
		args += ["--search", search]
	listing = gh(*args, "--json", "number,title")
	try:
		issues = json.loads(listing)
		return [{"number": int(i["number"]), "title": i["title"]} for i in issues]
	except (ValueError, KeyError, TypeError) as exc:
		raise IssueError(f"unexpected issue list from gh: {exc}") from exc


def find_issue(repo: str, title: str) -> int | None:
	"""Return the number of the open issue with exactly this title."""
	# The fallback covers a search index that lags behind a newly created issue.
	term = f'"{title.replace(chr(34), " ")}" in:title'
	issues = _list_issues(repo, SEARCH_LIMIT, term)
	matches = [i["number"] for i in issues if i["title"] == title]
	if matches:
		return min(matches)
	issues = _list_issues(repo, LIST_LIMIT)
	matches = [i["number"] for i in issues if i["title"] == title]
	return min(matches) if matches else None


def mentions_run(repo: str, number: int, url: str) -> bool:
	"""True when the issue already names this run attempt, so a rerun adds nothing."""
	view = gh("issue", "view", str(number), "--repo", repo, "--json", "body,comments")
	try:
		data = json.loads(view)
		texts = [str(data.get("body", ""))]
		texts += [str(c.get("body", "")) for c in data.get("comments") or []]
	except (ValueError, AttributeError, TypeError) as exc:
		raise IssueError(f"unexpected issue view from gh: {exc}") from exc
	return any(match.group(0) == url for text in texts for match in RUN_URL_RE.finditer(text))


def build_body(workflow: str, event: str, url: str) -> str:
	stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
	return (
		f"The scheduled workflow **{workflow}** failed ({event}, {stamp}).\n\n"
		f"Run: {url}\n\n"
		"The run summary lists the affected packages and the failed step. This issue "
		"stays open while the failure recurs; a later failed run adds a comment. "
		"Close it once a run is green again."
	)


def run(args: argparse.Namespace) -> None:
	repo = env_value("GITHUB_REPOSITORY", REPO_RE)
	url = run_url()
	body = build_body(
		os.environ.get("GITHUB_WORKFLOW", "unknown workflow"),
		os.environ.get("GITHUB_EVENT_NAME", "unknown event"),
		url,
	)
	number = find_issue(repo, args.title)
	if number is None:
		created = gh("issue", "create", "--repo", repo, "--title", args.title, "--body", body).strip()
		log("info", f"Opened tracking issue: {created}")
		return
	if mentions_run(repo, number, url):
		log("info", f"Issue #{number} already names this run attempt")
		return
	gh("issue", "comment", str(number), "--repo", repo, "--body", body)
	log("info", f"Added a comment to tracking issue #{number}")


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description=(__doc__ or "").strip().splitlines()[0])
	parser.add_argument("--title", required=True, help="Exact title of the one tracking issue")
	return parser


def main(argv: list[str] | None = None) -> int:
	print_header(SCRIPT, (__doc__ or "").strip().splitlines()[0], __author__, HELP_URL)
	args = build_parser().parse_args(argv)
	try:
		if not args.title.strip() or len(args.title) > TITLE_MAX or "\n" in args.title:
			raise IssueError(f"the title must be one line of 1 to {TITLE_MAX} chars")
		run(args)
	except (IssueError, OSError, ValueError) as exc:
		log("error", str(exc))
		return 1
	return 0


if __name__ == "__main__":
	sys.exit(main())
