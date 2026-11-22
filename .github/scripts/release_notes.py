#!/usr/bin/env python3
#
# .github/scripts/release_notes.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Compose the WireBuddy GitHub release notes from CHANGELOG.md, the published tags and the Trivy reports."""

import argparse
import sys
from pathlib import Path

import trivy_report
from ci_output import REPO_URL, log, print_header
from release_tags import DIGEST_RE, ReleaseTagsError, is_prerelease, release_version_key

__author__ = "Gill-Bates"
SCRIPT = Path(__file__).resolve()
HELP_URL = f"{REPO_URL}/blob/main/.github/scripts/{SCRIPT.name}"

MISSING_SECTION = "_No matching CHANGELOG entry found for this version._"


class ReleaseNotesError(Exception):
	"""The release notes cannot be assembled from the given inputs."""


def extract_release_section(changelog: str, version: str) -> str | None:
	"""Return the `## [<version>] - ...` section, or None when the changelog has none."""
	heading_prefix = f"## [{version}] - "
	lines = changelog.splitlines()
	start = next((index for index, line in enumerate(lines) if line.startswith(heading_prefix)), None)
	if start is None:
		return None
	# Older versions sit in a collapsed <details> block; its tags end the section too.
	boundaries = ("## [", "<details", "</details")
	end = next((index for index in range(start + 1, len(lines)) if lines[index].startswith(boundaries)), len(lines))
	return "\n".join(lines[start:end]).strip()


def trivy_verdict(arch: str, path: Path) -> str:
	"""Verdict of one image report; a missing or unproven report stops the release notes."""
	try:
		report = trivy_report.load_report(path)
		trivy_report.prove_coverage(report, ["os-pkgs", "lang-pkgs"], None)
	except trivy_report.ScanError as exc:
		raise ReleaseNotesError(f"Trivy report for {arch}: {exc}") from exc
	findings = trivy_report.collect_findings(report)
	critical = sum(1 for finding in findings if finding[0] == "CRITICAL")
	return trivy_report.verdict_line(critical, len(findings) - critical)


def compose_release_notes(
	*,
	version: str,
	changelog: str,
	image: str,
	index_digest: str,
	latest_moved: bool,
	run_url: str,
	asset_base: str,
	repo_url: str,
	trivy_reports: list[tuple[str, Path]],
) -> str:
	try:
		release_version_key(version)
	except ReleaseTagsError as exc:
		raise ReleaseNotesError(str(exc)) from exc
	if DIGEST_RE.fullmatch(index_digest) is None:
		raise ReleaseNotesError("index digest is not a sha256 digest")
	if not trivy_reports:
		raise ReleaseNotesError("no Trivy report given")
	if latest_moved and is_prerelease(version):
		raise ReleaseNotesError("a prerelease never moves latest")
	tags = [f"- `{image}:{version}` (multi-arch)"]
	if latest_moved:
		tags.append(f"- `{image}:latest` (multi-arch)")
	elif not is_prerelease(version):
		tags.append(f"- `{image}:latest` was left on a newer release")
	rows = [f"| {arch} | {trivy_verdict(arch, path)} | [trivy-{arch}.json]({asset_base}/trivy-{arch}.json) |" for arch, path in trivy_reports]
	section = extract_release_section(changelog, version)
	if section is None:
		log("warning", f"No matching CHANGELOG section for {version}; the release notes carry a hint instead.")
	lines = [
		f"## WireBuddy {version}",
		"",
		f"**Docker Image:** `docker pull {image}:{version}`",
		"",
		"### Available Tags",
		*tags,
		"",
		f"Index digest: `{index_digest}` (rollback target: `{image}@{index_digest}`)",
		"",
		"### Security Scan Results",
		"",
		"| Architecture | Status | Findings |",
		"|---|---|---|",
		*rows,
		f"| run | workflow details | [Actions Run]({run_url}) |",
		"",
		trivy_report.SCOPE_LINE,
		"",
		"### Changelog",
		section or MISSING_SECTION,
		"",
		f"**Source:** [WireBuddy Repository]({repo_url})",
	]
	return "\n".join(lines) + "\n"


def parse_trivy_report(value: str) -> tuple[str, Path]:
	arch, separator, path = value.partition("=")
	if not separator or not arch or not path:
		raise argparse.ArgumentTypeError("expected ARCH=PATH")
	return arch, Path(path)


def parse_bool(value: str) -> bool:
	if value not in ("true", "false"):
		raise argparse.ArgumentTypeError("expected true or false")
	return value == "true"


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description=(__doc__ or "").strip().splitlines()[0])
	parser.add_argument("--version", required=True)
	parser.add_argument("--changelog", type=Path, required=True)
	parser.add_argument("--image", required=True, help="Image name without tag, e.g. owner/wirebuddy")
	parser.add_argument("--index-digest", required=True)
	parser.add_argument("--latest-moved", type=parse_bool, required=True, metavar="true|false")
	parser.add_argument("--run-url", required=True)
	parser.add_argument("--asset-base", required=True, help="Download URL prefix of the release assets")
	parser.add_argument("--repo-url", required=True)
	parser.add_argument("--trivy-report", action="append", type=parse_trivy_report, required=True, metavar="ARCH=PATH")
	parser.add_argument("--output", type=Path, required=True)
	return parser


def main(argv: list[str] | None = None) -> int:
	if hasattr(sys.stdout, "reconfigure"):  # a test may swap stdout for a StringIO
		sys.stdout.reconfigure(line_buffering=True, encoding="utf-8")
	print_header(SCRIPT, (__doc__ or "").strip().splitlines()[0], __author__, HELP_URL)
	args = build_parser().parse_args(argv)
	try:
		try:
			changelog = args.changelog.read_text(encoding="utf-8")
		except OSError as exc:
			log("warning", f"Could not read {args.changelog} ({exc.__class__.__name__}).")
			changelog = ""
		notes = compose_release_notes(
			version=args.version,
			changelog=changelog,
			image=args.image,
			index_digest=args.index_digest,
			latest_moved=args.latest_moved,
			run_url=args.run_url,
			asset_base=args.asset_base,
			repo_url=args.repo_url,
			trivy_reports=args.trivy_report,
		)
		args.output.write_text(notes, encoding="utf-8")
	except (OSError, UnicodeError, ReleaseNotesError) as exc:
		log("error", f"could not build release notes: {exc}")
		return 1
	log("info", f"Wrote release notes for v{args.version} to {args.output}")
	return 0


if __name__ == "__main__":
	sys.exit(main())
