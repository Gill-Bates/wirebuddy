#!/usr/bin/env python3
#
# .github/scripts/trivy_report.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Validate a Trivy JSON report, state its available scan evidence and print a verdict.

Exit 0: valid report with required scan evidence (findings are counted, not failed on).
Exit 1: findings present and --fail-on-findings was given.
Exit 2: scanner evidence is invalid, such as a missing report or scan input, or a report
of another artifact than --expect-ref names.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from ci_output import REPO_URL, log, print_header

__author__ = "Gill-Bates"
SCRIPT = Path(__file__).resolve()
HELP_URL = f"{REPO_URL}/blob/main/.github/scripts/{SCRIPT.name}"

CLASSES = ("os-pkgs", "lang-pkgs", "secret")
# Report schema this gate was written against; an unknown one is refused, not guessed at.
SUPPORTED_SCHEMA_VERSIONS = (2,)
SCOPE_LINE = "_Scope: HIGH/CRITICAL findings from enabled scanners; vulnerability scans exclude unfixed CVEs and `.trivyignore` entries._"
# Trivy log lines that mean the scan gated on nothing or on stale rules.
FORBIDDEN_LOG_LINES = ("No enabled scanners found", "Falling back to embedded checks")
# Logged by Trivy (pkg/commands/artifact/run.go, v0.70.0) only when the secret scanner is on.
SCANNER_ENABLED_LOG_LINE = "Secret scanning is enabled"
SCAN_EVIDENCE_NOTE = (
	"Secret-scan evidence is limited to the enabled-scanner log and a non-empty input; Trivy's clean JSON report does not include a scanned-file count."
)
FAILED_PREFIX = "❌ Scan evaluation failed: "


class ScanError(Exception):
	"""The report or available scan evidence is missing or invalid."""


def load_report(path: Path) -> dict[str, Any]:
	"""Read the report and check it is a Trivy report with a supported SchemaVersion."""
	try:
		data = json.loads(path.read_text(encoding="utf-8"))
	except (OSError, ValueError) as exc:
		raise ScanError(f"report missing or unreadable ({exc.__class__.__name__})") from exc
	version = data.get("SchemaVersion") if isinstance(data, dict) else None
	if not isinstance(version, int) or isinstance(version, bool):
		raise ScanError("not a Trivy report (SchemaVersion is not an integer)")
	if version not in SUPPORTED_SCHEMA_VERSIONS:
		raise ScanError(f"unsupported Trivy report SchemaVersion {version}")
	results = data.get("Results")
	if results is not None and not (isinstance(results, list) and all(isinstance(r, dict) for r in results)):
		raise ScanError("Results is not a list of objects")
	return data


def results_of(report: dict[str, Any]) -> list[dict[str, Any]]:
	return report.get("Results") or []


def input_is_present(path: Path) -> bool:
	"""A scan input counts as present when it is a non-empty file or directory."""
	if path.is_dir():
		return any(path.iterdir())
	return path.is_file() and path.stat().st_size > 0


def prove_coverage(report: dict[str, Any], classes: list[str], scan_input: Path | None) -> list[str]:
	"""Return one line per available coverage proof; raise on the first missing proof."""
	covered: list[str] = []
	for cls in dict.fromkeys(classes):
		if cls == "secret":
			# Clean secret reports have no Results, so the non-empty input is the report-side evidence.
			if scan_input is None or not input_is_present(scan_input):
				raise ScanError("secret scan input missing or empty")
			covered.append(f"secret input: {scan_input} is present and non-empty")
			continue
		proofs = [r for r in results_of(report) if r.get("Class") == cls and isinstance(r.get("Packages"), list) and r["Packages"]]
		if not proofs:
			raise ScanError(f"no {cls} result with Packages in the report (scan without list-all-pkgs?)")
		covered.extend(f"{cls}: {r.get('Target', 'unknown target')}, {len(r['Packages'])} packages" for r in proofs)
	return covered


def prove_targets(report: dict[str, Any], targets: list[str]) -> list[str]:
	"""Each named target must be a result that lists packages, so a clean file counts."""
	covered: list[str] = []
	for target in dict.fromkeys(targets):
		hits = [r for r in results_of(report) if r.get("Target") == target and isinstance(r.get("Packages"), list) and r["Packages"]]
		if not hits:
			raise ScanError(f"scan target {target} has no result with packages")
		covered.append(f"target: {target}, {len(hits[0]['Packages'])} packages")
	return covered


def prove_ref(report: dict[str, Any], ref: str) -> str:
	"""The report must describe the scanned artifact, so a valid report of another image fails."""
	if not ref.strip():
		raise ScanError("expected artifact reference is empty")
	metadata = report.get("Metadata") if isinstance(report.get("Metadata"), dict) else {}
	names = [
		report.get("ArtifactName"),
		*(metadata.get("RepoTags") or []),
		*(metadata.get("RepoDigests") or []),
	]
	for name in names:
		if isinstance(name, str) and ref in name:
			return f"artifact: {name}"
	raise ScanError(f"report describes {report.get('ArtifactName')!r}, expected {ref!r}")


def check_scanner_log(path: Path, required: tuple[str, ...] = ()) -> None:
	"""Fail on a scan on nothing or on embedded rules, or on a missing required line."""
	try:
		lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
	except OSError as exc:
		raise ScanError(f"scanner log missing or unreadable ({exc.__class__.__name__})") from exc
	for marker in FORBIDDEN_LOG_LINES:
		if any(marker.lower() in line.lower() for line in lines):
			raise ScanError(f"scanner log contains '{marker}'")
	for marker in required:
		if not any(marker.lower() in line.lower() for line in lines):
			raise ScanError(f"scanner log lacks '{marker}'")


def _clean(value: Any) -> str:
	"""Make a report value safe for a markdown code block."""
	return re.sub(r"[`\r\n\t]+", " ", str(value))


def collect_findings(report: dict[str, Any]) -> list[tuple[str, str, str, str]]:
	"""Return (severity, id, subject, detail) for every HIGH or CRITICAL finding."""
	rows: list[tuple[str, str, str, str]] = []
	for r in results_of(report):
		rows.extend(
			(
				v.get("Severity", ""),
				v.get("VulnerabilityID", ""),
				v.get("PkgName", ""),
				v.get("InstalledVersion", ""),
			)
			for v in r.get("Vulnerabilities") or []
		)
		rows.extend(
			(m.get("Severity", ""), m.get("ID", ""), r.get("Target", ""), "") for m in r.get("Misconfigurations") or [] if m.get("Status", "FAIL") == "FAIL"
		)
		rows.extend((s.get("Severity", ""), s.get("RuleID", ""), r.get("Target", ""), "") for s in r.get("Secrets") or [])
	return [row for row in rows if row[0] in ("CRITICAL", "HIGH")]


def verdict_line(critical: int, high: int) -> str:
	if critical + high > 0:
		return f"⚠️ {critical} CRITICAL, {high} HIGH findings"
	return "✅ No HIGH/CRITICAL findings"


def render(title: str | None, verdict: str, rows: list[tuple[str, ...]], limit: int) -> str:
	"""Build stdout: the bare verdict line, or the full summary block with a title."""
	if title is None:
		return verdict
	lines = [f"### {_clean(title)}", verdict]
	if verdict.startswith(FAILED_PREFIX):
		return "\n".join(lines)
	lines += ["", SCOPE_LINE]
	if rows and limit > 0:
		lines.append("```")
		lines.extend("\t".join(_clean(c) for c in row) for row in rows[:limit])
		lines.append("```")
	return "\n".join(lines)


def run_status(args: argparse.Namespace) -> int:
	report = load_report(args.report)
	# A clean secret scan has no Results, so the log must show the scanner was enabled.
	required = (SCANNER_ENABLED_LOG_LINE,) if "secret" in args.expect_class else ()
	if required and args.log_file is None:
		raise ScanError("secret scan needs --log-file to prove the scanner ran")
	if args.log_file is not None:
		check_scanner_log(args.log_file, required)
	if args.expect_ref is not None:
		log("info", f"Scan evidence: {prove_ref(report, args.expect_ref)}")
	covered = prove_coverage(report, args.expect_class, args.input)
	for line in [*covered, *prove_targets(report, args.expect_target)]:
		log("info", f"Scan evidence: {line}")
	rows = collect_findings(report)
	critical = sum(1 for row in rows if row[0] == "CRITICAL")
	high = len(rows) - critical
	verdict = verdict_line(critical, high)
	summary = render(args.summary_title, verdict, rows, args.list)
	if "secret" in args.expect_class:
		summary = f"{summary}\n\n_{SCAN_EVIDENCE_NOTE}_"
	print(summary)
	if rows and args.fail_on_findings:
		log("error", verdict)
		return 1
	return 0


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description=(__doc__ or "").strip().splitlines()[0])
	sub = parser.add_subparsers(dest="command", required=True)
	status = sub.add_parser("status", help="Evaluate one report.")
	status.add_argument("report", type=Path, help="Trivy JSON report")
	status.add_argument(
		"--expect-class",
		action="append",
		choices=CLASSES,
		required=True,
		help="Result class the scan must cover; repeat for several",
	)
	status.add_argument(
		"--expect-target",
		action="append",
		default=[],
		help="Result target that must list packages; repeat for several",
	)
	status.add_argument(
		"--expect-ref",
		help="Image reference the report must describe (ArtifactName, RepoTags or RepoDigests)",
	)
	status.add_argument("--log-file", type=Path, help="Captured scanner log; required for class secret")
	status.add_argument("--input", type=Path, help="Scan input, required for 'secret'")
	status.add_argument("--fail-on-findings", action="store_true", help="Exit 1 on findings")
	status.add_argument("--summary-title", help="Print a markdown summary under this heading")
	status.add_argument("--list", type=int, default=0, help="List up to N findings")
	return parser


def main(argv: list[str] | None = None) -> int:
	sys.stdout.reconfigure(line_buffering=True, encoding="utf-8")  # type: ignore[attr-defined]
	print_header(SCRIPT, (__doc__ or "").strip().splitlines()[0], __author__, HELP_URL)
	args = build_parser().parse_args(argv)
	try:
		return run_status(args)
	except ScanError as exc:
		verdict = f"{FAILED_PREFIX}{exc}"
		log("error", verdict)
		print(render(args.summary_title, verdict, [], 0))
		return 2


if __name__ == "__main__":
	sys.exit(main())
