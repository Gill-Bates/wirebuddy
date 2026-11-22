#!/usr/bin/env python3
#
# .github/scripts/test_workflow_contracts.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Structural contracts of the workflows that no single run would notice drifting.

Text and regex parsing only, so the module runs on the stdlib like its siblings.
"""

import json
import re
import unittest
from pathlib import Path

import release_tags

WORKFLOWS = Path(__file__).resolve().parent.parent / "workflows"
NAMES = ("ci", "docker-build", "security", "docs-build")
JOB_RE = re.compile(r"^  ([A-Za-z0-9_-]+):$")
WRITE_RE = re.compile(r"^\s+([a-z-]+): write\s*$")
USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$")
PINNED_RE = re.compile(r"^\S+@[0-9a-f]{40} # v\S+$")
VERSION_GREP_RE = re.compile(r"""echo "\$VERSION" \| grep -qE '([^']+)'""")


def workflow(name: str) -> str:
	return (WORKFLOWS / f"{name}.yml").read_text(encoding="utf-8")


def split_jobs(text: str) -> tuple[str, dict[str, str]]:
	"""Return the text before `jobs:` and every job's block, keyed by job id."""
	lines = text.splitlines()
	start = lines.index("jobs:")
	jobs: dict[str, list[str]] = {}
	current: list[str] | None = None
	for line in lines[start + 1 :]:
		match = JOB_RE.match(line)
		if match:
			current = jobs.setdefault(match.group(1), [])
		elif re.match(r"^  \S", line) or re.match(r"^\S", line):
			current = None
		if current is not None:
			current.append(line)
	return "\n".join(lines[:start]), {job: "\n".join(body) for job, body in jobs.items()}


def job_block(name: str, job_id: str) -> str:
	jobs = split_jobs(workflow(name))[1]
	if job_id not in jobs:
		raise AssertionError(f"{name}.yml has no job {job_id}")
	return jobs[job_id]


class PlatformContractTest(unittest.TestCase):
	def test_rescan_platforms_equal_build_matrix_and_release_arches(self):
		match = re.search(r"BUILD_MATRIX: >-\n((?:[ \t]+.*\n)+?)[ \t]+run:", workflow("docker-build"))
		self.assertIsNotNone(match, "BUILD_MATRIX not found in docker-build.yml")
		matrix = {entry["platform"] for entry in json.loads(match.group(1))["include"]}
		expected = re.search(r"EXPECTED_PLATFORMS: '([^']*)'", workflow("security"))
		self.assertIsNotNone(expected, "EXPECTED_PLATFORMS not found in security.yml")
		self.assertEqual(matrix, set(expected.group(1).split()))
		self.assertEqual(matrix, {f"linux/{arch}" for arch in release_tags.ARCHES})


class VersionRegexContractTest(unittest.TestCase):
	def test_workflow_version_checks_equal_release_tags_rule(self):
		for name in ("ci", "docker-build"):
			patterns = VERSION_GREP_RE.findall(workflow(name))
			self.assertEqual(patterns, [release_tags.RELEASE_VERSION_RE.pattern], name)

	def test_version_rule_samples(self):
		for version in ("1.2.3", "1.2.3-rc.1", "10.0.0-beta-2"):
			self.assertIsNotNone(release_tags.RELEASE_VERSION_RE.fullmatch(version), version)
		for version in ("v1.2.3", "1.2", "1.2.3-", "1.2.3+build", "1.2.3-rc..1"):
			self.assertIsNone(release_tags.RELEASE_VERSION_RE.fullmatch(version), version)


class PermissionContractTest(unittest.TestCase):
	EXPECTED_WRITES = frozenset(
		{
			("docker-build", "create-release", "contents"),
			("docs-build", "deploy", "pages"),
			("docs-build", "deploy", "id-token"),
			("docs-build", "report-failure", "issues"),
			("security", "report-failure", "issues"),
		}
	)

	def test_write_permissions_are_exactly_the_known_set(self):
		writes = set()
		for name in NAMES:
			head, jobs = split_jobs(workflow(name))
			self.assertFalse([line for line in head.splitlines() if WRITE_RE.match(line)], f"{name}.yml grants write at workflow level")
			for job, block in jobs.items():
				writes.update((name, job, match.group(1)) for line in block.splitlines() if (match := WRITE_RE.match(line)))
		self.assertEqual(writes, self.EXPECTED_WRITES)

	def test_no_shorthand_or_flow_style_write_grant(self):
		# The block-style scan above would miss these forms.
		for name in NAMES:
			text = workflow(name)
			self.assertNotRegex(text, r"(?m)^\s*permissions:\s*write-all\b", name)
			self.assertNotRegex(text, r"(?m)^\s*permissions:\s*\{[^}]*:\s*write", name)

	def test_rescan_never_logs_in_or_pushes(self):
		text = workflow("security")
		for forbidden in ("docker/login-action", "imagetools create", "docker push"):
			self.assertNotIn(forbidden, text)


class ReleaseJobContractTest(unittest.TestCase):
	def test_fragment_cleanup_takes_arches_from_meta(self):
		block = job_block("docker-build", "cleanup-arch-tags")
		self.assertNotIn("download-artifact", block)
		self.assertIn("needs.meta.outputs.arches", block)

	def test_build_scans_before_the_push_login(self):
		block = job_block("docker-build", "build")
		steps = ("name: Trivy vulnerability scan", "name: Summarize Trivy report", "name: Log in to Docker Hub (push)")
		positions = [block.find(step) for step in steps]
		self.assertNotIn(-1, positions, positions)
		self.assertEqual(positions, sorted(positions))
		self.assertNotIn("continue-on-error", block)

	def test_release_runs_the_ci_gate_first(self):
		ci = workflow("ci")
		self.assertRegex(ci, r'(?m)^  push:\n    branches:\n      - "\*\*"$')
		self.assertRegex(ci, r"(?m)^  workflow_dispatch:")
		self.assertRegex(ci, r"(?m)^  workflow_call:\n    secrets:\n(?:      #.*\n)*      RELEASE_TOKEN:\n        required: true$")
		gate = job_block("docker-build", "ci")
		self.assertIn("uses: ./.github/workflows/ci.yml", gate)
		self.assertIn("RELEASE_TOKEN: ${{ secrets.RELEASE_TOKEN }}", gate)
		needs = re.search(r"(?m)^    needs: \[([^\]]*)\]$", job_block("docker-build", "build"))
		self.assertIsNotNone(needs, "build job has no needs list")
		self.assertTrue({"meta", "ci"} <= {item.strip() for item in needs.group(1).split(",")})


class ToolingContractTest(unittest.TestCase):
	def test_no_trivy_result_defaults_to_zero(self):
		for name in NAMES:
			self.assertNotIn("|| echo 0", workflow(name), name)

	def test_actions_are_pinned_to_a_full_sha_with_version_comment(self):
		for name in NAMES:
			for line in workflow(name).splitlines():
				match = USES_RE.match(line)
				if match and not match.group(1).startswith("./"):
					self.assertRegex(f"{match.group(1)}{match.group(2)}", PINNED_RE, f"{name}.yml: {line.strip()}")

	def test_source_scan_installs_a_checksum_verified_trivy(self):
		block = job_block("ci", "source-scan")
		self.assertRegex(block, r'TRIVY_VERSION: "[0-9]+\.[0-9]+\.[0-9]+"')
		self.assertRegex(block, r"TRIVY_SHA256: [0-9a-f]{64}\b")
		check, scan = block.find("sha256sum --check --strict"), block.find("trivy fs")
		self.assertNotEqual(check, -1, "no checksum check in source-scan")
		self.assertLess(check, scan)
		for name in NAMES:
			self.assertNotIn("aquasecurity/setup-trivy", workflow(name), name)


if __name__ == "__main__":
	unittest.main()
