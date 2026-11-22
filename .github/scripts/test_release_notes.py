#!/usr/bin/env python3
#
# .github/scripts/test_release_notes.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import release_notes

DIGEST = "sha256:" + "c" * 64
CHANGELOG = """## [1.8.0] - 2026-12-01
- ``New`` Feature A.
- ``Fix`` Bug B.
<details markdown="1">
<summary>Previous versions...</summary>
## [1.7.0] - 2026-10-28
- ``New`` Old feature.
</details>
"""


def report(vulnerabilities=()):
	return {
		"SchemaVersion": 2,
		"Results": [
			{"Target": "debian", "Class": "os-pkgs", "Packages": [{"Name": "libc"}], "Vulnerabilities": list(vulnerabilities)},
			{"Target": "python", "Class": "lang-pkgs", "Packages": [{"Name": "fastapi"}]},
		],
	}


class SectionTest(unittest.TestCase):
	def test_first_entry_stops_at_details(self):
		section = release_notes.extract_release_section(CHANGELOG, "1.8.0")
		self.assertTrue(section.startswith("## [1.8.0] - 2026-12-01"))
		self.assertIn("Bug B.", section)
		self.assertNotIn("details", section)
		self.assertNotIn("1.7.0", section)

	def test_older_entry_stops_at_closing_details(self):
		section = release_notes.extract_release_section(CHANGELOG, "1.7.0")
		self.assertEqual(section, "## [1.7.0] - 2026-10-28\n- ``New`` Old feature.")

	def test_missing_section(self):
		self.assertIsNone(release_notes.extract_release_section(CHANGELOG, "1.9.0"))


class ComposeTest(unittest.TestCase):
	def setUp(self):
		self.tmp = tempfile.TemporaryDirectory(prefix="release-notes-test-")
		self.addCleanup(self.tmp.cleanup)
		self.dir = Path(self.tmp.name)

	def write_report(self, arch, data):
		path = self.dir / f"trivy-{arch}.json"
		path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
		return arch, path

	def compose(self, version="1.8.0", latest_moved=True, reports=None, changelog=CHANGELOG):
		return release_notes.compose_release_notes(
			version=version,
			changelog=changelog,
			image="owner/wirebuddy",
			index_digest=DIGEST,
			latest_moved=latest_moved,
			run_url="https://github.com/o/r/actions/runs/1",
			asset_base="https://github.com/o/r/releases/download/v1.8.0",
			repo_url="https://github.com/o/r",
			trivy_reports=reports if reports is not None else [self.write_report("amd64", report()), self.write_report("arm64", report())],
		)

	def test_stable_newest_lists_latest_digest_and_changelog(self):
		notes = self.compose()
		self.assertIn("- `owner/wirebuddy:latest` (multi-arch)", notes)
		self.assertIn(f"owner/wirebuddy@{DIGEST}", notes)
		self.assertIn("Bug B.", notes)
		self.assertIn("| amd64 | ✅ No HIGH/CRITICAL findings | [trivy-amd64.json]", notes)

	def test_older_stable_and_prerelease_tag_lines(self):
		self.assertIn("was left on a newer release", self.compose(latest_moved=False))
		notes = self.compose(version="1.9.0-rc.1", latest_moved=False)
		self.assertNotIn(":latest", notes)
		with self.assertRaises(release_notes.ReleaseNotesError):
			self.compose(version="1.9.0-rc.1", latest_moved=True)

	def test_missing_changelog_section_gets_hint(self):
		with contextlib.redirect_stderr(io.StringIO()):
			notes = self.compose(changelog="")
		self.assertIn(release_notes.MISSING_SECTION, notes)

	def test_findings_are_counted_per_arch(self):
		vulns = [{"Severity": "CRITICAL", "VulnerabilityID": "CVE-1"}, {"Severity": "HIGH", "VulnerabilityID": "CVE-2"}]
		notes = self.compose(reports=[self.write_report("amd64", report(vulns)), self.write_report("arm64", report())])
		self.assertIn(f"| amd64 | {release_notes.trivy_report.verdict_line(1, 1)} |", notes)
		self.assertIn("| arm64 | ✅ No HIGH/CRITICAL findings |", notes)

	def test_invalid_or_unproven_report_fails(self):
		for data in ("not json", {"SchemaVersion": 2, "Results": []}):
			with self.assertRaises(release_notes.ReleaseNotesError):
				self.compose(reports=[self.write_report("amd64", data)])
		with self.assertRaises(release_notes.ReleaseNotesError):
			self.compose(reports=[("amd64", self.dir / "missing.json")])
		with self.assertRaises(release_notes.ReleaseNotesError):
			self.compose(reports=[])

	def test_main_fails_on_bad_report(self):
		arch, path = self.write_report("amd64", "{}")
		changelog = self.dir / "CHANGELOG.md"
		changelog.write_text(CHANGELOG, encoding="utf-8")
		argv = [
			"--version=1.8.0",
			f"--changelog={changelog}",
			"--image=owner/wirebuddy",
			f"--index-digest={DIGEST}",
			"--latest-moved=true",
			"--run-url=https://x/run",
			"--asset-base=https://x/assets",
			"--repo-url=https://x",
			f"--trivy-report={arch}={path}",
			f"--output={self.dir / 'notes.md'}",
		]
		with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
			self.assertEqual(release_notes.main(argv), 1)
		self.assertFalse((self.dir / "notes.md").exists())


if __name__ == "__main__":
	unittest.main()
