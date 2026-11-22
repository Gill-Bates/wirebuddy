#!/usr/bin/env python3
#
# .github/scripts/test_trivy_report.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import trivy_report


class FindingVerdictTest(unittest.TestCase):
	def test_secret_finding_without_fixed_version_is_not_reported_as_fixable(self):
		secret = {"Severity": "HIGH", "RuleID": "secret-rule"}
		report = {
			"SchemaVersion": 2,
			"Results": [{"Target": "config.env", "Secrets": [secret]}],
		}

		rows = trivy_report.collect_findings(report)
		verdict = trivy_report.verdict_line(0, len(rows))

		self.assertEqual(len(rows), 1)
		self.assertEqual(verdict, "⚠️ 0 CRITICAL, 1 HIGH findings")
		self.assertNotIn("fix available", verdict)


class SecretScanEvidenceTest(unittest.TestCase):
	def setUp(self):
		self.temp_dir = tempfile.TemporaryDirectory(prefix="trivy-report-test-")
		self.addCleanup(self.temp_dir.cleanup)
		self.root = Path(self.temp_dir.name)
		self.scan_input = self.root / "source"
		self.scan_input.mkdir()
		(self.scan_input / "app.py").write_text("print('safe')\n", encoding="utf-8")
		self.report = self.root / "report.json"
		self.report.write_text(json.dumps({"SchemaVersion": 2, "Results": []}), encoding="utf-8")
		self.log_file = self.root / "trivy.log"

	def _args(self):
		return trivy_report.build_parser().parse_args(
			[
				"status",
				str(self.report),
				"--expect-class",
				"secret",
				"--input",
				str(self.scan_input),
				"--log-file",
				str(self.log_file),
				"--summary-title",
				"Trivy source scan",
			]
		)

	def test_clean_secret_report_describes_input_evidence_without_claiming_file_count(self):
		self.log_file.write_text(f"INFO {trivy_report.SCANNER_ENABLED_LOG_LINE}\n", encoding="utf-8")
		output = io.StringIO()
		log_output = io.StringIO()

		with contextlib.redirect_stdout(output), contextlib.redirect_stderr(log_output):
			status = trivy_report.run_status(self._args())

		self.assertEqual(status, 0)
		self.assertIn(trivy_report.SCAN_EVIDENCE_NOTE, output.getvalue())
		self.assertIn(f"secret input: {self.scan_input} is present and non-empty", log_output.getvalue())

	def test_clean_secret_report_requires_nonempty_input(self):
		self.log_file.write_text(f"INFO {trivy_report.SCANNER_ENABLED_LOG_LINE}\n", encoding="utf-8")
		empty_input = self.root / "empty"
		empty_input.mkdir()
		args = self._args()
		args.input = empty_input

		with self.assertRaisesRegex(trivy_report.ScanError, "secret scan input missing or empty"):
			trivy_report.run_status(args)

	def test_unsupported_report_schema_is_rejected(self):
		self.report.write_text(json.dumps({"SchemaVersion": 3, "Results": []}), encoding="utf-8")

		with self.assertRaisesRegex(trivy_report.ScanError, "unsupported Trivy report SchemaVersion 3"):
			trivy_report.run_status(self._args())

	def test_secret_report_requires_enabled_scanner_log_line(self):
		self.log_file.write_text("INFO scan completed\n", encoding="utf-8")

		with self.assertRaisesRegex(trivy_report.ScanError, "lacks 'Secret scanning is enabled'"):
			trivy_report.run_status(self._args())


class ArtifactReferenceTest(unittest.TestCase):
	DIGEST = "sha256:" + "a" * 64

	def setUp(self):
		self.temp_dir = tempfile.TemporaryDirectory(prefix="trivy-report-test-")
		self.addCleanup(self.temp_dir.cleanup)
		self.report = Path(self.temp_dir.name) / "report.json"

	def _run(self, report, ref):
		self.report.write_text(json.dumps(report), encoding="utf-8")
		args = trivy_report.build_parser().parse_args(["status", str(self.report), "--expect-class", "os-pkgs", "--expect-ref", ref])
		with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
			return trivy_report.run_status(args)

	def _report(self, **fields):
		results = [{"Target": "debian", "Class": "os-pkgs", "Packages": [{"Name": "libc6"}]}]
		return {"SchemaVersion": 2, "Results": results, **fields}

	def test_matching_artifact_name_passes(self):
		self.assertEqual(self._run(self._report(ArtifactName="wirebuddy:test-amd64"), "wirebuddy:test-amd64"), 0)

	def test_match_only_through_repo_digests_passes(self):
		report = self._report(ArtifactName="other", Metadata={"RepoDigests": [f"owner/wirebuddy@{self.DIGEST}"]})
		self.assertEqual(self._run(report, self.DIGEST), 0)

	def test_report_of_another_artifact_fails(self):
		report = self._report(ArtifactName="wirebuddy:test-arm64", Metadata={"RepoTags": ["wirebuddy:test-arm64"]})
		with self.assertRaisesRegex(trivy_report.ScanError, "expected 'wirebuddy:test-amd64'"):
			self._run(report, "wirebuddy:test-amd64")

	def test_foreign_artifact_without_metadata_fails(self):
		with self.assertRaisesRegex(trivy_report.ScanError, "report describes 'other:1'"):
			self._run(self._report(ArtifactName="other:1"), self.DIGEST)

	def test_empty_reference_fails(self):
		with self.assertRaisesRegex(trivy_report.ScanError, "reference is empty"):
			self._run(self._report(ArtifactName="wirebuddy:test-amd64"), "")


if __name__ == "__main__":
	unittest.main()
