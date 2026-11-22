#!/usr/bin/env python3
#
# .github/scripts/test_ci_helpers.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ci_job_setup
import ci_output


class CiOutputTest(unittest.TestCase):
	def test_writes_single_line_outputs_to_stdout_and_github_file(self):
		with tempfile.TemporaryDirectory(prefix="ci-output-test-") as directory:
			output_file = Path(directory) / "github-output"
			stdout = io.StringIO()
			with patch.dict("os.environ", {"GITHUB_OUTPUT": str(output_file)}), contextlib.redirect_stdout(stdout):
				ci_output.write_outputs({"result": "passed"})

			self.assertEqual(stdout.getvalue(), "result=passed\n")
			self.assertEqual(output_file.read_text(encoding="utf-8"), "result=passed\n")

	def test_rejects_newline_before_writing_workflow_output(self):
		with tempfile.TemporaryDirectory(prefix="ci-output-test-") as directory:
			output_file = Path(directory) / "github-output"
			with (
				patch.dict("os.environ", {"GITHUB_OUTPUT": str(output_file)}),
				self.assertRaisesRegex(ValueError, "not a single line"),
			):
				ci_output.write_outputs({"result": "first\nsecond"})

			self.assertFalse(output_file.exists())

	def test_workflow_command_text_is_neutralized(self):
		self.assertEqual(
			ci_output.format_line("error", "::add-mask::secret", github=True),
			"::error::: :add-mask::secret",
		)


class JobTempSetupTest(unittest.TestCase):
	def test_writes_temp_variables_only_for_an_existing_runner_directory(self):
		with tempfile.TemporaryDirectory(prefix="ci-job-test-") as directory:
			root = Path(directory)
			runner_temp = root / "runner-temp"
			runner_temp.mkdir()
			env_file = root / "github-env"
			with patch.dict("os.environ", {"GITHUB_ENV": str(env_file), "RUNNER_TEMP": str(runner_temp)}):
				self.assertEqual(ci_job_setup.point_temp_at_runner_temp(), 0)

			self.assertEqual(
				env_file.read_text(encoding="utf-8"),
				f"TMPDIR={runner_temp}\nTMP={runner_temp}\nTEMP={runner_temp}\n",
			)

	def test_rejects_missing_runner_directory_without_writing_environment(self):
		with tempfile.TemporaryDirectory(prefix="ci-job-test-") as directory:
			root = Path(directory)
			env_file = root / "github-env"
			missing = root / "missing"
			output = io.StringIO()
			with (
				patch.dict("os.environ", {"GITHUB_ENV": str(env_file), "RUNNER_TEMP": str(missing)}),
				contextlib.redirect_stdout(output),
			):
				self.assertEqual(ci_job_setup.point_temp_at_runner_temp(), 1)

			self.assertIn("RUNNER_TEMP is empty, multi-line or not a directory", output.getvalue())
			self.assertFalse(env_file.exists())


if __name__ == "__main__":
	unittest.main()
