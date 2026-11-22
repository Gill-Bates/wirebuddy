#!/usr/bin/env python3
#
# .github/scripts/test_ui_changes.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import ui_changes
from ui_changes import decide


class DecideTest(unittest.TestCase):
	def run_for(self, files, event="push", ref="refs/heads/x"):
		return decide(event, ref, files)[0]

	def test_documentation_and_unrelated_files_skip(self):
		for files in (
			["README.md", "docs/a.md", "CHANGELOG.md"],
			["docker/Dockerfile"],
			["tests/test_x.py", "tools/ui-lint/a.mjs"],
			[".github/workflows/docs-build.yml"],
			["app/AGENTS.md"],
			[],
		):
			self.assertFalse(self.run_for(files), files)

	def test_ui_relevant_files_run(self):
		for path in (
			"app/static/css/a.css",
			"app/templates/x.html",
			"app/api/auth.py",
			"app/main.py",
			"tests/layout/auth.spec.mjs",
			"package-lock.json",
			"pyproject.toml",
			".github/workflows/ci.yml",
		):
			self.assertTrue(self.run_for(["README.md", path]), path)

	def test_release_tag_manual_and_unknown_base_run(self):
		self.assertTrue(self.run_for(["README.md"], ref="refs/tags/v1.2.3"))
		self.assertTrue(self.run_for(["README.md"], event="workflow_dispatch"))
		self.assertTrue(self.run_for(None))


def run_git(git: list[str], *args: str) -> None:
	subprocess.run([*git, *args], check=True)  # noqa: S603 - fixed argument vector in a temp repo


class ChangedFilesTest(unittest.TestCase):
	def test_move_out_of_ui_path_reports_old_path(self):
		with tempfile.TemporaryDirectory() as tmp:
			git = ["git", "-C", tmp, "-c", "user.name=t", "-c", "user.email=t@t"]
			Path(tmp, "app/static").mkdir(parents=True)
			Path(tmp, "docs").mkdir()
			Path(tmp, "app/static/a.js").write_text("x = 1\n" * 20)
			run_git(git, "init", "-q")
			run_git(git, "add", ".")
			run_git(git, "commit", "-qm", "a")
			run_git(git, "mv", "app/static/a.js", "docs/a.js")
			run_git(git, "commit", "-qm", "b")
			with mock.patch.object(ui_changes, "SCRIPT", Path(tmp, "x", "y", "ui_changes.py")):
				Path(tmp, "x", "y").mkdir(parents=True)
				files = ui_changes.changed_files("push", {"BEFORE": "HEAD~1", "AFTER": "HEAD"})
		self.assertIn("app/static/a.js", files)

	def test_missing_git_fails_open(self):
		with mock.patch.object(ui_changes.subprocess, "run", side_effect=FileNotFoundError("git")):
			self.assertIsNone(ui_changes.changed_files("push", {"BEFORE": "a" * 40, "AFTER": "b" * 40}))


if __name__ == "__main__":
	unittest.main()
