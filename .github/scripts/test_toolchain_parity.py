#!/usr/bin/env python3
#
# .github/scripts/test_toolchain_parity.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import toolchain_parity

RECORD = """python=3.14.1
wireguard_tools=v1.0.20250521
unbound=1.22.0
sqlite3=3.46.1
iptables=v1.8.11
openssl=3.5.1
app_version=1.8.0
build_info=GIT_SHA=abc123
BUILD_DATE=2026-11-22T10:00:00Z
"""


class ToolchainParityTest(unittest.TestCase):
	def setUp(self):
		self.tmp = tempfile.TemporaryDirectory(prefix="toolchain-parity-test-")
		self.addCleanup(self.tmp.cleanup)
		self.dir = Path(self.tmp.name)

	def write(self, arch, text):
		(self.dir / f"{arch}.txt").write_text(text, encoding="utf-8")

	def run_main(self, arches="amd64 arm64"):
		out, err = io.StringIO(), io.StringIO()
		with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
			code = toolchain_parity.main(["--dir", str(self.dir), "--arches", arches])
		return code, out.getvalue(), err.getvalue()

	def test_identical_records_pass(self):
		self.write("amd64", RECORD)
		self.write("arm64", RECORD)
		code, out, _ = self.run_main()
		self.assertEqual(code, 0)
		self.assertIn("OK: amd64, arm64", out)

	def test_mismatch_names_the_field(self):
		self.write("amd64", RECORD)
		self.write("arm64", RECORD.replace("openssl=3.5.1", "openssl=3.5.2"))
		code, _, err = self.run_main()
		self.assertEqual(code, 1)
		self.assertIn("openssl: amd64=3.5.1, arm64=3.5.2", err)

	def test_build_info_keys_are_compared(self):
		self.write("amd64", RECORD)
		self.write("arm64", RECORD.replace("BUILD_DATE=2026-11-22T10:00:00Z", "BUILD_DATE=2026-11-23T10:00:00Z"))
		self.assertEqual(self.run_main()[0], 1)

	def test_missing_architecture_fails(self):
		self.write("amd64", RECORD)
		code, _, err = self.run_main()
		self.assertEqual(code, 1)
		self.assertIn("no toolchain record for arm64", err)

	def test_extra_architecture_fails(self):
		for arch in ("amd64", "arm64", "riscv64"):
			self.write(arch, RECORD)
		self.assertEqual(self.run_main()[0], 1)

	def test_empty_required_field_fails_even_when_equal(self):
		record = RECORD.replace("unbound=1.22.0", "unbound=")
		self.write("amd64", record)
		self.write("arm64", record)
		code, _, err = self.run_main()
		self.assertEqual(code, 1)
		self.assertIn("lacks unbound", err)

	def test_missing_required_field_fails(self):
		record = RECORD.replace("iptables=v1.8.11\n", "")
		self.write("amd64", record)
		self.write("arm64", record)
		self.assertEqual(self.run_main()[0], 1)


if __name__ == "__main__":
	unittest.main()
