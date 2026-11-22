#!/usr/bin/env python3
#
# .github/scripts/test_failure_issue.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import json
import unittest
from unittest.mock import patch

import failure_issue


class FindIssueTest(unittest.TestCase):
	def test_exact_search_hit_skips_full_issue_listing(self):
		with patch.object(failure_issue, "_list_issues", return_value=[{"number": 7, "title": "Build failed"}]) as listing:
			self.assertEqual(failure_issue.find_issue("owner/repo", "Build failed"), 7)

		listing.assert_called_once()

	def test_full_listing_runs_only_when_search_has_no_exact_hit(self):
		with patch.object(
			failure_issue,
			"_list_issues",
			side_effect=[[], [{"number": 9, "title": "Build failed"}]],
		) as listing:
			self.assertEqual(failure_issue.find_issue("owner/repo", "Build failed"), 9)

		self.assertEqual(listing.call_count, 2)


class RunAttemptDeduplicationTest(unittest.TestCase):
	def test_attempt_one_does_not_match_attempt_ten(self):
		url = "https://github.com/owner/repo/actions/runs/123/attempts/1"
		response = json.dumps({"body": "Earlier run: https://github.com/owner/repo/actions/runs/123/attempts/10", "comments": []})
		with patch.object(failure_issue, "gh", return_value=response):
			self.assertFalse(failure_issue.mentions_run("owner/repo", 1, url))

	def test_full_run_attempt_url_matches(self):
		url = "https://github.com/owner/repo/actions/runs/123/attempts/1"
		response = json.dumps({"body": f"Run: {url}", "comments": []})
		with patch.object(failure_issue, "gh", return_value=response):
			self.assertTrue(failure_issue.mentions_run("owner/repo", 1, url))


if __name__ == "__main__":
	unittest.main()
