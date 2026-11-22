#!/usr/bin/env python3
#
# .github/scripts/test_release_tags.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

import json
import tempfile
import unittest
from pathlib import Path

import release_tags
from release_tags import ReleaseTagsError

AMD = "sha256:" + "a" * 64
ARM = "sha256:" + "b" * 64
INDEX = "sha256:" + "c" * 64
OTHER = "sha256:" + "d" * 64
EXPECTED = {"linux/amd64": AMD, "linux/arm64": ARM}
IMAGE = "owner/wirebuddy"
CANDIDATE = "candidate-1.8.0-42-1"


def page(names, next_url=None):
	return 200, json.dumps({"results": [{"name": n} for n in names], "next": next_url}).encode()


class VersionRuleTest(unittest.TestCase):
	def test_fragments_candidates_and_latest_are_not_releases(self):
		for tag in ("1.8.0-amd64", "1.8.0-rc.1-arm64", "latest", CANDIDATE, "sha-abc"):
			self.assertIsNone(release_tags.version_key(tag), tag)

	def test_prerelease_ordering(self):
		key = release_tags.version_key
		self.assertGreater(key("1.7.0-rc.10"), key("1.7.0-rc.2"))
		self.assertLess(key("1.7.0-rc.1"), key("1.7.0"))
		self.assertEqual(key("1.7"), key("1.7.0"))

	def test_newer_prerelease_blocks_is_newest(self):
		self.assertEqual(release_tags.newer_release_tags("1.7.0", ["1.7.0", "1.8.0-rc.1", "latest"]), ["1.8.0-rc.1"])

	def test_own_fragments_do_not_block_a_prerelease(self):
		tags = ["1.8.0-rc.1", "1.8.0-rc.1-amd64", "1.8.0-rc.1-arm64", "candidate-1.8.0-rc.1-1-1"]
		self.assertEqual(release_tags.newer_release_tags("1.8.0-rc.1", tags), [])

	def test_release_version_must_be_strict(self):
		for bad in ("1.8", "v1.8.0", "1.8.0-", ""):
			with self.assertRaises(ReleaseTagsError, msg=bad):
				release_tags.release_version_key(bad)

	def test_newest_stable_tag(self):
		self.assertEqual(release_tags.newest_stable_tag(["1.7.0", "1.10.0", "1.11.0-rc.1", "latest"]), "1.10.0")
		with self.assertRaises(ReleaseTagsError):
			release_tags.newest_stable_tag(["1.8.0-rc.1", "latest"])

	def test_rescan_subject_falls_back_to_latest_after_a_prerelease(self):
		self.assertEqual(release_tags.rescan_subject(["1.7.0", "1.8.0-rc.1", "latest"]), "1.7.0")
		# What the pruning leaves after a newest prerelease: no stable version tag, latest unchanged.
		self.assertEqual(release_tags.rescan_subject(["1.8.0-rc.1", "latest"]), "latest")
		with self.assertRaises(ReleaseTagsError):
			release_tags.rescan_subject(["1.8.0-rc.1"])

	def test_candidate_tag_shape(self):
		self.assertEqual(release_tags.candidate_tag("1.8.0", "42", "1"), CANDIDATE)
		with self.assertRaises(ReleaseTagsError):
			release_tags.check_candidate_tag("1.8.0", "candidate-1.7.0-42-1")
		with self.assertRaises(ReleaseTagsError):
			release_tags.candidate_tag("1.8.0", "42;rm", "1")


class MatrixTest(unittest.TestCase):
	def entry(self, arch, platform=None):
		return {"arch": arch, "runner": "ubuntu-26.04", "platform": platform or f"linux/{arch}"}

	def test_valid_matrix(self):
		matrix, arches = release_tags.validate_matrix(json.dumps({"include": [self.entry("amd64"), self.entry("arm64")]}))
		self.assertEqual(arches, ("amd64", "arm64"))
		self.assertNotIn(" ", matrix)

	def test_rejects_missing_arch_wrong_platform_and_extra_keys(self):
		bad = [
			{"include": [self.entry("amd64")]},
			{"include": [self.entry("amd64"), self.entry("arm64", "linux/amd64")]},
			{"include": [self.entry("amd64"), {**self.entry("arm64"), "extra": "x"}]},
			{"include": [self.entry("amd64"), self.entry("arm64"), self.entry("arm64")]},
		]
		for matrix in bad:
			with self.assertRaises(ReleaseTagsError, msg=matrix):
				release_tags.validate_matrix(json.dumps(matrix))


class DigestAndManifestTest(unittest.TestCase):
	def setUp(self):
		self.tmp = tempfile.TemporaryDirectory(prefix="release-tags-test-")
		self.addCleanup(self.tmp.cleanup)
		self.dir = Path(self.tmp.name)

	def test_expected_manifest(self):
		(self.dir / "amd64").write_text(AMD + "\n")
		(self.dir / "arm64").write_text(ARM)
		self.assertEqual(release_tags.expected_manifest(self.dir, ("amd64", "arm64")), EXPECTED)
		(self.dir / "riscv64").write_text(AMD)
		with self.assertRaises(ReleaseTagsError):
			release_tags.expected_manifest(self.dir, ("amd64", "arm64"))

	def test_missing_or_invalid_digest(self):
		(self.dir / "amd64").write_text("sha256:short")
		with self.assertRaises(ReleaseTagsError):
			release_tags.expected_manifest(self.dir, ("amd64", "arm64"))

	def inspection(self, manifests):
		return json.dumps({"digest": INDEX, "manifests": manifests})

	def test_parse_inspection_ignores_attestations_and_rejects_duplicates(self):
		manifests = [
			{"digest": AMD, "platform": {"os": "linux", "architecture": "amd64"}},
			{"digest": ARM, "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}},
			{"digest": OTHER, "platform": {"os": "unknown", "architecture": "unknown"}},
		]
		self.assertEqual(release_tags.parse_manifest_inspection(self.inspection(manifests)), (INDEX, EXPECTED))
		manifests.append({"digest": OTHER, "platform": {"os": "linux", "architecture": "amd64"}})
		with self.assertRaises(ReleaseTagsError):
			release_tags.parse_manifest_inspection(self.inspection(manifests))

	def test_verify_manifest_rejects_missing_and_extra_platform(self):
		with self.assertRaises(ReleaseTagsError):
			release_tags.verify_manifest(EXPECTED, {"linux/amd64": AMD}, "ref")
		with self.assertRaises(ReleaseTagsError):
			release_tags.verify_manifest(EXPECTED, {**EXPECTED, "linux/riscv64": OTHER}, "ref")

	def test_push_digest(self):
		output = f"abc: Pushed\n1.8.0-amd64: digest: {AMD} size: 1234\n"
		self.assertEqual(release_tags.parse_push_digest(output), AMD)
		with self.assertRaises(ReleaseTagsError):
			release_tags.parse_push_digest("no digest here")

	def test_create_candidate_verifies_read_back(self):
		created = []
		index = release_tags.create_candidate(
			IMAGE, "1.8.0", CANDIDATE, EXPECTED, create=lambda ref, src: created.append((ref, src)), inspect=lambda _ref: (INDEX, EXPECTED)
		)
		self.assertEqual(index, INDEX)
		self.assertEqual(created, [(f"{IMAGE}:{CANDIDATE}", [f"{IMAGE}@{AMD}", f"{IMAGE}@{ARM}"])])
		with self.assertRaises(ReleaseTagsError):
			release_tags.create_candidate(IMAGE, "1.8.0", CANDIDATE, EXPECTED, create=lambda *_: None, inspect=lambda _ref: (INDEX, {"linux/amd64": AMD}))

	def test_resolve_platforms(self):
		index, matrix = release_tags.resolve_platforms("ref", "linux/amd64 linux/arm64", inspect=lambda _ref: (INDEX, EXPECTED))
		self.assertEqual(index, INDEX)
		self.assertEqual(matrix["include"], [{"arch": "amd64", "digest": AMD}, {"arch": "arm64", "digest": ARM}])
		with self.assertRaises(ReleaseTagsError):
			release_tags.resolve_platforms("ref", "linux/amd64 linux/arm64", inspect=lambda _ref: (INDEX, {"linux/amd64": AMD}))


class ListingTest(unittest.TestCase):
	base = "https://hub.docker.com/v2/namespaces/owner/repositories/wirebuddy/tags"

	def run_listing(self, responses, allow_empty=False):
		calls = []

		def request(url, **kwargs):
			calls.append((url, kwargs))
			return responses.pop(0)

		return release_tags.list_published_tags("owner", "tok", allow_empty=allow_empty, request=request), calls

	def test_follows_pagination_with_token(self):
		tags, calls = self.run_listing([page(["1.7.0"], f"{self.base}?page=2"), page(["latest"])])
		self.assertEqual(tags, ["1.7.0", "latest"])
		self.assertEqual(calls[0][1]["headers"], {"Authorization": "Bearer tok"})

	def test_unauthenticated_listing_sends_no_header(self):
		calls = []
		release_tags.list_published_tags("owner", None, allow_empty=False, request=lambda _url, **kw: calls.append(kw) or page([]))
		self.assertEqual(calls[0]["headers"], {})

	def test_first_page_404_only_with_allow_empty(self):
		self.assertEqual(self.run_listing([(404, b"")], allow_empty=True)[0], [])
		with self.assertRaises(ReleaseTagsError):
			self.run_listing([(404, b"")])
		with self.assertRaises(ReleaseTagsError):
			self.run_listing([page(["1.7.0"], f"{self.base}?page=2"), (404, b"")], allow_empty=True)

	def test_malformed_and_foreign_pagination_fail(self):
		for responses in (
			[(200, b"not json")],
			[(200, json.dumps({"next": None}).encode())],
			[page(["1.7.0"], "https://evil.example/v2/x")],
			[page(["1.7.0"], self.base + "?page_size=100")],
		):
			with self.assertRaises(ReleaseTagsError):
				self.run_listing(responses)

	def test_delete_tag_statuses(self):
		self.assertTrue(release_tags.delete_tag("owner", "tok", "1.7.0", request=lambda _url, **_kw: (204, b"")))
		self.assertFalse(release_tags.delete_tag("owner", "tok", "1.7.0", request=lambda _url, **_kw: (404, b"")))
		with self.assertRaises(ReleaseTagsError):
			release_tags.delete_tag("owner", "tok", "../x", request=lambda _url, **_kw: (204, b""))

	def test_hub_url_must_be_https_docker_hub(self):
		for url in ("http://hub.docker.com/v2/", "https://hub.docker.com.evil/v2/", "https://user:pw@hub.docker.com/v2/"):
			with self.assertRaises(ReleaseTagsError):
				release_tags.check_hub_url(url)


class PromoteTest(unittest.TestCase):
	def setUp(self):
		self.events = []
		self.tags = {CANDIDATE: INDEX}

	def inspect(self, reference):
		self.events.append(("inspect", reference))
		tag = reference.rsplit(":", 1)[1]
		return self.tags[tag], EXPECTED

	def retag(self, _image, tag, digest):
		self.events.append(("tag", tag))
		self.tags[tag] = digest

	def listing(self, tags):
		def list_tags():
			self.events.append(("list",))
			return tags

		return list_tags

	def promote(self, version, published, candidate=CANDIDATE):
		return release_tags.promote_release(
			IMAGE, version, candidate, INDEX, EXPECTED, list_tags=self.listing(published), inspect=self.inspect, retag=self.retag
		)

	def test_newest_stable_moves_latest_after_verifying_candidate(self):
		self.assertEqual(self.promote("1.8.0", ["1.7.0", "latest"]), (True, True))
		self.assertEqual(self.events[0], ("inspect", f"{IMAGE}:{CANDIDATE}"))
		self.assertEqual(self.events[1], ("list",))
		first_write = next(i for i, e in enumerate(self.events) if e[0] == "tag")
		self.assertGreater(first_write, 2)
		self.assertEqual(self.tags["1.8.0"], INDEX)
		self.assertEqual(self.tags["latest"], INDEX)

	def test_older_rerun_republishes_version_but_not_latest(self):
		candidate = "candidate-1.7.0-42-1"
		self.tags[candidate] = INDEX
		self.tags["1.7.0"] = OTHER
		self.assertEqual(self.promote("1.7.0", ["1.7.0", "1.8.0", "latest"], candidate), (False, False))
		self.assertEqual(self.tags["1.7.0"], INDEX)
		self.assertNotIn("latest", self.tags)

	def test_prerelease_never_moves_latest(self):
		candidate = "candidate-1.9.0-rc.1-42-1"
		self.tags[candidate] = INDEX
		self.assertEqual(self.promote("1.9.0-rc.1", ["1.8.0", "latest"], candidate), (True, False))
		self.assertNotIn("latest", self.tags)

	def test_candidate_change_between_reads_aborts_before_any_write(self):
		def list_tags():
			self.tags[CANDIDATE] = OTHER
			return ["1.7.0"]

		with self.assertRaises(ReleaseTagsError):
			release_tags.promote_release(IMAGE, "1.8.0", CANDIDATE, INDEX, EXPECTED, list_tags=list_tags, inspect=self.inspect, retag=self.retag)
		self.assertNotIn(("tag", "1.8.0"), self.events)

	def test_wrong_candidate_digest_fails_before_listing(self):
		self.tags[CANDIDATE] = OTHER
		with self.assertRaises(ReleaseTagsError):
			self.promote("1.8.0", ["1.7.0"])
		self.assertNotIn(("list",), self.events)

	def test_version_tag_read_back_must_match(self):
		def bad_retag(_image, tag, _digest):
			self.tags[tag] = OTHER

		with self.assertRaises(ReleaseTagsError):
			release_tags.promote_release(IMAGE, "1.8.0", CANDIDATE, INDEX, EXPECTED, list_tags=list, inspect=self.inspect, retag=bad_retag)


class CleanupAndPruneTest(unittest.TestCase):
	def test_fragment_tags_are_only_this_release(self):
		self.assertEqual(release_tags.fragment_tags("1.8.0", ("amd64", "arm64"), None), ["1.8.0-amd64", "1.8.0-arm64"])
		self.assertEqual(release_tags.fragment_tags("1.8.0", ("amd64", "arm64"), CANDIDATE)[-1], CANDIDATE)
		with self.assertRaises(ReleaseTagsError):
			release_tags.fragment_tags("1.8.0", ("amd64", "arm64"), "1.7.0")

	def test_cleanup_tolerates_absent_and_propagates_errors(self):
		release_tags.cleanup_fragments(["a", "b"], lambda tag: tag == "a")

		def failing(_tag):
			raise ReleaseTagsError("HTTP 500")

		with self.assertRaises(ReleaseTagsError):
			release_tags.cleanup_fragments(["a"], failing)

	def make_registry(self, tags):
		state = set(tags)

		def delete(tag):
			existed = tag in state
			state.discard(tag)
			return existed

		return state, (lambda: sorted(state)), delete, (lambda tag: tag in state)

	def test_prune_keeps_version_and_latest(self):
		state, list_tags, delete, present = self.make_registry(["1.7.0", "1.8.0", "latest", "candidate-1.7.0-1-1"])
		deleted = release_tags.prune_tags("1.8.0", list_tags=list_tags, delete=delete, present=present, sleep=lambda _: None)
		self.assertEqual(sorted(deleted), ["1.7.0", "candidate-1.7.0-1-1"])
		self.assertEqual(state, {"1.8.0", "latest"})

	def test_prune_refuses_when_newer_release_appears(self):
		state, list_tags, delete, present = self.make_registry(["1.7.0", "1.8.0", "1.9.0-rc.1", "latest"])
		with self.assertRaises(ReleaseTagsError):
			release_tags.prune_tags("1.8.0", list_tags=list_tags, delete=delete, present=present, sleep=lambda _: None)
		self.assertIn("1.7.0", state)

	def test_prune_fails_on_remaining_tag_and_missing_latest(self):
		_, list_tags, delete, present = self.make_registry(["1.8.0", "latest", "1.7.0"])
		with self.assertRaises(ReleaseTagsError):
			release_tags.prune_tags("1.8.0", list_tags=list_tags, delete=lambda _tag: True, present=lambda _tag: False, sleep=lambda _: None)
		_, list_tags, delete, present = self.make_registry(["1.8.0"])
		with self.assertRaises(ReleaseTagsError):
			release_tags.prune_tags("1.8.0", list_tags=list_tags, delete=delete, present=present, sleep=lambda _: None)
		_, list_tags, delete, present = self.make_registry(["1.9.0-rc.1"])
		release_tags.prune_tags("1.9.0-rc.1", list_tags=list_tags, delete=delete, present=present, sleep=lambda _: None)

	def test_deletion_must_propagate(self):
		with self.assertRaises(ReleaseTagsError):
			release_tags.wait_until_absent(lambda _tag: True, "1.7.0", attempts=2, sleep=lambda _: None)


if __name__ == "__main__":
	unittest.main()
