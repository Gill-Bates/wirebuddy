#!/usr/bin/env python3
#
# .github/scripts/release_tags.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Decide, create, verify, promote and prune the WireBuddy Docker Hub release tags."""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ci_output import REPO_URL, log, print_header, write_outputs

__author__ = "Gill-Bates"
SCRIPT = Path(__file__).resolve()
HELP_URL = f"{REPO_URL}/blob/main/.github/scripts/{SCRIPT.name}"

REPOSITORY = "wirebuddy"
# The architectures every release must carry; the build matrix in docker-build.yml is checked against it.
ARCHES = ("amd64", "arm64")
# Architecture fragments (1.6.1-amd64) would otherwise parse as prereleases of 1.6.1.
ARCH_SUFFIXES = frozenset({"amd64", "arm64", "arm", "armv6", "armv7", "386", "ppc64le", "s390x", "riscv64", "mips64le", "loong64"})
# The version this run releases: strict X.Y.Z with an optional prerelease, as in ci.yml and docker-build.yml.
RELEASE_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$")
# Published tags are parsed tolerantly: a hypothetical 1.7 must still count as 1.7.0, because
# misreading a tag here can let the pruning delete a newer release.
PUBLISHED_RE = re.compile(r"^(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.-]+))?$")
NAMESPACE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
DOCKERHUB_LOGIN_URL = "https://hub.docker.com/v2/users/login/"
RETRYABLE_STATUS = {429, 500, 502, 503, 504}
REQUEST_TIMEOUT_SECONDS = 15
REQUEST_ATTEMPTS = 5
RETRY_DELAY_SECONDS = 2
MAX_TAG_PAGES = 10_000
DELETE_POLL_ATTEMPTS = 12
DELETE_POLL_SECONDS = 5
INSPECT_FORMAT = "{{json .Manifest}}"
VersionKey = tuple[tuple[int, ...], tuple[int, tuple[tuple[int, int, str], ...]]]


class ReleaseTagsError(Exception):
	"""A release tag listing, candidate, promotion or deletion could not be verified."""


class _DockerHubRedirectHandler(HTTPRedirectHandler):
	def redirect_request(self, request: Request, fp: Any, code: int, message: str, headers: Any, new_url: str) -> Request | None:
		try:
			destination = urlsplit(new_url)
			port = destination.port
		except ValueError:
			return None
		if destination.scheme != "https" or destination.hostname != "hub.docker.com" or port not in (None, 443):
			return None
		return super().redirect_request(request, fp, code, message, headers, new_url)


_DOCKERHUB_OPENER = build_opener(_DockerHubRedirectHandler())


# --------------------------------------------------------------------------- versions


def _suffix_key(suffix: str) -> tuple[tuple[int, int, str], ...]:
	# Numeric identifiers compare as numbers, so rc.10 sorts above rc.2.
	return tuple((0, int(part), "") if part.isdigit() else (1, 0, part) for part in suffix.split("."))


def version_key(tag: str) -> VersionKey | None:
	"""Return the sortable release key of a tag, or None for latest, candidate and arch tags."""
	match = PUBLISHED_RE.fullmatch(tag)
	if match is None:
		return None
	suffix = match.group(2)
	# Also 1.8.0-rc.1-amd64: the fragment of a prerelease would otherwise sort above it.
	if suffix is not None and suffix.rsplit("-", 1)[-1] in ARCH_SUFFIXES:
		return None
	release = tuple(int(part) for part in match.group(1).split("."))
	if len(release) < 3:
		release += (0,) * (3 - len(release))
	# A prerelease sorts below its own release: 1.7.0-rc.1 < 1.7.0.
	return release, ((0, _suffix_key(suffix)) if suffix else (1, ()))


def release_version_key(version: str) -> VersionKey:
	"""Key of the version this run releases; it must be strictly release-shaped."""
	if RELEASE_VERSION_RE.fullmatch(version) is None:
		raise ReleaseTagsError(f"invalid release version: {version!r}")
	key = version_key(version)
	if key is None:
		raise ReleaseTagsError(f"release version {version!r} looks like an architecture fragment")
	return key


def is_prerelease(version: str) -> bool:
	return "-" in version


def newer_release_tags(version: str, tags: Iterable[str]) -> list[str]:
	"""Every published release above `version`, prereleases included (WireBuddy's is_newest rule)."""
	current = release_version_key(version)
	return sorted(tag for tag in set(tags) if (key := version_key(tag)) is not None and key > current)


def newest_stable_tag(tags: Iterable[str]) -> str:
	"""The highest published stable version tag: the release `latest` points at."""
	stable = [(key, tag) for tag in set(tags) if (key := version_key(tag)) is not None and key[1][0] == 1]
	if not stable:
		raise ReleaseTagsError("Docker Hub lists no stable release tag")
	return max(stable)[1]


def rescan_subject(tags: Iterable[str]) -> str:
	"""The tag the weekly rescan scans: the newest stable version tag, else `latest` itself.

	After a newest prerelease the pruning keeps only that prerelease and `latest`, so no stable
	version tag remains while `latest` still serves the previous stable image.
	"""
	listed = set(tags)
	try:
		return newest_stable_tag(listed)
	except ReleaseTagsError:
		if "latest" not in listed:
			raise ReleaseTagsError("Docker Hub lists neither a stable release tag nor latest") from None
	log("info", "No stable version tag is listed (a prerelease is newest); rescanning 'latest'.")
	return "latest"


def _log_newest(version: str, newer: list[str]) -> None:
	if newer:
		log("info", f"Newer versions already published: {', '.join(newer)}")
		log("info", f"{version} is republished, but 'latest' stays put and nothing is pruned.")
	else:
		log("info", f"{version} is the newest published version.")


def candidate_tag(version: str, run_id: str, run_attempt: str) -> str:
	release_version_key(version)
	if not run_id.isdigit() or not run_attempt.isdigit():
		raise ReleaseTagsError("GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT must contain only digits")
	return f"candidate-{version}-{run_id}-{run_attempt}"


def check_candidate_tag(version: str, candidate: str) -> str:
	"""A candidate name handed between jobs must still be this version's candidate."""
	release_version_key(version)
	if re.fullmatch(rf"candidate-{re.escape(version)}-[0-9]+-[0-9]+", candidate) is None:
		raise ReleaseTagsError(f"{candidate!r} is not a candidate tag of {version}")
	return candidate


# --------------------------------------------------------------------------- matrix and digests


def parse_arches(raw: str) -> tuple[str, ...]:
	arches = tuple(raw.split())
	if sorted(arches) != sorted(ARCHES) or len(set(arches)) != len(arches):
		raise ReleaseTagsError(f"architectures {' '.join(arches) or '(none)'} differ from {' '.join(ARCHES)}")
	return arches


def validate_matrix(raw: str) -> tuple[str, tuple[str, ...]]:
	"""Check the build matrix declared in meta and return it compact, plus its architectures."""
	try:
		matrix = json.loads(raw)
	except json.JSONDecodeError as exc:
		raise ReleaseTagsError("BUILD_MATRIX is not valid JSON") from exc
	include = matrix.get("include") if isinstance(matrix, dict) else None
	if not isinstance(include, list) or not include:
		raise ReleaseTagsError("BUILD_MATRIX has no include list")
	arches: list[str] = []
	for entry in include:
		if not isinstance(entry, dict) or set(entry) != {"arch", "runner", "platform"}:
			raise ReleaseTagsError("every BUILD_MATRIX entry needs exactly arch, runner and platform")
		if not all(isinstance(value, str) and value for value in entry.values()):
			raise ReleaseTagsError("BUILD_MATRIX values must be non-empty strings")
		if entry["platform"] != f"linux/{entry['arch']}":
			raise ReleaseTagsError(f"BUILD_MATRIX platform {entry['platform']} does not match arch {entry['arch']}")
		arches.append(entry["arch"])
	return json.dumps(matrix, separators=(",", ":")), parse_arches(" ".join(arches))


def expected_manifest(digest_dir: Path, arches: tuple[str, ...]) -> dict[str, str]:
	"""Read one digest per architecture; a missing, invalid or extra file fails."""
	expected: dict[str, str] = {}
	for arch in arches:
		path = digest_dir / arch
		try:
			digest = path.read_text(encoding="utf-8").strip()
		except OSError as exc:
			raise ReleaseTagsError(f"digest artifact for {arch} is missing") from exc
		if DIGEST_RE.fullmatch(digest) is None:
			raise ReleaseTagsError(f"digest artifact for {arch} is invalid")
		expected[f"linux/{arch}"] = digest
	extra = sorted(p.name for p in digest_dir.iterdir() if p.name not in arches) if digest_dir.is_dir() else []
	if extra:
		raise ReleaseTagsError(f"unexpected digest artifacts: {', '.join(extra)}")
	return expected


def parse_manifest_inspection(output: str) -> tuple[str, dict[str, str]]:
	"""Parse imagetools' index digest and the platform child digests it reports."""
	try:
		manifest = json.loads(output)
	except json.JSONDecodeError as exc:
		raise ReleaseTagsError("registry index inspection returned invalid JSON") from exc
	if not isinstance(manifest, dict):
		raise ReleaseTagsError("registry index inspection did not return a manifest object")
	index_digest = manifest.get("digest")
	descriptors = manifest.get("manifests")
	if not isinstance(index_digest, str) or DIGEST_RE.fullmatch(index_digest) is None:
		raise ReleaseTagsError("registry index has no valid manifest digest")
	if not isinstance(descriptors, list):
		raise ReleaseTagsError("registry index has no manifest list")
	entries: dict[str, str] = {}
	for descriptor in descriptors:
		if not isinstance(descriptor, dict):
			raise ReleaseTagsError("registry index returned a malformed manifest descriptor")
		platform = descriptor.get("platform")
		digest = descriptor.get("digest")
		if not isinstance(platform, dict) or not isinstance(digest, str):
			raise ReleaseTagsError("registry index returned a malformed platform entry")
		architecture = platform.get("architecture")
		operating_system = platform.get("os")
		# Attestations ride along as unknown/unknown entries.
		if architecture == "unknown" and operating_system == "unknown":
			continue
		if not isinstance(architecture, str) or not isinstance(operating_system, str):
			raise ReleaseTagsError("registry index returned a malformed platform entry")
		platform_name = f"{operating_system}/{architecture}"
		if platform_name in entries:
			raise ReleaseTagsError(f"registry index contains duplicate platform {platform_name}")
		if DIGEST_RE.fullmatch(digest) is None:
			raise ReleaseTagsError(f"registry index contains an invalid digest for {platform_name}")
		entries[platform_name] = digest
	return index_digest, entries


def parse_push_digest(output: str) -> str:
	"""Extract the digest Docker reports after a successful push."""
	matches = re.findall(r"^[^\r\n]*digest: (sha256:[0-9a-f]{64})(?:\s|$)", output, re.MULTILINE)
	if len(set(matches)) != 1:
		raise ReleaseTagsError("Docker push output did not report one image digest")
	return matches[0]


def verify_manifest(expected: dict[str, str], actual: dict[str, str], reference: str) -> None:
	if actual != expected:
		expected_text = ", ".join(f"{key}={value}" for key, value in sorted(expected.items()))
		actual_text = ", ".join(f"{key}={value}" for key, value in sorted(actual.items())) or "none"
		raise ReleaseTagsError(f"{reference} does not match the build digests: {actual_text} != {expected_text}")


# --------------------------------------------------------------------------- docker


def docker_command(arguments: list[str], *, input_text: str | None = None, timeout: int = 180) -> str:
	try:
		result = subprocess.run(  # noqa: S603 - fixed argument list, no shell
			["docker", *arguments],  # noqa: S607 - the runner's docker CLI
			input=input_text,
			capture_output=True,
			text=True,
			timeout=timeout,
			check=False,
		)
	except (OSError, subprocess.SubprocessError) as exc:
		raise ReleaseTagsError(f"Docker command failed ({exc.__class__.__name__})") from exc
	if result.returncode != 0:
		raise ReleaseTagsError(f"Docker command failed with exit code {result.returncode}")
	return result.stdout.strip()


def inspect_manifest(reference: str) -> tuple[str, dict[str, str]]:
	output = docker_command(["buildx", "imagetools", "inspect", reference, "--format", INSPECT_FORMAT])
	return parse_manifest_inspection(output)


def tag_manifest(image: str, tag: str, digest: str) -> None:
	docker_command(["buildx", "imagetools", "create", "--tag", f"{image}:{tag}", f"{image}@{digest}"])


def create_index(reference: str, sources: list[str]) -> None:
	docker_command(["buildx", "imagetools", "create", "--tag", reference, *sources])


# --------------------------------------------------------------------------- docker hub api


def check_hub_url(url: str) -> None:
	try:
		parsed = urlsplit(url)
		port = parsed.port
	except ValueError as exc:
		raise ReleaseTagsError("Docker Hub API URL is malformed") from exc
	if parsed.scheme != "https" or parsed.hostname != "hub.docker.com" or parsed.username is not None or parsed.password is not None or port not in (None, 443):
		raise ReleaseTagsError("Docker Hub API URL is not an approved HTTPS endpoint")


def _request(
	url: str,
	*,
	method: str = "GET",
	headers: dict[str, str] | None = None,
	body: bytes | None = None,
	attempts: int = REQUEST_ATTEMPTS,
) -> tuple[int, bytes]:
	"""Return (status, body) for a 2xx or 404 answer; retry 429/5xx, raise on anything else."""
	check_hub_url(url)
	request = Request(url, data=body, headers=headers or {}, method=method)  # noqa: S310 - restricted to HTTPS hub.docker.com above
	for attempt in range(attempts):
		try:
			with _DOCKERHUB_OPENER.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
				return response.status, response.read()
		except HTTPError as exc:
			if exc.code == 404:
				return 404, b""
			if exc.code not in RETRYABLE_STATUS or attempt == attempts - 1:
				raise ReleaseTagsError(f"Docker Hub API returned HTTP {exc.code}") from exc
		except (OSError, TimeoutError, URLError) as exc:
			if attempt == attempts - 1:
				raise ReleaseTagsError(f"Docker Hub API request failed ({exc.__class__.__name__})") from exc
		time.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
	raise ReleaseTagsError("Docker Hub API request exhausted retries")


def _json_body(raw: bytes) -> dict[str, Any] | None:
	try:
		payload = json.loads(raw)
	except (UnicodeDecodeError, json.JSONDecodeError) as exc:
		raise ReleaseTagsError("Docker Hub API returned invalid JSON") from exc
	return payload if isinstance(payload, dict) else None


def _auth(token: str | None) -> dict[str, str]:
	return {"Authorization": f"Bearer {token}"} if token else {}


def _check_namespace(username: str) -> None:
	if NAMESPACE_RE.fullmatch(username) is None:
		raise ReleaseTagsError("Docker Hub namespace is missing or malformed")


def dockerhub_token(username: str, password: str) -> str:
	_check_namespace(username)
	if not password:
		raise ReleaseTagsError("Docker Hub token is missing")
	status, raw = _request(
		DOCKERHUB_LOGIN_URL,
		method="POST",
		headers={"Content-Type": "application/json"},
		body=json.dumps({"username": username, "password": password}).encode("utf-8"),
		attempts=1,
	)
	login = _json_body(raw) if status == 200 else None
	token = (login.get("token") or login.get("access_token")) if login else None
	if not isinstance(token, str) or not token:
		raise ReleaseTagsError(f"Docker Hub login failed (HTTP {status})")
	return token


def tags_url(username: str) -> str:
	_check_namespace(username)
	return f"https://hub.docker.com/v2/namespaces/{username}/repositories/{REPOSITORY}/tags"


def list_published_tags(
	username: str,
	token: str | None,
	*,
	allow_empty: bool,
	request: Callable[..., tuple[int, bytes]] = _request,
) -> list[str]:
	"""The complete tag listing. Fails closed: only a 404 on the first page may mean "no repository yet"."""
	base = tags_url(username)
	base_path = urlsplit(base).path
	next_url = f"{base}?page_size=100"
	visited: set[str] = set()
	tags: list[str] = []
	first_page = True
	while next_url:
		parsed = urlsplit(next_url)
		if parsed.scheme != "https" or parsed.netloc != "hub.docker.com" or parsed.path != base_path:
			raise ReleaseTagsError("Docker Hub returned an unexpected pagination URL")
		if next_url in visited or len(visited) >= MAX_TAG_PAGES:
			raise ReleaseTagsError("Docker Hub tag listing pagination did not finish")
		visited.add(next_url)
		status, raw = request(next_url, headers=_auth(token))
		if status == 404 and first_page and allow_empty:
			log("info", f"Docker Hub has no {username}/{REPOSITORY} repository yet; treating this as the first release.")
			return []
		page = _json_body(raw) if status == 200 else None
		if page is None:
			raise ReleaseTagsError(f"Docker Hub tag listing failed (HTTP {status})")
		results = page.get("results")
		if not isinstance(results, list):
			raise ReleaseTagsError("Docker Hub tag listing has no results array")
		for result in results:
			if not isinstance(result, dict) or not isinstance(result.get("name"), str):
				raise ReleaseTagsError("Docker Hub returned a malformed tag entry")
			tags.append(result["name"])
		page_next = page.get("next")
		if page_next in (None, "", "null"):
			next_url = ""
		elif isinstance(page_next, str):
			next_url = page_next
		else:
			raise ReleaseTagsError("Docker Hub returned a malformed pagination cursor")
		first_page = False
	return tags


def delete_tag(username: str, token: str, tag: str, *, request: Callable[..., tuple[int, bytes]] = _request) -> bool:
	"""Delete one tag; True when deleted, False when it was already absent."""
	if TAG_RE.fullmatch(tag) is None:
		raise ReleaseTagsError(f"refusing to delete malformed tag {tag!r}")
	status, _ = request(f"{tags_url(username)}/{quote(tag, safe='')}", method="DELETE", headers=_auth(token))
	if status in (200, 202, 204):
		return True
	if status == 404:
		return False
	raise ReleaseTagsError(f"deleting {tag} returned HTTP {status}")


def tag_present(username: str, token: str, tag: str, *, request: Callable[..., tuple[int, bytes]] = _request) -> bool:
	status, _ = request(f"{tags_url(username)}/{quote(tag, safe='')}", headers=_auth(token))
	if status == 200:
		return True
	if status == 404:
		return False
	raise ReleaseTagsError(f"checking {tag} returned HTTP {status}")


def wait_until_absent(present: Callable[[str], bool], tag: str, *, attempts: int = DELETE_POLL_ATTEMPTS, sleep: Callable[[float], None] = time.sleep) -> None:
	for _ in range(attempts):
		if not present(tag):
			log("info", f"Confirmed tag absent: {tag}")
			return
		sleep(DELETE_POLL_SECONDS)
	raise ReleaseTagsError(f"tag still visible after deletion: {tag}")


# --------------------------------------------------------------------------- release steps


def create_candidate(
	image: str,
	version: str,
	candidate: str,
	expected: dict[str, str],
	*,
	create: Callable[[str, list[str]], None] = create_index,
	inspect: Callable[[str], tuple[str, dict[str, str]]] = inspect_manifest,
) -> str:
	"""Push the candidate index from the build digests and read it back."""
	check_candidate_tag(version, candidate)
	reference = f"{image}:{candidate}"
	create(reference, [f"{image}@{digest}" for _, digest in sorted(expected.items())])
	index_digest, actual = inspect(reference)
	verify_manifest(expected, actual, reference)
	log("info", f"Created and verified candidate {candidate} ({index_digest}).")
	return index_digest


def _publish_tag(
	image: str,
	tag: str,
	candidate_digest: str,
	expected: dict[str, str],
	inspect: Callable[[str], tuple[str, dict[str, str]]],
	retag: Callable[[str, str, str], None],
) -> None:
	retag(image, tag, candidate_digest)
	digest, entries = inspect(f"{image}:{tag}")
	verify_manifest(expected, entries, f"{image}:{tag}")
	if digest != candidate_digest:
		raise ReleaseTagsError(f"{tag} does not reference the verified candidate digest")


def promote_release(
	image: str,
	version: str,
	candidate: str,
	index_digest: str,
	expected: dict[str, str],
	*,
	list_tags: Callable[[], list[str]],
	inspect: Callable[[str], tuple[str, dict[str, str]]] = inspect_manifest,
	retag: Callable[[str, str, str], None] = tag_manifest,
) -> tuple[bool, bool]:
	"""Verify the candidate, decide is_newest on a fresh listing, then publish. Returns (is_newest, latest_moved)."""
	check_candidate_tag(version, candidate)
	if DIGEST_RE.fullmatch(index_digest) is None:
		raise ReleaseTagsError("INDEX_DIGEST is not a sha256 digest")
	reference = f"{image}:{candidate}"

	def verified_candidate() -> None:
		digest, entries = inspect(reference)
		verify_manifest(expected, entries, reference)
		if digest != index_digest:
			raise ReleaseTagsError(f"candidate {candidate} no longer references {index_digest}")

	verified_candidate()
	newer = newer_release_tags(version, list_tags())
	is_newest = not newer
	verified_candidate()
	_log_newest(version, newer)
	# A rerun republishes its own version tag onto the newly verified candidate (WireBuddy rule).
	_publish_tag(image, version, index_digest, expected, inspect, retag)
	log("info", f"Published {image}:{version} ({index_digest}).")
	if is_prerelease(version):
		log("info", f"Skipping 'latest': {version} is a prerelease.")
		return is_newest, False
	if not is_newest:
		log("info", "Skipping 'latest': a newer version is already published, and 'latest' must never move backwards.")
		return is_newest, False
	_publish_tag(image, "latest", index_digest, expected, inspect, retag)
	log("info", f"Moved {image}:latest to {index_digest}.")
	return is_newest, True


def fragment_tags(version: str, arches: tuple[str, ...], candidate: str | None) -> list[str]:
	release_version_key(version)
	tags = [f"{version}-{arch}" for arch in arches]
	if candidate:
		tags.append(check_candidate_tag(version, candidate))
	return tags


def cleanup_fragments(tags: list[str], delete: Callable[[str], bool]) -> None:
	for tag in tags:
		if delete(tag):
			log("info", f"Deleted fragment tag: {tag}")
		else:
			log("info", f"Fragment tag already absent: {tag}")


def prune_tags(
	version: str,
	*,
	list_tags: Callable[[], list[str]],
	delete: Callable[[str], bool],
	present: Callable[[str], bool],
	sleep: Callable[[float], None] = time.sleep,
) -> list[str]:
	"""Delete every tag except the version and latest, only while this version is still the newest."""
	published = list_tags()
	newer = newer_release_tags(version, published)
	if newer:
		raise ReleaseTagsError(f"refusing to prune: newer versions are published ({', '.join(newer)})")
	keep = {version, "latest"}
	deleted: list[str] = []
	for tag in sorted(set(published) - keep):
		log("info", f"Deleting tag: {tag}")
		if delete(tag):
			wait_until_absent(present, tag, sleep=sleep)
			deleted.append(tag)
		else:
			log("info", f"Tag already absent: {tag}")
	remaining = set(list_tags())
	unexpected = sorted(remaining - keep)
	if unexpected:
		raise ReleaseTagsError(f"unexpected tags remained after pruning: {', '.join(unexpected)}")
	# Prereleases never publish 'latest', so it is required only for a stable version.
	required = {version} if is_prerelease(version) else keep
	missing = sorted(required - remaining)
	if missing:
		raise ReleaseTagsError(f"expected tags missing after pruning: {', '.join(missing)}")
	return deleted


def resolve_platforms(
	reference: str, expected_platforms: str, inspect: Callable[[str], tuple[str, dict[str, str]]] = inspect_manifest
) -> tuple[str, dict[str, Any]]:
	"""Index digest and per-platform matrix of a published release; the platform set must match exactly."""
	expected = sorted(expected_platforms.split())
	if not expected:
		raise ReleaseTagsError("EXPECTED_PLATFORMS is empty")
	index_digest, entries = inspect(reference)
	if sorted(entries) != expected:
		raise ReleaseTagsError(f"{reference} lists {', '.join(sorted(entries)) or 'no platform'}, expected {', '.join(expected)}")
	matrix = {"include": [{"arch": name.split("/", 1)[1], "digest": entries[name]} for name in expected]}
	return index_digest, matrix


# --------------------------------------------------------------------------- commands


def _require_env(name: str) -> str:
	value = os.environ.get(name, "")
	if not value:
		raise ReleaseTagsError(f"missing required environment variable {name}")
	return value


def _credentials() -> tuple[str, str]:
	username = _require_env("DOCKERHUB_USERNAME")
	_check_namespace(username)
	return username, _require_env("DOCKERHUB_TOKEN")


def run_matrix() -> int:
	matrix, arches = validate_matrix(_require_env("BUILD_MATRIX"))
	write_outputs({"matrix": matrix, "arches": " ".join(arches)})
	return 0


def run_newest() -> int:
	version = _require_env("VERSION")
	release_version_key(version)
	username, password = _credentials()
	token = dockerhub_token(username, password)
	newer = newer_release_tags(version, list_published_tags(username, token, allow_empty=True))
	_log_newest(version, newer)
	write_outputs({"is_newest": str(not newer).lower()})
	return 0


def run_record_pushed_digest() -> int:
	push_output_file = Path(_require_env("PUSH_OUTPUT_FILE"))
	digest_file = Path(_require_env("DIGEST_FILE"))
	try:
		output = push_output_file.read_text(encoding="utf-8")
	except OSError as exc:
		raise ReleaseTagsError("Docker push output is missing") from exc
	digest = parse_push_digest(output)
	digest_file.parent.mkdir(parents=True, exist_ok=True)
	digest_file.write_text(digest, encoding="utf-8")
	log("info", f"Recorded the pushed digest {digest}.")
	return 0


def run_create_candidate() -> int:
	version = _require_env("VERSION")
	arches = parse_arches(_require_env("ARCHES"))
	candidate = candidate_tag(version, _require_env("GITHUB_RUN_ID"), _require_env("GITHUB_RUN_ATTEMPT"))
	expected = expected_manifest(Path(_require_env("DIGEST_DIR")), arches)
	index_digest = create_candidate(_require_env("IMAGE_NAME"), version, candidate, expected)
	write_outputs({"candidate": candidate, "index_digest": index_digest})
	return 0


def _docker_login(username: str, password: str) -> None:
	docker_command(["login", "--username", username, "--password-stdin"], input_text=f"{password}\n", timeout=120)


def _docker_logout() -> None:
	try:
		docker_command(["logout", "docker.io"], timeout=30)
	except ReleaseTagsError:
		log("warning", "Docker Hub logout could not complete.")


def run_promote() -> int:
	version = _require_env("VERSION")
	image = _require_env("IMAGE_NAME")
	candidate = check_candidate_tag(version, _require_env("CANDIDATE"))
	index_digest = _require_env("INDEX_DIGEST")
	expected = expected_manifest(Path(_require_env("DIGEST_DIR")), parse_arches(_require_env("ARCHES")))
	username, password = _credentials()
	hint = os.environ.get("META_IS_NEWEST", "")
	_docker_login(username, password)
	try:
		token = dockerhub_token(username, password)
		is_newest, latest_moved = promote_release(
			image,
			version,
			candidate,
			index_digest,
			expected,
			list_tags=lambda: list_published_tags(username, token, allow_empty=False),
		)
	finally:
		_docker_logout()
	if hint in {"true", "false"} and (hint == "true") != is_newest:
		log("warning", "Docker Hub release state changed since the meta job; the fresh listing decided.")
	write_outputs({"is_newest": str(is_newest).lower(), "latest_moved": str(latest_moved).lower()})
	return 0


def run_cleanup_fragments() -> int:
	version = _require_env("VERSION")
	arches = parse_arches(_require_env("ARCHES"))
	candidate = os.environ.get("CANDIDATE", "") if os.environ.get("DELETE_CANDIDATE") == "true" else ""
	tags = fragment_tags(version, arches, candidate or None)
	username, password = _credentials()
	token = dockerhub_token(username, password)
	cleanup_fragments(tags, lambda tag: delete_tag(username, token, tag))
	return 0


def run_prune() -> int:
	version = _require_env("VERSION")
	username, password = _credentials()
	token = dockerhub_token(username, password)
	log("info", f"Keeping Docker Hub tags {username}/{REPOSITORY}:{version} and :latest")
	prune_tags(
		version,
		list_tags=lambda: list_published_tags(username, token, allow_empty=False),
		delete=lambda tag: delete_tag(username, token, tag),
		present=lambda tag: tag_present(username, token, tag),
	)
	return 0


def run_stable_latest() -> int:
	username = _require_env("DOCKERHUB_USERNAME")
	# The image is public; the rescan lists it without credentials.
	version = rescan_subject(list_published_tags(username, None, allow_empty=False))
	log("info", f"Rescan subject: {version}")
	write_outputs({"version": version})
	return 0


def run_resolve() -> int:
	version = _require_env("VERSION")
	# `latest` is the fallback subject of stable-latest when only a prerelease carries a version tag.
	if version != "latest" and version_key(version) is None:
		raise ReleaseTagsError(f"invalid published version: {version!r}")
	reference = f"{_require_env('IMAGE_NAME')}:{version}"
	index_digest, matrix = resolve_platforms(reference, _require_env("EXPECTED_PLATFORMS"))
	log("info", f"Resolved {version} to {index_digest}")
	write_outputs({"version": version, "index_digest": index_digest, "matrix": json.dumps(matrix, separators=(",", ":"))})
	return 0


COMMANDS: dict[str, Callable[[], int]] = {
	"matrix": run_matrix,
	"newest": run_newest,
	"record-pushed-digest": run_record_pushed_digest,
	"create-candidate": run_create_candidate,
	"promote": run_promote,
	"cleanup-fragments": run_cleanup_fragments,
	"prune": run_prune,
	"stable-latest": run_stable_latest,
	"resolve": run_resolve,
}


def main(argv: list[str] | None = None) -> int:
	sys.stdout.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
	description = (__doc__ or "").strip().splitlines()[0]
	print_header(SCRIPT, description, __author__, HELP_URL)
	parser = argparse.ArgumentParser(description=description)
	parser.add_argument("command", choices=tuple(COMMANDS))
	args = parser.parse_args(argv)
	try:
		return COMMANDS[args.command]()
	except ReleaseTagsError as exc:
		log("error", str(exc))
		return 1


if __name__ == "__main__":
	sys.exit(main())
