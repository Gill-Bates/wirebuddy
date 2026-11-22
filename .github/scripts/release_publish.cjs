"use strict";
// .github/scripts/release_publish.cjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates

const crypto = require("node:crypto");
const fs = require("node:fs");

const SCRIPT_NAME = "release_publish.cjs";
const SCRIPT_DESCRIPTION = "Create the GitHub Release as a draft, attach the scan reports, verify them and publish.";
const SCRIPT_SOURCE = ".github/scripts/release_publish.cjs";
const SCRIPT_AUTHOR = "Gill-Bates";
const SCRIPT_HELP = `https://github.com/Gill-Bates/wirebuddy/blob/main/${SCRIPT_SOURCE}`;

// Returns a problem description, or null when the release carries exactly the expected assets.
function assetMismatch(actual, expected) {
  const missing = expected.filter((name) => !actual.includes(name));
  const extra = actual.filter((name) => !expected.includes(name));
  const duplicates = actual.filter((name, index) => actual.indexOf(name) !== index);
  const problems = [];
  if (missing.length) problems.push(`missing ${missing.join(", ")}`);
  if (extra.length) problems.push(`unexpected ${extra.join(", ")}`);
  if (duplicates.length) problems.push(`duplicate ${duplicates.join(", ")}`);
  return problems.length ? problems.join("; ") : null;
}

const sha256 = (data) => crypto.createHash("sha256").update(data).digest("hex");

// Returns a problem description, or null when the listed assets are exactly the expected
// files, fully uploaded, with their size and SHA-256. The API digest is used where GitHub
// reports one; otherwise the asset is downloaded and hashed, so a file of the right name
// but the wrong content is never accepted.
async function verifyAssets({ github, owner, repo, assets, files }) {
  const mismatch = assetMismatch(
    assets.map((asset) => asset.name),
    files.map((file) => file.name),
  );
  if (mismatch) return mismatch;
  const problems = [];
  for (const file of files) {
    const asset = assets.find((candidate) => candidate.name === file.name);
    if (asset.state !== "uploaded") problems.push(`${file.name} is in state ${asset.state}`);
    if (asset.size !== file.size) problems.push(`${file.name} has ${asset.size} bytes, expected ${file.size}`);
    let actual;
    if (asset.digest) {
      actual = asset.digest;
    } else {
      const { data } = await github.rest.repos.getReleaseAsset({
        owner,
        repo,
        asset_id: asset.id,
        headers: { accept: "application/octet-stream" },
      });
      actual = `sha256:${sha256(Buffer.from(data))}`;
    }
    if (actual !== `sha256:${file.sha256}`) problems.push(`${file.name} has digest ${actual}, expected sha256:${file.sha256}`);
  }
  return problems.length ? problems.join("; ") : null;
}

async function publishRelease({ github, context, core, version, releaseNotesFile, assets, latestMoved }) {
  core.info(`Script: ${SCRIPT_NAME}`);
  core.info(`Description: ${SCRIPT_DESCRIPTION}`);
  core.info(`Version: ${context.sha || "unknown"}`);
  core.info(`Source: ${SCRIPT_SOURCE}`);
  core.info(`Author: ${SCRIPT_AUTHOR}`);
  core.info(`Help: ${SCRIPT_HELP}`);

  const body = fs.readFileSync(releaseNotesFile, "utf8");
  if (!body.trim()) throw new Error("release notes are empty");
  if (!Array.isArray(assets) || assets.length === 0) throw new Error("no release assets given");
  // GitHub marks a published release "Latest" unless told otherwise, so the Docker `latest`
  // decision must be passed explicitly; a missing value fails instead of defaulting.
  if (typeof latestMoved !== "boolean") throw new Error("latestMoved must be a boolean");
  // Read every asset before the first write, so a missing report cannot leave a half-built draft.
  const files = assets.map((asset) => {
    const data = fs.readFileSync(asset.path);
    return { name: asset.name, data, size: data.length, sha256: sha256(data) };
  });
  for (const file of files) {
    if (file.data.length === 0) throw new Error(`release asset ${file.name} is empty`);
  }

  const tagName = `v${version}`;
  const { owner, repo } = context.repo;
  const fields = { owner, repo, tag_name: tagName, name: `WireBuddy ${version}`, body, prerelease: version.includes("-") };
  // GitHub "Latest" follows the Docker `latest` decision; a prerelease is never "Latest".
  const makeLatest = latestMoved && !fields.prerelease ? "true" : "false";

  // listReleases also returns drafts (getReleaseByTag does not), so a draft left
  // behind by an interrupted run is reused instead of duplicated.
  const releases = await github.paginate(github.rest.repos.listReleases, { owner, repo, per_page: 100 });
  let release = releases.find((candidate) => candidate.tag_name === tagName);
  const listAssets = async () =>
    github.paginate(github.rest.repos.listReleaseAssets, { owner, repo, release_id: release.id, per_page: 100 });
  const assetProblem = async () => verifyAssets({ github, owner, repo, assets: await listAssets(), files });

  const published = Boolean(release && !release.draft);
  if (published) {
    // A rerun republishes :<version> onto a new digest, so a published release whose body
    // differs (index digest, rollback target, Trivy verdicts) is brought up to date below.
    const problem = await assetProblem();
    if (!problem && (release.body || "") === body) {
      core.info(`Release ${tagName} is already published with these notes and the expected assets`);
      return;
    }
    core.info(`Updating published release ${tagName} to this run's image and reports`);
  }
  if (!release) {
    // target_commitish pins the tag to the commit this run built, not the default branch.
    ({ data: release } = await github.rest.repos.createRelease({ ...fields, target_commitish: context.sha, draft: true }));
    core.info(`Created draft release ${tagName}`);
  }

  // Run artifacts expire; release assets keep the links in the body valid. Each report is
  // uploaded under a staging name first, so an existing asset is replaced only once its
  // successor is in place.
  for (const file of files) {
    const stagingName = `${file.name}.staging`;
    const existing = await listAssets();
    for (const stale of existing.filter((asset) => asset.name === stagingName)) {
      await github.rest.repos.deleteReleaseAsset({ owner, repo, asset_id: stale.id });
    }
    const { data: uploaded } = await github.rest.repos.uploadReleaseAsset({
      owner,
      repo,
      release_id: release.id,
      name: stagingName,
      data: file.data,
      headers: { "content-type": "application/json", "content-length": file.data.length },
    });
    for (const previous of existing.filter((asset) => asset.name === file.name)) {
      await github.rest.repos.deleteReleaseAsset({ owner, repo, asset_id: previous.id });
    }
    await github.rest.repos.updateReleaseAsset({ owner, repo, asset_id: uploaded.id, name: file.name });
    core.info(`Attached ${file.name}`);
  }

  const problem = await assetProblem();
  if (problem) throw new Error(`Release ${tagName} is not ready to publish: ${problem}`);
  if (published) {
    // The tag already exists, so target_commitish is left alone.
    await github.rest.repos.updateRelease({ ...fields, release_id: release.id, draft: false, make_latest: makeLatest });
  } else {
    await github.rest.repos.updateRelease({
      ...fields,
      release_id: release.id,
      target_commitish: context.sha,
      draft: false,
      make_latest: makeLatest,
    });
  }
  // Read back after publishing: what the release now carries is what users download.
  const finalProblem = await assetProblem();
  if (finalProblem) throw new Error(`Release ${tagName} was published but its assets differ: ${finalProblem}`);
  core.info(`${published ? "Updated published" : "Published"} release ${tagName} (make_latest=${makeLatest})`);
}

module.exports = { assetMismatch, verifyAssets, publishRelease };
