"use strict";
// .github/scripts/test_release_publish.cjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { assetMismatch, verifyAssets, publishRelease } = require("./release_publish.cjs");

const CONTENT = "{}";
const digestOf = (content) => `sha256:${crypto.createHash("sha256").update(content).digest("hex")}`;

// A listed release asset as GitHub reports it; the fake also keeps its bytes for download.
function asset(id, name, { content = CONTENT, state = "uploaded", digest = digestOf(content) } = {}) {
  return { id, name, state, size: Buffer.byteLength(content), digest, content };
}

// A fake GitHub API holding releases and their assets in memory.
function fakeGithub(releases = [], { uploadDigest = true } = {}) {
  const calls = [];
  let nextId = 100;
  const byId = (id) => releases.find((release) => release.id === id);
  const github = {
    paginate: async (method, params) => method(params),
    rest: {
      repos: {
        listReleases: async () => releases,
        listReleaseAssets: async ({ release_id }) => byId(release_id).assets.slice(),
        createRelease: async (input) => {
          calls.push(["create", input]);
          const release = { id: nextId++, tag_name: input.tag_name, draft: input.draft, assets: [] };
          releases.push(release);
          return { data: release };
        },
        uploadReleaseAsset: async ({ release_id, name, data }) => {
          calls.push(["upload", name]);
          const uploaded = asset(nextId++, name, { content: Buffer.from(data).toString("utf8") });
          if (!uploadDigest) uploaded.digest = null;
          byId(release_id).assets.push(uploaded);
          return { data: uploaded };
        },
        getReleaseAsset: async ({ asset_id }) => {
          calls.push(["download", asset_id]);
          for (const release of releases) {
            const found = release.assets.find((candidate) => candidate.id === asset_id);
            if (found) return { data: Buffer.from(found.content) };
          }
          throw new Error(`no asset ${asset_id}`);
        },
        deleteReleaseAsset: async ({ asset_id }) => {
          calls.push(["delete", asset_id]);
          for (const release of releases) release.assets = release.assets.filter((asset) => asset.id !== asset_id);
        },
        updateReleaseAsset: async ({ asset_id, name }) => {
          calls.push(["rename", name]);
          for (const release of releases) {
            for (const asset of release.assets) if (asset.id === asset_id) asset.name = name;
          }
        },
        updateRelease: async (input) => {
          calls.push(["update", input]);
          Object.assign(byId(input.release_id), { draft: input.draft, body: input.body });
        },
      },
    },
  };
  return { github, calls, releases };
}

function fixture(t, releases, options) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "release-publish-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const releaseNotesFile = path.join(directory, "release-notes.md");
  fs.writeFileSync(releaseNotesFile, "Release notes\n", "utf8");
  const assets = ["amd64", "arm64"].map((arch) => {
    const file = path.join(directory, `trivy-${arch}.json`);
    fs.writeFileSync(file, CONTENT, "utf8");
    return { name: `trivy-${arch}.json`, path: file };
  });
  const fake = fakeGithub(releases, options);
  const core = { info() {} };
  const context = { sha: "abc123", repo: { owner: "owner", repo: "repo" } };
  return { ...fake, releaseNotesFile, assets, core, context, directory, latestMoved: true };
}

test("assetMismatch names missing, unexpected and duplicate assets", () => {
  assert.equal(assetMismatch(["a", "b"], ["a", "b"]), null);
  assert.match(assetMismatch(["a"], ["a", "b"]), /missing b/);
  assert.match(assetMismatch(["a", "b", "c"], ["a", "b"]), /unexpected c/);
  assert.match(assetMismatch(["a", "a", "b"], ["a", "b"]), /duplicate a/);
});

test("a new release is created as a draft, gets its assets and is then published", async (t) => {
  const f = fixture(t);
  await publishRelease({ ...f, version: "1.2.3" });
  const kinds = f.calls.map(([kind]) => kind);
  assert.equal(kinds[0], "create");
  assert.equal(f.calls[0][1].draft, true);
  assert.equal(f.calls[0][1].target_commitish, "abc123");
  assert.equal(f.calls[0][1].prerelease, false);
  assert.equal(kinds.at(-1), "update");
  assert.equal(f.calls.at(-1)[1].draft, false);
  assert.deepEqual(f.releases[0].assets.map((asset) => asset.name).sort(), ["trivy-amd64.json", "trivy-arm64.json"]);
});

test("a leftover draft is reused and its stale asset replaced", async (t) => {
  const f = fixture(t, [{ id: 7, tag_name: "v1.2.3", draft: true, assets: [asset(8, "trivy-amd64.json")] }]);
  await publishRelease({ ...f, version: "1.2.3" });
  assert.equal(f.calls.filter(([kind]) => kind === "create").length, 0);
  assert.ok(f.calls.some(([kind, id]) => kind === "delete" && id === 8));
  assert.equal(f.releases[0].draft, false);
  assert.equal(f.releases[0].assets.length, 2);
});

test("a published release with the same notes and the expected assets is only verified", async (t) => {
  const assets = [asset(1, "trivy-amd64.json"), asset(2, "trivy-arm64.json")];
  const f = fixture(t, [{ id: 7, tag_name: "v1.2.3", draft: false, body: "Release notes\n", assets }]);
  await publishRelease({ ...f, version: "1.2.3" });
  assert.deepEqual(f.calls, []);
});

test("a rerun updates a published release whose notes name another image", async (t) => {
  const assets = [asset(1, "trivy-amd64.json"), asset(2, "trivy-arm64.json")];
  const f = fixture(t, [{ id: 7, tag_name: "v1.2.3", draft: false, body: "Index digest: old\n", assets }]);
  await publishRelease({ ...f, version: "1.2.3" });
  assert.equal(f.calls.filter(([kind]) => kind === "create").length, 0);
  assert.ok(f.calls.some(([kind, id]) => kind === "delete" && id === 1));
  assert.ok(f.calls.some(([kind, id]) => kind === "delete" && id === 2));
  const update = f.calls.at(-1);
  assert.equal(update[0], "update");
  assert.equal(update[1].draft, false);
  assert.equal(update[1].target_commitish, undefined);
  assert.equal(f.releases[0].body, "Release notes\n");
  assert.deepEqual(f.releases[0].assets.map((asset) => asset.name).sort(), ["trivy-amd64.json", "trivy-arm64.json"]);
});

test("a published release with a missing asset gets the full set again", async (t) => {
  const f = fixture(t, [{ id: 7, tag_name: "v1.2.3", draft: false, body: "Release notes\n", assets: [asset(1, "trivy-amd64.json")] }]);
  await publishRelease({ ...f, version: "1.2.3" });
  assert.deepEqual(f.releases[0].assets.map((asset) => asset.name).sort(), ["trivy-amd64.json", "trivy-arm64.json"]);
  assert.equal(f.releases[0].draft, false);
});

test("empty notes or a missing asset file fail before any write", async (t) => {
  const f = fixture(t);
  fs.writeFileSync(f.releaseNotesFile, "  \n", "utf8");
  await assert.rejects(publishRelease({ ...f, version: "1.2.3" }), /release notes are empty/);
  fs.writeFileSync(f.releaseNotesFile, "Notes\n", "utf8");
  await assert.rejects(
    publishRelease({ ...f, version: "1.2.3", assets: [{ name: "x.json", path: path.join(f.directory, "missing.json") }] }),
    /ENOENT/,
  );
  assert.deepEqual(f.calls, []);
});

test("a prerelease version is flagged as prerelease", async (t) => {
  const f = fixture(t);
  await publishRelease({ ...f, version: "1.2.3-rc.1" });
  assert.equal(f.calls[0][1].prerelease, true);
  assert.equal(f.calls[0][1].tag_name, "v1.2.3-rc.1");
});

const publishCalls = (calls) => calls.filter(([kind, input]) => kind === "update" && input.draft === false);

test("make_latest follows latestMoved on first publish and on a published update", async (t) => {
  for (const [latestMoved, expected] of [
    [true, "true"],
    [false, "false"],
  ]) {
    const fresh = fixture(t);
    await publishRelease({ ...fresh, version: "1.2.3", latestMoved });
    assert.equal(publishCalls(fresh.calls)[0][1].make_latest, expected);
    const assets = [asset(1, "trivy-amd64.json"), asset(2, "trivy-arm64.json")];
    const rerun = fixture(t, [{ id: 7, tag_name: "v1.2.3", draft: false, body: "old\n", assets }]);
    await publishRelease({ ...rerun, version: "1.2.3", latestMoved });
    assert.equal(publishCalls(rerun.calls)[0][1].make_latest, expected);
  }
});

test("a prerelease is never marked latest", async (t) => {
  const f = fixture(t);
  await publishRelease({ ...f, version: "1.2.3-rc.1", latestMoved: true });
  assert.equal(publishCalls(f.calls)[0][1].make_latest, "false");
});

test("a missing latestMoved fails before any write", async (t) => {
  const f = fixture(t);
  await assert.rejects(publishRelease({ ...f, version: "1.2.3", latestMoved: undefined }), /latestMoved must be a boolean/);
  assert.deepEqual(f.calls, []);
});

test("verifyAssets reports state, size and digest problems", async (t) => {
  const f = fixture(t);
  const files = [{ name: "a.json", size: 2, sha256: digestOf(CONTENT).slice(7) }];
  const verify = (assets) => verifyAssets({ github: f.github, owner: "o", repo: "r", assets, files });
  assert.equal(await verify([asset(1, "a.json")]), null);
  assert.match(await verify([asset(1, "a.json", { state: "starter" })]), /a\.json is in state starter/);
  assert.match(await verify([asset(1, "a.json", { content: "{ }" })]), /a\.json has 3 bytes, expected 2/);
  assert.match(await verify([asset(1, "a.json", { digest: digestOf("[]") })]), /a\.json has digest/);
  assert.match(await verify([]), /missing a\.json/);
});

test("without an API digest the asset is downloaded and hashed", async (t) => {
  const f = fixture(t);
  const files = [{ name: "a.json", size: 2, sha256: digestOf(CONTENT).slice(7) }];
  f.releases.push({ id: 9, assets: [asset(1, "a.json", { digest: null }), asset(2, "b.json", { content: "[]", digest: null })] });
  const verify = (assets) => verifyAssets({ github: f.github, owner: "o", repo: "r", assets, files });
  assert.equal(await verify([f.releases[0].assets[0]]), null);
  const wrong = { ...f.releases[0].assets[1], name: "a.json" };
  assert.match(await verify([wrong]), /a\.json has digest/);
  assert.ok(f.calls.some(([kind]) => kind === "download"));
});

test("a release is published when uploads carry no digest and the downloaded bytes match", async (t) => {
  const f = fixture(t, [], { uploadDigest: false });
  await publishRelease({ ...f, version: "1.2.3" });
  assert.equal(publishCalls(f.calls).length, 1);
  assert.ok(f.calls.some(([kind]) => kind === "download"));
});

test("an uploaded asset with the wrong size fails before publishing", async (t) => {
  const f = fixture(t);
  const upload = f.github.rest.repos.uploadReleaseAsset;
  f.github.rest.repos.uploadReleaseAsset = async (input) => {
    const result = await upload(input);
    result.data.size += 1;
    return result;
  };
  await assert.rejects(publishRelease({ ...f, version: "1.2.3" }), /not ready to publish: .*bytes, expected/);
  assert.equal(publishCalls(f.calls).length, 0);
});

test("a published release whose assets changed after publishing fails", async (t) => {
  const f = fixture(t);
  const update = f.github.rest.repos.updateRelease;
  f.github.rest.repos.updateRelease = async (input) => {
    await update(input);
    for (const listed of f.releases[0].assets) listed.digest = digestOf("tampered");
  };
  await assert.rejects(publishRelease({ ...f, version: "1.2.3" }), /was published but its assets differ/);
});
