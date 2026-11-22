//
// tests/layout/run.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Entry point of the layout suite: maps options onto the WIREBUDDY_LAYOUT_* variables and runs the
// repository-local Playwright CLI. Extra arguments after `--` go to `playwright test` (e.g. `--list`).
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "../..");
const flags = new Set(["self-test", "help"]);
const valued = new Set(["profile", "browsers", "pages", "viewports"]);
const options = new Map();
const passthrough = [];
const argv = process.argv.slice(2);
for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--") {
        passthrough.push(...argv.slice(index + 1));
        break;
    }
    if (!argument.startsWith("--")) throw new Error(`Unexpected argument: ${argument}`);
    const name = argument.slice(2);
    if (flags.has(name)) options.set(name, true);
    else if (valued.has(name)) {
        const value = argv[index + 1];
        if (!value || value.startsWith("--")) throw new Error(`Missing value for ${argument}`);
        options.set(name, value);
        index += 1;
    } else throw new Error(`Unknown option: ${argument}`);
}

if (options.has("help")) {
    console.log("node tests/layout/run.mjs [--profile quick|full] [--browsers chromium,webkit,firefox] [--pages ids] [--viewports names] [--self-test] [-- <playwright test args>]");
} else {
    const env = { ...process.env };
    for (const [option, variable] of [
        ["profile", "WIREBUDDY_LAYOUT_PROFILE"],
        ["browsers", "WIREBUDDY_LAYOUT_BROWSERS"],
        ["pages", "WIREBUDDY_LAYOUT_PAGES"],
        ["viewports", "WIREBUDDY_LAYOUT_VIEWPORTS"],
    ]) {
        if (options.has(option)) env[variable] = options.get(option);
    }
    const cli = path.join(repo, "node_modules/@playwright/test/cli.js");
    if (!fs.existsSync(cli)) throw new Error("Playwright is not installed; run `npm ci` in the repository root first");
    const grep = options.has("self-test") ? "@audit-self-test" : "@layout";
    const result = spawnSync(process.execPath, [cli, "test", "--config", path.join(here, "playwright.config.mjs"), "--grep", grep, ...passthrough], {
        cwd: repo,
        env,
        stdio: "inherit",
    });
    if (result.error) throw result.error;
    process.exitCode = result.status ?? 2;
}
