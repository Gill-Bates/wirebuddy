//
// tests/layout/playwright.config.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Environment (all validated, an unknown value fails the run):
//   WIREBUDDY_LAYOUT_BROWSERS  chromium,webkit,firefox subset, default chromium
//   WIREBUDDY_LAYOUT_PROFILE   quick | full, default quick (read by harness.mjs)
//   WIREBUDDY_LAYOUT_WORKERS   positive integer; default min(2, cpus), CI always 2
//   WIREBUDDY_LAYOUT_OUTPUT    Playwright output dir (traces, screenshots)
//   WIREBUDDY_LAYOUT_JUNIT     JUnit XML file
//   WIREBUDDY_LAYOUT_LOGS      server log directory (kept outside the output dir, Playwright cleans that)
import { defineConfig } from "@playwright/test";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { layoutProfile } from "./harness.mjs";

const supported = new Set(["chromium", "firefox", "webkit"]);
const browsers = (process.env.WIREBUDDY_LAYOUT_BROWSERS || "chromium").split(",").map((name) => name.trim()).filter(Boolean);
const unknown = browsers.filter((name) => !supported.has(name));
if (!browsers.length || unknown.length) throw new Error(`Unsupported WIREBUDDY_LAYOUT_BROWSERS selection: ${unknown.join(", ") || "empty"}`);
layoutProfile();

const workers = (() => {
    const raw = process.env.WIREBUDDY_LAYOUT_WORKERS;
    if (raw !== undefined && raw !== "") {
        if (!/^[1-9][0-9]{0,3}$/.test(raw)) throw new Error(`WIREBUDDY_LAYOUT_WORKERS must be a positive integer, got ${JSON.stringify(raw)}`);
        return Number(raw);
    }
    return process.env.CI ? 2 : Math.max(1, Math.min(2, os.cpus().length));
})();

const reporters = [["list"]];
if (process.env.WIREBUDDY_LAYOUT_JUNIT) reporters.push(["junit", { outputFile: process.env.WIREBUDDY_LAYOUT_JUNIT }]);

// WebKit runs the mobile and tablet viewports (the iOS-like cells); Firefox cannot emulate a device
// descriptor (isMobile), so @device cells are left out there. a11y runs once, in Chromium.
const projectFilters = {
    chromium: {},
    webkit: { grep: /@mobile/, testIgnore: "a11y.spec.mjs" },
    firefox: { grepInvert: /@device/, testIgnore: "a11y.spec.mjs" },
};

export default defineConfig({
    forbidOnly: true,
    testDir: path.dirname(fileURLToPath(import.meta.url)),
    testMatch: "*.spec.mjs",
    // Budgets, not fixes for slow tests: a cell takes a few seconds; globalTimeout stays below the 30 min CI job limit.
    timeout: 120_000,
    globalTimeout: 1_500_000,
    expect: { timeout: 10_000 },
    fullyParallel: true,
    workers,
    retries: 0,
    reporter: reporters,
    outputDir: process.env.WIREBUDDY_LAYOUT_OUTPUT || path.join(os.tmpdir(), `wirebuddy-layout-${process.pid}`),
    use: {
        trace: "retain-on-failure",
        screenshot: "only-on-failure",
        video: "off",
    },
    projects: browsers.map((name) => ({
        name,
        ...projectFilters[name],
        use: {
            browserName: name,
            launchOptions: name === "chromium" ? { args: ["--disable-threaded-animation"] } : {},
        },
    })),
});
