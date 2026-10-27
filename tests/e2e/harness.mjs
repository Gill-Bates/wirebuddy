//
// tests/e2e/harness.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Shared setup of the browser E2E drivers: Playwright from the central toolset, the artifact
// directory, the result log and the isolated WireBuddy server. Importing it creates the artifact
// directory named by argv[2].
// Matrix cell: PLAYWRIGHT_BROWSER=chromium|webkit|firefox (legacy BROWSER only when it names an engine),
// COLOR_SCHEME=light|dark. Server: PYTHON, defaults
// to <repo>/.venv/bin/python. Credentials are generated per run, never configured.
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

if (!process.env.PLAYWRIGHT_DIR) {
    console.error('PLAYWRIGHT_DIR must point at the central toolset (e.g. /opt/ux-test-tools)');
    process.exit(2);
}
if (!process.argv[2]) {
    console.error('usage: node <driver>.mjs <artifact-dir>');
    process.exit(2);
}

const require = createRequire(path.join(process.env.PLAYWRIGHT_DIR, 'noop.js'));
const playwright = require('playwright');

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const ENGINES = ['chromium', 'webkit', 'firefox'];
// An explicit PLAYWRIGHT_BROWSER must be an engine name (a typo would silently test the wrong engine).
// The legacy BROWSER is ambient on desktops (BROWSER=xdg-open), so it only counts when it is valid.
export const resolveBrowser = (fallback) => {
    const explicit = process.env.PLAYWRIGHT_BROWSER;
    if (explicit !== undefined && explicit !== '') {
        if (!ENGINES.includes(explicit)) {
            console.error(`Invalid PLAYWRIGHT_BROWSER '${explicit}'. Valid values: ${ENGINES.join(', ')}`);
            process.exit(2);
        }
        return explicit;
    }
    return ENGINES.includes(process.env.BROWSER) ? process.env.BROWSER : fallback;
};
export const BROWSER = resolveBrowser('chromium');
export const THEME = process.env.COLOR_SCHEME === 'dark' ? 'dark' : 'light';
export const engines = { chromium: playwright.chromium, webkit: playwright.webkit, firefox: playwright.firefox };
export const engine = engines[BROWSER];
export const devices = playwright.devices;
export const OUT = path.resolve(process.argv[2]);
fs.mkdirSync(OUT, { recursive: true });
const PY = process.env.PYTHON || path.join(ROOT, '.venv/bin/python');
export const results = [];

export const check = (name, ok, detail = '') => {
    results.push({ name, ok, detail });
    console.log(`${ok ? 'PASS' : 'FAIL'} ${name} ${detail}`);
};
export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export const freePort = () => new Promise((resolve) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
        const { port } = server.address();
        server.close(() => resolve(port));
    });
});

const procs = [];
const killAll = () => {
    for (const proc of procs) if (proc.exitCode === null) proc.kill('SIGKILL');
};
process.once('exit', killAll);
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { killAll(); process.exit(130); });

// Registers a child spawned elsewhere so the exit hook reaps it too.
export const track = (proc) => { procs.push(proc); return proc; };

// Spawns a child with its output appended to a log file in OUT; the exit hook above reaps it.
export function spawnProc(command, args, log, env = {}) {
    const proc = spawn(command, args, { cwd: ROOT, env: { ...process.env, PYTHONUNBUFFERED: '1', ...env } });
    let out = '';
    proc.stdout.on('data', (data) => { out += data; fs.appendFileSync(log, data); });
    proc.stderr.on('data', (data) => fs.appendFileSync(log, data));
    procs.push(proc);
    return { proc, output: () => out };
}

// Starts WireBuddy on a free port with a throwaway data dir below OUT and a freshly seeded admin.
// The password is random per call and only travels through the child's environment.
export async function startServer(tag = 'e2e') {
    const port = await freePort();
    const dataDir = fs.mkdtempSync(path.join(OUT, `data-${tag}-`));
    const username = 'admin';
    const password = `E2e1!${crypto.randomBytes(15).toString('base64url')}`;
    const secretKey = crypto.randomBytes(32).toString('base64');
    const server = spawnProc(PY, [path.join(ROOT, 'tests/e2e/run_server.py'), dataDir, String(port)], path.join(OUT, `server-${tag}.log`), {
        E2E_ADMIN_USERNAME: username,
        E2E_ADMIN_PASSWORD: password,
        WIREBUDDY_SECRET_KEY: secretKey,
        NO_COLOR: '1',
    });
    const base = `http://127.0.0.1:${port}`;
    let up = false;
    for (let i = 0; i < 150 && server.proc.exitCode === null; i++) {
        try {
            if ((await fetch(`${base}/login`)).ok) { up = true; break; }
        } catch { /* not listening yet */ }
        await sleep(200);
    }
    if (!up) throw new Error(`server did not start; see ${path.join(OUT, `server-${tag}.log`)}`);
    // A gate that is still armed would 302/423 every view; stop with the reason instead.
    const status = await (await fetch(`${base}/api/system/status`)).text();
    if (status.includes('bootstrap_waiting')) throw new Error('bootstrap gate is active; the admin seed did not take effect');
    return { base, username, password, dataDir, ...server };
}

// Logs in through the form like a user; the page lands on the post-login view.
export async function login(page, { base, username, password }) {
    await page.goto(`${base}/login`);
    await page.fill('#username', username);
    await page.fill('#password', password);
    await Promise.all([
        page.waitForURL((url) => !url.pathname.startsWith('/login'), { timeout: 20000 }),
        page.click('#submit-btn'),
    ]);
}

// Writes results-<tag>.json, prints the tally and exits non-zero on any failure.
export function finish(tag) {
    fs.writeFileSync(path.join(OUT, `results-${tag}.json`), JSON.stringify(results, null, 2));
    const failed = results.filter((r) => !r.ok);
    console.log(`\n${tag} ${BROWSER}/${THEME}: ${results.length - failed.length}/${results.length} checks passed`);
    process.exit(failed.length ? 1 : 0);
}
