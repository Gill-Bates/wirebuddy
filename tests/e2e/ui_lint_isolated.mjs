//
// tests/e2e/ui_lint_isolated.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Runs the full tools/ui-lint audit against a throwaway WireBuddy instance: starts the server on a
// free port with an empty data dir and a seeded admin (random credentials per run), points the
// UI_LINT_* environment at it and writes everything into <artifact-dir> (ui-lint/ for findings and
// screenshots, audit.log, server-*.log). Exits with the audit's exit code.
// Usage: PLAYWRIGHT_DIR=<dir> PYTHON=<venv python> [PLAYWRIGHT_BROWSER=chromium|webkit|firefox] \
//   [COLOR_SCHEME=light|dark] node tests/e2e/ui_lint_isolated.mjs <artifact-dir>
// PLAYWRIGHT_BROWSER (or a valid legacy BROWSER) maps onto UI_LINT_BROWSERS only when that is unset; any other UI_LINT_* value passes through.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { BROWSER, check, OUT, ROOT, startServer, track } from './harness.mjs';

let server;
let code = 1;
try {
    server = await startServer('ui-lint');
    const outputDir = path.join(OUT, 'ui-lint');
    fs.mkdirSync(outputDir, { recursive: true });
    const log = fs.createWriteStream(path.join(OUT, 'audit.log'));
    const audit = track(spawn(process.execPath, [path.join(ROOT, 'tools/ui-lint/run-ui-lint.mjs')], {
        cwd: path.join(ROOT, 'tools/ui-lint'),
        env: {
            ...process.env,
            UI_LINT_BASE_URL: server.base,
            UI_LINT_USERNAME: server.username,
            UI_LINT_PASSWORD: server.password,
            UI_LINT_OUTPUT_DIR: process.env.UI_LINT_OUTPUT_DIR || outputDir,
            UI_LINT_BROWSERS: process.env.UI_LINT_BROWSERS || BROWSER,
        },
    }));
    for (const stream of [audit.stdout, audit.stderr]) {
        stream.on('data', (chunk) => { process.stdout.write(chunk); log.write(chunk); });
    }
    code = await new Promise((resolve) => audit.on('close', (exitCode, signal) => resolve(exitCode ?? (signal ? 1 : 0))));
    log.end();
    check('ui-lint audit exited cleanly', code === 0, `exit=${code}`);
} catch (error) {
    check('isolated server started', false, String(error?.message || error));
} finally {
    if (server?.proc.exitCode === null) server.proc.kill('SIGTERM');
}
process.exit(code);
