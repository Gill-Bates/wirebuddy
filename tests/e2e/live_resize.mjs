//
// tests/e2e/live_resize.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Browser E2E: a viewport resize DRIVEN MID-SESSION (no reload) must reflow the main views without
// horizontal overflow and without tearing the layout down. Each page is loaded once at desktop
// width, then resized live through tablet, phone and back; at every step the document must not
// scroll horizontally and the content structure (widgets, cards, tabs) must still be present.
// Distinct from a fresh load at each width, which ui-lint and ios_viewport_audit.mjs cover.
// Usage: PLAYWRIGHT_DIR=<dir> PYTHON=<venv python> PLAYWRIGHT_BROWSER=chromium|firefox|webkit \
//   COLOR_SCHEME=light|dark node tests/e2e/live_resize.mjs <artifact-dir>
import path from 'node:path';
import { BROWSER, check, engine, finish, login, OUT, sleep, startServer, THEME } from './harness.mjs';

// Desktop -> tablet landscape -> tablet portrait -> phone -> back to desktop, all without a reload.
const STEPS = [[1280, 900], [1024, 768], [820, 1180], [390, 844], [1280, 900]];
// slug -> selector that counts the structural elements which must survive a resize.
const PAGES = [
    ['dashboard', '.grid-stack-item'],
    ['peers', 'main.main-content .card'],
    ['dns', 'main.main-content .card'],
    ['settings', '#settingsTabs .nav-link'],
];
// Console noise that is not a layout defect (third-party tile/CDN fetches, CSP reports).
const IGNORED = /Content Security Policy|Failed to load resource/;
const problems = [];

// Measured from the DOM, not from a screenshot.
const overflow = (page) => page.evaluate(() => Math.max(0, document.documentElement.scrollWidth - document.documentElement.clientWidth));

const server = await startServer(`resize-${THEME}`);
let browser;
try {
    browser = await engine.launch();
    const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: 'en-GB', colorScheme: THEME });
    const page = await context.newPage();
    page.on('console', (m) => { if (['error', 'warning'].includes(m.type())) problems.push(`console ${m.type()}: ${m.text()}`); });
    page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));

    await login(page, server);

    for (const [slug, selector] of PAGES) {
        await page.setViewportSize({ width: 1280, height: 900 });
        await page.goto(`${server.base}/ui/${slug}`);
        await page.waitForSelector(selector, { timeout: 20000 });
        await sleep(600); // let charts and grid layout settle at the starting width
        const baseCount = await page.locator(selector).count();
        check(`${slug}: structure renders before resizing`, baseCount >= 1, `${selector} x${baseCount}`);

        for (const [w, h] of STEPS) {
            await page.setViewportSize({ width: w, height: h });
            await sleep(400); // allow the resize-driven reflow (gridstack, container queries) to settle
            const ov = await overflow(page);
            const count = await page.locator(selector).count();
            await page.screenshot({ path: path.join(OUT, `resize-${slug}-${w}-${THEME}.png`), fullPage: false });
            check(`${slug}: no horizontal overflow after live resize to ${w}px (${THEME})`, ov === 0, `overflow=${ov}px`);
            check(`${slug}: structure survives the live resize to ${w}px (${THEME})`, count === baseCount, `count=${count} base=${baseCount}`);
        }
    }

    const unexpected = problems.filter((p) => !IGNORED.test(p));
    check('no unexpected console or page errors during the resize session', unexpected.length === 0, unexpected.join(' | '));
} catch (error) {
    check('driver ran to completion', false, String(error?.stack || error));
} finally {
    if (browser) await browser.close();
    if (server.proc.exitCode === null) server.proc.kill('SIGTERM');
}
finish(`resize-${BROWSER}-${THEME}`);
