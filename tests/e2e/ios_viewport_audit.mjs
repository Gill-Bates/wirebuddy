//
// tests/e2e/ios_viewport_audit.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Browser E2E: the iOS failure classes headless WebKit does not show on its own, audited on every
// main view across a phone/tablet device matrix (shared approach with rct-manager):
//   - env(safe-area-inset-*) without viewport-fit=cover (every inset silently resolves to 0),
//   - height/min-height/max-height in vh without a dvh/svh replacement (iOS URL-bar jump),
//   - html/body locked by a viewport unit plus overflow hidden (scroll trap),
//   - text controls rendered below 16px after the content zoom (Safari zooms in on focus and stays),
//   - one scroll container really scrolling inside another one (nested scroll trap),
//   - single elements wider than the viewport outside a horizontal scroller (named, not just "the page"),
//   - buttons and form controls under 44px on a phone.
// Usage: PLAYWRIGHT_DIR=<dir> PYTHON=<python> PLAYWRIGHT_BROWSER=webkit|chromium COLOR_SCHEME=light|dark \
//   [DEVICES='iPhone 14,iPad Mini'] node tests/e2e/ios_viewport_audit.mjs <artifact-dir>
import path from 'node:path';
import { check, devices, engines, finish, login, OUT, resolveBrowser, sleep, startServer } from './harness.mjs';

const scheme = process.env.COLOR_SCHEME === 'dark' ? 'dark' : 'light';
// This driver is about WebKit, so its default differs from the harness default (chromium).
const browserName = resolveBrowser('webkit');
const engine = engines[browserName];
// iPhone SE: narrowest supported phone. iPad Mini landscape: exactly 1024px, the off-by-one breakpoint
// edge. iPad Pro 11 landscape: a touch screen wider than every width breakpoint.
const DEVICE_NAMES = (process.env.DEVICES
    || 'iPhone SE,iPhone 14,iPhone 14 landscape,iPad Mini,iPad Mini landscape,iPad Pro 11 landscape')
    .split(',').map((d) => d.trim()).filter(Boolean);
const PAGES = ['dashboard', 'peers', 'users', 'nodes', 'dns', 'traffic', 'settings', 'about'];
const PHONE_MAX_WIDTH = 767.98; // Bootstrap md breakpoint minus a hair

// Runs in the page. Everything is measured from computed styles and rendered boxes.
function audit({ phoneMaxWidth }) {
    const vw = document.documentElement.clientWidth;
    const visible = (el) => {
        const r = el.getBoundingClientRect();
        const cs = getComputedStyle(el);
        return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none';
    };
    const describe = (el) => `${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ''}${[...el.classList].slice(0, 3).map((c) => `.${c}`).join('')}`;
    // CSS zoom compounds down the tree; the rendered size is the computed size times every ancestor zoom.
    const zoomOf = (el) => {
        let z = 1;
        for (let n = el; n && n.nodeType === 1; n = n.parentElement) z *= parseFloat(getComputedStyle(n).zoom) || 1;
        return z;
    };

    // Own stylesheets only, flattened so rules inside @media/@supports are inspected one by one.
    const rules = [];
    const walk = (list) => { for (const r of list) { if (r.cssRules?.length) walk(r.cssRules); else if (r.selectorText && r.style) rules.push(r); } };
    for (const sheet of document.styleSheets) {
        if (!sheet.href || sheet.href.includes('/vendor/')) continue;
        try { walk(sheet.cssRules); } catch { /* cross-origin */ }
    }
    const css = rules.map((r) => r.cssText).join('\n');
    const meta = document.querySelector('meta[name="viewport"]')?.content || '';

    // CSSOM keeps only the last declaration of a property, so a rule still reporting vh has no fallback.
    const vhTraps = [];
    for (const r of rules) {
        for (const prop of ['height', 'min-height', 'max-height']) {
            const v = r.style.getPropertyValue(prop);
            if (/\d(?:\.\d+)?vh\b/.test(v)) vhTraps.push(`${r.selectorText.slice(0, 80)} { ${prop}: ${v} }`);
        }
    }

    const locked = [document.documentElement, document.body].filter((el) => {
        const cs = getComputedStyle(el);
        return (cs.overflowY === 'hidden' || cs.overflow === 'hidden') && /vh/.test(el.style.height + el.style.minHeight)
            && !document.querySelector('.modal.show'); // Bootstrap locks the body while a modal is open, by design
    }).map(describe);

    // All text controls, hidden ones (closed modals, inactive tabs) included: their font does not depend on visibility.
    const smallInputs = [...document.querySelectorAll('input:not([type=checkbox]):not([type=radio]):not([type=range]):not([type=hidden]):not([type=submit]):not([type=button]):not([type=color]):not([type=file]), select, textarea')]
        .map((el) => ({ el: describe(el), px: Math.round(parseFloat(getComputedStyle(el).fontSize) * zoomOf(el) * 100) / 100 }))
        .filter((c) => c.px < 16 - 0.01);

    const scrollers = [...document.querySelectorAll('body *')].filter((el) => {
        const cs = getComputedStyle(el);
        return visible(el) && /(auto|scroll)/.test(cs.overflowY) && el.scrollHeight > el.clientHeight + 2;
    });
    const nested = scrollers.filter((el) => scrollers.some((outer) => outer !== el && outer.contains(el))).map(describe);

    const horizontallyClipped = (el) => {
        for (let n = el.parentElement; n && n !== document.body; n = n.parentElement) {
            if (/(auto|scroll|hidden|clip)/.test(getComputedStyle(n).overflowX)) return true;
        }
        return false;
    };
    const overflowing = [...document.querySelectorAll('body *')]
        .filter((el) => visible(el) && getComputedStyle(el).position !== 'fixed')
        .filter((el) => { const r = el.getBoundingClientRect(); return r.right > vw + 1 || r.left < -1; })
        .filter((el) => !horizontallyClipped(el))
        // Report the outermost offender only; its children overflow with it.
        .filter((el, _, all) => !all.some((o) => o !== el && o.contains(el)))
        .map((el) => { const r = el.getBoundingClientRect(); return `${describe(el)} [${Math.round(r.left)}..${Math.round(r.right)}]`; });

    const smallTargets = vw > phoneMaxWidth ? [] : [...document.querySelectorAll('main.main-content :is(.btn, .form-control, .form-select)')]
        .filter(visible)
        .map((el) => { const r = el.getBoundingClientRect(); return { el: describe(el), w: Math.round(r.width), h: Math.round(r.height) }; })
        // Height is the contract for every control; width only for buttons (inputs are full-width anyway).
        .filter((t) => t.h < 44 - 0.5 || (/^(button|a)/.test(t.el) && t.w < 44 - 0.5));

    return {
        vw, docScroll: document.documentElement.scrollWidth,
        safeAreaWithoutCover: /env\(\s*safe-area-inset-/.test(css) && !/viewport-fit\s*=\s*cover/.test(meta),
        bottomInsetDeclared: /env\(\s*safe-area-inset-bottom/.test(css),
        vhTraps, locked, smallInputs, nested, overflowing, smallTargets,
    };
}

const server = await startServer(`ios-${browserName}-${scheme}`);
let browser;
try {
    browser = await engine.launch();
    // One login shared by every device context.
    let storageState;
    {
        const context = await browser.newContext({ locale: 'en-GB' });
        const page = await context.newPage();
        await login(page, server);
        storageState = await context.storageState();
        await context.close();
    }

    for (const name of DEVICE_NAMES) {
        const descriptor = devices[name];
        if (!descriptor) { check(`device profile "${name}" exists in Playwright`, false); continue; }
        // Firefox has no isMobile; drop it there so the matrix still runs on every engine.
        const { defaultBrowserType, ...options } = descriptor;
        if (browserName === 'firefox') delete options.isMobile;
        const context = await browser.newContext({ ...options, storageState, locale: 'en-GB', colorScheme: scheme });
        const page = await context.newPage();
        const tag = `[${browserName}-${scheme}] ${name}`;

        for (const slug of PAGES) {
            await page.goto(`${server.base}/ui/${slug}`);
            // No networkidle: polling and live widgets keep the network busy for good.
            await page.waitForSelector('main.main-content', { timeout: 15000 });
            await page.evaluate(() => document.fonts.ready);
            await sleep(700);
            const where = `${tag} ${slug}`;
            const a = await page.evaluate(audit, { phoneMaxWidth: PHONE_MAX_WIDTH });
            // The page-wide CSS checks are identical everywhere; report them once per device.
            if (slug === PAGES[0]) {
                check(`${tag}: safe-area insets are live (viewport-fit=cover)`, !a.safeAreaWithoutCover);
                check(`${tag}: the stylesheet reserves safe-area-inset-bottom`, a.bottomInsetDeclared);
                check(`${tag}: no vh height without a dvh/svh replacement`, a.vhTraps.length === 0, a.vhTraps.join(' | '));
            }
            check(`${where}: html/body are not viewport-locked`, a.locked.length === 0, a.locked.join(', '));
            check(`${where}: text controls render at >=16px (no iOS focus zoom)`, a.smallInputs.length === 0, JSON.stringify(a.smallInputs.slice(0, 8)));
            check(`${where}: no scroll container scrolls inside another`, a.nested.length === 0, a.nested.join(', '));
            check(`${where}: no element sticks out of the viewport`, a.overflowing.length === 0 && a.docScroll <= a.vw + 1,
                `vw=${a.vw} scrollW=${a.docScroll} ${a.overflowing.slice(0, 6).join(', ')}`);
            if (a.vw <= PHONE_MAX_WIDTH) {
                check(`${where}: buttons and controls are >=44px touch targets`, a.smallTargets.length === 0, JSON.stringify(a.smallTargets.slice(0, 8)));
            }
            await page.screenshot({ path: path.join(OUT, `${slug}-${name.replace(/\W+/g, '_')}-${browserName}-${scheme}.png`), fullPage: true });
        }
        await context.close();
    }
} catch (error) {
    check('driver ran to completion', false, String(error?.stack || error));
} finally {
    if (browser) await browser.close();
    if (server.proc.exitCode === null) server.proc.kill('SIGTERM');
}
finish(`ios-${browserName}-${scheme}`);
