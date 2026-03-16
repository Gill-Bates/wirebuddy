//
// tools/ui-lint/run-ui-lint.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// tools/ui-lint/run-ui-lint.mjs
// Copyright (C) 2025 Gill-Bates http://github.com/Gill-Bates
//

import fs from 'node:fs';
import path from 'node:path';

import pixelmatch from 'pixelmatch';
import { PNG } from 'pngjs';
import { chromium, devices } from 'playwright';

const BASE_URL = process.env.UI_LINT_BASE_URL || 'http://localhost:8000';
const USERNAME = process.env.UI_LINT_USERNAME || 'admin';
const PASSWORD = process.env.UI_LINT_PASSWORD || 'admin';
const OUTPUT_DIR = path.resolve(process.cwd(), process.env.UI_LINT_OUTPUT_DIR || 'ui-lint-output');
const SCREENSHOT_DIR = path.resolve(
    OUTPUT_DIR,
    process.env.UI_LINT_SCREENSHOT_DIR || 'screenshots'
);

// Thresholds and timing constants
const VERTICAL_GAP_MIN = 22;
const VERTICAL_GAP_MAX = 26;
const VISUAL_DRIFT_THRESHOLD = 0.0025;
const SCREENSHOT_SETTLE_MS = 800;
const TAB_SWITCH_SETTLE_MS = 700;
const DETAILS_EXPAND_SETTLE_MS = 300;
const OVERFLOW_TOLERANCE_PX = 2;
const FOOTER_OVERLAP_TOLERANCE_PX = 1;
const SCROLL_EDGE_CLEARANCE_MIN = 12;
const LAYOUT_SHIFT_THRESHOLD = 0.02;
const COMPONENT_LAYOUT_SHIFT_THRESHOLD_PX = 2;
const COMPONENT_LAYOUT_SHIFT_SETTLE_MS = 500;
const CLICK_TARGET_MIN_SIZE_PX = 44;
const LOGIN_ERROR_SETTLE_MS = 120;
const LOGIN_LOCKOUT_RESET_MS = 16000;
const LOGS_DELETE_HAIRLINE_TOLERANCE_PX = 2;
const BADGE_FONT_SIZE_TOLERANCE_PX = 0.5;
const BADGE_FONT_WEIGHT_TOLERANCE = 50;
const BADGE_RADIUS_TOLERANCE_PX = 1;
const BADGE_PADDING_TOLERANCE_PX = 1;
const MONOSPACE_RADIUS_TOLERANCE_PX = 1;
const MONOSPACE_PADDING_TOLERANCE_PX = 1;
const SLIDER_TICK_ALIGNMENT_TOLERANCE_PX = 3;
const SLIDER_VISIBLE_LABEL_GAP_MIN_PX = 4;
const SLIDER_LABEL_HIDDEN_OPACITY_MAX = 0.05;
const MODAL_BACKDROP_BLUR_EXPECTED_PX = 8;
const MODAL_BACKDROP_BLUR_TOLERANCE_PX = 0.25;
const MODAL_BACKDROP_SATURATE_EXPECTED = 0.8;
const MODAL_BACKDROP_SATURATE_TOLERANCE = 0.05;
const MODAL_BACKDROP_ALPHA_EXPECTED = 0.6;
const MODAL_BACKDROP_ALPHA_TOLERANCE = 0.05;

// Form Control Height validation (input-group consistency)
// Current Bootstrap-based WireBuddy controls render at ~44px total height
// for default-sized .form-control/.btn combinations in settings input groups.
const INPUT_GROUP_HEIGHT_EXPECTED_PX = 44;
const INPUT_GROUP_HEIGHT_TOLERANCE_PX = 2;

// KPI Card validation constants
const KPI_CARD_PADDING_EXPECTED = 16; // px (1rem)
const KPI_CARD_PADDING_TOLERANCE = 1;
const KPI_ICON_MIN = 32;
const KPI_ICON_MAX = 40;
const KPI_VISUAL_DRIFT_THRESHOLD = 0.01;
const KPI_HEIGHT_TOLERANCE_PX = 2;
const KPI_ROW_VARIANCE_MAX = 3;
const KPI_CARD_REQUIRED_SCOPES = ['dashboard', 'dns'];
const THEMES = ['light', 'dark'];

// WCAG 2.1 AA contrast requirements
const WCAG_CONTRAST = {
    NORMAL_AA: 4.5,
    LARGE_AA: 3.0,
    LARGE_TEXT_SIZE_PX: 24,
    LARGE_TEXT_SIZE_BOLD_PX: 18.66,
    BOLD_WEIGHT: 700,
};

const STATUS_FLOW_NODE_EXPECTATIONS = [
    { key: 'client', label: 'Client', icon: 'devices' },
    { key: 'wireguard', label: 'WireGuard', icon: 'vpn_lock' },
    { key: 'internet', label: 'Internet', icon: 'public' },
];

const STATUS_FLOW_CONNECTOR_EXPECTATIONS = [
    'client-wireguard',
    'wireguard-internet',
];

const LOGIN_FAILURE_VIEW_DEFS = [
    { name: 'login-error', url: '/login', scope: 'login' },
];

// View definitions (DRY: desktop and mobile generated from base definitions)
const VIEW_DEFS = [
    { name: 'dashboard', url: '/ui/dashboard', scope: 'dashboard' },
    { name: 'peers', url: '/ui/peers', scope: 'peers' },
    { name: 'users', url: '/ui/users', scope: 'users' },
    { name: 'dns', url: '/ui/dns', scope: 'dns' },
    { name: 'traffic', url: '/ui/traffic', scope: 'traffic' },
    { name: 'status', url: '/status', scope: 'status' },
    { name: 'about', url: '/ui/about', scope: 'about' },
    { name: 'settings-general', url: '/ui/settings', scope: 'settings', tab: '#general-tab' },
    { name: 'settings-wireguard', url: '/ui/settings', scope: 'settings', tab: '#wireguard-tab' },
    { name: 'settings-dns', url: '/ui/settings', scope: 'settings', tab: '#dns-tab' },
    { name: 'settings-letsencrypt', url: '/ui/settings', scope: 'settings', tab: '#letsencrypt-tab' },
    { name: 'settings-logs', url: '/ui/settings', scope: 'settings', tab: '#logs-tab' },
];

/**
 * Expands view definitions into desktop/mobile × light/dark variants.
 * @param {Array} viewDefs - Base view definitions
 * @returns {Array} Expanded view definitions with all variants
 */
function expandViewDefinitions(viewDefs) {
    return viewDefs.flatMap((def) =>
        THEMES.flatMap((theme) => [
            { ...def, name: `desktop-${def.name}-${theme}`, mobile: false, theme },
            { ...def, name: `mobile-${def.name}-${theme}`, mobile: true, theme },
        ])
    );
}

const VIEWS = expandViewDefinitions(VIEW_DEFS);
const LOGIN_FAILURE_VIEWS = expandViewDefinitions(LOGIN_FAILURE_VIEW_DEFS);

// Base motion reset CSS (generic)
const MOTION_RESET_CSS = `
  *, *::before, *::after {
    animation: none !important;
    transition: none !important;
    scroll-behavior: auto !important;
    caret-color: transparent !important;
  }
`;

// Application-specific motion resets (WireBuddy)
const APP_SPECIFIC_MOTION_RESET_CSS = `
  .pulse-marker,
  .leaflet-pane,
  .leaflet-control-container,
  #peer-map img,
  #peer-map canvas {
    animation: none !important;
    transition: none !important;
  }
`;

const FULL_MOTION_RESET_CSS = MOTION_RESET_CSS + APP_SPECIFIC_MOTION_RESET_CSS;

function sanitize(name) {
    return name.replace(/[^a-z0-9-_]+/g, '_').toLowerCase();
}

function ensureDir(dirPath) {
    fs.mkdirSync(dirPath, { recursive: true });
}

async function installLayoutShiftObserver(context) {
    await context.addInitScript(() => {
        window.__uiLintLayoutShift = { value: 0, count: 0 };
        if (!('PerformanceObserver' in window)) return;
        try {
            const observer = new PerformanceObserver((list) => {
                for (const entry of list.getEntries()) {
                    if (entry.hadRecentInput) continue;
                    window.__uiLintLayoutShift.value += entry.value || 0;
                    window.__uiLintLayoutShift.count += 1;
                }
            });
            observer.observe({ type: 'layout-shift', buffered: true });
        } catch {
            // Ignore unsupported browsers.
        }
    });
}

async function disableMotion(page, viewName = 'unknown') {
    await page.addStyleTag({ content: FULL_MOTION_RESET_CSS })
        .catch((err) => console.warn(`[${viewName}] Failed to inject motion reset CSS: ${err.message}`));
}

async function resetLayoutShiftMetric(page) {
    await page.evaluate(() => {
        window.__uiLintLayoutShift = { value: 0, count: 0 };
    }).catch(() => { });
}

async function login(page) {
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 10000 });
    await disableMotion(page, 'login');

    // Clear any previous form state
    await page.fill('#username', '');
    await page.fill('#password', '');

    await page.fill('#username', USERNAME);
    await page.fill('#password', PASSWORD);
    await Promise.all([
        page.waitForURL((url) => !url.toString().includes('/login'), { timeout: 10000 }),
        page.click('#submit-btn'),
    ]);

    // Check only visible login errors. The app layout contains a hidden
    // key-mismatch banner that should not fail the login flow.
    const errorText = await page.locator('.alert-danger, .login-error, .error-message').evaluateAll((elements) => {
        const isVisible = (el) => {
            if (!el || !el.isConnected) return false;
            if (el.closest('.d-none, [hidden], [aria-hidden="true"]')) return false;
            const style = window.getComputedStyle(el);
            if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
            const rect = el.getBoundingClientRect();
            return rect.width > 0 && rect.height > 0;
        };

        const visibleError = elements.find((el) => isVisible(el));
        return visibleError ? (visibleError.textContent || '').trim() : '';
    });
    if (errorText) {
        throw new Error(`Login failed: ${errorText}`);
    }

    await disableMotion(page, 'login');
}

async function applyTheme(page, theme, label = 'unknown') {
    let sameOrigin = false;
    try {
        sameOrigin = page.url().startsWith(BASE_URL);
    } catch (err) {
        console.warn(`[${label}] Unable to verify origin: ${err.message}`);
    }

    if (!sameOrigin) {
        await page.goto(`${BASE_URL}/login`, { waitUntil: 'domcontentloaded', timeout: 30000 })
            .catch((err) => console.warn(`[${label}] Failed to bootstrap origin for theme setup: ${err.message}`));
    }

    await page.evaluate((nextTheme) => {
        localStorage.setItem('theme', nextTheme);
        document.documentElement.setAttribute('data-bs-theme', nextTheme);
        if (typeof window.updateThemeIcon === 'function') {
            window.updateThemeIcon(nextTheme);
        }
    }, theme).catch((err) => {
        throw new Error(`[${label}] Failed to apply theme ${theme}: ${err.message}`);
    });
}

function collectConsoleAndNetwork(page) {
    const consoleEntries = [];
    const pageErrors = [];
    const requestFailures = [];
    const badResponses = [];
    const requests = [];

    const onConsole = (msg) => {
        if (['error', 'warning'].includes(msg.type())) {
            consoleEntries.push({ type: msg.type(), text: msg.text() });
        }
    };
    const onPageError = (err) => pageErrors.push(String(err?.message || err));
    const onRequest = (req) => {
        requests.push({
            url: req.url(),
            method: req.method(),
            resourceType: req.resourceType(),
        });
    };
    const onRequestFailed = (req) => requestFailures.push({ url: req.url(), error: req.failure()?.errorText || 'unknown' });
    const onResponse = (res) => {
        if (res.status() >= 400) {
            badResponses.push({ url: res.url(), status: res.status() });
        }
    };

    page.on('console', onConsole);
    page.on('pageerror', onPageError);
    page.on('request', onRequest);
    page.on('requestfailed', onRequestFailed);
    page.on('response', onResponse);

    return () => {
        page.off('console', onConsole);
        page.off('pageerror', onPageError);
        page.off('request', onRequest);
        page.off('requestfailed', onRequestFailed);
        page.off('response', onResponse);
        return { consoleEntries, pageErrors, requestFailures, badResponses, requests };
    };
}

async function captureStablePair(page, name) {
    await disableMotion(page, name);
    await page.waitForLoadState('networkidle', { timeout: 30000 })
        .catch((err) => console.warn(`[${name}] waitForLoadState timed out: ${err.message}`));
    // Note: waitForTimeout is flaky but needed for animations to settle after motion reset
    await page.waitForTimeout(SCREENSHOT_SETTLE_MS);
    const safeName = sanitize(name);
    const shotA = path.join(SCREENSHOT_DIR, `${safeName}-a.png`);
    const shotB = path.join(SCREENSHOT_DIR, `${safeName}-b.png`);
    await page.screenshot({ path: shotA, fullPage: true });
    await page.waitForTimeout(SCREENSHOT_SETTLE_MS);
    await page.screenshot({ path: shotB, fullPage: true });
    return { shotA, shotB };
}

/**
 * Compares two screenshots pixel-by-pixel using pixelmatch algorithm.
 * Detects visual regressions by measuring pixel differences between two PNG images.
 * 
 * @param {string} name - View name for output files (used for diff image naming)
 * @param {string} shotA - Absolute path to first PNG screenshot
 * @param {string} shotB - Absolute path to second PNG screenshot
 * @returns {Object} Diff metrics: { ratio: number (0-1), mismatched: number, total: number, sizeMismatch: boolean, diffPath: string }
 * @throws {Error} If PNG files cannot be read or dimensions mismatch severely
 */
function diffScreenshots(name, shotA, shotB) {
    const img1 = PNG.sync.read(fs.readFileSync(shotA));
    const img2 = PNG.sync.read(fs.readFileSync(shotB));
    const sizeMismatch = img1.width !== img2.width || img1.height !== img2.height;
    const width = Math.min(img1.width, img2.width);
    const height = Math.min(img1.height, img2.height);
    const pngA = new PNG({ width, height });
    const pngB = new PNG({ width, height });
    PNG.bitblt(img1, pngA, 0, 0, width, height, 0, 0);
    PNG.bitblt(img2, pngB, 0, 0, width, height, 0, 0);
    const diff = new PNG({ width, height });
    const mismatchedPixels = pixelmatch(pngA.data, pngB.data, diff.data, width, height, { threshold: 0.1 });
    const diffPath = path.join(SCREENSHOT_DIR, `${sanitize(name)}-diff.png`);
    fs.writeFileSync(diffPath, PNG.sync.write(diff));
    const totalPixels = width * height;
    return {
        mismatchedPixels,
        totalPixels,
        ratio: totalPixels > 0 ? mismatchedPixels / totalPixels : 0,
        sizeMismatch,
        dimensions: sizeMismatch ? { img1: { width: img1.width, height: img1.height }, img2: { width: img2.width, height: img2.height } } : null,
        diffPath,
    };
}

async function captureKpiCards(page, viewName) {
    const cards = await page.$$('.wb-kpi-card');
    const paths = [];

    for (let i = 0; i < cards.length; i += 1) {
        const card = cards[i];
        const pathOut = path.join(
            SCREENSHOT_DIR,
            `${sanitize(viewName)}-kpi-${i}.png`
        );

        await card.screenshot({ path: pathOut });
        paths.push(pathOut);
    }

    return paths;
}

/**
 * Compares KPI card screenshots between two sets.
 * @param {string} nameA - Name of first view
 * @param {Array<string>} setA - Paths to first set of KPI screenshots
 * @param {string} nameB - Name of second view
 * @param {Array<string>} setB - Paths to second set of KPI screenshots
 * @returns {Array<Object>} Comparison results with diff ratios per card
 */
function diffKpiSets(nameA, setA, nameB, setB) {
    const results = [];
    const minSetLength = Math.min(setA.length, setB.length);

    for (let i = 0; i < minSetLength; i += 1) {
        const img1 = PNG.sync.read(fs.readFileSync(setA[i]));
        const img2 = PNG.sync.read(fs.readFileSync(setB[i]));

        const width = Math.min(img1.width, img2.width);
        const height = Math.min(img1.height, img2.height);

        const pngA = new PNG({ width, height });
        const pngB = new PNG({ width, height });

        PNG.bitblt(img1, pngA, 0, 0, width, height, 0, 0);
        PNG.bitblt(img2, pngB, 0, 0, width, height, 0, 0);

        const diff = new PNG({ width, height });

        const mismatched = pixelmatch(
            pngA.data,
            pngB.data,
            diff.data,
            width,
            height,
            { threshold: 0.1 }
        );

        const ratio = mismatched / (width * height);

        results.push({
            index: i,
            ratio,
        });
    }

    return results;
}

async function collectPageMetrics(page, scope) {
    return page.evaluate(async ({ scope, constants }) => {
        const round = (value) => Math.round(value * 10) / 10;
        const norm = (value) => (value || '').replace(/\s+/g, ' ').trim();
        const interactiveSelector = 'button, [role="button"], a[href], input:not([type="hidden"]), select, textarea';
        const clickTargetSelector = [
            'button',
            '.btn',
            '[role="button"]',
            'a[href]',
            'summary',
            'input[type="button"]',
            'input[type="submit"]',
            'input[type="reset"]',
        ].join(', ');
        const focusableSelector = [
            'a[href]',
            'button',
            'input:not([type="hidden"])',
            'select',
            'textarea',
            'summary',
            '[tabindex]',
        ].join(', ');
        const allowedOverflowSelector = '.leaflet-tile-container, .leaflet-tile, #settingsTabs .nav-item, #settingsTabs .nav-link';
        const badgeConsistencyExcludeSelector = [
            '.wb-onboarding-step-badge',
            '.dns-badge-custom-rule',
            '.custom-chart-legend .badge',
            '.blocklist-hero-meta .badge',
            '.map-popup-header .badge',
            '.badge.small',
            '.badge.rounded-circle',
        ].join(', ');
        const monospaceToneExcludeSelector = [
            'input',
            'textarea',
            'select',
            'button',
            'pre',
            'td',
            'th',
            '.form-control',
            '.otp-digit',
            '#recovery-codes',
            '.peer-last-seen',
            'td[data-label="Last Seen"]',
        ].join(', ');
        const contentRoot = document.querySelector('main.main-content') || document.body;

        const isInsideInactivePane = (el) => {
            const pane = el.closest('.tab-pane');
            return Boolean(pane && !pane.classList.contains('active'));
        };

        const isIntentionallyHidden = (el) => Boolean(
            el.closest('.modal:not(.show)')
            || el.closest('.collapse:not(.show)')
            || el.closest('.navbar-collapse:not(.show)')
            || el.closest('.hidden')
            || el.closest('.d-none')
            || el.closest('[hidden]')
            || el.closest('[aria-hidden="true"]')
            || el.closest('[role="presentation"]')
        );

        const isVisible = (el) => {
            if (!el || !el.isConnected || isInsideInactivePane(el) || isIntentionallyHidden(el)) return false;
            const style = window.getComputedStyle(el);
            if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
            const rect = el.getBoundingClientRect();
            return rect.width > 0 && rect.height > 0;
        };

        const isInContentRoot = (el) => contentRoot === document.body || contentRoot.contains(el);

        const isDisabled = (el) => Boolean(
            el.disabled
            || el.getAttribute('aria-disabled') === 'true'
            || el.getAttribute('disabled') !== null
        );

        const shouldSkipInlineClickTarget = (el) => {
            if (el.tagName !== 'A') return false;
            if (el.classList.contains('btn') || el.getAttribute('role') === 'button') return false;
            return Boolean(el.closest('p, li, td, th, .table, .dropdown-menu, .breadcrumb, .pagination'));
        };

        const shouldSkipCompactControlClickTarget = (el) => {
            if (el.tagName === 'BUTTON' || el.tagName === 'SUMMARY') return true;
            if (el.classList.contains('btn')) return true;
            if (el.matches('.leaflet-control-zoom a, .leaflet-bar a')) return true;
            return false;
        };

        const focusStyleSnapshot = (el) => {
            const style = window.getComputedStyle(el);
            return {
                outlineStyle: style.outlineStyle,
                outlineWidth: Number.parseFloat(style.outlineWidth || '0'),
                outlineColor: normalizeColor(style.outlineColor),
                boxShadow: style.boxShadow,
                borderColor: normalizeColor(style.borderTopColor),
                backgroundColor: normalizeColor(style.backgroundColor),
                color: normalizeColor(style.color),
            };
        };

        const hasVisibleFocusIndicator = (before, after) => {
            const outlineVisible = after.outlineStyle !== 'none' && after.outlineWidth > 0;
            const outlineChanged =
                before.outlineStyle !== after.outlineStyle ||
                Math.abs(before.outlineWidth - after.outlineWidth) > 0.1 ||
                before.outlineColor !== after.outlineColor;
            const boxShadowChanged = before.boxShadow !== after.boxShadow && after.boxShadow !== 'none';
            const borderChanged = before.borderColor !== after.borderColor;
            const backgroundChanged = before.backgroundColor !== after.backgroundColor;
            const colorChanged = before.color !== after.color;

            return (outlineVisible && outlineChanged) || boxShadowChanged || borderChanged || backgroundChanged || colorChanged;
        };

        const rectInfo = (el) => {
            const rect = el.getBoundingClientRect();
            return {
                tag: el.tagName,
                id: el.id || null,
                className: typeof el.className === 'string' ? el.className : null,
                left: round(rect.left),
                right: round(rect.right),
                top: round(rect.top),
                bottom: round(rect.bottom),
                width: round(rect.width),
                height: round(rect.height),
            };
        };

        const normalizeFontFamily = (value) =>
            String(value || '')
                .toLowerCase()
                .replace(/["']/g, '')
                .replace(/\s+/g, ' ')
                .trim();
        const normalizeColor = (value) =>
            String(value || '')
                .toLowerCase()
                .replace(/\s+/g, '');
        const parseBackdropFilter = (value) => {
            const raw = String(value || '');
            const blurMatch = raw.match(/blur\(([-\d.]+)px\)/i);
            const saturateMatch = raw.match(/saturate\(([-\d.]+)\)/i);
            return {
                raw,
                blurPx: blurMatch ? Number.parseFloat(blurMatch[1]) : null,
                saturate: saturateMatch ? Number.parseFloat(saturateMatch[1]) : null,
            };
        };

        const duplicateIdsMap = new Map();
        for (const el of document.querySelectorAll('[id]')) {
            duplicateIdsMap.set(el.id, (duplicateIdsMap.get(el.id) || 0) + 1);
        }
        const duplicateIds = Array.from(duplicateIdsMap.entries())
            .filter(([, count]) => count > 1)
            .map(([id, count]) => ({ id, count }));

        const emptyAriaLabels = Array.from(document.querySelectorAll('[aria-label]'))
            .filter((el) => isVisible(el) && !norm(el.getAttribute('aria-label')))
            .map(rectInfo);

        const imgsWithoutAlt = Array.from(document.images)
            .filter((img) => isVisible(img) && !img.hasAttribute('alt'))
            .map((img) => ({ src: img.getAttribute('src'), className: img.className || null }));

        const emptyAltInteractive = Array.from(document.querySelectorAll('a img, button img'))
            .filter((img) => isVisible(img) && norm(img.getAttribute('alt')) === '')
            .map((img) => ({ src: img.getAttribute('src'), parentTag: img.parentElement?.tagName || null }));

        const unlabeledControls = Array.from(document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="reset"]), select, textarea'))
            .filter((el) => {
                if (!isVisible(el) || !isInContentRoot(el) || el.disabled) return false;
                const id = el.id;
                const hasLabelFor = id && document.querySelector(`label[for="${CSS.escape(id)}"]`);
                const wrappedLabel = el.closest('label');
                const ariaLabel = norm(el.getAttribute('aria-label'));
                const ariaLabelledBy = norm(el.getAttribute('aria-labelledby'));
                const title = norm(el.getAttribute('title'));
                return !(hasLabelFor || wrappedLabel || ariaLabel || ariaLabelledBy || title);
            })
            .map((el) => ({ tag: el.tagName, id: el.id || null, type: el.getAttribute('type') || null }));

        const namelessButtons = Array.from(document.querySelectorAll('button, [role="button"]'))
            .filter((el) => {
                if (!isVisible(el) || !isInContentRoot(el)) return false;
                const text = norm(el.textContent);
                const ariaLabel = norm(el.getAttribute('aria-label'));
                const ariaLabelledBy = norm(el.getAttribute('aria-labelledby'));
                const title = norm(el.getAttribute('title'));
                return !(text || ariaLabel || ariaLabelledBy || title);
            })
            .map(rectInfo);

        const clickTargetsTooSmall = Array.from(contentRoot.querySelectorAll(clickTargetSelector))
            .filter((el) => isVisible(el) && isInContentRoot(el) && !isDisabled(el))
            .filter((el) => !shouldSkipInlineClickTarget(el))
            .filter((el) => !shouldSkipCompactControlClickTarget(el))
            .filter((el) => {
                const rect = el.getBoundingClientRect();
                return rect.width < constants.CLICK_TARGET_MIN_SIZE_PX || rect.height < constants.CLICK_TARGET_MIN_SIZE_PX;
            })
            .slice(0, 20)
            .map((el) => ({
                ...rectInfo(el),
                text: norm(el.textContent).slice(0, 60) || null,
            }));

        const focusableElements = Array.from(contentRoot.querySelectorAll(focusableSelector))
            .filter((el) => isVisible(el) && isInContentRoot(el) && !isDisabled(el))
            .filter((el) => el.tabIndex >= 0);

        const focusOrderIssues = [];
        for (let index = 1; index < focusableElements.length; index += 1) {
            const previous = focusableElements[index - 1];
            const current = focusableElements[index];
            const prevRect = previous.getBoundingClientRect();
            const currRect = current.getBoundingClientRect();

            if (currRect.top + 4 < prevRect.top) {
                focusOrderIssues.push({
                    previous: rectInfo(previous),
                    current: rectInfo(current),
                });
            }
        }

        const focusIndicatorMissing = [];
        const focusSample = focusableElements.slice(0, 20);
        const priorFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
        for (const el of focusSample) {
            const before = focusStyleSnapshot(el);
            try {
                el.focus({ preventScroll: true });
            } catch {
                continue;
            }

            const after = focusStyleSnapshot(el);
            if (document.activeElement === el && !hasVisibleFocusIndicator(before, after)) {
                focusIndicatorMissing.push({
                    ...rectInfo(el),
                    text: norm(el.textContent).slice(0, 60) || null,
                });
            }
        }
        if (priorFocused && typeof priorFocused.focus === 'function') {
            priorFocused.focus({ preventScroll: true });
        } else if (document.activeElement instanceof HTMLElement) {
            document.activeElement.blur();
        }

        const headings = Array.from(document.querySelectorAll('h1,h2,h3,h4,h5,h6'))
            .filter((el) => isVisible(el))
            .map((el) => ({ tag: el.tagName, level: Number(el.tagName.slice(1)), text: norm(el.textContent).slice(0, 120) }));
        const headingSkips = [];
        for (let index = 1; index < headings.length; index += 1) {
            const prev = headings[index - 1];
            const current = headings[index];
            if (current.level - prev.level > 1) {
                headingSkips.push({ from: prev.tag, to: current.tag, text: current.text });
            }
        }

        const tablesWithoutHeaders = Array.from(document.querySelectorAll('table'))
            .filter((table) => isVisible(table) && isInContentRoot(table) && !table.querySelector('th'))
            .map(rectInfo);

        const doc = document.documentElement;
        const horizontalOverflow = {
            hasOverflow: doc.scrollWidth > window.innerWidth + 2,
            scrollWidth: doc.scrollWidth,
            viewportWidth: window.innerWidth,
            contentRight: round(contentRoot.getBoundingClientRect().right),
            contentLeft: round(contentRoot.getBoundingClientRect().left),
            offenders: Array.from(document.querySelectorAll('body *'))
                .filter((el) => isVisible(el) && isInContentRoot(el) && !el.matches(allowedOverflowSelector))
                .filter((el) => {
                    const rootRect = contentRoot.getBoundingClientRect();
                    const rect = el.getBoundingClientRect();
                    return rect.right - rootRect.right > 2 || rect.left < rootRect.left - 2;
                })
                .slice(0, 20)
                .map(rectInfo),
        };

        const clippedButtons = Array.from(document.querySelectorAll('button, .btn, [role="button"]'))
            .filter((el) => isVisible(el) && isInContentRoot(el) && !el.closest('#settingsTabs'))
            .filter((el) => !el.matches('.blocklist-source-info') && !el.closest('.input-group'))
            .filter((el) => {
                const rect = el.getBoundingClientRect();
                const intersectsViewport = rect.bottom > 0 && rect.top < window.innerHeight && rect.right > 0 && rect.left < window.innerWidth;
                if (!intersectsViewport) return false;
                const insetX = Math.max(6, Math.min(10, rect.width * 0.2));
                const insetY = Math.max(6, Math.min(10, rect.height * 0.2));
                const samplePoints = [
                    [rect.left + rect.width / 2, rect.top + rect.height / 2],
                    [rect.left + insetX, rect.top + insetY],
                    [rect.right - insetX, rect.top + insetY],
                    [rect.left + insetX, rect.bottom - insetY],
                    [rect.right - insetX, rect.bottom - insetY],
                ];
                const occluded = samplePoints.some(([x, y]) => {
                    if (x < 0 || y < 0 || x >= window.innerWidth || y >= window.innerHeight) {
                        return true;
                    }
                    const topEl = document.elementFromPoint(x, y);
                    // Filter out known overlay elements (tooltips, dropdowns, sticky headers)
                    if (topEl && topEl.closest('[role="tooltip"], .tooltip, .popover, .dropdown-menu, .sticky-top, .modal')) {
                        return false;
                    }
                    return Boolean(topEl && topEl !== el && !el.contains(topEl) && !topEl.contains(el));
                });
                return occluded;
            })
            .map(rectInfo);

        const hiddenInteractiveElements = Array.from(contentRoot.querySelectorAll(interactiveSelector))
            .filter((el) => {
                if (el.disabled || isInsideInactivePane(el) || isIntentionallyHidden(el)) return false;
                const style = window.getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                return style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0' || rect.width === 0 || rect.height === 0;
            })
            .slice(0, 20)
            .map((el) => ({
                tag: el.tagName,
                id: el.id || null,
                className: typeof el.className === 'string' ? el.className : null,
            }));

        const scrollEdgeCrowding = Array.from(contentRoot.querySelectorAll('.top-domain-scroll-area .top-domain-percent'))
            .filter((el) => isVisible(el))
            .map((el) => {
                const scrollContainer = el.closest('.top-domain-scroll-area');
                if (!scrollContainer || !isVisible(scrollContainer)) return null;

                const badgeRect = el.getBoundingClientRect();
                const containerRect = scrollContainer.getBoundingClientRect();
                const clearance = round(containerRect.right - badgeRect.right);

                if (clearance >= constants.SCROLL_EDGE_CLEARANCE_MIN) return null;

                return {
                    clearance,
                    badge: rectInfo(el),
                    container: rectInfo(scrollContainer),
                };
            })
            .filter(Boolean);

        const isScrollContainer = (el) => {
            if (!el || !isVisible(el) || !isInContentRoot(el)) return false;
            const style = window.getComputedStyle(el);
            return style.overflowY === 'auto' || style.overflowY === 'scroll';
        };

        // Generic scroll-bottom clearance check.
        const scrollBottomCrowding = Array.from(contentRoot.querySelectorAll('*'))
            .filter((el) => isScrollContainer(el))
            .map((container) => {
                const children = Array.from(container.children)
                    .filter((child) => isVisible(child));

                if (!children.length) return null;

                const lastChild = children[children.length - 1];
                const containerRect = container.getBoundingClientRect();
                const childRect = lastChild.getBoundingClientRect();
                const clearance = round(containerRect.bottom - childRect.bottom);

                if (clearance >= constants.SCROLL_EDGE_CLEARANCE_MIN) return null;

                return {
                    clearance,
                    container: rectInfo(container),
                    lastChild: rectInfo(lastChild),
                };
            })
            .filter(Boolean)
            .slice(0, 20);

        // Detect scroll-in-scroll and direct .card > scroll-container patterns.
        const nestedScrollContainers = Array.from(contentRoot.querySelectorAll('*'))
            .filter((el) => isScrollContainer(el))
            .map((container) => {
                let parentScroll = null;
                let ancestor = container.parentElement;
                while (ancestor && ancestor !== contentRoot.parentElement) {
                    if (isScrollContainer(ancestor)) {
                        parentScroll = ancestor;
                        break;
                    }
                    ancestor = ancestor.parentElement;
                }

                const directCardParent = container.parentElement?.classList?.contains('card') || false;
                if (!parentScroll && !directCardParent) return null;

                return {
                    container: rectInfo(container),
                    parent: parentScroll ? rectInfo(parentScroll) : null,
                    directCardParent,
                };
            })
            .filter(Boolean)
            .slice(0, 20);

        const referenceBadge = document.createElement('span');
        referenceBadge.className = 'badge bg-secondary';
        referenceBadge.textContent = 'Reference';
        referenceBadge.setAttribute('aria-hidden', 'true');
        referenceBadge.style.position = 'fixed';
        referenceBadge.style.left = '-9999px';
        referenceBadge.style.top = '0';
        referenceBadge.style.pointerEvents = 'none';
        referenceBadge.style.visibility = 'hidden';
        document.body.appendChild(referenceBadge);

        const referenceBadgeStyle = window.getComputedStyle(referenceBadge);
        const badgeReference = {
            fontFamily: normalizeFontFamily(referenceBadgeStyle.fontFamily),
            fontSize: Number.parseFloat(referenceBadgeStyle.fontSize || '0'),
            fontWeight: Number.parseInt(referenceBadgeStyle.fontWeight || '400', 10),
            borderRadius: Number.parseFloat(referenceBadgeStyle.borderTopLeftRadius || '0'),
            paddingTop: Number.parseFloat(referenceBadgeStyle.paddingTop || '0'),
            paddingRight: Number.parseFloat(referenceBadgeStyle.paddingRight || '0'),
            paddingBottom: Number.parseFloat(referenceBadgeStyle.paddingBottom || '0'),
            paddingLeft: Number.parseFloat(referenceBadgeStyle.paddingLeft || '0'),
        };
        referenceBadge.remove();

        const badgeStyleMismatches = Array.from(contentRoot.querySelectorAll('.badge'))
            .filter((el) => isVisible(el) && isInContentRoot(el))
            .filter((el) => !el.matches(badgeConsistencyExcludeSelector))
            .map((el) => {
                const style = window.getComputedStyle(el);
                const reasons = [];
                const normalizedFontFamily = normalizeFontFamily(style.fontFamily);
                const fontSize = Number.parseFloat(style.fontSize || '0');
                const fontWeight = Number.parseInt(style.fontWeight || '400', 10);
                const borderRadius = Number.parseFloat(style.borderTopLeftRadius || '0');
                const paddingTop = Number.parseFloat(style.paddingTop || '0');
                const paddingRight = Number.parseFloat(style.paddingRight || '0');
                const paddingBottom = Number.parseFloat(style.paddingBottom || '0');
                const paddingLeft = Number.parseFloat(style.paddingLeft || '0');

                if (normalizedFontFamily !== badgeReference.fontFamily) {
                    reasons.push('fontFamily');
                }
                if (Math.abs(fontSize - badgeReference.fontSize) > constants.BADGE_FONT_SIZE_TOLERANCE_PX) {
                    reasons.push('fontSize');
                }
                if (Math.abs(fontWeight - badgeReference.fontWeight) > constants.BADGE_FONT_WEIGHT_TOLERANCE) {
                    reasons.push('fontWeight');
                }
                if (Math.abs(borderRadius - badgeReference.borderRadius) > constants.BADGE_RADIUS_TOLERANCE_PX) {
                    reasons.push('borderRadius');
                }
                if (
                    Math.abs(paddingTop - badgeReference.paddingTop) > constants.BADGE_PADDING_TOLERANCE_PX ||
                    Math.abs(paddingRight - badgeReference.paddingRight) > constants.BADGE_PADDING_TOLERANCE_PX ||
                    Math.abs(paddingBottom - badgeReference.paddingBottom) > constants.BADGE_PADDING_TOLERANCE_PX ||
                    Math.abs(paddingLeft - badgeReference.paddingLeft) > constants.BADGE_PADDING_TOLERANCE_PX
                ) {
                    reasons.push('padding');
                }

                if (!reasons.length) return null;

                return {
                    reasons,
                    text: norm(el.textContent).slice(0, 60),
                    className: typeof el.className === 'string' ? el.className : null,
                    fontFamily: normalizedFontFamily,
                    fontSize: round(fontSize),
                    fontWeight,
                    borderRadius: round(borderRadius),
                    paddingTop: round(paddingTop),
                    paddingRight: round(paddingRight),
                    paddingBottom: round(paddingBottom),
                    paddingLeft: round(paddingLeft),
                    reference: {
                        ...badgeReference,
                        fontSize: round(badgeReference.fontSize),
                        borderRadius: round(badgeReference.borderRadius),
                        paddingTop: round(badgeReference.paddingTop),
                        paddingRight: round(badgeReference.paddingRight),
                        paddingBottom: round(badgeReference.paddingBottom),
                        paddingLeft: round(badgeReference.paddingLeft),
                    },
                };
            })
            .filter(Boolean)
            .slice(0, 20);

        const referenceMonospace = document.createElement('span');
        referenceMonospace.className = 'wb-monospace-value font-monospace';
        referenceMonospace.textContent = 'Reference';
        referenceMonospace.setAttribute('aria-hidden', 'true');
        referenceMonospace.style.position = 'fixed';
        referenceMonospace.style.left = '-9999px';
        referenceMonospace.style.top = '0';
        referenceMonospace.style.pointerEvents = 'none';
        referenceMonospace.style.visibility = 'hidden';
        document.body.appendChild(referenceMonospace);

        const referenceMonospaceStyle = window.getComputedStyle(referenceMonospace);
        const monospaceReference = {
            color: normalizeColor(referenceMonospaceStyle.color),
            backgroundColor: normalizeColor(referenceMonospaceStyle.backgroundColor),
            borderRadius: Number.parseFloat(referenceMonospaceStyle.borderTopLeftRadius || '0'),
            paddingTop: Number.parseFloat(referenceMonospaceStyle.paddingTop || '0'),
            paddingRight: Number.parseFloat(referenceMonospaceStyle.paddingRight || '0'),
            paddingBottom: Number.parseFloat(referenceMonospaceStyle.paddingBottom || '0'),
            paddingLeft: Number.parseFloat(referenceMonospaceStyle.paddingLeft || '0'),
        };
        referenceMonospace.remove();

        const monospaceToneMismatches = Array.from(contentRoot.querySelectorAll('code, kbd, samp, .wb-monospace-value, .font-monospace, .asn-badge, .asn-inline'))
            .filter((el) => isVisible(el) && isInContentRoot(el))
            .filter((el) => !el.matches(monospaceToneExcludeSelector) && !el.closest(monospaceToneExcludeSelector))
            .map((el) => {
                const style = window.getComputedStyle(el);
                const color = normalizeColor(style.color);
                const backgroundColor = normalizeColor(style.backgroundColor);
                const borderRadius = Number.parseFloat(style.borderTopLeftRadius || '0');
                const paddingTop = Number.parseFloat(style.paddingTop || '0');
                const paddingRight = Number.parseFloat(style.paddingRight || '0');
                const paddingBottom = Number.parseFloat(style.paddingBottom || '0');
                const paddingLeft = Number.parseFloat(style.paddingLeft || '0');
                const reasons = [];

                if (color !== monospaceReference.color) reasons.push('color');
                if (backgroundColor !== monospaceReference.backgroundColor) reasons.push('backgroundColor');
                if (Math.abs(borderRadius - monospaceReference.borderRadius) > constants.MONOSPACE_RADIUS_TOLERANCE_PX) reasons.push('borderRadius');
                if (
                    Math.abs(paddingTop - monospaceReference.paddingTop) > constants.MONOSPACE_PADDING_TOLERANCE_PX ||
                    Math.abs(paddingRight - monospaceReference.paddingRight) > constants.MONOSPACE_PADDING_TOLERANCE_PX ||
                    Math.abs(paddingBottom - monospaceReference.paddingBottom) > constants.MONOSPACE_PADDING_TOLERANCE_PX ||
                    Math.abs(paddingLeft - monospaceReference.paddingLeft) > constants.MONOSPACE_PADDING_TOLERANCE_PX
                ) reasons.push('padding');

                if (!reasons.length) return null;

                return {
                    tag: el.tagName,
                    id: el.id || null,
                    className: typeof el.className === 'string' ? el.className : null,
                    text: norm(el.textContent).slice(0, 60),
                    reasons,
                    color,
                    backgroundColor,
                    borderRadius: round(borderRadius),
                    paddingTop: round(paddingTop),
                    paddingRight: round(paddingRight),
                    paddingBottom: round(paddingBottom),
                    paddingLeft: round(paddingLeft),
                };
            })
            .filter(Boolean)
            .slice(0, 20);

        const parseColor = (raw) => {
            const match = raw.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([0-9.]+))?\)/i);
            if (!match) return null;
            return {
                r: Number(match[1]),
                g: Number(match[2]),
                b: Number(match[3]),
                a: match[4] == null ? 1 : Number(match[4]),
            };
        };
        const modalBackdropProbe = document.createElement('div');
        modalBackdropProbe.className = 'modal-backdrop show';
        modalBackdropProbe.setAttribute('aria-hidden', 'true');
        modalBackdropProbe.style.position = 'fixed';
        modalBackdropProbe.style.left = '-9999px';
        modalBackdropProbe.style.top = '0';
        modalBackdropProbe.style.pointerEvents = 'none';
        modalBackdropProbe.style.opacity = '1';
        document.body.appendChild(modalBackdropProbe);

        const modalBackdropStyle = window.getComputedStyle(modalBackdropProbe);
        const modalBackdropFilter = parseBackdropFilter(
            modalBackdropStyle.backdropFilter || modalBackdropStyle.webkitBackdropFilter || ''
        );
        const modalBackdropColor = parseColor(modalBackdropStyle.backgroundColor || '');
        const modalBackdrop = {
            backgroundColor: normalizeColor(modalBackdropStyle.backgroundColor),
            alpha: modalBackdropColor?.a ?? null,
            blurPx: modalBackdropFilter.blurPx,
            saturate: modalBackdropFilter.saturate,
            filterRaw: modalBackdropFilter.raw,
            blurMatchesReference: modalBackdropFilter.blurPx !== null &&
                Math.abs(modalBackdropFilter.blurPx - constants.MODAL_BACKDROP_BLUR_EXPECTED_PX) <= constants.MODAL_BACKDROP_BLUR_TOLERANCE_PX,
            saturateMatchesReference: modalBackdropFilter.saturate !== null &&
                Math.abs(modalBackdropFilter.saturate - constants.MODAL_BACKDROP_SATURATE_EXPECTED) <= constants.MODAL_BACKDROP_SATURATE_TOLERANCE,
            alphaMatchesReference: modalBackdropColor?.a != null &&
                Math.abs(modalBackdropColor.a - constants.MODAL_BACKDROP_ALPHA_EXPECTED) <= constants.MODAL_BACKDROP_ALPHA_TOLERANCE,
        };
        modalBackdropProbe.remove();

        const toLuminance = (channel) => {
            const value = channel / 255;
            return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
        };
        const contrastRatio = (fg, bg) => {
            const lumFg = 0.2126 * toLuminance(fg.r) + 0.7152 * toLuminance(fg.g) + 0.0722 * toLuminance(fg.b);
            const lumBg = 0.2126 * toLuminance(bg.r) + 0.7152 * toLuminance(bg.g) + 0.0722 * toLuminance(bg.b);
            const lighter = Math.max(lumFg, lumBg);
            const darker = Math.min(lumFg, lumBg);
            return (lighter + 0.05) / (darker + 0.05);
        };
        const getOpaqueBackground = (el) => {
            let current = el;
            while (current) {
                const color = parseColor(window.getComputedStyle(current).backgroundColor || '');
                if (color && color.a > 0.98) return color;
                current = current.parentElement;
            }
            const bodyColor = parseColor(window.getComputedStyle(document.body).backgroundColor || '');
            return bodyColor && bodyColor.a > 0.98 ? bodyColor : { r: 255, g: 255, b: 255, a: 1 };
        };

        const contrastProblems = Array.from(contentRoot.querySelectorAll('*'))
            .filter((el) => isVisible(el))
            .flatMap((el) => {
                const text = norm(el.textContent);
                if (!text || text.length < 2 || el.children.length > 0) return [];
                if (el.classList.contains('material-icons') || el.closest('.material-icons')) return [];
                if (el.closest('.navbar') || el.closest('.wb-footer')) return [];
                const disabledAncestor = el.closest('button, [role="button"], input, select, textarea, .btn');
                if (disabledAncestor && isDisabled(disabledAncestor)) return [];
                const style = window.getComputedStyle(el);
                const color = parseColor(style.color || '');
                if (!color || color.a < 0.99) return [];
                if ((style.backgroundImage || 'none') !== 'none') return [];
                // Note: This skips semi-transparent backgrounds (known limitation)
                // Elements with stacked semi-transparent layers may produce false positives/negatives
                const bg = getOpaqueBackground(el);
                const ratio = contrastRatio(color, bg);
                const fontSize = Number.parseFloat(style.fontSize || '16');
                const fontWeight = Number.parseInt(style.fontWeight || '400', 10);
                const isLargeText = fontSize >= constants.WCAG_LARGE_TEXT_SIZE_PX ||
                    (fontSize >= constants.WCAG_LARGE_TEXT_SIZE_BOLD_PX && fontWeight >= constants.WCAG_BOLD_WEIGHT);
                const minimum = isLargeText ? constants.WCAG_LARGE_AA : constants.WCAG_NORMAL_AA;
                if (ratio >= minimum) return [];
                return [{
                    tag: el.tagName,
                    id: el.id || null,
                    text: text.slice(0, 80),
                    ratio: round(ratio),
                    minimum,
                }];
            })
            .sort((a, b) => a.ratio - b.ratio)
            .slice(0, 20);

        const layoutShift = window.__uiLintLayoutShift || { value: 0, count: 0 };

        const collectComponentRects = () => Array.from(contentRoot.querySelectorAll('.card, .leaflet-container, svg, canvas, table'))
            .filter((el) => isVisible(el) && isInContentRoot(el))
            .filter((el) => {
                const rect = el.getBoundingClientRect();
                return rect.width >= 32 && rect.height >= 32;
            })
            .map((el, index) => {
                const rect = el.getBoundingClientRect();
                return {
                    key: `${el.tagName}:${el.id || ''}:${typeof el.className === 'string' ? el.className : ''}:${index}`,
                    rect: {
                        width: rect.width,
                        height: rect.height,
                    },
                    element: el,
                };
            });

        const componentRectsBefore = collectComponentRects();
        await new Promise((resolve) => window.setTimeout(resolve, constants.COMPONENT_LAYOUT_SHIFT_SETTLE_MS));
        const componentRectsAfter = collectComponentRects();
        const componentRectsAfterMap = new Map(componentRectsAfter.map((entry) => [entry.key, entry]));
        const componentLayoutShift = componentRectsBefore
            .map((beforeEntry) => {
                const afterEntry = componentRectsAfterMap.get(beforeEntry.key);
                if (!afterEntry) return null;

                const deltaHeight = Math.abs(afterEntry.rect.height - beforeEntry.rect.height);
                const deltaWidth = Math.abs(afterEntry.rect.width - beforeEntry.rect.width);
                if (
                    deltaHeight <= constants.COMPONENT_LAYOUT_SHIFT_THRESHOLD_PX &&
                    deltaWidth <= constants.COMPONENT_LAYOUT_SHIFT_THRESHOLD_PX
                ) {
                    return null;
                }

                return {
                    before: {
                        width: round(beforeEntry.rect.width),
                        height: round(beforeEntry.rect.height),
                    },
                    after: {
                        width: round(afterEntry.rect.width),
                        height: round(afterEntry.rect.height),
                    },
                    deltaWidth: round(deltaWidth),
                    deltaHeight: round(deltaHeight),
                    component: rectInfo(afterEntry.element),
                };
            })
            .filter(Boolean)
            .slice(0, 20);

        const spacing = {};
        const cardContainment = {
            cardsPastFooter: [],
        };

        const footer = document.querySelector('.wb-footer');
        const pageHasVerticalOverflow = Math.max(
            contentRoot.scrollHeight,
            document.documentElement.scrollHeight,
            document.body.scrollHeight
        ) > Math.max(contentRoot.clientHeight, window.innerHeight) + 2;
        if (footer && !pageHasVerticalOverflow) {
            const footerRect = footer.getBoundingClientRect();
            cardContainment.cardsPastFooter = Array.from(contentRoot.querySelectorAll('.card'))
                .filter((card) => isVisible(card))
                .filter((card) => {
                    const rect = card.getBoundingClientRect();
                    return rect.top < footerRect.top && rect.bottom > footerRect.top + constants.FOOTER_OVERLAP_TOLERANCE_PX;
                })
                .slice(0, 20)
                .map(rectInfo);
        }

        const measureStandardMainGridGap = () => {
            const mainGridRow = document.querySelector('.wb-main-grid');
            const statsRow = mainGridRow?.previousElementSibling;
            if (!mainGridRow || !statsRow || !statsRow.classList.contains('row')) return;
            const statsRect = statsRow.getBoundingClientRect();
            const mainRect = mainGridRow.getBoundingClientRect();
            spacing.rowToRowGap = round(mainRect.top - statsRect.bottom);
            spacing.rowToRowGapInRange =
                spacing.rowToRowGap >= constants.VERTICAL_GAP_MIN &&
                spacing.rowToRowGap <= constants.VERTICAL_GAP_MAX;
        };

        if (scope === 'dashboard' || scope === 'dns') {
            measureStandardMainGridGap();
        }

        if (scope === 'dashboard') {
            const statCards = Array.from(document.querySelectorAll('.dashboard-stats-row > div .card')).slice(0, 4);
            spacing.statCardWidths = statCards.map((card) => round(card.getBoundingClientRect().width));

            const mapCard = document.querySelector('.dashboard-map-col .card');
            const recentCard = document.querySelector('.dashboard-recent-peers-col .card');
            const speedCard = document.querySelector('.dashboard-speedtest-col .card');
            if (mapCard && recentCard && speedCard && window.innerWidth >= 1200) {
                const mapRect = mapCard.getBoundingClientRect();
                const recentRect = recentCard.getBoundingClientRect();
                const speedRect = speedCard.getBoundingClientRect();
                spacing.desktopColumnAlignment = {
                    mapBottom: round(mapRect.bottom),
                    recentBottom: round(recentRect.bottom),
                    bottomDelta: round(Math.abs(mapRect.bottom - recentRect.bottom)),
                    speedBottom: round(speedRect.bottom),
                    verticalGap: round(recentRect.top - speedRect.bottom),
                };
            }
        }

        if (scope === 'settings') {
            const activePane = document.querySelector('#settingsTabContent > .tab-pane.active');
            const cardRects = activePane
                ? Array.from(activePane.querySelectorAll('.card'))
                    .filter((card) => isVisible(card))
                    .map((card) => card.getBoundingClientRect())
                : [];
            const verticalGaps = [];
            for (let index = 1; index < cardRects.length; index += 1) {
                const prev = cardRects[index - 1];
                const current = cardRects[index];
                if (Math.abs(prev.left - current.left) < 4 && current.top >= prev.bottom) {
                    verticalGaps.push(round(current.top - prev.bottom));
                }
            }
            spacing.activePaneId = activePane?.id || null;
            spacing.verticalGaps = verticalGaps;
            spacing.outlierVerticalGaps = verticalGaps.filter((gap) => gap > constants.VERTICAL_GAP_MAX || gap < constants.VERTICAL_GAP_MIN);

            if (activePane?.id === 'logs-pane') {
                const logCards = Array.from(activePane.querySelectorAll('.card'))
                    .filter((card) => isVisible(card));
                const deleteBlocks = Array.from(activePane.querySelectorAll('.metrics-delete'))
                    .filter((el) => isVisible(el));
                const deleteInners = Array.from(activePane.querySelectorAll('.metrics-delete-inner'))
                    .filter((el) => isVisible(el));
                const deleteHairlines = Array.from(activePane.querySelectorAll('.metrics-delete hr'))
                    .filter((el) => isVisible(el));
                const hairlineTops = deleteHairlines.map((el) => round(el.getBoundingClientRect().top));
                const hairlineVariance = hairlineTops.length > 1
                    ? round(Math.max(...hairlineTops) - Math.min(...hairlineTops))
                    : 0;

                spacing.logsDeleteLayout = {
                    cardCount: logCards.length,
                    deleteBlockCount: deleteBlocks.length,
                    deleteInnerCount: deleteInners.length,
                    hairlineCount: deleteHairlines.length,
                    hairlineTops,
                    hairlineVariance,
                    hairlineAligned: hairlineVariance <= constants.LOGS_DELETE_HAIRLINE_TOLERANCE_PX,
                };
            }

            // Retention slider tick alignment validation
            const sliderScales = Array.from(activePane?.querySelectorAll('.retention-scale') ?? [])
                .filter((el) => isVisible(el));
            spacing.sliderAlignment = sliderScales.map((scale) => {
                const slider = scale.querySelector('input[type="range"]');
                const tickContainer = scale.querySelector('.retention-ticks');
                const labelContainer = scale.querySelector('.retention-labels');
                if (!slider || !tickContainer) return null;

                const sliderRect = slider.getBoundingClientRect();
                const ticks = Array.from(tickContainer.querySelectorAll('.retention-tick'));
                const labels = labelContainer
                    ? Array.from(labelContainer.querySelectorAll('.retention-label'))
                    : [];

                const thumbSize = Number.parseFloat(
                    window.getComputedStyle(scale).getPropertyValue('--thumb-size') || '16'
                );
                const trackLeft = sliderRect.left + thumbSize / 2;
                const trackRight = sliderRect.right - thumbSize / 2;
                const trackWidth = trackRight - trackLeft;
                const max = Number(slider.max) || 1;

                const tickIssues = ticks.map((tick, idx) => {
                    const tickRect = tick.getBoundingClientRect();
                    const tickCenter = tickRect.left + tickRect.width / 2;
                    const iValue = Number(
                        window.getComputedStyle(tick).getPropertyValue('--i') || idx
                    );
                    const expectedCenter = trackLeft + (iValue / max) * trackWidth;
                    const delta = Math.abs(tickCenter - expectedCenter);
                    return delta > constants.SLIDER_TICK_ALIGNMENT_TOLERANCE_PX
                        ? { index: idx, delta: round(delta), expected: round(expectedCenter), actual: round(tickCenter) }
                        : null;
                }).filter(Boolean);

                const labelMetrics = labels.map((label, idx) => {
                    const style = window.getComputedStyle(label);
                    const labelRect = label.getBoundingClientRect();
                    const iValue = Number(
                        style.getPropertyValue('--i') || idx
                    );
                    const opacity = Number.parseFloat(style.opacity || '1');
                    const hidden = style.display === 'none'
                        || style.visibility === 'hidden'
                        || opacity <= constants.SLIDER_LABEL_HIDDEN_OPACITY_MAX
                        || labelRect.width === 0
                        || labelRect.height === 0;

                    let alignment = 'center';
                    let expected = trackLeft + (iValue / max) * trackWidth;
                    let actual = labelRect.left + labelRect.width / 2;

                    if (iValue <= 0) {
                        alignment = 'start';
                        expected = trackLeft;
                        actual = labelRect.left;
                    } else if (iValue >= max) {
                        alignment = 'end';
                        expected = trackRight;
                        actual = labelRect.right;
                    }

                    return {
                        index: idx,
                        hidden,
                        text: (label.textContent || '').replace(/\s+/g, ' ').trim(),
                        left: round(labelRect.left),
                        right: round(labelRect.right),
                        alignment,
                        expected: round(expected),
                        actual: round(actual),
                        delta: round(Math.abs(actual - expected)),
                    };
                });

                const labelIssues = labelMetrics
                    .filter((label) => !label.hidden && label.delta > constants.SLIDER_TICK_ALIGNMENT_TOLERANCE_PX)
                    .map((label) => ({
                        index: label.index,
                        delta: label.delta,
                        alignment: label.alignment,
                        expected: label.expected,
                        actual: label.actual,
                    }));

                const visibleLabels = labelMetrics.filter((label) => !label.hidden);
                const labelOverlap = [];
                for (let index = 1; index < visibleLabels.length; index += 1) {
                    const prev = visibleLabels[index - 1];
                    const current = visibleLabels[index];
                    const gap = current.left - prev.right;
                    if (gap < constants.SLIDER_VISIBLE_LABEL_GAP_MIN_PX) {
                        labelOverlap.push({
                            leftIndex: prev.index,
                            rightIndex: current.index,
                            gap: round(gap),
                            leftText: prev.text,
                            rightText: current.text,
                        });
                    }
                }

                const sliderId = slider.id || null;
                const tickCount = ticks.length;
                const expectedTickCount = max + 1;
                const usesIndexVar = ticks.every((t) => t.style.getPropertyValue('--i') !== '');

                return {
                    sliderId,
                    tickCount,
                    expectedTickCount,
                    tickCountMatch: tickCount === expectedTickCount,
                    usesIndexVar,
                    visibleLabelCount: visibleLabels.length,
                    hiddenLabelCount: labelMetrics.length - visibleLabels.length,
                    tickMisaligned: tickIssues,
                    labelMisaligned: labelIssues,
                    labelOverlap,
                };
            }).filter(Boolean);
        }

        if (scope === 'about') {
            const changelogCard = document.querySelector('.about-changelog-col .card');
            const changelogBody = document.querySelector('.about-changelog-col .card-body');
            const depsCard = document.querySelector('.about-deps-col .card');
            const aboutReferenceValue = document.querySelector('.about-reference-value');
            const aboutReferenceStyle = aboutReferenceValue ? window.getComputedStyle(aboutReferenceValue) : null;
            const aboutReferenceMetrics = aboutReferenceStyle ? {
                color: normalizeColor(aboutReferenceStyle.color),
                fontSize: Number.parseFloat(aboutReferenceStyle.fontSize || '0'),
                backgroundColor: normalizeColor(aboutReferenceStyle.backgroundColor),
            } : null;
            const updateValueStyleMismatches = aboutReferenceMetrics
                ? Array.from(document.querySelectorAll('.about-update-value'))
                    .filter((el) => isVisible(el))
                    .map((el) => {
                        const style = window.getComputedStyle(el);
                        const color = normalizeColor(style.color);
                        const fontSize = Number.parseFloat(style.fontSize || '0');
                        const backgroundColor = normalizeColor(style.backgroundColor);
                        const reasons = [];

                        if (color !== aboutReferenceMetrics.color) {
                            reasons.push('color');
                        }
                        if (Math.abs(fontSize - aboutReferenceMetrics.fontSize) > 0.5) {
                            reasons.push('fontSize');
                        }
                        if (backgroundColor !== aboutReferenceMetrics.backgroundColor) {
                            reasons.push('backgroundColor');
                        }

                        if (!reasons.length) return null;

                        return {
                            text: norm(el.textContent).slice(0, 60),
                            id: el.id || null,
                            reasons,
                            color,
                            fontSize: round(fontSize),
                            backgroundColor,
                            reference: {
                                color: aboutReferenceMetrics.color,
                                fontSize: round(aboutReferenceMetrics.fontSize),
                                backgroundColor: aboutReferenceMetrics.backgroundColor,
                            },
                        };
                    })
                    .filter(Boolean)
                : [];
            spacing.about = {
                changelogCardBottom: changelogCard ? round(changelogCard.getBoundingClientRect().bottom) : null,
                changelogBodyScrollHeight: changelogBody?.scrollHeight ?? null,
                changelogBodyClientHeight: changelogBody?.clientHeight ?? null,
                depsCardBottom: depsCard ? round(depsCard.getBoundingClientRect().bottom) : null,
                footerTop: footer ? round(footer.getBoundingClientRect().top) : null,
                updateValueStyleMismatches,
            };
        }

        // Status page: Network flow diagram validation
        if (scope === 'status') {
            const flowWrapper = document.querySelector('[data-ui-lint="status-flow"]') || document.querySelector('.flow-wrapper');
            const flowNodes = Array.from((flowWrapper || document).querySelectorAll('.flow-node'))
                .filter((el) => isVisible(el));
            const flowConnectors = Array.from((flowWrapper || document).querySelectorAll('.flow-connector'))
                .filter((el) => isVisible(el));
            const flowWrapperRect = flowWrapper ? flowWrapper.getBoundingClientRect() : null;
            const desktopLayout = window.innerWidth > 991.98;

            const flowNodeMetrics = flowNodes.map((node) => {
                const icon = node.querySelector('.material-icons.flow-icon');
                const label = node.querySelector('.flow-label');
                const meta = node.querySelector('.flow-meta');
                const style = window.getComputedStyle(node);
                const rect = node.getBoundingClientRect();
                const nodeKey = node.getAttribute('data-flow-node') || null;
                const iconName = norm(icon?.textContent);
                const labelText = label ? norm(label.textContent) : null;

                return {
                    key: nodeKey,
                    width: round(rect.width),
                    height: round(rect.height),
                    left: round(rect.left),
                    right: round(rect.right),
                    top: round(rect.top),
                    bottom: round(rect.bottom),
                    borderWidth: Number.parseFloat(style.borderTopWidth || '0'),
                    borderRadius: Number.parseFloat(style.borderTopLeftRadius || '0'),
                    padding: Number.parseFloat(style.padding || '0'),
                    hasActiveClass: node.classList.contains('flow-node-active'),
                    hasInactiveClass: node.classList.contains('flow-node-inactive'),
                    hasIcon: Boolean(icon),
                    hasLabel: Boolean(label),
                    hasMeta: Boolean(meta),
                    iconName,
                    labelText,
                    metaText: meta ? norm(meta.textContent) : null,
                };
            });

            const flowConnectorMetrics = flowConnectors.map((connector) => {
                const line = connector.querySelector('.flow-line');
                const lineStyle = line ? window.getComputedStyle(line) : null;
                const rect = connector.getBoundingClientRect();
                const lineRect = line ? line.getBoundingClientRect() : null;
                const connectorKey = connector.getAttribute('data-flow-connector') || line?.getAttribute('data-flow-line') || null;

                return {
                    key: connectorKey,
                    width: round(rect.width),
                    height: round(rect.height),
                    left: round(rect.left),
                    right: round(rect.right),
                    top: round(rect.top),
                    bottom: round(rect.bottom),
                    hasLine: Boolean(line),
                    lineHeight: lineRect ? round(lineRect.height) : (lineStyle ? Number.parseFloat(lineStyle.height || '0') : null),
                    lineWidth: lineRect ? round(lineRect.width) : (lineStyle ? Number.parseFloat(lineStyle.width || '0') : null),
                    hasAnimation: lineStyle ? lineStyle.animationName !== 'none' : false,
                    hasInactiveClass: line ? line.classList.contains('flow-line-inactive') : false,
                };
            });

            const flowHeightVariance = flowNodeMetrics.length > 1
                ? Math.max(...flowNodeMetrics.map(n => n.height)) - Math.min(...flowNodeMetrics.map(n => n.height))
                : 0;
            const flowWidthVariance = flowNodeMetrics.length > 1
                ? Math.max(...flowNodeMetrics.map((node) => node.width)) - Math.min(...flowNodeMetrics.map((node) => node.width))
                : 0;
            const orderedNodeKeys = flowNodeMetrics.map((node) => node.key);
            const orderedConnectorKeys = flowConnectorMetrics.map((connector) => connector.key);
            const expectedNodeKeys = constants.STATUS_FLOW_NODE_EXPECTATIONS.map((node) => node.key);
            const expectedConnectorKeys = constants.STATUS_FLOW_CONNECTOR_EXPECTATIONS;
            const expectedNodeLabels = new Map(constants.STATUS_FLOW_NODE_EXPECTATIONS.map((node) => [node.key, node.label]));
            const expectedNodeIcons = new Map(constants.STATUS_FLOW_NODE_EXPECTATIONS.map((node) => [node.key, node.icon]));
            const labelMismatches = flowNodeMetrics
                .filter((node) => node.key && expectedNodeLabels.has(node.key))
                .filter((node) => node.labelText !== expectedNodeLabels.get(node.key))
                .map((node) => ({ key: node.key, labelText: node.labelText, expected: expectedNodeLabels.get(node.key) }));
            const iconMismatches = flowNodeMetrics
                .filter((node) => node.key && expectedNodeIcons.has(node.key))
                .filter((node) => node.iconName !== expectedNodeIcons.get(node.key))
                .map((node) => ({ key: node.key, iconName: node.iconName, expected: expectedNodeIcons.get(node.key) }));
            const nodeStateConflicts = flowNodeMetrics
                .filter((node) => node.hasActiveClass === node.hasInactiveClass)
                .map((node) => ({ key: node.key, active: node.hasActiveClass, inactive: node.hasInactiveClass }));
            const expectedOrientation = desktopLayout ? 'horizontal' : 'vertical';
            const orientationIssues = [];

            if (flowNodeMetrics.length === expectedNodeKeys.length) {
                for (let index = 1; index < flowNodeMetrics.length; index += 1) {
                    const previous = flowNodeMetrics[index - 1];
                    const current = flowNodeMetrics[index];
                    if (desktopLayout) {
                        if (current.left <= previous.left || Math.abs(current.top - previous.top) > 8) {
                            orientationIssues.push({ index, expectedOrientation, previous, current });
                        }
                    } else if (current.top <= previous.top || Math.abs(current.left - previous.left) > 8) {
                        orientationIssues.push({ index, expectedOrientation, previous, current });
                    }
                }
            }

            const connectorOrientationIssues = flowConnectorMetrics.filter((connector) => {
                if (desktopLayout) {
                    return !((connector.lineWidth || 0) > (connector.lineHeight || 0));
                }
                return !((connector.lineHeight || 0) > (connector.lineWidth || 0));
            }).map((connector) => ({
                key: connector.key,
                width: connector.width,
                height: connector.height,
                lineWidth: connector.lineWidth,
                lineHeight: connector.lineHeight,
                expectedOrientation,
            }));

            spacing.statusFlow = {
                hasWrapper: Boolean(flowWrapper),
                wrapperWidth: flowWrapperRect ? round(flowWrapperRect.width) : null,
                wrapperHeight: flowWrapperRect ? round(flowWrapperRect.height) : null,
                expectedOrientation,
                nodeCount: flowNodes.length,
                connectorCount: flowConnectors.length,
                expectedNodeCount: 3, // Client, WireGuard, Internet
                expectedConnectorCount: 2,
                nodeCountMatch: flowNodes.length === 3,
                connectorCountMatch: flowConnectors.length === 2,
                nodeOrderMatches: orderedNodeKeys.join('|') === expectedNodeKeys.join('|'),
                connectorOrderMatches: orderedConnectorKeys.join('|') === expectedConnectorKeys.join('|'),
                nodes: flowNodeMetrics,
                connectors: flowConnectorMetrics,
                heightVariance: round(flowHeightVariance),
                widthVariance: round(flowWidthVariance),
                allNodesHaveStructure: flowNodeMetrics.every(n => n.hasIcon && n.hasLabel && n.hasMeta),
                labelMismatches,
                iconMismatches,
                nodeStateConflicts,
                orientationIssues,
                connectorOrientationIssues,
            };
        }

        let loginFailure = null;
        if (scope === 'login') {
            const errorAlert = document.getElementById('error-alert');
            const passwordInput = document.getElementById('password');
            const loginCard = document.querySelector('.login-card');
            const passwordStyle = passwordInput ? window.getComputedStyle(passwordInput) : null;
            const cardStyle = loginCard ? window.getComputedStyle(loginCard) : null;
            const borderColor = parseColor(passwordStyle?.borderTopColor || '');
            const dangerLikeBorder = Boolean(
                borderColor
                && borderColor.r >= 180
                && borderColor.g <= 100
                && borderColor.b <= 120
            );

            loginFailure = {
                alertVisible: Boolean(errorAlert && isVisible(errorAlert)),
                errorText: norm(errorAlert?.textContent),
                passwordInvalidClass: Boolean(passwordInput?.classList.contains('is-invalid')),
                passwordAriaInvalid: passwordInput?.getAttribute('aria-invalid') === 'true',
                passwordBorderColor: passwordStyle?.borderTopColor || null,
                passwordBorderIsDangerLike: dangerLikeBorder,
                passwordBoxShadow: passwordStyle?.boxShadow || null,
                cardShakeClass: Boolean(loginCard?.classList.contains('login-card-shake')),
                cardAnimationName: cardStyle?.animationName || null,
                cardAnimationDuration: cardStyle?.animationDuration || null,
                cardAnimationActive: Boolean(cardStyle && cardStyle.animationName && cardStyle.animationName !== 'none'),
            };
        }

        // KPI Card validation: measure padding, icon size, and height consistency
        const kpiCards = Array.from(document.querySelectorAll('.wb-kpi-card'))
            .filter((el) => isVisible(el))
            .map((card) => {
                const body = card.querySelector('.card-body');
                const icon = card.querySelector('.wb-kpi-icon, .dashboard-stat-icon, .dns-stat-icon');

                const bodyStyle = body ? window.getComputedStyle(body) : null;
                const iconRect = icon ? icon.getBoundingClientRect() : null;

                return {
                    paddingTop: bodyStyle ? Number.parseFloat(bodyStyle.paddingTop) : null,
                    paddingBottom: bodyStyle ? Number.parseFloat(bodyStyle.paddingBottom) : null,
                    paddingLeft: bodyStyle ? Number.parseFloat(bodyStyle.paddingLeft) : null,
                    paddingRight: bodyStyle ? Number.parseFloat(bodyStyle.paddingRight) : null,
                    iconSize: iconRect ? round(iconRect.height) : null,
                };
            });

        const kpiHeights = Array.from(document.querySelectorAll('.wb-kpi-card'))
            .filter((el) => isVisible(el))
            .map((card) => {
                const rect = card.getBoundingClientRect();
                return round(rect.height);
            });

        const kpiHeightVariance =
            kpiHeights.length > 1
                ? Math.max(...kpiHeights) - Math.min(...kpiHeights)
                : 0;

        const cardsWithoutKpiClass = Array.from(document.querySelectorAll('.card'))
            .filter((el) => isVisible(el) && isInContentRoot(el))
            .filter((card) => {
                if (card.classList.contains('wb-kpi-card')) return false;

                // Only check stat-card candidates
                const hasIcon =
                    card.querySelector('.material-icons') ||
                    card.querySelector('.wb-kpi-icon') ||
                    card.querySelector('.dns-stat-icon') ||
                    card.querySelector('.dashboard-stat-icon');

                const hasLargeValue =
                    card.querySelector('.h3') ||
                    card.querySelector('.dns-stat-value') ||
                    card.querySelector('.wb-kpi-value');

                return hasIcon && hasLargeValue;
            })
            .slice(0, 10)
            .map(rectInfo);

        spacing.kpiCards = kpiCards;
        spacing.kpiHeights = kpiHeights;
        spacing.kpiHeightVariance = kpiHeightVariance;
        spacing.cardsMissingKpiClass = cardsWithoutKpiClass;

        // Visual containment issues: detect rendering problems in rounded cards
        const visualContainmentIssues = [];
        for (const card of document.querySelectorAll('.card')) {
            if (!isVisible(card) || !isInContentRoot(card)) continue;

            const cardStyle = window.getComputedStyle(card);
            const radius = Number.parseFloat(cardStyle.borderTopLeftRadius || '0');

            if (radius <= 0) continue;

            const cardRect = card.getBoundingClientRect();
            const cardOverflow = cardStyle.overflow;
            const clipsRoundedContent = cardOverflow === 'hidden' || cardOverflow === 'clip';

            for (const child of Array.from(card.children)) {
                const childStyle = window.getComputedStyle(child);

                // Check for scroll containers without clipping
                const isScrollContainer = childStyle.overflowY === 'auto' || childStyle.overflowY === 'scroll';
                if (isScrollContainer && !clipsRoundedContent) {
                    visualContainmentIssues.push({
                        type: 'scrollContainerWithoutClipping',
                        card: rectInfo(card),
                        child: rectInfo(child),
                    });
                }

                // Check for children overflowing card bounds
                const childRect = child.getBoundingClientRect();
                if (
                    childRect.left < cardRect.left - 1 ||
                    childRect.right > cardRect.right + 1 ||
                    childRect.bottom > cardRect.bottom + 1
                ) {
                    visualContainmentIssues.push({
                        type: 'childOverflowingRoundedCard',
                        card: rectInfo(card),
                        child: rectInfo(child),
                    });
                }

                // Check for sticky elements inside rounded cards
                if (childStyle.position === 'sticky' || childStyle.position === '-webkit-sticky') {
                    visualContainmentIssues.push({
                        type: 'stickyElementInsideRoundedCard',
                        card: rectInfo(card),
                        child: rectInfo(child),
                    });
                }
            }
        }

        // Form-switch margin consistency: expect mb-2 (12px) for proper card spacing
        // Exception: switches in mb-3 wrappers (no direct margin) are also valid
        const FORM_SWITCH_EXPECTED_MARGIN_PX = 12;
        const FORM_SWITCH_MARGIN_TOLERANCE_PX = 2;
        const formSwitchMarginIssues = Array.from(contentRoot.querySelectorAll('.form-check.form-switch'))
            .filter((el) => isVisible(el) && isInContentRoot(el))
            .map((el) => {
                const style = window.getComputedStyle(el);
                const marginBottom = Number.parseFloat(style.marginBottom || '0');
                const hasMb0 = el.classList.contains('mb-0');
                const hasMb2 = el.classList.contains('mb-2');
                const marginOk = Math.abs(marginBottom - FORM_SWITCH_EXPECTED_MARGIN_PX) <= FORM_SWITCH_MARGIN_TOLERANCE_PX;

                // Check if switch is in an mb-3 wrapper (valid pattern)
                const parentHasMb3 = el.parentElement?.classList.contains('mb-3');
                const isInMb3Wrapper = parentHasMb3 && marginBottom <= FORM_SWITCH_MARGIN_TOLERANCE_PX;

                // Valid patterns: mb-2 on switch, mb-0 on switch, or switch in mb-3 wrapper
                if (marginOk || hasMb0 || isInMb3Wrapper) return null;

                return {
                    ...rectInfo(el),
                    marginBottom: round(marginBottom),
                    hasMb0,
                    hasMb2,
                    parentHasMb3,
                    label: el.querySelector('.form-check-label')?.textContent?.trim().slice(0, 40) || null,
                };
            })
            .filter(Boolean);

        // Input-group height consistency: all children must have matching heights
        // and the group height should be close to the expected form-control height (~34px)
        const inputGroupHeightIssues = Array.from(contentRoot.querySelectorAll('.input-group'))
            .filter((group) => isVisible(group) && isInContentRoot(group))
            .map((group) => {
                const children = Array.from(group.children).filter((el) => isVisible(el));
                if (children.length < 2) return null;

                const heights = children.map((el) => {
                    const rect = el.getBoundingClientRect();
                    return round(rect.height);
                });

                const minHeight = Math.min(...heights);
                const maxHeight = Math.max(...heights);
                const heightVariance = maxHeight - minHeight;
                const avgHeight = heights.reduce((a, b) => a + b, 0) / heights.length;
                const expectedDeviation = Math.abs(avgHeight - constants.INPUT_GROUP_HEIGHT_EXPECTED_PX);

                // Issue if: children don't match OR height deviates from expected
                const hasVarianceIssue = heightVariance > constants.INPUT_GROUP_HEIGHT_TOLERANCE_PX;
                const hasExpectedHeightIssue = expectedDeviation > constants.INPUT_GROUP_HEIGHT_TOLERANCE_PX;

                if (!hasVarianceIssue && !hasExpectedHeightIssue) return null;

                return {
                    ...rectInfo(group),
                    heights,
                    minHeight,
                    maxHeight,
                    avgHeight: round(avgHeight),
                    expectedHeight: constants.INPUT_GROUP_HEIGHT_EXPECTED_PX,
                    heightVariance,
                    expectedDeviation: round(expectedDeviation),
                    issues: [
                        hasVarianceIssue && 'childHeightMismatch',
                        hasExpectedHeightIssue && 'unexpectedGroupHeight',
                    ].filter(Boolean),
                    childCount: children.length,
                    childInfo: children.map((el) => ({
                        tag: el.tagName,
                        classList: typeof el.className === 'string' ? el.className.split(' ').filter(Boolean) : [],
                        height: round(el.getBoundingClientRect().height),
                    })),
                };
            })
            .filter(Boolean);

        return {
            duplicateIds,
            emptyAriaLabels,
            imgsWithoutAlt,
            emptyAltInteractive,
            unlabeledControls,
            namelessButtons,
            headingSkips,
            tablesWithoutHeaders,
            horizontalOverflow,
            clippedButtons,
            clickTargetsTooSmall,
            hiddenInteractiveElements,
            focusOrderIssues,
            focusIndicatorMissing,
            scrollEdgeCrowding,
            scrollBottomCrowding,
            nestedScrollContainers,
            badgeStyleMismatches,
            monospaceToneMismatches,
            layoutShift,
            componentLayoutShift,
            contrastProblems,
            cardContainment,
            spacing,
            loginFailure,
            modalBackdrop,
            visualContainmentIssues,
            formSwitchMarginIssues,
            inputGroupHeightIssues,
        };
    }, {
        scope, constants: {
            OVERFLOW_TOLERANCE_PX,
            FOOTER_OVERLAP_TOLERANCE_PX,
            VERTICAL_GAP_MIN,
            VERTICAL_GAP_MAX,
            SCROLL_EDGE_CLEARANCE_MIN,
            COMPONENT_LAYOUT_SHIFT_THRESHOLD_PX,
            COMPONENT_LAYOUT_SHIFT_SETTLE_MS,
            CLICK_TARGET_MIN_SIZE_PX,
            LOGS_DELETE_HAIRLINE_TOLERANCE_PX,
            BADGE_FONT_SIZE_TOLERANCE_PX,
            BADGE_FONT_WEIGHT_TOLERANCE,
            BADGE_RADIUS_TOLERANCE_PX,
            BADGE_PADDING_TOLERANCE_PX,
            MONOSPACE_RADIUS_TOLERANCE_PX,
            MONOSPACE_PADDING_TOLERANCE_PX,
            SLIDER_TICK_ALIGNMENT_TOLERANCE_PX,
            SLIDER_VISIBLE_LABEL_GAP_MIN_PX,
            SLIDER_LABEL_HIDDEN_OPACITY_MAX,
            MODAL_BACKDROP_BLUR_EXPECTED_PX,
            MODAL_BACKDROP_BLUR_TOLERANCE_PX,
            MODAL_BACKDROP_SATURATE_EXPECTED,
            MODAL_BACKDROP_SATURATE_TOLERANCE,
            MODAL_BACKDROP_ALPHA_EXPECTED,
            MODAL_BACKDROP_ALPHA_TOLERANCE,
            INPUT_GROUP_HEIGHT_EXPECTED_PX,
            INPUT_GROUP_HEIGHT_TOLERANCE_PX,
            STATUS_FLOW_NODE_EXPECTATIONS,
            STATUS_FLOW_CONNECTOR_EXPECTATIONS,
            WCAG_NORMAL_AA: WCAG_CONTRAST.NORMAL_AA,
            WCAG_LARGE_AA: WCAG_CONTRAST.LARGE_AA,
            WCAG_LARGE_TEXT_SIZE_PX: WCAG_CONTRAST.LARGE_TEXT_SIZE_PX,
            WCAG_LARGE_TEXT_SIZE_BOLD_PX: WCAG_CONTRAST.LARGE_TEXT_SIZE_BOLD_PX,
            WCAG_BOLD_WEIGHT: WCAG_CONTRAST.BOLD_WEIGHT,
        }
    });
}

function summarizeFindings(result) {
    const hardFindings = [];
    const warnings = [];
    const pushHard = (value) => hardFindings.push(value);
    const pushWarning = (value) => warnings.push(value);

    if (result.metrics.duplicateIds.length) pushHard(`duplicateIds=${result.metrics.duplicateIds.length}`);
    if (result.metrics.emptyAriaLabels.length) pushWarning(`emptyAriaLabels=${result.metrics.emptyAriaLabels.length}`);
    if (result.metrics.unlabeledControls.length) pushHard(`unlabeledControls=${result.metrics.unlabeledControls.length}`);
    if (result.metrics.namelessButtons.length) pushHard(`namelessButtons=${result.metrics.namelessButtons.length}`);
    if (result.metrics.headingSkips.length) pushWarning(`headingSkips=${result.metrics.headingSkips.length}`);
    if (result.metrics.tablesWithoutHeaders.length) pushWarning(`tablesWithoutHeaders=${result.metrics.tablesWithoutHeaders.length}`);
    if (result.metrics.horizontalOverflow.hasOverflow) pushHard('horizontalOverflow');
    if (result.metrics.horizontalOverflow.hasOverflow && result.metrics.horizontalOverflow.offenders.length) {
        pushHard(`overflowOffenders=${result.metrics.horizontalOverflow.offenders.length}`);
    }
    if (result.metrics.clippedButtons.length) pushWarning(`clippedButtons=${result.metrics.clippedButtons.length}`);
    if (result.metrics.clickTargetsTooSmall?.length) pushHard(`clickTargetsTooSmall=${result.metrics.clickTargetsTooSmall.length}`);
    if (result.metrics.hiddenInteractiveElements.length) pushHard(`hiddenInteractive=${result.metrics.hiddenInteractiveElements.length}`);
    if (result.metrics.focusOrderIssues?.length) pushWarning(`focusOrderIssues=${result.metrics.focusOrderIssues.length}`);
    if (result.metrics.focusIndicatorMissing?.length) pushWarning(`focusIndicatorMissing=${result.metrics.focusIndicatorMissing.length}`);
    if (result.metrics.scrollEdgeCrowding?.length) pushWarning(`scrollEdgeCrowding=${result.metrics.scrollEdgeCrowding.length}`);
    if (result.metrics.scrollBottomCrowding?.length) pushWarning(`scrollBottomCrowding=${result.metrics.scrollBottomCrowding.length}`);
    if (result.metrics.nestedScrollContainers?.length) pushWarning(`nestedScrollContainers=${result.metrics.nestedScrollContainers.length}`);
    if (result.metrics.badgeStyleMismatches?.length) pushWarning(`badgeStyleMismatches=${result.metrics.badgeStyleMismatches.length}`);
    if (result.metrics.monospaceToneMismatches?.length) pushWarning(`monospaceToneMismatches=${result.metrics.monospaceToneMismatches.length}`);
    if (result.metrics.cardContainment.cardsPastFooter.length) pushWarning(`cardsPastFooter=${result.metrics.cardContainment.cardsPastFooter.length}`);
    if (result.metrics.modalBackdrop) {
        if (!result.metrics.modalBackdrop.blurMatchesReference) {
            pushWarning(`modalBackdropBlur=${result.metrics.modalBackdrop.blurPx ?? 'missing'}`);
        }
        if (!result.metrics.modalBackdrop.saturateMatchesReference) {
            pushWarning(`modalBackdropSaturate=${result.metrics.modalBackdrop.saturate ?? 'missing'}`);
        }
        if (!result.metrics.modalBackdrop.alphaMatchesReference) {
            pushWarning(`modalBackdropAlpha=${result.metrics.modalBackdrop.alpha ?? 'missing'}`);
        }
    }
    if (result.metrics.spacing.rowToRowGap !== undefined && !result.metrics.spacing.rowToRowGapInRange) {
        pushWarning(`rowToRowGapOutOfRange=${result.metrics.spacing.rowToRowGap}`);
    }
    if (result.metrics.spacing.outlierVerticalGaps?.length) pushWarning(`outlierVerticalGaps=${result.metrics.spacing.outlierVerticalGaps.length}`);
    if (result.name.includes('desktop-settings-logs') && result.metrics.spacing.logsDeleteLayout) {
        const logsDeleteLayout = result.metrics.spacing.logsDeleteLayout;
        if (
            logsDeleteLayout.deleteBlockCount !== logsDeleteLayout.cardCount ||
            logsDeleteLayout.deleteInnerCount !== logsDeleteLayout.cardCount ||
            logsDeleteLayout.hairlineCount !== logsDeleteLayout.cardCount
        ) {
            pushWarning(`logsDeleteStructureMismatch=${logsDeleteLayout.cardCount}`);
        }
        if (!logsDeleteLayout.hairlineAligned) {
            pushWarning(`logsDeleteHairlineVariance=${logsDeleteLayout.hairlineVariance}`);
        }
    }
    if (result.metrics.spacing.about?.updateValueStyleMismatches?.length) pushWarning(`aboutUpdateValueStyleMismatches=${result.metrics.spacing.about.updateValueStyleMismatches.length}`);
    if (result.metrics.layoutShift.value > LAYOUT_SHIFT_THRESHOLD) pushHard(`layoutShift=${result.metrics.layoutShift.value.toFixed(4)}`);
    if (result.metrics.componentLayoutShift?.length) pushHard(`componentLayoutShift=${result.metrics.componentLayoutShift.length}`);
    if (result.metrics.contrastProblems.length) pushHard(`contrastProblems=${result.metrics.contrastProblems.length}`);
    if (result.metrics.visualContainmentIssues?.length) pushWarning(`visualContainmentIssues=${result.metrics.visualContainmentIssues.length}`);
    if (result.metrics.formSwitchMarginIssues?.length) pushWarning(`formSwitchMarginIssues=${result.metrics.formSwitchMarginIssues.length}`);
    if (result.metrics.inputGroupHeightIssues?.length) pushHard(`inputGroupHeightIssues=${result.metrics.inputGroupHeightIssues.length}`);
    if (result.diff.ratio > VISUAL_DRIFT_THRESHOLD) pushHard(`visualDrift=${result.diff.ratio.toFixed(4)}`);
    if (result.network.consoleEntries.length) pushHard(`console=${result.network.consoleEntries.length}`);
    if (result.network.pageErrors.length) pushHard(`pageErrors=${result.network.pageErrors.length}`);
    if (result.network.requestFailures.length) pushHard(`failedRequests=${result.network.requestFailures.length}`);
    if (result.network.badResponses.length) pushHard(`badResponses=${result.network.badResponses.length}`);
    if (result.diff.sizeMismatch) pushHard('screenshotSizeMismatch');

    const duplicateRequestMap = new Map();
    for (const entry of result.network.requests || []) {
        if (!entry?.url || entry.method !== 'GET') continue;
        duplicateRequestMap.set(entry.url, (duplicateRequestMap.get(entry.url) || 0) + 1);
    }
    result.network.duplicateRequests = Array.from(duplicateRequestMap.entries())
        .filter(([, count]) => count > 3)
        .map(([url, count]) => ({ url, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);
    if (result.network.duplicateRequests.length) pushWarning(`duplicateRequests=${result.network.duplicateRequests.length}`);

    // KPI Card validation findings
    if (result.metrics.spacing.kpiCards?.length) {
        const paddingProblems = result.metrics.spacing.kpiCards.filter((card) =>
            Math.abs(card.paddingTop - KPI_CARD_PADDING_EXPECTED) > KPI_CARD_PADDING_TOLERANCE ||
            Math.abs(card.paddingBottom - KPI_CARD_PADDING_EXPECTED) > KPI_CARD_PADDING_TOLERANCE
        );

        if (paddingProblems.length) {
            pushWarning(`kpiPaddingMismatch=${paddingProblems.length}`);
        }

        const iconProblems = result.metrics.spacing.kpiCards.filter((card) =>
            card.iconSize &&
            (card.iconSize < KPI_ICON_MIN || card.iconSize > KPI_ICON_MAX)
        );

        if (iconProblems.length) {
            pushWarning(`kpiIconSizeMismatch=${iconProblems.length}`);
        }
    }

    // Dashboard KPI card width variance
    if (result.name.includes('dashboard') && result.metrics.spacing.kpiCards?.length) {
        const widths = result.metrics.spacing.statCardWidths || [];
        if (widths.length > 1) {
            const variance = Math.max(...widths) - Math.min(...widths);
            if (variance > 8) {
                pushWarning(`kpiCardWidthVariance=${variance}`);
            }
        }
    }

    // KPI card height consistency
    if (result.metrics.spacing.kpiHeights?.length) {
        const variance = result.metrics.spacing.kpiHeightVariance || 0;

        if (variance > KPI_ROW_VARIANCE_MAX) {
            pushWarning(`kpiHeightVariance=${variance}`);
        }

        const uneven = result.metrics.spacing.kpiHeights.filter(
            (h) => Math.abs(h - result.metrics.spacing.kpiHeights[0]) > KPI_HEIGHT_TOLERANCE_PX
        );

        if (uneven.length) {
            pushWarning(`kpiHeightMismatch=${uneven.length}`);
        }
    }

    // Desktop-only: first KPI row height consistency
    if (result.name.includes('desktop') && result.metrics.spacing.kpiHeights?.length >= 4) {
        const firstRow = result.metrics.spacing.kpiHeights.slice(0, 4);
        const variance = Math.max(...firstRow) - Math.min(...firstRow);

        if (variance > KPI_ROW_VARIANCE_MAX) {
            pushWarning(`kpiRowHeightVariance=${variance}`);
        }
    }

    // Missing KPI class on stat cards
    if (
        KPI_CARD_REQUIRED_SCOPES.some((scope) => result.name.includes(scope)) &&
        result.metrics.spacing.cardsMissingKpiClass?.length
    ) {
        pushWarning(
            `cardsMissingKpiClass=${result.metrics.spacing.cardsMissingKpiClass.length}`
        );
    }

    // Slider tick alignment (settings-logs views)
    if (result.name.includes('settings-logs') && result.metrics.spacing.sliderAlignment?.length) {
        for (const slider of result.metrics.spacing.sliderAlignment) {
            if (!slider.tickCountMatch) {
                pushWarning(`sliderTickCount:${slider.sliderId}=${slider.tickCount}/${slider.expectedTickCount}`);
            }
            if (!slider.usesIndexVar) {
                pushWarning(`sliderMissingIndexVar:${slider.sliderId}`);
            }
            if (slider.tickMisaligned.length) {
                pushHard(`sliderTickMisaligned:${slider.sliderId}=${slider.tickMisaligned.length}`);
            }
            if (slider.labelMisaligned.length) {
                pushWarning(`sliderLabelMisaligned:${slider.sliderId}=${slider.labelMisaligned.length}`);
            }
            if (slider.labelOverlap.length) {
                pushHard(`sliderLabelOverlap:${slider.sliderId}=${slider.labelOverlap.length}`);
            }
        }
    }

    // Status page: Network flow diagram validation
    if (result.name.includes('status') && result.metrics.spacing.statusFlow) {
        const flow = result.metrics.spacing.statusFlow;

        if (!flow.hasWrapper) {
            pushHard('statusFlowWrapperMissing');
        }
        if (!flow.nodeCountMatch) {
            pushHard(`statusFlowNodeCount=${flow.nodeCount}/${flow.expectedNodeCount}`);
        }
        if (!flow.connectorCountMatch) {
            pushHard(`statusFlowConnectorCount=${flow.connectorCount}/${flow.expectedConnectorCount}`);
        }
        if (!flow.nodeOrderMatches) {
            pushHard('statusFlowNodeOrderMismatch');
        }
        if (!flow.connectorOrderMatches) {
            pushHard('statusFlowConnectorOrderMismatch');
        }
        if (!flow.allNodesHaveStructure) {
            const incomplete = flow.nodes.filter(n => !n.hasIcon || !n.hasLabel || !n.hasMeta);
            pushWarning(`statusFlowIncompleteNodes=${incomplete.length}`);
        }
        if (flow.labelMismatches.length) {
            pushHard(`statusFlowLabelMismatch=${flow.labelMismatches.length}`);
        }
        if (flow.iconMismatches.length) {
            pushHard(`statusFlowIconMismatch=${flow.iconMismatches.length}`);
        }
        if (flow.nodeStateConflicts.length) {
            pushHard(`statusFlowStateConflict=${flow.nodeStateConflicts.length}`);
        }
        if (flow.heightVariance > 5) {
            pushWarning(`statusFlowHeightVariance=${flow.heightVariance}`);
        }
        if (flow.widthVariance > 24) {
            pushWarning(`statusFlowWidthVariance=${flow.widthVariance}`);
        }
        if (flow.orientationIssues.length) {
            pushHard(`statusFlowOrientation=${flow.orientationIssues.length}`);
        }
        if (flow.connectorOrientationIssues.length) {
            pushHard(`statusFlowConnectorOrientation=${flow.connectorOrientationIssues.length}`);
        }
    }

    if (result.name.includes('login-error')) {
        const loginFailure = result.metrics.loginFailure || {};
        const errorText = loginFailure.errorText || '';

        // Rate limiting triggers a different error message - skip validation if rate limited
        const isRateLimited = errorText.toLowerCase().includes('too many') || errorText.toLowerCase().includes('try again later');
        if (isRateLimited) {
            pushWarning('rateLimited');
        } else {
            // Alert is considered present if visible OR if error text is populated
            // (visibility can be affected by motion reset CSS)
            const alertPresent = loginFailure.alertVisible || errorText.length > 0;
            if (!alertPresent) pushHard('loginErrorAlertMissing');
            if (!loginFailure.passwordInvalidClass) pushHard('loginPasswordNotInvalid');
            if (!loginFailure.passwordAriaInvalid) pushHard('loginPasswordAriaInvalidMissing');
            if (!loginFailure.passwordBorderIsDangerLike) pushWarning('loginPasswordNotDangerStyled');
            // Check for shake class - animation is disabled by motion reset CSS, so only check the class
            if (!loginFailure.cardShakeClass) pushWarning('loginCardShakeClassMissing');
        }
    }

    return {
        findings: [...hardFindings, ...warnings],
        hardFindings,
        warnings,
    };
}

function isExpectedStatusUnavailable(view, response) {
    if (view.scope !== 'status' || !response) return false;
    try {
        return new URL(response.url()).pathname === '/status' && response.status() === 404;
    } catch {
        return false;
    }
}

async function auditView(page, view) {
    const detachNetwork = collectConsoleAndNetwork(page);
    await applyTheme(page, view.theme, view.name);
    const response = await page.goto(`${BASE_URL}${view.url}`, { waitUntil: 'networkidle', timeout: 30000 });
    await disableMotion(page, view.name);
    if (view.scope === 'about') {
        await page.evaluate(() => {
            const details = document.querySelector('.about-changelog-col details');
            if (details) details.open = true;
        });
        await page.waitForTimeout(DETAILS_EXPAND_SETTLE_MS);
    }
    if (view.tab) {
        await page.click(view.tab);
        await page.waitForTimeout(TAB_SWITCH_SETTLE_MS);
    }
    if (view.scope === 'traffic') {
        await page.waitForFunction(() => {
            const chartLoading = document.getElementById('traffic-combined-loading');
            const countryLoading = document.getElementById('country-traffic-loading');
            const asnLoading = document.getElementById('asn-traffic-loading');
            const hidden = (el) => !el || el.classList.contains('d-none');
            return hidden(chartLoading) && hidden(countryLoading) && hidden(asnLoading);
        }, { timeout: 10000 }).catch(() => { });
    }
    await resetLayoutShiftMetric(page);
    await page.waitForTimeout(SCREENSHOT_SETTLE_MS);
    const shots = await captureStablePair(page, view.name);
    const kpiShots = await captureKpiCards(page, view.name);
    const diff = diffScreenshots(view.name, shots.shotA, shots.shotB);
    const metrics = await collectPageMetrics(page, view.scope);
    const network = detachNetwork();
    const statusUnavailableExpected = isExpectedStatusUnavailable(view, response);
    network.requestFailures = network.requestFailures.filter((entry) => entry.error !== 'net::ERR_ABORTED');
    if (statusUnavailableExpected) {
        network.consoleEntries = network.consoleEntries.filter((entry) => {
            const text = String(entry.text || '');
            return !(text.includes('/status') && text.includes('404'));
        });
        network.badResponses = network.badResponses.filter((entry) => {
            try {
                return !(entry.status === 404 && new URL(entry.url).pathname === '/status');
            } catch {
                return true;
            }
        });
    }
    return {
        name: view.name,
        url: page.url(),
        theme: view.theme,
        diff,
        metrics,
        network,
        statusUnavailableExpected,
        findings: [],
        screenshots: shots,
        kpiShots,
    };
}

async function auditLoginFailureView(page, view) {
    const detachNetwork = collectConsoleAndNetwork(page);
    await page.goto(`${BASE_URL}${view.url}`, { waitUntil: 'networkidle', timeout: 10000 });
    await disableMotion(page, view.name);
    await applyTheme(page, view.theme, view.name);

    const invalidPassword = `${PASSWORD}__ui_lint_invalid`;
    await page.fill('#username', USERNAME);
    await page.fill('#password', invalidPassword);

    const [loginResponse] = await Promise.all([
        page.waitForResponse((response) => {
            try {
                return new URL(response.url()).pathname === '/api/login';
            } catch {
                return false;
            }
        }, { timeout: 30000 }),
        page.click('#submit-btn'),
    ]);

    // Wait for error alert to appear (attached to DOM without d-none class)
    // Use 'attached' state since visibility can be affected by animations
    await page.waitForSelector('#error-alert:not(.d-none)', { state: 'attached', timeout: 30000 });
    await page.waitForTimeout(LOGIN_ERROR_SETTLE_MS);

    const metrics = await collectPageMetrics(page, view.scope);
    const shots = await captureStablePair(page, view.name);
    const kpiShots = await captureKpiCards(page, view.name);
    const diff = diffScreenshots(view.name, shots.shotA, shots.shotB);
    const network = detachNetwork();
    network.consoleEntries = network.consoleEntries.filter((entry) =>
        !(loginResponse.status() === 401 && entry.text.includes('401 (Unauthorized)'))
    );
    network.requestFailures = network.requestFailures.filter((entry) => entry.error !== 'net::ERR_ABORTED');
    network.badResponses = network.badResponses.filter((entry) => {
        try {
            return !(entry.status === 401 && new URL(entry.url).pathname === '/api/login');
        } catch {
            return true;
        }
    });

    return {
        name: view.name,
        url: page.url(),
        theme: view.theme,
        diff,
        metrics,
        network,
        findings: [],
        screenshots: shots,
        kpiShots,
        loginResponseStatus: loginResponse.status(),
    };
}

async function main() {
    // Clean up old output files
    if (fs.existsSync(OUTPUT_DIR)) {
        const files = fs.readdirSync(OUTPUT_DIR);
        for (const file of files) {
            if (file.endsWith('.png') || file.endsWith('.json')) {
                fs.unlinkSync(path.join(OUTPUT_DIR, file));
            }
        }
    }
    ensureDir(OUTPUT_DIR);
    fs.rmSync(SCREENSHOT_DIR, { recursive: true, force: true });
    ensureDir(SCREENSHOT_DIR);

    const results = [];
    let browser;

    try {
        browser = await chromium.launch({ headless: true });
        const authContext = await browser.newContext({ viewport: { width: 1440, height: 1100 } });
        await login(await authContext.newPage());
        const authState = await authContext.storageState();
        await authContext.close();

        const desktopContext = await browser.newContext({
            viewport: { width: 1440, height: 1100 },
            storageState: authState,
        });
        const mobileContext = await browser.newContext({
            ...devices['iPhone 13'],
            storageState: authState,
        });
        await installLayoutShiftObserver(desktopContext);
        await installLayoutShiftObserver(mobileContext);

        const desktopPage = await desktopContext.newPage();
        const mobilePage = await mobileContext.newPage();

        // Run authenticated view tests
        for (const view of VIEWS) {
            const page = view.mobile ? mobilePage : desktopPage;
            try {
                const result = await auditView(page, view);
                const summarized = summarizeFindings(result);
                result.findings = summarized.findings;
                result.hardFindings = summarized.hardFindings;
                result.warnings = summarized.warnings;
                results.push(result);
            } catch (err) {
                console.error(`[${view.name}] Audit failed: ${err.message}`);
                results.push({
                    name: view.name,
                    url: view.url,
                    theme: view.theme,
                    error: err.message,
                    findings: ['auditError'],
                    hardFindings: ['auditError'],
                    warnings: [],
                    diff: { ratio: 0, sizeMismatch: false },
                    metrics: {},
                    network: { consoleEntries: [], pageErrors: [], requestFailures: [], badResponses: [], requests: [], duplicateRequests: [] },
                });
            }
        }

        // Run login-failure tests LAST to avoid rate limiting blocking the real login
        for (const [index, view] of LOGIN_FAILURE_VIEWS.entries()) {
            const page = view.mobile ? mobilePage : desktopPage;

            // Retry logic for rate limiting: detect "too many attempts" and wait before retry
            let result;
            let attempt = 0;
            const maxRetries = 3;

            while (attempt < maxRetries) {
                try {
                    // Preventive delay every 3 tests
                    if (index > 0 && index % 3 === 0 && attempt === 0) {
                        await new Promise((resolve) => setTimeout(resolve, LOGIN_LOCKOUT_RESET_MS));
                    }

                    result = await auditLoginFailureView(page, view);

                    // Check if rate limited by examining error text
                    const errorText = result?.metrics?.loginFailure?.errorText?.toLowerCase() || '';
                    if (errorText.includes('too many') || errorText.includes('rate limit') || errorText.includes('locked')) {
                        if (attempt < maxRetries - 1) {
                            console.warn(`[${view.name}] Rate limited, waiting ${LOGIN_LOCKOUT_RESET_MS}ms before retry ${attempt + 1}/${maxRetries - 1}`);
                            await new Promise((resolve) => setTimeout(resolve, LOGIN_LOCKOUT_RESET_MS));
                            attempt++;
                            continue;
                        }
                    }

                    // Success or non-rate-limit error
                    break;
                } catch (err) {
                    if (attempt === maxRetries - 1) {
                        console.error(`[${view.name}] Audit failed after ${maxRetries} attempts: ${err.message}`);
                        result = {
                            name: view.name,
                            url: view.url,
                            theme: view.theme,
                            error: err.message,
                            findings: ['auditError'],
                            hardFindings: ['auditError'],
                            warnings: [],
                            diff: { ratio: 0, sizeMismatch: false },
                            metrics: {},
                            network: { consoleEntries: [], pageErrors: [], requestFailures: [], badResponses: [], requests: [], duplicateRequests: [] },
                        };
                        break;
                    }
                    attempt++;
                }
            }

            if (result) {
                const summarized = summarizeFindings(result);
                result.findings = summarized.findings;
                result.hardFindings = summarized.hardFindings;
                result.warnings = summarized.warnings;
                results.push(result);
            }
        }
    } finally {
        if (browser) {
            await browser.close();
        }
    }

    const summaryPath = path.join(OUTPUT_DIR, 'ui-lint-summary.json');
    fs.writeFileSync(summaryPath, JSON.stringify(results, null, 2));

    console.log('UI_LINT_START');
    for (const result of results) {
        const metrics = result.metrics || {};
        const spacing = metrics.spacing || {};
        const horizontalOverflow = metrics.horizontalOverflow || {};
        const layoutShiftValue = Number(metrics.layoutShift?.value || 0);
        console.log(JSON.stringify({
            name: result.name,
            url: result.url,
            theme: result.theme || null,
            findings: result.findings,
            hardFindings: result.hardFindings || [],
            warnings: result.warnings || [],
            diffRatio: Number(result.diff.ratio.toFixed(6)),
            layoutShift: Number(layoutShiftValue.toFixed(6)),
            overflowOffenders: horizontalOverflow.offenders?.length || 0,
            clippedButtons: metrics.clippedButtons?.length || 0,
            clickTargetsTooSmall: metrics.clickTargetsTooSmall?.length || 0,
            hiddenInteractive: metrics.hiddenInteractiveElements?.length || 0,
            focusOrderIssues: metrics.focusOrderIssues?.length || 0,
            focusIndicatorMissing: metrics.focusIndicatorMissing?.length || 0,
            scrollEdgeCrowding: metrics.scrollEdgeCrowding?.length || 0,
            scrollBottomCrowding: metrics.scrollBottomCrowding?.length || 0,
            nestedScrollContainers: metrics.nestedScrollContainers?.length || 0,
            badgeStyleMismatches: metrics.badgeStyleMismatches?.length || 0,
            monospaceToneMismatches: metrics.monospaceToneMismatches?.length || 0,
            modalBackdropBlur: metrics.modalBackdrop?.blurPx ?? null,
            modalBackdropSaturate: metrics.modalBackdrop?.saturate ?? null,
            modalBackdropAlpha: metrics.modalBackdrop?.alpha ?? null,
            contrastProblems: metrics.contrastProblems?.length || 0,
            componentLayoutShift: metrics.componentLayoutShift?.length || 0,
            visualContainmentIssues: metrics.visualContainmentIssues?.length || 0,
            sliderAlignment: spacing.sliderAlignment?.length || 0,
            sliderTickMisaligned: spacing.sliderAlignment?.filter((s) => s.tickMisaligned?.length)?.length || 0,
            sliderLabelOverlap: spacing.sliderAlignment?.filter((s) => s.labelOverlap?.length)?.length || 0,
            duplicateRequests: result.network.duplicateRequests?.length || 0,
            kpiCards: spacing.kpiCards?.length || 0,
            kpiMissingClass: spacing.cardsMissingKpiClass?.length || 0,
            kpiHeightVariance: spacing.kpiHeightVariance || 0,
            statusFlowNodes: spacing.statusFlow?.nodeCount || 0,
            statusFlowConnectors: spacing.statusFlow?.connectorCount || 0,
            statusFlowHeightVariance: spacing.statusFlow?.heightVariance || 0,
            loginErrorVisible: Boolean(metrics.loginFailure?.alertVisible),
            loginShakeActive: Boolean(metrics.loginFailure?.cardAnimationActive),
            loginPasswordInvalid: Boolean(metrics.loginFailure?.passwordInvalidClass),
            summaryPath,
        }));
    }
    console.log('UI_LINT_END');

    const hasHardFindings = results.some((result) => (result.hardFindings || []).length > 0);
    process.exitCode = hasHardFindings ? 1 : 0;
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
