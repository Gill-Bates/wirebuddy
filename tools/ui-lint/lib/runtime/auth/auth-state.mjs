//
// tools/ui-lint/lib/runtime/auth/auth-state.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//
// Seeding the theme needs a settled, same-origin document, because the theme
// lives in localStorage. Getting that wrong used to lose most of an audit run:
// the origin was bootstrapped by navigating to `/login`, and for an
// authenticated session the server answers that with 303 -> /ui/dashboard
// (app/api/frontend_pages.py, login_page()). The evaluate that followed then
// raced the redirect and the dashboard's own boot scripts, so the run reported
// "Execution context was destroyed, most likely because of a navigation" - or,
// when nothing had committed yet and the document was still about:blank,
// "SecurityError: Failed to read the 'localStorage' property".
//
// Two changes keep that from happening: callers pass the page they are actually
// about to audit as the bootstrap target, so the navigation does not go through
// a redirecting URL, and the evaluate is retried once after the document
// settles, which covers a late client-side navigation we cannot predict.
//

const SETTLE_TIMEOUT_MS = 15000;
// Covers both symptoms seen in the wild for the same underlying race: Chromium
// reports the destroyed execution context directly, while a mid-navigation
// document (about:blank, or a page whose origin just changed under it) denies
// script access to localStorage instead - "Failed to read the 'localStorage'
// property from 'Window': Access is denied for this document" in Chromium,
// "Access is denied for this document" alone in WebKit.
const NAVIGATION_RACE_PATTERN = /execution context was destroyed|most likely because of a navigation|access is denied for this document|cannot find context|failed to read the 'localstorage' property/i;

/** True when the page holds a committed document on *baseUrl*. */
function isUsableDocument(page, baseUrl) {
    try {
        const url = page.url();
        return Boolean(url) && url !== 'about:blank' && url.startsWith(baseUrl);
    } catch {
        return false;
    }
}

/** Wait for the document to stop moving, without failing the caller. */
async function settle(page) {
    await page.waitForLoadState('domcontentloaded', { timeout: SETTLE_TIMEOUT_MS }).catch(() => { });
}

function themeSeed(nextTheme) {
    localStorage.setItem('theme', nextTheme);
    document.documentElement.setAttribute('data-bs-theme', nextTheme);
    if (typeof window.updateThemeIcon === 'function') {
        window.updateThemeIcon(nextTheme);
    }
}

/**
 * Put *theme* into localStorage and onto the live document.
 *
 * `bootstrapUrl` is an app-relative path to land on when the page has no usable
 * document yet. Pass the view about to be audited: `/login` is the wrong choice
 * for an authenticated session because it redirects.
 */
export async function applyTheme(page, { baseUrl, theme, label = 'unknown', bootstrapUrl = '/login' } = {}) {
    if (!baseUrl || !theme) return;

    if (!isUsableDocument(page, baseUrl)) {
        await page.goto(`${baseUrl}${bootstrapUrl}`, { waitUntil: 'domcontentloaded', timeout: 30000 })
            .catch((err) => console.warn(`[${label}] Failed to bootstrap origin for theme setup: ${err.message}`));
    }

    await settle(page);

    if (!isUsableDocument(page, baseUrl)) {
        throw new Error(`[${label}] Cannot apply theme ${theme}: no same-origin document (at ${page.url()})`);
    }

    try {
        await page.evaluate(themeSeed, theme);
        return;
    } catch (err) {
        if (!NAVIGATION_RACE_PATTERN.test(err.message)) {
            throw new Error(`[${label}] Failed to apply theme ${theme}: ${err.message}`);
        }
        // The document moved under us. Let it land and seed the new one, which
        // is the document the audit will actually measure.
        await settle(page);
    }

    try {
        await page.evaluate(themeSeed, theme);
    } catch (err) {
        throw new Error(`[${label}] Failed to apply theme ${theme} after renavigation: ${err.message}`);
    }
}

/**
 * Establish the app origin for a freshly logged-in page.
 *
 * Navigates to the dashboard rather than `/login`, which would immediately
 * redirect there anyway now that the session exists.
 */
export async function bootstrapAuthenticatedSession(page, { baseUrl, theme } = {}) {
    if (!baseUrl) return;

    await page.goto(`${baseUrl}/ui/dashboard`, { waitUntil: 'domcontentloaded', timeout: 30000 })
        .catch((err) => console.warn(`[auth] Failed to bootstrap origin: ${err.message}`));

    if (theme) {
        await applyTheme(page, { baseUrl, theme, label: 'auth', bootstrapUrl: '/ui/dashboard' })
            .catch((err) => console.warn(`[auth] ${err.message}`));
    }
}
