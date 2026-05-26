//
// tools/ui-lint/lib/runtime/auth/auth-state.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export async function bootstrapAuthenticatedSession(page, { baseUrl, theme } = {}) {
    if (!baseUrl) return;

    await page.goto(`${baseUrl}/login`, { waitUntil: 'domcontentloaded', timeout: 30000 })
        .catch((err) => console.warn(`[auth] Failed to bootstrap origin: ${err.message}`));

    if (theme) {
        await page.evaluate((nextTheme) => {
            localStorage.setItem('theme', nextTheme);
            document.documentElement.setAttribute('data-bs-theme', nextTheme);
        }, theme).catch(() => { });
    }
}

export async function applyTheme(page, { baseUrl, theme, label = 'unknown' }) {
    let sameOrigin = false;
    try {
        sameOrigin = page.url().startsWith(baseUrl);
    } catch (err) {
        console.warn(`[${label}] Unable to verify origin: ${err.message}`);
    }

    if (!sameOrigin) {
        await page.goto(`${baseUrl}/login`, { waitUntil: 'domcontentloaded', timeout: 30000 })
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
