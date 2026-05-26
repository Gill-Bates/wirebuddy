//
// tools/ui-lint/lib/browsers/launcher.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const BrowserAdapters = {
    chromium: {
        name: 'chromium',
        async launch(playwright, options = {}) {
            return playwright.chromium.launch({ headless: true, ...options });
        },
    },
    webkit: {
        name: 'webkit',
        async launch(playwright, options = {}) {
            return playwright.webkit.launch({ headless: true, ...options });
        },
    },
    firefox: {
        name: 'firefox',
        async launch(playwright, options = {}) {
            return playwright.firefox.launch({ headless: true, ...options });
        },
    },
};

export function getBrowserLauncher(browserName) {
    const adapter = BrowserAdapters[String(browserName || '').toLowerCase()] || BrowserAdapters.chromium;
    return async (playwright, options = {}) => adapter.launch(playwright, options);
}
