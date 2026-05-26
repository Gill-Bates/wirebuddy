//
// tools/ui-lint/lib/browsers/capabilities.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

const WEBKIT_LIKE = new Set(['webkit', 'safari']);

export function supportsMemoryAPI(browserName) {
    return String(browserName || '').toLowerCase() === 'chromium';
}

export function supportsLCP(browserName) {
    return !WEBKIT_LIKE.has(String(browserName || '').toLowerCase());
}

export function supportsINP(browserName) {
    return supportsLCP(browserName);
}

export function supportsVisualViewport(browserName) {
    return String(browserName || '').toLowerCase() !== 'firefox';
}
