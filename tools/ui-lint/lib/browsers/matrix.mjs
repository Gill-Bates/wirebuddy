//
// tools/ui-lint/lib/browsers/matrix.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { supportsINP, supportsLCP, supportsMemoryAPI, supportsVisualViewport } from './capabilities.mjs';

export const BROWSER_CONFIGS = [
    {
        name: 'chromium',
        launcher: 'chromium',
        capabilities: {
            memory: supportsMemoryAPI('chromium'),
            lcp: supportsLCP('chromium'),
            inp: supportsINP('chromium'),
            visualViewport: supportsVisualViewport('chromium'),
        },
    },
    {
        name: 'webkit',
        launcher: 'webkit',
        capabilities: {
            memory: supportsMemoryAPI('webkit'),
            lcp: supportsLCP('webkit'),
            inp: supportsINP('webkit'),
            visualViewport: supportsVisualViewport('webkit'),
        },
    },
    {
        name: 'firefox',
        launcher: 'firefox',
        capabilities: {
            memory: supportsMemoryAPI('firefox'),
            lcp: supportsLCP('firefox'),
            inp: supportsINP('firefox'),
            visualViewport: supportsVisualViewport('firefox'),
        },
    },
];

export function getBrowserCapabilityProfile(browserName) {
    return BROWSER_CONFIGS.find((entry) => entry.name === browserName) || null;
}
