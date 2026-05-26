//
// tools/ui-lint/tests/audit-helpers.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import {
    filterConsoleEntries,
    scoreConsoleSeverity,
    BROWSER_CONFIGS,
} from '../lib/audit-helpers.mjs';

// -----------------------------------------------------------------------------
// Console Allowlist Tests
// -----------------------------------------------------------------------------

test('filterConsoleEntries removes known noise patterns', async () => {
    const entries = [
        { type: 'error', text: 'ResizeObserver loop limit exceeded' },
        { type: 'error', text: 'Real application error' },
        { type: 'warning', text: 'DevTools failed to load source map' },
        { type: 'warning', text: 'Bootstrap deprecated feature warning' },
        { type: 'error', text: 'Network request failed' },
    ];

    const filtered = filterConsoleEntries(entries);

    expect(filtered).toHaveLength(2);
    expect(filtered[0].text).toBe('Real application error');
    expect(filtered[1].text).toBe('Network request failed');
});

test('filterConsoleEntries with custom allowlist', async () => {
    const entries = [
        { type: 'error', text: 'Custom noise pattern XYZ' },
        { type: 'error', text: 'Real error' },
    ];

    const filtered = filterConsoleEntries(entries, {
        allowlist: [/Custom noise pattern/i],
    });

    expect(filtered).toHaveLength(1);
    expect(filtered[0].text).toBe('Real error');
});

test('scoreConsoleSeverity computes correct severity breakdown', async () => {
    const entries = [
        { type: 'error', text: 'Critical failure' },
        { type: 'error', text: 'Another error' },
        { type: 'warning', text: 'Some warning' },
        { type: 'info', text: 'Info message' },
        { type: 'log', text: 'Debug log' },
    ];

    const result = scoreConsoleSeverity(entries);

    expect(result.total).toBe(5);
    expect(result.critical).toHaveLength(2);
    expect(result.serious).toHaveLength(1);
    expect(result.minor).toHaveLength(1);
    expect(result.score).toBe(3 + 3 + 2 + 1 + 0); // 9
});

// -----------------------------------------------------------------------------
// Browser Matrix Tests
// -----------------------------------------------------------------------------

test('BROWSER_CONFIGS contains expected browsers', async () => {
    expect(BROWSER_CONFIGS).toHaveLength(3);

    const names = BROWSER_CONFIGS.map((c) => c.name);
    expect(names).toContain('chromium');
    expect(names).toContain('webkit');
    expect(names).toContain('firefox');
});
