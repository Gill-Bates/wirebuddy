//
// tools/ui-lint/tests/ux-health.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import { correlateConsoleEntries } from '../lib/dom-health.mjs';
import { buildUIHealthReport } from '../lib/ui-health-score.mjs';

test('console entries are enriched with route, component, and browser context', async () => {
    const entries = correlateConsoleEntries(
        [{ type: 'error', text: 'ResizeObserver loop limit exceeded' }],
        {
            horizontalOverflow: { hasOverflow: true, scrollWidth: 430, viewportWidth: 390, offenderCount: 2, offenders: [] },
            layoutShiftCount: 1,
            layoutShiftValue: 0.12,
            clippedButtonCount: 0,
            touchTargetViolationCount: 0,
            hiddenInteractiveCount: 0,
            componentLayoutShiftCount: 0,
        },
        {
            route: '/ui/peers',
            browser: 'webkit',
            scope: 'peers',
        }
    );

    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
        route: '/ui/peers',
        component: 'peers',
        browser: 'webkit',
        uxSeverity: 'critical',
    });
    expect(entries[0].correlatedSignals).toContain('resize-observer');
    expect(entries[0].correlatedSignals).toContain('horizontal-overflow');
});

test('UI health scoring treats mobile overflow and touch issues as release blockers', async () => {
    const report = buildUIHealthReport({
        name: 'mobile-peers-light',
        url: '/ui/peers',
        browser: 'webkit',
        scope: 'peers',
        diff: { ratio: 0.04 },
        metrics: {
            horizontalOverflow: {
                hasOverflow: true,
                scrollWidth: 430,
                viewportWidth: 390,
                offenderCount: 2,
                offenders: [{ tag: 'DIV' }],
            },
            clippedButtons: [{ tag: 'BUTTON' }],
            clickTargetsTooSmall: [{ tag: 'BUTTON' }],
            hiddenInteractiveElements: [],
            layoutShift: { value: 0.12, count: 2 },
            componentLayoutShift: [{ component: 'peer-card' }],
            axe: {
                critical: [{ id: 'color-contrast' }],
                serious: [{ id: 'aria-required-children' }],
                moderate: [],
                minor: [{ id: 'landmark-unique' }],
            },
            safariTableOverflowRisks: [{ tag: 'TABLE' }],
        },
        network: {
            consoleSeverity: {
                score: 5,
                critical: [{ text: 'critical' }],
                serious: [{ text: 'serious' }],
                minor: [],
                total: 2,
            },
            consoleEntries: [{ type: 'error', text: 'ResizeObserver loop limit exceeded' }],
        },
    });

    expect(report.score).toBeLessThan(85);
    expect(report.severity).toBe('critical');
    expect(report.console.critical).toBe(1);
    expect(report.ux.critical).toBeGreaterThan(0);
    expect(report.gates.hardBlock).toBeTruthy();
});