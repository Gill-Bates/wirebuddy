//
// tools/ui-lint/tests/findings/layout-policy.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import { summarizeFindings } from '../../lib/findings.mjs';

test('standard button height token drift becomes a hard finding', async () => {
    const summarized = summarizeFindings({
        name: 'settings-backup-desktop',
        metrics: {
            standardButtonHeightContract: {
                count: 3,
                mismatchCount: 1,
                expectedHeight: 38,
                tolerance: 2,
                sample: [{
                    tag: 'BUTTON',
                    className: 'btn btn-primary w-100',
                    height: 44,
                    minHeight: 44,
                    expectedHeight: 38,
                }],
            },
        },
        network: {},
        diff: { ratio: 0, sizeMismatch: false },
    });

    expect(summarized.hardFindings).toContain('standardButtonHeightContract=1');
    expect(summarized.structuredFindings).toEqual(expect.arrayContaining([
        expect.objectContaining({
            id: 'standard-button-height-contract',
            severity: 'error',
        }),
    ]));
});

test('standard button height contract stays quiet when there is no mismatch', async () => {
    const summarized = summarizeFindings({
        name: 'settings-backup-desktop',
        metrics: {
            standardButtonHeightContract: {
                count: 2,
                mismatchCount: 0,
                expectedHeight: 38,
                tolerance: 2,
                sample: [],
            },
        },
        network: {},
        diff: { ratio: 0, sizeMismatch: false },
    });

    expect(summarized.hardFindings).not.toContain('standardButtonHeightContract=0');
    expect(summarized.structuredFindings.find((finding) => finding.id === 'standard-button-height-contract')).toBeUndefined();
});

test('form switch helper spacing produces the updated layout warning', async () => {
    const summarized = summarizeFindings({
        name: 'settings-general-desktop',
        metrics: {
            formSwitchMarginIssues: [{
                label: 'Enable Status Page',
                marginBottom: 8,
                descriptionMarginTop: 0,
            }],
        },
        network: {},
        diff: { ratio: 0, sizeMismatch: false },
    });

    expect(summarized.warnings).toContain('formSwitchMarginIssues=1');
    expect(summarized.structuredFindings).toEqual(expect.arrayContaining([
        expect.objectContaining({
            id: 'form-switch-margin',
            message: 'Form switch description spacing issues detected',
            severity: 'warning',
        }),
    ]));
});

test('resized and reordered dashboard widgets do not create layout findings', async () => {
    const summarized = summarizeFindings({
        name: 'dashboard-main-mobile',
        metrics: {
            spacing: {
                dashboardWidgetOverlaps: [],
                statCardWidths: [120, 540, 320, 320],
                dashboardTopRowAlignment: { variance: 50, aligned: false },
                dashboardMobileStackOrder: { speedtestAboveMap: false, mapAboveRecent: false },
                kpiHeightVariance: 50,
            },
        },
        network: {},
        diff: { ratio: 0, sizeMismatch: false },
    });

    expect(summarized.structuredFindings.filter((finding) => finding.category === 'layout')).toEqual([]);
});

test('overlapping visible dashboard widgets produce a layout finding', async () => {
    const summarized = summarizeFindings({
        name: 'dashboard-main-mobile',
        metrics: {
            spacing: {
                dashboardWidgetOverlaps: [{ ids: ['kpi-nodes', 'kpi-connections'], width: 24, height: 80 }],
            },
        },
        network: {},
        diff: { ratio: 0, sizeMismatch: false },
    });

    expect(summarized.hardFindings).toContain('dashboardWidgetOverlaps=1');
    expect(summarized.structuredFindings).toEqual(expect.arrayContaining([
        expect.objectContaining({ id: 'dashboard-widget-overlap', count: 1, severity: 'error' }),
    ]));
});
