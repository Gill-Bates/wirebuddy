//
// tools/ui-lint/tests/runtime/views-orchestration.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import {
    LOGIN_FAILURE_VIEWS,
    VIEW_DEFS,
    VIEWS,
    adaptiveCoverageExpansion,
    clearViewProviders,
    composeViewExecutionPlan,
    discoverViews,
    registerViewProvider,
    whyWasViewScheduled,
} from '../../lib/views.mjs';

test.afterEach(() => {
    clearViewProviders();
});

test('legacy matrices preserve the existing compatibility expansion', async () => {
    expect(VIEWS).toHaveLength(VIEW_DEFS.length * 3 * 4);
    expect(LOGIN_FAILURE_VIEWS).toHaveLength(1 * 3 * 2);

    expect(VIEWS[0]).toMatchObject({
        id: 'dashboard-main',
        name: 'desktop-dashboard-light',
        family: 'dashboard',
        device: 'desktop',
        theme: 'light',
    });

    expect(LOGIN_FAILURE_VIEWS[0]).toMatchObject({
        id: 'login-error-main',
        name: 'desktop-login-error-light',
        family: 'auth',
        device: 'desktop',
        theme: 'light',
    });
});

test('view orchestration can discover plugin views and build execution plans', async () => {
    registerViewProvider(() => [{
        id: 'analytics-overview-main',
        name: 'analytics-overview',
        family: 'analytics',
        url: '/ui/analytics',
        scope: 'analytics',
        risk: 'low',
        priority: 10,
        executionModes: ['smoke'],
        metadata: { owner: 'analytics' },
        tags: ['plugin', 'analytics'],
        condition: (ctx) => ctx.features?.analyticsEnabled !== false,
    }]);

    const discovered = discoverViews();
    expect(discovered.some((definition) => definition.id === 'analytics-overview-main')).toBe(true);

    const plan = composeViewExecutionPlan({
        viewDefs: discovered,
        runtimeContext: {
            device: 'mobile',
            theme: 'dark',
            environment: 'ci',
            mode: 'smoke',
            browser: 'webkit',
            features: {
                analyticsEnabled: true,
                dnsEnabled: false,
                dashboardEnabled: true,
                peersEnabled: true,
                nodesEnabled: true,
                usersEnabled: true,
                trafficEnabled: true,
                statusEnabled: true,
                settingsEnabled: true,
            },
            historicalFailures: {
                'dashboard-main': 2,
            },
        },
    });

    expect(plan.runtimeVersion).toBe('2026.05');
    expect(plan.views.every((view) => view.device === 'mobile')).toBe(true);
    expect(plan.views.every((view) => view.theme === 'dark')).toBe(true);
    expect(plan.views.some((view) => view.id === 'dns-main')).toBe(false);
    expect(plan.views.some((view) => view.id === 'analytics-overview-main')).toBe(true);
    expect(plan.executionGraph.nodes.length).toBeGreaterThan(0);
    expect(plan.viewExecutionAnalytics.totalViews).toBe(plan.views.length);

    const explanation = whyWasViewScheduled(plan.views[0], plan.runtimeContext);
    expect(explanation).toMatchObject({
        viewId: plan.views[0].id,
        executionId: plan.views[0].executionId,
        parallelGroup: plan.views[0].parallelGroup,
    });
});

test('adaptive coverage expansion still supports selective runtime filtering', async () => {
    const filtered = adaptiveCoverageExpansion(VIEW_DEFS, {
        device: 'tablet',
        theme: 'highContrast',
        mode: 'regression',
        environment: 'nightly',
        features: {
            dashboardEnabled: true,
            dnsEnabled: true,
            peersEnabled: true,
            nodesEnabled: true,
            usersEnabled: true,
            trafficEnabled: true,
            statusEnabled: true,
            settingsEnabled: true,
            settingsDnsEnabled: true,
        },
    });

    expect(filtered.every((view) => view.device === 'tablet')).toBe(true);
    expect(filtered.every((view) => view.theme === 'highContrast')).toBe(true);
    expect(filtered.every((view) => view.runtimeMode === 'regression')).toBe(true);
});