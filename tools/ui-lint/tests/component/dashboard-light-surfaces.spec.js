//
// tools/ui-lint/tests/component/dashboard-light-surfaces.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import dashboardLightSurfacesRule from '../../rules/component/dashboard-light-surfaces.mjs';

test('dashboard light surfaces accept a light KPI card', async ({ page }) => {
    await page.setContent(`
        <html data-bs-theme="light"><body>
            <div class="wb-kpi-card" style="background-color: rgb(255, 255, 255)"></div>
        </body></html>
    `);

    const findings = await dashboardLightSurfacesRule.run({ page, browser: 'chromium', scope: 'dashboard' });

    expect(findings).toEqual([]);
});

test('dashboard light surfaces flag dark KPI cards in the light theme', async ({ page }) => {
    await page.setContent(`
        <html data-bs-theme="light"><body>
            <div id="bad-kpi" class="dashboard-kpi-card" style="background-color: rgb(33, 37, 41)"></div>
        </body></html>
    `);

    const findings = await dashboardLightSurfacesRule.run({ page, browser: 'chromium', scope: 'dashboard' });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
        kind: 'dashboard-light-surface-dark',
        selector: '#bad-kpi',
    });
});

test('dashboard light surfaces do not constrain dark theme cards', async ({ page }) => {
    await page.setContent(`
        <html data-bs-theme="dark"><body>
            <div class="dashboard-kpi-card" style="background-color: rgb(33, 37, 41)"></div>
        </body></html>
    `);

    const findings = await dashboardLightSurfacesRule.run({ page, browser: 'chromium', scope: 'dashboard' });

    expect(findings).toEqual([]);
});
