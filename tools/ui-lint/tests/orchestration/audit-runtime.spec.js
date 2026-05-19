//
// tools/ui-lint/tests/orchestration/audit-runtime.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import { BrowserAdapters, BROWSER_CONFIGS } from '../../lib/orchestration/audit-runner.mjs';
import { installDOMStabilityObserver, collectDOMStabilityMetrics } from '../../lib/orchestration/audit-runner.mjs';

test('browser adapters and capability matrix stay aligned', async () => {
    expect(Object.keys(BrowserAdapters)).toEqual(expect.arrayContaining(['chromium', 'webkit', 'firefox']));
    expect(BROWSER_CONFIGS.map((entry) => entry.name)).toEqual(expect.arrayContaining(['chromium', 'webkit', 'firefox']));
    expect(BROWSER_CONFIGS.find((entry) => entry.name === 'chromium')?.capabilities.memory).toBeTruthy();
});

test('dom stability observer stores runtime state under a symbol key', async ({ page }) => {
    await installDOMStabilityObserver(page.context());

    const observedPage = await page.context().newPage();
    await observedPage.setContent('<!doctype html><html><body><main class="main-content"><div id="root"></div></main></body></html>');
    const stats = await collectDOMStabilityMetrics(observedPage);

    expect(stats).toMatchObject({
        mutationCount: 0,
        mutationBursts: 0,
        reconnectCount: 0,
        severity: 'diagnostic',
    });

    const hasSymbolRuntime = await observedPage.evaluate(() => Boolean(window[Symbol.for('uiLint.runtime')]));
    expect(hasSymbolRuntime).toBeTruthy();

    await observedPage.close();
});