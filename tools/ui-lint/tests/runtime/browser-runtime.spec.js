//
// tools/ui-lint/tests/runtime/browser-runtime.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { expect, test } from '@playwright/test';

import {
    captureStablePair,
    collectConsoleAndNetwork,
    diffScreenshots,
    ensureDir,
    installLayoutShiftObserver,
    disableMotion,
    resetLayoutShiftMetric,
    sanitize,
} from '../../lib/browser-utils.mjs';

test('browser runtime facade preserves legacy CLS helpers', async ({ page }) => {
    await installLayoutShiftObserver(page.context());

    const observerPage = await page.context().newPage();
    try {
        await observerPage.goto('about:blank');
        await observerPage.evaluate(() => {
            window[Symbol.for('uiLint.layoutShift')] = { value: 5, count: 1, entries: [{ value: 5 }] };
            window[Symbol.for('uiLint.runtime')] = {
                performance: {
                    webVitals: { cls: 5 },
                },
            };
        });

        await resetLayoutShiftMetric(observerPage);

        const layoutShift = await observerPage.evaluate(() => window[Symbol.for('uiLint.layoutShift')]);
        const runtimeCls = await observerPage.evaluate(() => window[Symbol.for('uiLint.runtime')].performance.webVitals.cls);

        expect(layoutShift).toEqual({ value: 0, count: 0, entries: [] });
        expect(runtimeCls).toBe(0);
    } finally {
        await observerPage.close();
    }
});

test('browser runtime facade captures console telemetry and stable screenshot diffs', async ({ page }, testInfo) => {
    const collect = collectConsoleAndNetwork(page);
    await page.setContent(`
        <!doctype html>
        <html>
            <head>
                <meta charset="utf-8">
                <style>
                    body {
                        margin: 0;
                        font-family: sans-serif;
                    }
                    .panel {
                        width: 240px;
                        height: 120px;
                        margin: 16px;
                        background: linear-gradient(135deg, #1f2937, #3b82f6);
                        color: white;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                    }
                </style>
            </head>
            <body>
                <div class="panel">browser runtime</div>
                <script>
                    console.error('browser-runtime boom');
                </script>
            </body>
        </html>
    `);

    const telemetry = collect();
    expect(telemetry.consoleEntries.some((entry) => entry.text.includes('browser-runtime boom'))).toBe(true);
    expect(Array.isArray(telemetry.requestTimeline)).toBe(true);

    const screenshotDir = testInfo.outputPath('browser-runtime');
    ensureDir(screenshotDir);

    const shots = await captureStablePair(page, {
        motionResetCss: '',
        name: 'browser runtime stable pair',
        screenshotDir,
        screenshotSettleMs: 10,
    });

    expect(fs.existsSync(shots.shotA)).toBe(true);
    expect(fs.existsSync(shots.shotB)).toBe(true);

    const diff = diffScreenshots({
        name: 'browser runtime stable pair',
        shotA: shots.shotA,
        shotB: shots.shotB,
        screenshotDir,
    });

    expect(diff.mismatchedPixels).toBe(0);
    expect(diff.ratio).toBe(0);
    expect(diff.sizeMismatch).toBe(false);
    expect(fs.existsSync(diff.diffPath)).toBe(true);
    expect(sanitize('Browser runtime stable pair')).toBe('browser_runtime_stable_pair');
});

test('disableMotion serves motion reset CSS through a routed stylesheet', async () => {
    const routeHandlers = [];
    const addStyleTagCalls = [];

    const fakePage = {
        async route(pattern, handler) {
            routeHandlers.push({ pattern, handler });
        },
        async addStyleTag(options) {
            addStyleTagCalls.push(options);
        },
    };

    await disableMotion(fakePage, 'body { animation: none; }', 'test-view');

    expect(routeHandlers).toHaveLength(1);
    expect(routeHandlers[0].pattern).toMatch(/__ui_lint__\/motion-reset-[a-f0-9]{16}\.css$/);
    expect(addStyleTagCalls).toHaveLength(1);
    expect(addStyleTagCalls[0]).toMatchObject({ url: expect.stringMatching(/^\/__ui_lint__\/motion-reset-[a-f0-9]{16}\.css$/) });
    expect(addStyleTagCalls[0]).not.toHaveProperty('content');
});
