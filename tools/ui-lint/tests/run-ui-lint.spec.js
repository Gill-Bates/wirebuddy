//
// tools/ui-lint/tests/run-ui-lint.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import path from 'node:path';

import { expect, test } from '@playwright/test';

import {
    buildRunPaths,
    getAuthenticatedContextOptions,
    getLoginFailureContextOptions,
} from '../lib/runtime-config.mjs';

const fakeDevices = {
    'iPad Pro 11': {
        viewport: { width: 834, height: 1194 },
        userAgent: 'tablet-agent',
    },
    'iPhone 13': {
        viewport: { width: 390, height: 844 },
        userAgent: 'mobile-agent',
    },
};

test('buildRunPaths keeps screenshot and summary output inside the run directory', async () => {
    const scriptDir = '/opt/wirebuddy/tools/ui-lint';
    const paths = buildRunPaths({
        scriptDir,
        sessionId: 42,
        outputDir: '/tmp/wirebuddy-ui-lint-42',
        screenshotDir: 'screenshots/mobile',
    });

    expect(paths.outputDir).toBe('/tmp/wirebuddy-ui-lint-42');
    expect(paths.screenshotDir).toBe('/tmp/wirebuddy-ui-lint-42/screenshots/mobile');
    expect(paths.summaryPath).toBe('/tmp/wirebuddy-ui-lint-42/ui-lint-summary.json');
    expect(paths.latestSummaryPath).toBe(path.join(scriptDir, 'ui-lint-summary.latest.json'));
});

test('buildRunPaths rejects absolute screenshot directories', async () => {
    expect(() => buildRunPaths({
        scriptDir: '/opt/wirebuddy/tools/ui-lint',
        sessionId: 1,
        outputDir: '/tmp/wirebuddy-ui-lint-1',
        screenshotDir: '/var/tmp/elsewhere',
    })).toThrow('UI_LINT_SCREENSHOT_DIR must be a relative path');
});

test('buildRunPaths rejects screenshot traversal outside output directory', async () => {
    expect(() => buildRunPaths({
        scriptDir: '/opt/wirebuddy/tools/ui-lint',
        sessionId: 1,
        outputDir: '/tmp/wirebuddy-ui-lint-1',
        screenshotDir: '../escape',
    })).toThrow('UI_LINT_SCREENSHOT_DIR must stay inside UI_LINT_OUTPUT_DIR');
});

test('authenticated contexts inherit device options and storage state', async () => {
    const authState = { cookies: [{ name: 'session', value: 'abc' }], origins: [] };

    expect(getAuthenticatedContextOptions('desktop', fakeDevices, authState)).toEqual({
        viewport: { width: 1440, height: 1100 },
        storageState: authState,
    });

    expect(getAuthenticatedContextOptions('mobile', fakeDevices, authState)).toEqual({
        viewport: { width: 390, height: 844 },
        userAgent: 'mobile-agent',
        storageState: authState,
    });
});

test('login failure contexts stay unauthenticated', async () => {
    const options = getLoginFailureContextOptions('tablet', fakeDevices);

    expect(options).toEqual({
        viewport: { width: 834, height: 1194 },
        userAgent: 'tablet-agent',
    });
    expect(options).not.toHaveProperty('storageState');
});