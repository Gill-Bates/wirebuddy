//
// tools/ui-lint/tests/config/device-runtime.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import {
    buildPlaywrightOptions,
    createDeviceMatrixRuntime,
    createDeviceRuntime,
    getDevice,
    matrixHash,
    resolveDeviceMatrix,
    resolveDeviceMatrixRuntime,
} from '../../lib/device-matrix.mjs';

test('device runtime captures browser, viewport, and safe-area state', () => {
    const runtime = createDeviceRuntime({
        descriptor: getDevice('iPhone 15').descriptor,
        browser: 'webkit',
        scenario: 'one-handed-mobile',
    });

    const snapshot = runtime.snapshot();

    expect(snapshot.browser).toBe('webkit');
    expect(snapshot.capabilities.touch).toBe(true);
    expect(snapshot.capabilities.safeAreaInsets).toBe(true);
    expect(snapshot.viewport.visual.height).toBeLessThan(snapshot.viewport.layout.height);
    expect(snapshot.dpr.devicePixelRatio).toBeGreaterThan(1);
    expect(runtime.rotate('landscape')).toBe('landscape');
    expect(runtime.snapshot().orientation).toBe('landscape');
});

test('matrix runtime resolves deterministically and hashes stably', () => {
    const matrixRuntime = createDeviceMatrixRuntime({
        entries: ['webkit@iPhone 15', { browser: 'firefox', device: 'Desktop Firefox', scenario: 'desktop-default' }],
    });

    const resolved = matrixRuntime.resolve();
    const firstHash = matrixRuntime.hash();
    const secondHash = matrixRuntime.hash();

    expect(resolved).toHaveLength(2);
    expect(matrixRuntime.query({ browser: 'webkit' })).toHaveLength(1);
    expect(firstHash).toBe(secondHash);
    expect(matrixHash(['webkit@iPhone 15', 'firefox@Desktop Firefox'])).toBe(matrixHash(['webkit@iPhone 15', 'firefox@Desktop Firefox']));
});

test('playwright adapter and environment resolution stay compatible', () => {
    const originalMatrix = process.env.UI_LINT_DEVICE_MATRIX;
    const originalExtended = process.env.UI_LINT_EXTENDED_MATRIX;

    try {
        process.env.UI_LINT_DEVICE_MATRIX = 'webkit@iPhone 15,firefox@Desktop Firefox';
        delete process.env.UI_LINT_EXTENDED_MATRIX;

        const resolvedMatrix = resolveDeviceMatrix();
        const runtime = resolveDeviceMatrixRuntime();
        const options = buildPlaywrightOptions('iPhone 15', { browser: 'webkit' });

        expect(resolvedMatrix).toHaveLength(2);
        expect(runtime.entries).toHaveLength(2);
        expect(options.viewport.width).toBe(393);
        expect(options.hasTouch).toBe(true);
        expect(options.isMobile).toBe(true);
    } finally {
        if (originalMatrix === undefined) {
            delete process.env.UI_LINT_DEVICE_MATRIX;
        } else {
            process.env.UI_LINT_DEVICE_MATRIX = originalMatrix;
        }
        if (originalExtended === undefined) {
            delete process.env.UI_LINT_EXTENDED_MATRIX;
        } else {
            process.env.UI_LINT_EXTENDED_MATRIX = originalExtended;
        }
    }
});
