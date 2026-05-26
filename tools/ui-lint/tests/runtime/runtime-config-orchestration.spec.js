//
// tools/ui-lint/tests/runtime/runtime-config-orchestration.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import {
    RUNTIME_VERSION,
    buildRunPaths,
    createRuntimeContext,
    getAuthenticatedContextOptions,
    getLoginFailureContextOptions,
    resolveRuntimeProfile,
    whyWasThisProfileChosen,
} from '../../lib/runtime-config.mjs';

const availableDevices = {
    'iPad Pro 11': {
        viewport: { width: 834, height: 1194 },
        userAgent: 'tablet-agent',
    },
    'iPhone 13': {
        viewport: { width: 390, height: 844 },
        userAgent: 'mobile-agent',
    },
};

test('runtime profiles are resolved with environment and capability metadata', async () => {
    const profile = resolveRuntimeProfile({
        device: 'mobile',
        environment: 'ci',
        mode: 'regression',
        availableDevices,
        options: { seed: 'seed-123' },
    });

    expect(profile.runtimeVersion).toBe(RUNTIME_VERSION);
    expect(profile.deviceClass).toBe('mobile');
    expect(profile.device).toBe('iPhone 13');
    expect(profile.capabilitySet).toEqual(expect.arrayContaining(['touch', 'ios', 'safari', 'lowBandwidth']));
    expect(profile.executionPolicy).toMatchObject({ maxParallelPages: 2, retryFlakyRules: true, timeoutMultiplier: 1.75 });
    expect(profile.environmentPolicy).toMatchObject({ environment: 'ci', profileDepth: 'full' });
    expect(profile.artifactNamespace).toContain('mobile/ci/regression');

    const explanation = whyWasThisProfileChosen(profile);
    expect(explanation).toMatchObject({
        runtimeId: profile.runtimeId,
        sandboxId: profile.sandboxId,
        reason: expect.stringContaining('mobile'),
    });
});

test('runtime context composes isolation, telemetry and scheduling metadata', async () => {
    const context = createRuntimeContext({
        scriptDir: '/opt/wirebuddy/tools/ui-lint',
        sessionId: 99,
        outputDir: '/tmp/wirebuddy-ui-lint-99',
        screenshotDir: 'screenshots/mobile',
        device: 'tablet',
        environment: 'nightly',
        mode: 'full',
        availableDevices,
        options: { seed: 'seed-456', startupTimeMs: 12, contextCreationTimeMs: 34, screenshotTimeMs: 56 },
        storageState: { cookies: [], origins: [] },
    });

    expect(context.runtimeVersion).toBe(RUNTIME_VERSION);
    expect(context.runtimeProfile.family).toBe('tablet');
    expect(context.artifactPolicy).toMatchObject({ retentionDays: 14, compressScreenshots: true, archiveOnFailure: true });
    expect(context.isolation).toMatchObject({ storage: 'ephemeral', cookies: 'sandboxed' });
    expect(context.auth.strategy).toBe('storageState');
    expect(context.auth.storageState).toEqual({ cookies: [], origins: [] });
    expect(context.runtimeScheduler.parallelizationStrategy).toBe('adaptive');
    expect(context.health).toMatchObject({ playwrightReady: true, screenshotWritable: true, browserHealthy: true });
    expect(context.telemetry).toMatchObject({ startupTimeMs: 12, contextCreationTimeMs: 34, screenshotTimeMs: 56 });
    expect(context.runPaths.runtimeId).toBe(context.runtimeId);
    expect(context.runPaths.artifactMetadata.profile).toBe('tablet');
    expect(context.cleanup({ removeTmpDirs: false, preserveFailures: true })).toMatchObject({ removedTmpDirs: false, preservedFailures: true });
});

test('legacy context helpers remain stable while using runtime profiles', async () => {
    const authState = { cookies: [{ name: 'session', value: 'abc' }], origins: [] };

    expect(getAuthenticatedContextOptions('desktop', availableDevices, authState)).toEqual({
        viewport: { width: 1440, height: 1100 },
        storageState: authState,
    });

    expect(getAuthenticatedContextOptions('mobile', availableDevices, authState)).toEqual({
        viewport: { width: 390, height: 844 },
        userAgent: 'mobile-agent',
        storageState: authState,
    });

    expect(getLoginFailureContextOptions('tablet', availableDevices)).toEqual({
        viewport: { width: 834, height: 1194 },
        userAgent: 'tablet-agent',
    });

    const runPaths = buildRunPaths({
        scriptDir: '/opt/wirebuddy/tools/ui-lint',
        sessionId: 7,
        outputDir: '/tmp/wirebuddy-ui-lint-7',
        screenshotDir: 'shots',
    });

    expect(runPaths.runtimeVersion).toBe(RUNTIME_VERSION);
    expect(runPaths.runtimeId).toMatch(/^rt-/);
    expect(runPaths.sandboxId).toMatch(/^sb-/);
    expect(runPaths.artifactMetadata).toMatchObject({ runtimeId: runPaths.runtimeId, profile: 'desktop' });
});