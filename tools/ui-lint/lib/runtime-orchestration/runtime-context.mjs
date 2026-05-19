//
// tools/ui-lint/lib/runtime-orchestration/runtime-context.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import crypto from 'node:crypto';
import path from 'node:path';

import { createRuntimeScheduler } from './runtime-scheduler.mjs';
import { createRuntimeStateStore } from './runtime-state-store.mjs';
import { buildEnvironmentPolicy, validateRuntimePolicy } from './runtime-policies.mjs';
import { createRuntimeTelemetry, buildRuntimeAnalytics } from './runtime-telemetry.mjs';
import { listRuntimeProfiles, RUNTIME_PROFILES, RUNTIME_VERSION } from './runtime-profiles.mjs';

function hashInput(input) {
    return crypto.createHash('sha256').update(JSON.stringify(input)).digest('hex').slice(0, 16);
}

function normalizeDevice(device) {
    if (!device || device === 'desktop') return 'desktop';
    if (device === 'tablet' || device === 'mobile' || device === 'large-desktop') return device;
    return 'desktop';
}

function resolveBaseContextOptions(profile, availableDevices = {}) {
    if (profile.device && availableDevices[profile.device]) {
        return { ...availableDevices[profile.device] };
    }

    return {
        viewport: { ...profile.viewport },
        ...(profile.device ? { userAgent: `${profile.family}-agent` } : {}),
    };
}

export function resolveRuntimeProfile({ device, browser = null, environment = 'local', mode = 'full', availableDevices = {}, options = {} } = {}) {
    const resolvedDevice = normalizeDevice(device);
    const profile = RUNTIME_PROFILES[resolvedDevice] || RUNTIME_PROFILES.desktop;
    const executionPolicy = validateRuntimePolicy(profile.executionPolicy || {});
    const environmentPolicy = buildEnvironmentPolicy(environment);
    const runtimeSeed = options.seed || hashInput({ device: resolvedDevice, browser, environment, mode, family: profile.family });

    return {
        ...profile,
        device: profile.device,
        deviceClass: resolvedDevice,
        browser: browser || profile.browser,
        environment,
        mode,
        runtimeVersion: RUNTIME_VERSION,
        runtimeSeed,
        runtimeId: `rt-${runtimeSeed}`,
        sandboxId: `sb-${hashInput({ runtimeSeed, environment, mode })}`,
        artifactNamespace: `${profile.family}/${environment}/${mode}/${runtimeSeed}`,
        executionPolicy,
        environmentPolicy,
        runtimePolicies: {
            environment: environmentPolicy,
            execution: executionPolicy,
        },
        baseContextOptions: resolveBaseContextOptions(profile, availableDevices),
        capabilitySet: [...profile.capabilities],
        browserPolicies: profile.browserPolicies || {},
        artifactPolicy: profile.artifactPolicy || {},
        isolation: profile.isolation || {},
        auth: profile.auth || {},
        limits: profile.limits || {},
        features: [...(profile.features || [])],
        emulation: { ...profile.emulation },
        networkProfile: profile.networkProfile,
        why: `Selected ${profile.name} runtime profile for ${resolvedDevice} in ${environment} mode`,
    };
}

export function whyWasThisProfileChosen(runtimeProfile) {
    return {
        runtimeId: runtimeProfile.runtimeId,
        sandboxId: runtimeProfile.sandboxId,
        reason: runtimeProfile.why,
        capabilities: runtimeProfile.capabilitySet,
        browserPolicies: runtimeProfile.browserPolicies,
        executionPolicy: runtimeProfile.executionPolicy,
        environmentPolicy: runtimeProfile.environmentPolicy,
    };
}

export function buildRunPaths({ scriptDir, sessionId, outputDir, screenshotDir = 'screenshots', runtimeProfile = null } = {}) {
    const resolvedOutputDir = path.resolve(outputDir || `/tmp/wirebuddy-ui-lint-${sessionId}`);

    if (path.isAbsolute(screenshotDir)) {
        throw new Error('UI_LINT_SCREENSHOT_DIR must be a relative path');
    }

    const resolvedScreenshotDir = path.resolve(resolvedOutputDir, screenshotDir);
    const relativeScreenshotDir = path.relative(resolvedOutputDir, resolvedScreenshotDir);
    if (relativeScreenshotDir.startsWith('..') || path.isAbsolute(relativeScreenshotDir)) {
        throw new Error('UI_LINT_SCREENSHOT_DIR must stay inside UI_LINT_OUTPUT_DIR');
    }

    const profile = runtimeProfile || RUNTIME_PROFILES.desktop;
    const namespace = `${profile.family}/${sessionId || 'session'}`;

    return {
        outputDir: resolvedOutputDir,
        screenshotDir: resolvedScreenshotDir,
        summaryPath: path.join(resolvedOutputDir, 'ui-lint-summary.json'),
        latestSummaryPath: path.join(scriptDir, 'ui-lint-summary.latest.json'),
        runtimeId: `rt-${hashInput({ scriptDir, sessionId, outputDir: resolvedOutputDir, namespace })}`,
        sandboxId: `sb-${hashInput({ scriptDir, sessionId, namespace, outputDir: resolvedOutputDir })}`,
        artifactNamespace: namespace,
        runtimeVersion: RUNTIME_VERSION,
        artifactMetadata: {
            createdAt: new Date().toISOString(),
            runtimeId: `rt-${hashInput({ scriptDir, sessionId, outputDir: resolvedOutputDir, namespace })}`,
            profile: profile.name,
        },
    };
}

export function createRuntimeContext({
    scriptDir,
    sessionId,
    outputDir,
    screenshotDir = 'screenshots',
    device = 'desktop',
    browser = null,
    environment = 'local',
    mode = 'full',
    availableDevices = {},
    options = {},
    storageState = null,
} = {}) {
    const telemetry = createRuntimeTelemetry();
    const runtimeProfile = resolveRuntimeProfile({ device, browser, environment, mode, availableDevices, options });
    const runPaths = buildRunPaths({ scriptDir, sessionId, outputDir, screenshotDir, runtimeProfile });
    const runtimeStateStore = createRuntimeStateStore();
    const runtimeScheduler = createRuntimeScheduler(runtimeProfile);
    const sessionManager = {
        register: (nextSessionId) => runtimeStateStore.create(nextSessionId, runtimeContext),
        get: (nextSessionId) => runtimeStateStore.get(nextSessionId),
        close: (nextSessionId, status) => runtimeStateStore.close(nextSessionId, status),
        snapshot: () => runtimeStateStore.snapshot(),
    };

    const runtimeContext = {
        scriptDir,
        sessionId,
        outputDir: runPaths.outputDir,
        screenshotDir: runPaths.screenshotDir,
        runtimeId: runPaths.runtimeId,
        sandboxId: runPaths.sandboxId,
        runtimeVersion: RUNTIME_VERSION,
        runtimeProfile,
        runPaths,
        artifactNamespace: runPaths.artifactNamespace,
        artifactPolicy: runtimeProfile.artifactPolicy,
        artifactMetadata: runPaths.artifactMetadata,
        environment,
        environmentPolicy: runtimeProfile.environmentPolicy,
        executionPolicy: runtimeProfile.executionPolicy,
        browserPolicies: runtimeProfile.browserPolicies,
        isolation: runtimeProfile.isolation,
        auth: {
            ...runtimeProfile.auth,
            storageState,
        },
        emulation: runtimeProfile.emulation,
        capabilities: runtimeProfile.capabilitySet,
        features: runtimeProfile.features,
        limits: runtimeProfile.limits,
        networkProfile: runtimeProfile.networkProfile,
        deviceFamily: runtimeProfile.deviceFamily,
        family: runtimeProfile.family,
        browser: browser || runtimeProfile.browser,
        mode,
        seed: runtimeProfile.runtimeSeed,
        telemetry,
        runtimeAnalytics: buildRuntimeAnalytics(telemetry, { runtimeId: runPaths.runtimeId, sandboxId: runPaths.sandboxId }),
        runtimeScheduler,
        sessionManager,
        health: {
            playwrightReady: true,
            screenshotWritable: true,
            browserHealthy: true,
        },
        why: whyWasThisProfileChosen(runtimeProfile),
        policies: {
            environment: runtimeProfile.environmentPolicy,
            execution: runtimeProfile.executionPolicy,
            artifact: runtimeProfile.artifactPolicy,
            browser: runtimeProfile.browserPolicies,
            isolation: runtimeProfile.isolation,
        },
        composeRuntime(overrides = {}) {
            return createRuntimeContext({
                scriptDir,
                sessionId,
                outputDir,
                screenshotDir,
                device: overrides.device || device,
                browser: overrides.browser || browser,
                environment: overrides.environment || environment,
                mode: overrides.mode || mode,
                availableDevices,
                options: { ...options, ...overrides.options },
                storageState: overrides.storageState ?? storageState,
            });
        },
        beforeRuntime() {
            telemetry.runtimeAnalyticEvents += 1;
            return runtimeContext;
        },
        afterRuntime(result = {}) {
            telemetry.runtimeAnalyticEvents += 1;
            return {
                ...runtimeContext,
                result,
            };
        },
        cleanup({ removeTmpDirs = true, preserveFailures = true } = {}) {
            telemetry.runtimeAnalyticEvents += 1;
            return {
                removedTmpDirs: Boolean(removeTmpDirs),
                preservedFailures: Boolean(preserveFailures),
                artifactNamespace: runtimeContext.artifactNamespace,
            };
        },
    };

    telemetry.startupTimeMs = options.startupTimeMs || 0;
    telemetry.contextCreationTimeMs = options.contextCreationTimeMs || 0;
    telemetry.screenshotTimeMs = options.screenshotTimeMs || 0;

    return runtimeContext;
}

export function getBaseContextOptions(device, availableDevices, options = {}) {
    return resolveRuntimeProfile({ device, availableDevices, options }).baseContextOptions;
}

export function getAuthenticatedContextOptions(device, availableDevices, storageState, options = {}) {
    return {
        ...getBaseContextOptions(device, availableDevices, options),
        storageState,
    };
}

export function getLoginFailureContextOptions(device, availableDevices, options = {}) {
    return getBaseContextOptions(device, availableDevices, options);
}

export { RUNTIME_VERSION, RUNTIME_PROFILES, listRuntimeProfiles };
