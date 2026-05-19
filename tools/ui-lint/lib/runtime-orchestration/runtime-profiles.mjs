//
// tools/ui-lint/lib/runtime-orchestration/runtime-profiles.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const RUNTIME_VERSION = '2026.05';

export const RUNTIME_PROFILES = Object.freeze({
    desktop: {
        name: 'desktop',
        family: 'desktop',
        device: null,
        browser: 'chromium',
        engine: 'chromium',
        capabilities: ['hover', 'retina', 'wideViewport'],
        networkProfile: 'fast4g',
        emulation: {
            reducedMotion: false,
            locale: 'en-US',
            timezone: 'UTC',
            forcedColors: 'none',
            colorScheme: 'light',
        },
        viewport: { width: 1440, height: 1100 },
        executionMode: 'full',
        executionPolicy: {
            maxParallelPages: 4,
            retryFlakyRules: true,
            timeoutMultiplier: 1.25,
        },
        browserPolicies: {
            chromium: { overflowTolerance: 2 },
            webkit: { overflowTolerance: 4 },
            firefox: { overflowTolerance: 2 },
        },
        artifactPolicy: {
            retentionDays: 14,
            compressScreenshots: true,
            archiveOnFailure: true,
            removeTmpDirs: true,
            preserveFailures: true,
        },
        isolation: {
            storage: 'ephemeral',
            cookies: 'sandboxed',
            localStorage: 'sandboxed',
        },
        auth: {
            strategy: 'storageState',
            refreshOn401: true,
        },
        limits: {
            maxScreenshots: 12,
            maxMemoryMb: 768,
            maxPageEvaluations: 150,
        },
        features: ['advanced-motion-control', 'dom-stability-observer'],
        deviceFamily: 'desktop',
    },
    tablet: {
        name: 'tablet',
        family: 'tablet',
        device: 'iPad Pro 11',
        browser: 'webkit',
        engine: 'webkit',
        capabilities: ['touch', 'hover', 'retina', 'ios', 'safari'],
        networkProfile: 'fast4g',
        emulation: {
            reducedMotion: true,
            locale: 'de-DE',
            timezone: 'Europe/Berlin',
            forcedColors: 'none',
            colorScheme: 'light',
        },
        viewport: { width: 834, height: 1194 },
        executionMode: 'regression',
        executionPolicy: {
            maxParallelPages: 3,
            retryFlakyRules: true,
            timeoutMultiplier: 1.5,
        },
        browserPolicies: {
            webkit: { overflowTolerance: 4 },
        },
        artifactPolicy: {
            retentionDays: 14,
            compressScreenshots: true,
            archiveOnFailure: true,
            removeTmpDirs: true,
            preserveFailures: true,
        },
        isolation: {
            storage: 'ephemeral',
            cookies: 'sandboxed',
            localStorage: 'sandboxed',
        },
        auth: {
            strategy: 'storageState',
            refreshOn401: true,
        },
        limits: {
            maxScreenshots: 10,
            maxMemoryMb: 640,
            maxPageEvaluations: 120,
        },
        features: ['advanced-motion-control', 'dom-stability-observer'],
        deviceFamily: 'tablet',
    },
    mobile: {
        name: 'mobile',
        family: 'mobile',
        device: 'iPhone 13',
        browser: 'webkit',
        engine: 'webkit',
        capabilities: ['touch', 'retina', 'ios', 'safari', 'lowBandwidth'],
        networkProfile: 'slow3g',
        emulation: {
            reducedMotion: true,
            locale: 'de-DE',
            timezone: 'Europe/Berlin',
            forcedColors: 'none',
            colorScheme: 'dark',
        },
        viewport: { width: 390, height: 844 },
        executionMode: 'accessibility',
        executionPolicy: {
            maxParallelPages: 2,
            retryFlakyRules: true,
            timeoutMultiplier: 1.75,
        },
        browserPolicies: {
            webkit: { overflowTolerance: 4 },
        },
        artifactPolicy: {
            retentionDays: 21,
            compressScreenshots: true,
            archiveOnFailure: true,
            removeTmpDirs: true,
            preserveFailures: true,
        },
        isolation: {
            storage: 'ephemeral',
            cookies: 'sandboxed',
            localStorage: 'sandboxed',
        },
        auth: {
            strategy: 'storageState',
            refreshOn401: true,
        },
        limits: {
            maxScreenshots: 8,
            maxMemoryMb: 512,
            maxPageEvaluations: 100,
        },
        features: ['advanced-motion-control', 'dom-stability-observer', 'touch-heuristics'],
        deviceFamily: 'mobile',
    },
    'large-desktop': {
        name: 'large-desktop',
        family: 'desktop',
        device: null,
        browser: 'chromium',
        engine: 'chromium',
        capabilities: ['hover', 'retina', 'wideViewport', 'highDpi'],
        networkProfile: 'fast4g',
        emulation: {
            reducedMotion: false,
            locale: 'en-US',
            timezone: 'UTC',
            forcedColors: 'none',
            colorScheme: 'light',
        },
        viewport: { width: 1600, height: 1100 },
        executionMode: 'full',
        executionPolicy: {
            maxParallelPages: 4,
            retryFlakyRules: true,
            timeoutMultiplier: 1.2,
        },
        browserPolicies: {
            chromium: { overflowTolerance: 2 },
            webkit: { overflowTolerance: 4 },
            firefox: { overflowTolerance: 2 },
        },
        artifactPolicy: {
            retentionDays: 14,
            compressScreenshots: true,
            archiveOnFailure: true,
            removeTmpDirs: true,
            preserveFailures: true,
        },
        isolation: {
            storage: 'ephemeral',
            cookies: 'sandboxed',
            localStorage: 'sandboxed',
        },
        auth: {
            strategy: 'storageState',
            refreshOn401: true,
        },
        limits: {
            maxScreenshots: 16,
            maxMemoryMb: 1024,
            maxPageEvaluations: 180,
        },
        features: ['advanced-motion-control', 'dom-stability-observer'],
        deviceFamily: 'desktop',
    },
});

export function listRuntimeProfiles() {
    return Object.values(RUNTIME_PROFILES);
}
