//
// tools/ui-lint/lib/device-matrix.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Device orchestration runtime for responsive and multi-engine audits.

import { devices as playwrightDevices } from 'playwright';

import {
    BROWSER_PROFILES,
    CUSTOM_VIEWPORTS,
    DEFAULT_MATRIX,
    DEVICE_CATALOG,
    DEVICE_CATEGORIES,
    EXTENDED_MATRIX,
    NETWORK_PROFILES,
    SCENARIOS,
    buildMatrixHash,
    buildSerializableRuntime,
    createDeviceRuntime,
    createMatrixRuntime,
    getBrowserProfile,
    getNetworkProfile,
    getScenario,
    toPlaywrightOptions,
} from './device-runtime/index.mjs';

export const DEVICE_RUNTIME_VERSION = 1;

function inferBrowserFromName(name) {
    if (/firefox/i.test(name)) return 'firefox';
    if (/safari|iphone|ipad/i.test(name)) return 'webkit';
    return 'chromium';
}

function inferPlatformFromName(name) {
    if (/iphone|ipad/i.test(name)) return 'ios';
    if (/pixel|galaxy/i.test(name)) return 'android';
    return 'desktop';
}

function inferScenarioFromName(name) {
    if (/fold/i.test(name)) return 'foldable-open';
    if (/iphone se/i.test(name)) return 'low-end-mobile';
    if (/iphone/i.test(name)) return 'one-handed-mobile';
    if (/pixel/i.test(name)) return 'low-end-android';
    if (/ipad/i.test(name)) return /mini/i.test(name) ? 'portrait-tablet' : 'landscape-tablet';
    return 'desktop-default';
}

function normalizeMatrixEntry(entry) {
    if (typeof entry === 'string') {
        const trimmed = entry.trim();
        if (!trimmed) return null;
        const atIndex = trimmed.lastIndexOf('@');
        const pipeIndex = trimmed.lastIndexOf('|');
        const separatorIndex = Math.max(atIndex, pipeIndex);

        if (separatorIndex > 0) {
            const left = trimmed.slice(0, separatorIndex).trim();
            const right = trimmed.slice(separatorIndex + 1).trim();
            const browserNames = new Set(['chromium', 'webkit', 'firefox']);
            if (browserNames.has(left)) {
                return { browser: left, device: right, scenario: inferScenarioFromName(right), platform: inferPlatformFromName(right) };
            }
            if (browserNames.has(right)) {
                return { browser: right, device: left, scenario: inferScenarioFromName(left), platform: inferPlatformFromName(left) };
            }
        }

        return {
            browser: inferBrowserFromName(trimmed),
            device: trimmed,
            scenario: inferScenarioFromName(trimmed),
            platform: inferPlatformFromName(trimmed),
        };
    }

    return {
        browser: entry.browser || inferBrowserFromName(entry.device || ''),
        device: entry.device,
        scenario: entry.scenario || inferScenarioFromName(entry.device || ''),
        platform: entry.platform || inferPlatformFromName(entry.device || ''),
    };
}

function getCatalogDescriptor(name) {
    if (CUSTOM_VIEWPORTS[name]) {
        return {
            name,
            ...CUSTOM_VIEWPORTS[name],
            browser: CUSTOM_VIEWPORTS[name].browser || 'chromium',
            platform: CUSTOM_VIEWPORTS[name].platform || 'desktop',
            scenario: 'custom-viewport',
        };
    }

    const catalogDescriptor = DEVICE_CATALOG[name] || null;
    const presetDescriptor = playwrightDevices[name] || null;

    if (!catalogDescriptor && !presetDescriptor) {
        return null;
    }

    return {
        name,
        ...(catalogDescriptor || {}),
        ...(presetDescriptor || {}),
        browser: (catalogDescriptor || {}).browser || inferBrowserFromName(name),
        platform: (catalogDescriptor || {}).platform || inferPlatformFromName(name),
        scenario: (catalogDescriptor || {}).scenario || inferScenarioFromName(name),
    };
}

export function createDeviceMatrixRuntime({ entries = DEFAULT_MATRIX } = {}) {
    const matrixRuntime = createMatrixRuntime({ entries: entries.map(normalizeMatrixEntry).filter(Boolean) });

    return {
        ...matrixRuntime,
        resolve() {
            return matrixRuntime.entries.map((entry) => {
                const descriptor = getCatalogDescriptor(entry.device);
                if (!descriptor) return null;
                return createDeviceRuntime({
                    descriptor,
                    browser: entry.browser,
                    platform: entry.platform,
                    scenario: entry.scenario,
                });
            }).filter(Boolean);
        },
    };
}

export function getDevice(name, options = {}) {
    const descriptor = getCatalogDescriptor(name);
    if (!descriptor) {
        console.warn(`Unknown device: ${name}`);
        return null;
    }

    return createDeviceRuntime({
        descriptor,
        browser: options.browser || descriptor.browser || inferBrowserFromName(name),
        platform: options.platform || descriptor.platform || inferPlatformFromName(name),
        scenario: options.scenario || descriptor.scenario || inferScenarioFromName(name),
        capabilities: options.capabilities || {},
    });
}

export function getDevices(matrix) {
    return (matrix || []).map((entry) => {
        const normalized = normalizeMatrixEntry(entry);
        if (!normalized) return null;

        const descriptor = getCatalogDescriptor(normalized.device);
        if (!descriptor) return null;

        const capabilities = entry && typeof entry === 'object' ? entry.capabilities || {} : {};

        return createDeviceRuntime({
            descriptor,
            browser: normalized.browser || descriptor.browser,
            platform: normalized.platform || descriptor.platform,
            scenario: normalized.scenario || descriptor.scenario,
            capabilities,
        });
    }).filter(Boolean);
}

export function getDevicesByCategory(category) {
    const names = DEVICE_CATEGORIES[category] || [];
    return getDevices(names);
}

export function resolveDeviceMatrix() {
    const envMatrix = process.env.UI_LINT_DEVICE_MATRIX;

    if (envMatrix) {
        return getDevices(envMatrix.split(',').map((entry) => entry.trim()).filter(Boolean));
    }

    if (process.env.UI_LINT_EXTENDED_MATRIX === 'true') {
        return getDevices(EXTENDED_MATRIX);
    }

    return getDevices(DEFAULT_MATRIX);
}

export function resolveDeviceMatrixRuntime() {
    const entries = process.env.UI_LINT_DEVICE_MATRIX
        ? process.env.UI_LINT_DEVICE_MATRIX.split(',').map((entry) => entry.trim()).filter(Boolean)
        : (process.env.UI_LINT_EXTENDED_MATRIX === 'true' ? EXTENDED_MATRIX : DEFAULT_MATRIX);

    return createDeviceMatrixRuntime({ entries });
}

export function getBreakpointViewports() {
    return [
        getDevice('Desktop 576')?.snapshot?.() || { name: 'Desktop 576', viewport: { width: 576, height: 900 }, isMobile: false },
        getDevice('Desktop 768')?.snapshot?.() || { name: 'Desktop 768', viewport: { width: 768, height: 1024 }, isMobile: false },
        getDevice('Desktop 1080p')?.snapshot?.() || { name: 'Desktop 1080p', viewport: { width: 1920, height: 1080 }, isMobile: false },
        { name: 'base (320px)', viewport: { width: 320, height: 568 }, isMobile: true },
        { name: 'sm (576px)', viewport: { width: 576, height: 900 }, isMobile: false },
        { name: 'md (768px)', viewport: { width: 768, height: 1024 }, isMobile: false },
        { name: 'lg (992px)', viewport: { width: 992, height: 768 }, isMobile: false },
        { name: 'xl (1200px)', viewport: { width: 1200, height: 900 }, isMobile: false },
        { name: 'xxl (1400px)', viewport: { width: 1400, height: 900 }, isMobile: false },
    ];
}

export function isMobileDevice(device) {
    return Boolean(device?.snapshot ? device.snapshot().capabilities?.touch : device?.isMobile || device?.touch);
}

export function isIOSDevice(device) {
    const snapshot = device?.snapshot ? device.snapshot() : device;
    return Boolean(
        snapshot?.platform === 'ios' ||
        snapshot?.name?.includes('iPhone') ||
        snapshot?.name?.includes('iPad') ||
        snapshot?.userAgent?.includes('iPhone') ||
        snapshot?.userAgent?.includes('iPad')
    );
}

export function isTablet(device) {
    const snapshot = device?.snapshot ? device.snapshot() : device;
    return Boolean(
        (snapshot?.platform === 'ios' && snapshot?.capabilities?.touch && snapshot?.viewport?.layout?.width >= 744) ||
        snapshot?.name?.includes('iPad') ||
        snapshot?.name?.includes('Galaxy Tab') ||
        (snapshot?.viewport?.layout?.width >= 768 && snapshot?.isMobile)
    );
}

export function matrixHash(entries = DEFAULT_MATRIX) {
    return buildMatrixHash(createDeviceMatrixRuntime({ entries }));
}

export function buildPlaywrightOptions(name, options = {}) {
    const device = getDevice(name, options);
    return device ? toPlaywrightOptions(device) : null;
}

export {
    BROWSER_PROFILES,
    CUSTOM_VIEWPORTS,
    DEFAULT_MATRIX,
    DEVICE_CATALOG,
    DEVICE_CATEGORIES,
    EXTENDED_MATRIX,
    NETWORK_PROFILES,
    SCENARIOS,
    buildMatrixHash,
    buildSerializableRuntime,
    createDeviceRuntime,
    createMatrixRuntime,
    getBrowserProfile,
    getNetworkProfile,
    getScenario,
    toPlaywrightOptions,
};
