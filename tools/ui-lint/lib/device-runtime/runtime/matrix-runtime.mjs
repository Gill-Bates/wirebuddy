//
// tools/ui-lint/lib/device-runtime/runtime/matrix-runtime.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import crypto from 'node:crypto';

import { createDeviceRuntime } from './device-runtime.mjs';

function normalizeEntry(entry) {
    if (typeof entry === 'string') {
        return { browser: 'chromium', device: entry, scenario: 'desktop-default' };
    }
    return {
        browser: entry.browser || 'chromium',
        device: entry.device,
        scenario: entry.scenario || 'desktop-default',
        platform: entry.platform,
    };
}

function stableStringify(value) {
    if (Array.isArray(value)) {
        return `[${value.map((entry) => stableStringify(entry)).join(',')}]`;
    }
    if (value && typeof value === 'object') {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
    }
    return JSON.stringify(value);
}

export function createMatrixRuntime({ entries = [] } = {}) {
    const normalizedEntries = entries.map(normalizeEntry);

    return {
        entries: normalizedEntries,
        resolve(descriptors) {
            return normalizedEntries.map((entry) => {
                const descriptor = descriptors[entry.device];
                if (!descriptor) return null;
                return createDeviceRuntime({
                    descriptor,
                    browser: entry.browser,
                    platform: entry.platform || descriptor.platform,
                    scenario: entry.scenario,
                });
            }).filter(Boolean);
        },
        hash() {
            const digest = crypto.createHash('sha256');
            digest.update(stableStringify(normalizedEntries));
            return digest.digest('hex');
        },
        query(criteria = {}) {
            return normalizedEntries.filter((entry) => Object.entries(criteria).every(([key, expected]) => entry[key] === expected));
        },
    };
}