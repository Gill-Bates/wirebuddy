//
// tools/ui-lint/lib/device-runtime/network/profiles.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const NETWORK_PROFILES = Object.freeze({
    online: Object.freeze({ name: 'online', latencyMs: 20, throughputMbps: 100 }),
    'slow-4g': Object.freeze({ name: 'slow-4g', latencyMs: 300, throughputMbps: 1.6 }),
    'fast-3g': Object.freeze({ name: 'fast-3g', latencyMs: 150, throughputMbps: 3.2 }),
});

export function getNetworkProfile(name) {
    return NETWORK_PROFILES[name] || NETWORK_PROFILES.online;
}