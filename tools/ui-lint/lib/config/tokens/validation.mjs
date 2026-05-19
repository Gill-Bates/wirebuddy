//
// tools/ui-lint/lib/config/tokens/validation.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function validateTokenPath(tokenPath) {
    if (typeof tokenPath !== 'string' || !tokenPath.trim()) {
        throw new TypeError('tokenPath must be a non-empty string');
    }

    const path = tokenPath.trim();
    if (!/^([a-zA-Z_][a-zA-Z0-9_]*)(\.[a-zA-Z_][a-zA-Z0-9_]*)*$/.test(path)) {
        throw new TypeError(`Invalid token path: ${tokenPath}`);
    }

    return path;
}

export function validateAuditConfig(config) {
    if (config == null || typeof config !== 'object' || Array.isArray(config)) {
        throw new TypeError('config must be an object');
    }

    if (config.categories != null && !Array.isArray(config.categories)) {
        throw new TypeError('config.categories must be an array when provided');
    }

    if (config.categories?.some((category) => typeof category !== 'string' || !category.trim())) {
        throw new TypeError('config.categories must contain non-empty strings');
    }

    return true;
}

export function validateTokenResolution(resolution) {
    if (resolution == null || typeof resolution !== 'object') {
        throw new TypeError('resolution must be an object');
    }

    if (!('sourceToken' in resolution) || typeof resolution.sourceToken !== 'string') {
        throw new TypeError('resolution.sourceToken must be a string');
    }

    return true;
}