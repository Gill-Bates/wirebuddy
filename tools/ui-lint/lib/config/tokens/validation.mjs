//
// tools/ui-lint/lib/config/tokens/validation.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { isValidTokenCategory } from './schema.mjs';

const RESERVED_TOKEN_PATH_SEGMENTS = new Set(['__proto__', 'prototype', 'constructor']);

function assertObject(value, name) {
    if (value == null || typeof value !== 'object' || Array.isArray(value)) {
        throw new TypeError(`${name} must be an object`);
    }

    return value;
}

function assertNonEmptyString(value, field) {
    if (typeof value !== 'string' || !value.trim()) {
        throw new TypeError(`${field} must be a non-empty string`);
    }

    return value.trim();
}

function assertOptionalBoolean(value, field) {
    if (value != null && typeof value !== 'boolean') {
        throw new TypeError(`${field} must be a boolean when provided`);
    }

    return value;
}

function assertOptionalNonNegativeFiniteNumber(value, field) {
    if (value != null && (!Number.isFinite(value) || value < 0)) {
        throw new TypeError(`${field} must be a non-negative finite number when provided`);
    }

    return value;
}

function assertOptionalTokenCategory(value, field) {
    if (value != null && !isValidTokenCategory(value)) {
        throw new TypeError(`${field} must be a valid token category when provided`);
    }

    return value;
}

export function validateTokenPath(tokenPath) {
    const path = assertNonEmptyString(tokenPath, 'tokenPath');
    if (!/^([a-zA-Z_][a-zA-Z0-9_]*)(\.[a-zA-Z_][a-zA-Z0-9_]*)*$/.test(path)) {
        throw new TypeError(`Invalid token path: ${tokenPath}`);
    }

    for (const segment of path.split('.')) {
        if (RESERVED_TOKEN_PATH_SEGMENTS.has(segment)) {
            throw new TypeError(`Invalid token path segment: ${segment}`);
        }
    }

    return path;
}

export function validateAuditConfig(config) {
    assertObject(config, 'config');

    if (config.categories != null && !Array.isArray(config.categories)) {
        throw new TypeError('config.categories must be an array when provided');
    }

    for (const category of config.categories || []) {
        assertNonEmptyString(category, 'config.categories[]');
        assertOptionalTokenCategory(category, 'config.categories[]');
    }

    return true;
}

export function validateTokenResolution(resolution) {
    assertObject(resolution, 'resolution');

    if (!Object.hasOwn(resolution, 'sourceToken')) {
        throw new TypeError('resolution.sourceToken must be a string');
    }

    if (typeof resolution.sourceToken !== 'string') {
        throw new TypeError('resolution.sourceToken must be a string');
    }

    validateTokenPath(resolution.sourceToken);

    assertOptionalTokenCategory(resolution.category, 'resolution.category');
    assertOptionalBoolean(resolution.fallbackUsed, 'resolution.fallbackUsed');
    assertOptionalBoolean(resolution.exists, 'resolution.exists');
    assertOptionalNonNegativeFiniteNumber(resolution.version, 'resolution.version');

    return true;
}