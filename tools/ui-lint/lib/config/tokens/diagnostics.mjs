//
// tools/ui-lint/lib/config/tokens/diagnostics.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { validateTokenResolution } from './validation.mjs';

function normalizeFallbackUsed(value) {
    if (value == null) {
        return false;
    }
    if (typeof value !== 'boolean') {
        throw new TypeError('resolution.fallbackUsed must be a boolean when provided');
    }
    return value;
}

function normalizeVersion(value) {
    if (value == null) {
        return 1;
    }
    if (!Number.isFinite(value) || value < 0) {
        throw new TypeError('resolution.version must be a non-negative finite number when provided');
    }
    return value;
}

function normalizeCategory(value) {
    if (value == null) {
        return 'general';
    }
    if (typeof value !== 'string' || !value.trim()) {
        throw new TypeError('resolution.category must be a non-empty string when provided');
    }
    return value;
}

export function createTokenDiagnostics(resolution) {
    validateTokenResolution(resolution);

    return Object.freeze({
        sourceToken: resolution.sourceToken,
        fallbackUsed: normalizeFallbackUsed(resolution.fallbackUsed),
        version: normalizeVersion(resolution.version),
        category: normalizeCategory(resolution.category),
        rawValue: resolution.rawValue,
        resolvedValue: resolution.value,
    });
}