//
// tools/ui-lint/lib/config/tokens/resolver.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { tokens } from '../../design-tokens.mjs';

export const TOKEN_SCHEMA_VERSION = 1;

function normalizeTokenPath(tokenPath) {
    if (typeof tokenPath !== 'string' || !tokenPath.trim()) {
        throw new TypeError('tokenPath must be a non-empty string');
    }

    return tokenPath.trim().split('.').filter(Boolean);
}

function readToken(tokenPath) {
    const parts = normalizeTokenPath(tokenPath);
    let cursor = tokens;

    for (const part of parts) {
        if (cursor == null || typeof cursor !== 'object' || !(part in cursor)) {
            return undefined;
        }
        cursor = cursor[part];
    }

    return cursor;
}

/**
 * Resolve a token path and capture fallback metadata.
 *
 * @param {string} tokenPath
 * @param {{ fallback?: unknown, required?: boolean, category?: string, version?: number }} [options]
 * @returns {{ value: unknown, sourceToken: string, fallbackUsed: boolean, category: string, version: number, exists: boolean, rawValue: unknown }}
 */
export function resolveToken(tokenPath, options = {}) {
    const {
        fallback,
        required = false,
        category = 'general',
        version = TOKEN_SCHEMA_VERSION,
    } = options;

    const rawValue = readToken(tokenPath);
    const exists = rawValue !== undefined && rawValue !== null && rawValue !== '';

    if (!exists && required) {
        throw new Error(`Missing required design token: ${tokenPath}`);
    }

    return {
        value: exists ? rawValue : fallback,
        sourceToken: tokenPath,
        fallbackUsed: !exists,
        category,
        version,
        exists,
        rawValue,
    };
}

export function resolveRequiredToken(tokenPath, options = {}) {
    return resolveToken(tokenPath, { ...options, required: true }).value;
}

export function resolveOptionalToken(tokenPath, fallback, options = {}) {
    return resolveToken(tokenPath, { ...options, fallback }).value;
}

export function hasToken(tokenPath) {
    return resolveToken(tokenPath, { required: false }).exists;
}