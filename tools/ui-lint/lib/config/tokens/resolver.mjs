//
// tools/ui-lint/lib/config/tokens/resolver.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { tokens } from '../../design-tokens.mjs';
import { TOKEN_SCHEMA_VERSION } from './schema.mjs';
import { validateTokenPath } from './validation.mjs';

function normalizeTokenPath(tokenPath) {
    return validateTokenPath(tokenPath).split('.');
}

function readToken(tokenPath) {
    const parts = normalizeTokenPath(tokenPath);
    let cursor = tokens;

    for (const part of parts) {
        if (cursor == null || typeof cursor !== 'object' || !Object.hasOwn(cursor, part)) {
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
    const exists = rawValue !== undefined;

    if (!exists && required) {
        throw new Error(`Missing required design token: ${tokenPath}`);
    }

    return Object.freeze({
        value: exists ? rawValue : fallback,
        sourceToken: tokenPath,
        fallbackUsed: !exists && fallback !== undefined,
        category,
        version,
        exists,
        rawValue,
    });
}

export function resolveRequiredToken(tokenPath, options = {}) {
    return resolveToken(tokenPath, { ...options, required: true }).value;
}

export function resolveOptionalToken(tokenPath, fallback, options = {}) {
    return resolveToken(tokenPath, { ...options, fallback }).value;
}

export function hasToken(tokenPath) {
    return readToken(tokenPath) !== undefined;
}