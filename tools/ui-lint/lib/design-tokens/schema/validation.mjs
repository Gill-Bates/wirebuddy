//
// tools/ui-lint/lib/design-tokens/schema/validation.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { TOKEN_CATEGORIES } from './categories.mjs';
import { TOKEN_SCHEMA } from './token-schema.mjs';

function flattenSchema(schema, prefix = [], output = []) {
    for (const [key, value] of Object.entries(schema)) {
        const nextPath = [...prefix, key];
        if (typeof value === 'string') {
            output.push(nextPath.join('.'));
            continue;
        }
        flattenSchema(value, nextPath, output);
    }
    return output;
}

export function validateTokens(tokens) {
    if (tokens == null || typeof tokens !== 'object' || Array.isArray(tokens)) {
        throw new TypeError('tokens must be an object');
    }

    const missingTokens = findMissingTokens(tokens);
    return {
        valid: missingTokens.length === 0,
        missingTokens,
        unknownTokens: findUnknownTokens(tokens),
    };
}

export function findMissingTokens(tokens, schema = TOKEN_SCHEMA) {
    const requiredPaths = flattenSchema(schema);
    const missingTokens = [];

    for (const tokenPath of requiredPaths) {
        if (readPath(tokens, tokenPath) === undefined) {
            missingTokens.push(tokenPath);
        }
    }

    return missingTokens;
}

export function findUnknownTokens(tokens, schema = TOKEN_SCHEMA) {
    const schemaPaths = new Set(flattenSchema(schema));
    const unknownTokens = [];

    for (const tokenPath of flattenObject(tokens)) {
        if (!schemaPaths.has(tokenPath)) {
            unknownTokens.push(tokenPath);
        }
    }

    return unknownTokens;
}

export function findUnusedTokens(declarations, tokens = {}) {
    const knownTokenNames = new Set(declarations.map((entry) => entry.name.replace(/^--wb-/, '').replace(/-/g, '.')));
    const usedTokenNames = new Set(flattenObject(tokens));
    return [...knownTokenNames].filter((tokenPath) => !usedTokenNames.has(tokenPath));
}

export function validateCategory(category) {
    if (!TOKEN_CATEGORIES.includes(category)) {
        throw new Error(`Unknown token category: ${category}`);
    }
    return category;
}

function flattenObject(value, prefix = [], output = []) {
    for (const [key, entry] of Object.entries(value || {})) {
        const nextPath = [...prefix, key];
        if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
            flattenObject(entry, nextPath, output);
            continue;
        }
        output.push(nextPath.join('.'));
    }
    return output;
}

function readPath(value, tokenPath) {
    return tokenPath.split('.').reduce((cursor, segment) => (cursor && typeof cursor === 'object' ? cursor[segment] : undefined), value);
}