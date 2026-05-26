//
// tools/ui-lint/lib/design-tokens/providers/css-provider.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import crypto from 'node:crypto';
import fs from 'node:fs';
import fsPromises from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { buildDependencyGraph, detectCircularDependencies } from '../parser/dependency-graph.mjs';
import { parseDesignTokens } from '../parser/css-parser.mjs';
import { buildTokenIndex, collectTokenDeclarations } from '../parser/variable-parser.mjs';

export const DEFAULT_TOKENS_CSS_PATH = new URL('../../../../../app/static/css/core/tokens.css', import.meta.url);

const RESERVED_TOKEN_PATH_SEGMENTS = new Set(['__proto__', 'prototype', 'constructor']);

const DEFAULT_TOKEN_VALUES = deepFreeze({
    spacing: { xs: 4, sm: 8, md: 16, lg: 24, xl: 32 },
    radius: { none: 0, sm: 6, md: 12, lg: 16, pill: 9999 },
    colors: { danger: '#c53a2f', warning: '#b7791f', success: '#2f855a', info: '#3182ce' },
    interaction: {
        touchTargetMin: 44,
        touchTargetMinMobile: 44,
        touchTargetMinTablet: 40,
        touchTargetMinDesktop: 32,
        touchTargetComfortable: 48,
        focusRingWidth: 3,
    },
    animation: { fast: 150, base: 200, slow: 300 },
    breakpoints: { sm: 576, md: 768, lg: 992, xl: 1200, xxl: 1400 },
    badge: { paddingY: '0.35em', paddingX: '0.65em', radius: 6, fontSize: '0.75em', fontWeight: '600' },
    card: { padding: 24, radius: 12, borderWidth: 1 },
    modal: { backdropBlur: 4, backdropOpacity: 0.5, radius: 16, padding: 24 },
    form: { inputHeight: 38, inputRadius: 6, switchHeight: 24 },
    wcag: { contrastAA: 4.5, contrastAALarge: 3, contrastAAA: 7, contrastAAALarge: 4.5 },
});

const FALLBACK_SOURCE_HASH = createSourceHash(JSON.stringify(DEFAULT_TOKEN_VALUES));

function deepFreeze(value) {
    if (value == null || typeof value !== 'object' || Object.isFrozen(value)) {
        return value;
    }

    Object.freeze(value);
    for (const nestedValue of Object.values(value)) {
        deepFreeze(nestedValue);
    }

    return value;
}

function assertString(value, field) {
    if (typeof value !== 'string') {
        throw new TypeError(`${field} must be a string`);
    }

    return value;
}

function isPlainObject(value) {
    if (value == null || typeof value !== 'object' || Array.isArray(value)) {
        return false;
    }

    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function normalizeProviderOptions({ filePath = DEFAULT_TOKENS_CSS_PATH, name = 'css', strict = false, includeAst = true } = {}) {
    const normalizedFilePath = filePath instanceof URL ? fileURLToPath(filePath) : filePath;

    return {
        sourcePath: String(normalizedFilePath),
        filePath: normalizedFilePath,
        name: String(name),
        strict: Boolean(strict),
        includeAst: Boolean(includeAst),
    };
}

function createSourceHash(sourceText) {
    return crypto.createHash('sha256').update(sourceText).digest('hex');
}

function normalizeErrorMetadata(error) {
    if (error == null) {
        return null;
    }

    if (error instanceof Error) {
        const metadata = {
            name: error.name,
            message: error.message,
        };

        if (typeof error.code === 'string' && error.code) {
            metadata.code = error.code;
        }

        return metadata;
    }

    return {
        name: 'Error',
        message: String(error),
    };
}

function createPayloadMetadata({ fallbackUsed, declarations, dependencyGraph, error = null }) {
    return {
        fallbackUsed,
        tokenCount: declarations.length,
        dependencyCount: dependencyGraph.size,
        error: normalizeErrorMetadata(error),
    };
}

export function createCssTokenProvider(options = {}) {
    const providerOptions = normalizeProviderOptions(options);

    return {
        type: 'css',
        name: providerOptions.name,
        filePath: providerOptions.sourcePath,
        loadSync() {
            try {
                const cssText = fs.readFileSync(providerOptions.filePath, 'utf-8');
                return createCssTokenPayload(cssText, providerOptions);
            } catch (error) {
                if (providerOptions.strict) {
                    throw error;
                }

                return createFallbackCssTokenPayload({
                    filePath: providerOptions.sourcePath,
                    name: providerOptions.name,
                    error,
                });
            }
        },
        async load() {
            try {
                const cssText = await fsPromises.readFile(providerOptions.filePath, 'utf-8');
                return createCssTokenPayload(cssText, providerOptions);
            } catch (error) {
                if (providerOptions.strict) {
                    throw error;
                }

                return createFallbackCssTokenPayload({
                    filePath: providerOptions.sourcePath,
                    name: providerOptions.name,
                    error,
                });
            }
        },
    };
}

export function createCssTokenPayload(cssText, { filePath = 'tokens.css', name = 'css', includeAst = true } = {}) {
    const sourceText = assertString(cssText, 'cssText');
    const sourceHash = createSourceHash(sourceText);
    const ast = parseDesignTokens(sourceText, { from: filePath });
    const declarations = collectTokenDeclarations(ast);
    const index = buildTokenIndex(declarations);
    const dependencyGraph = buildDependencyGraph(declarations);
    const circularDependencies = detectCircularDependencies(dependencyGraph);
    const metadata = createPayloadMetadata({
        fallbackUsed: false,
        declarations,
        dependencyGraph,
    });

    return {
        provider: name,
        source: filePath,
        sourceHash,
        ast: includeAst ? ast : null,
        declarations,
        index,
        dependencyGraph,
        circularDependencies,
        fallbackUsed: metadata.fallbackUsed,
        tokenCount: metadata.tokenCount,
        dependencyCount: metadata.dependencyCount,
        error: metadata.error,
    };
}

function createFallbackCssTokenPayload({ filePath = 'tokens.css', name = 'css', error = null } = {}) {
    const declarations = flattenTokenValues(DEFAULT_TOKEN_VALUES);
    const dependencyGraph = buildDependencyGraph(declarations);
    const metadata = createPayloadMetadata({
        fallbackUsed: true,
        declarations,
        dependencyGraph,
        error,
    });

    return {
        provider: name,
        source: filePath,
        sourceHash: FALLBACK_SOURCE_HASH,
        ast: null,
        declarations,
        index: buildTokenIndex(declarations),
        dependencyGraph,
        circularDependencies: detectCircularDependencies(dependencyGraph),
        fallbackUsed: metadata.fallbackUsed,
        tokenCount: metadata.tokenCount,
        dependencyCount: metadata.dependencyCount,
        error: metadata.error,
    };
}

function flattenTokenValues(values, prefix = '--wb-') {
    if (!isPlainObject(values)) {
        throw new TypeError('values must be a plain object');
    }

    const declarations = [];

    const stack = [{ entry: values, pathSegments: [] }];
    while (stack.length > 0) {
        const { entry, pathSegments } = stack.pop();
        const keys = Object.keys(entry).sort();

        for (let index = keys.length - 1; index >= 0; index -= 1) {
            const key = keys[index];
            if (RESERVED_TOKEN_PATH_SEGMENTS.has(key)) {
                throw new TypeError(`Reserved token path segment is not allowed: ${key}`);
            }

            const value = entry[key];
            const nextPath = [...pathSegments, key];
            if (isPlainObject(value)) {
                stack.push({ entry: value, pathSegments: nextPath });
                continue;
            }

            declarations.push({
                name: `${prefix}${nextPath.join('-')}`,
                value: serializeTokenValue(value, nextPath),
                selector: ':root',
                theme: 'base',
                source: 'fallback',
                line: null,
                column: null,
            });
        }
    }

    return declarations;
}

function serializeTokenValue(value, pathSegments) {
    if (typeof value === 'string' || typeof value === 'boolean' || typeof value === 'bigint') {
        return String(value);
    }

    if (typeof value === 'number') {
        if (!Number.isFinite(value)) {
            throw new TypeError(`Token value for ${pathSegments.join('.')} must be a finite number`);
        }

        return String(value);
    }

    throw new TypeError(`Token value for ${pathSegments.join('.')} must be a primitive string, boolean, bigint, or finite number`);
}