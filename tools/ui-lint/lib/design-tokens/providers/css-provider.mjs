//
// tools/ui-lint/lib/design-tokens/providers/css-provider.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import crypto from 'node:crypto';
import fs from 'node:fs';

import { buildDependencyGraph, detectCircularDependencies } from '../parser/dependency-graph.mjs';
import { parseDesignTokens } from '../parser/css-parser.mjs';
import { buildTokenIndex, collectTokenDeclarations } from '../parser/variable-parser.mjs';

export const DEFAULT_TOKENS_CSS_PATH = new URL('../../../../../app/static/css/core/tokens.css', import.meta.url);

const DEFAULT_TOKEN_VALUES = {
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
};

export function createCssTokenProvider({ filePath = DEFAULT_TOKENS_CSS_PATH, name = 'css' } = {}) {
    return {
        type: 'css',
        name,
        filePath: String(filePath),
        loadSync() {
            try {
                const cssText = fs.readFileSync(filePath, 'utf-8');
                return createCssTokenPayload(cssText, { filePath: String(filePath), name });
            } catch {
                return createFallbackCssTokenPayload({ filePath: String(filePath), name });
            }
        },
        async load() {
            return this.loadSync();
        },
    };
}

export function createCssTokenPayload(cssText, { filePath = 'tokens.css', name = 'css' } = {}) {
    const sourceText = String(cssText ?? '');
    const sourceHash = crypto.createHash('sha256').update(sourceText).digest('hex');
    const ast = parseDesignTokens(sourceText, { from: filePath });
    const declarations = collectTokenDeclarations(ast);
    const index = buildTokenIndex(declarations);
    const dependencyGraph = buildDependencyGraph(declarations);
    const circularDependencies = detectCircularDependencies(dependencyGraph);

    return {
        provider: name,
        source: filePath,
        sourceHash,
        ast,
        declarations,
        index,
        dependencyGraph,
        circularDependencies,
    };
}

function createFallbackCssTokenPayload({ filePath = 'tokens.css', name = 'css' } = {}) {
    const declarations = flattenTokenValues(DEFAULT_TOKEN_VALUES);
    return {
        provider: name,
        source: filePath,
        sourceHash: crypto.createHash('sha256').update(JSON.stringify(DEFAULT_TOKEN_VALUES)).digest('hex'),
        ast: null,
        declarations,
        index: buildTokenIndex(declarations),
        dependencyGraph: buildDependencyGraph(declarations),
        circularDependencies: detectCircularDependencies(buildDependencyGraph(declarations)),
    };
}

function flattenTokenValues(values, prefix = '--wb-') {
    const declarations = [];

    const walk = (entry, pathSegments = []) => {
        for (const [key, value] of Object.entries(entry || {})) {
            const nextPath = [...pathSegments, key];
            if (value && typeof value === 'object' && !Array.isArray(value)) {
                walk(value, nextPath);
                continue;
            }

            declarations.push({
                name: `${prefix}${nextPath.join('-')}`,
                value: String(value),
                selector: ':root',
                theme: 'base',
                source: 'fallback',
                line: null,
                column: null,
            });
        }
    };

    walk(values);
    return declarations;
}