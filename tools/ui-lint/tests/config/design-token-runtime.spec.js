//
// tools/ui-lint/tests/config/design-token-runtime.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import {
    buildEvaluationPayload,
    buildSerializableConstants,
    createTokenRuntimeEngine,
    detectTokenDrift,
    evaluateDimension,
    evaluateDuration,
    loadDesignTokenSnapshot,
    loadDesignTokens,
    registerTokenProvider,
    resolveToken,
    tokens,
    buildSerializableTokenPayload,
} from '../../lib/design-tokens.mjs';

const inlineProvider = {
    type: 'inline',
    name: 'inline',
    loadSync() {
        return {
            provider: 'inline',
            source: 'inline',
            sourceHash: 'inline-hash',
            ast: null,
            declarations: [
                { name: '--wb-spacing-md', value: '24px', selector: ':root', theme: 'base', source: 'inline', line: null, column: null },
                { name: '--wb-spacing-lg', value: 'var(--wb-spacing-md)', selector: ':root', theme: 'base', source: 'inline', line: null, column: null },
                { name: '--wb-transition-fast', value: '150ms', selector: ':root', theme: 'base', source: 'inline', line: null, column: null },
            ],
            index: new Map([
                ['--wb-spacing-md', new Map([['base', { name: '--wb-spacing-md', value: '24px', source: 'inline' }]])],
                ['--wb-spacing-lg', new Map([['base', { name: '--wb-spacing-lg', value: 'var(--wb-spacing-md)', source: 'inline' }]])],
                ['--wb-transition-fast', new Map([['base', { name: '--wb-transition-fast', value: '150ms', source: 'inline' }]])],
            ]),
            dependencyGraph: new Map([
                ['--wb-spacing-lg', new Set(['--wb-spacing-md'])],
            ]),
            circularDependencies: [],
        };
    },
    async load() {
        return this.loadSync();
    },
};

test('default token runtime preserves the legacy snapshot surface', () => {
    const snapshot = loadDesignTokenSnapshot();
    const values = loadDesignTokens();

    expect(tokens.interaction.touchTargetMin).toBe(values.interaction.touchTargetMin);
    expect(snapshot.values.card.radius).toBe(values.card.radius);
    expect(snapshot.derived.interaction.comfortableTouchTarget).toBeGreaterThanOrEqual(values.interaction.touchTargetMin);
    expect(snapshot.sourceHash).toBeTruthy();
    expect(snapshot.diagnostics).toHaveProperty('missingTokens');
});

test('inline token runtime resolves var chains and units', () => {
    const runtime = createTokenRuntimeEngine({ providers: [inlineProvider] });
    const snapshot = runtime.loadSync();

    expect(snapshot.values.spacing.md).toBe(24);
    expect(snapshot.values.spacing.lg).toBe(24);
    expect(snapshot.values.animation.fast).toBe(150);
    expect(runtime.export({ category: 'derived' })).toHaveProperty('interaction.comfortableTouchTarget');

    const resolution = resolveToken('--wb-spacing-lg', {
        index: inlineProvider.loadSync().index,
        type: 'dimension',
    });

    expect(resolution.value).toBe(24);
    expect(evaluateDimension('calc(12px * 2)', { rootFontSize: 16 })).toBe(24);
    expect(evaluateDuration('1.5s')).toBe(1500);
});

test('serializable payload builders and drift detection stay stable', () => {
    const evaluationPayload = buildEvaluationPayload({ categories: ['layout', 'themes'] });
    const serializable = buildSerializableConstants({ categories: ['layout'] });
    const auditPayload = buildSerializableTokenPayload(loadDesignTokenSnapshot(), { category: 'spacing' });

    expect(evaluationPayload.categories).toEqual(['layout', 'themes']);
    expect(serializable).toHaveProperty('browserCapabilities');
    expect(auditPayload).toHaveProperty('md');

    const drift = detectTokenDrift({
        baseline: { spacing: { md: 16 } },
        current: { spacing: { md: 20 }, radius: { md: 12 } },
    });

    expect(drift.changed).toEqual([{ path: 'spacing.md', before: 16, after: 20 }]);
    expect(drift.added).toEqual([{ path: 'radius.md', value: 12 }]);
});

test('registerTokenProvider appends provider entries without mutating inputs', () => {
    const providers = [inlineProvider];
    const nextProviders = registerTokenProvider(providers, inlineProvider);

    expect(nextProviders).toHaveLength(2);
    expect(providers).toHaveLength(1);
});
