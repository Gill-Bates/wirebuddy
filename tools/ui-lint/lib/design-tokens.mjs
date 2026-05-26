//
// tools/ui-lint/lib/design-tokens.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import {
    buildAuditTokenSnapshot,
} from './design-tokens/exports/audit-snapshots.mjs';
import {
    buildBrowserTokenPayload,
} from './design-tokens/exports/browser-payloads.mjs';
import {
    buildSerializableTokenPayload,
} from './design-tokens/exports/serializable.mjs';
import {
    DEFAULT_TOKENS_CSS_PATH,
    createCssTokenProvider,
} from './design-tokens/providers/css-provider.mjs';
import { createJsonTokenProvider } from './design-tokens/providers/json-provider.mjs';
import { createFigmaTokenProvider } from './design-tokens/providers/figma-provider.mjs';
import {
    TOKEN_CATEGORIES,
} from './design-tokens/schema/categories.mjs';
import {
    TOKEN_SCHEMA,
    TOKEN_SCHEMA_VERSION,
} from './design-tokens/schema/token-schema.mjs';
import {
    findMissingTokens,
    findUnknownTokens,
    findUnusedTokens,
    validateTokens,
} from './design-tokens/schema/validation.mjs';
import {
    parseDesignTokens,
} from './design-tokens/parser/css-parser.mjs';
import {
    collectTokenDeclarations,
} from './design-tokens/parser/variable-parser.mjs';
import {
    buildDependencyGraph,
    detectCircularDependencies,
    extractVarReferences,
} from './design-tokens/parser/dependency-graph.mjs';
import {
    buildEvaluationPayload,
    buildSerializableConstants,
    detectTokenDrift,
    BROWSER_CAPABILITIES,
    DEFAULT_EVALUATION_CATEGORIES,
    DEVICE_PROFILE_REGISTRY,
    UI_LINT_PROFILES,
} from './design-tokens/runtime/policies.mjs';
import {
    buildRuntimeDiagnostics,
} from './design-tokens/runtime/diagnostics.mjs';
import {
    createTokenRuntime,
} from './design-tokens/runtime/runtime.mjs';
import {
    createThemeRuntime,
} from './design-tokens/themes/theme-runtime.mjs';
import {
    buildThemeOverlay,
    THEME_REGISTRY,
} from './design-tokens/themes/overlays.mjs';
import {
    detectTokenDrift as diffThemes,
} from './design-tokens/themes/theme-diffing.mjs';
import {
    evaluateDimension,
    evaluateDuration,
} from './design-tokens/resolver/evaluate-units.mjs';
import {
    resolveToken,
} from './design-tokens/resolver/resolve-token.mjs';
import {
    resolveVarChain,
} from './design-tokens/resolver/resolve-var-chain.mjs';

export const TOKEN_RUNTIME_VERSION = 1;
export const TOKEN_SOURCE_PATH = String(DEFAULT_TOKENS_CSS_PATH);

const tokenRuntime = createTokenRuntime({
    providers: [createCssTokenProvider({ filePath: DEFAULT_TOKENS_CSS_PATH })],
});

const initialSnapshot = tokenRuntime.loadSync();

export const TOKEN_SOURCE_HASH = initialSnapshot.sourceHash;
export const tokenRuntimeFacade = tokenRuntime;
export const tokens = initialSnapshot.values;

export function loadDesignTokens() {
    return tokenRuntime.snapshot().values;
}

export function loadDesignTokenSnapshot() {
    return tokenRuntime.snapshot();
}

export async function loadDesignTokensAsync() {
    const snapshot = await tokenRuntime.load();
    return snapshot.values;
}

export function createTokenRuntimeEngine(options = {}) {
    return createTokenRuntime(options);
}

export function registerTokenProvider(providers, provider) {
    return [...providers, provider];
}

export {
    buildAuditTokenSnapshot,
    buildBrowserTokenPayload,
    buildDependencyGraph,
    buildEvaluationPayload,
    buildSerializableConstants,
    buildSerializableTokenPayload,
    buildThemeOverlay,
    buildRuntimeDiagnostics,
    collectTokenDeclarations,
    createCssTokenProvider,
    createFigmaTokenProvider,
    createJsonTokenProvider,
    createThemeRuntime,
    detectCircularDependencies,
    diffThemes,
    detectTokenDrift,
    evaluateDimension,
    evaluateDuration,
    extractVarReferences,
    findMissingTokens,
    findUnknownTokens,
    findUnusedTokens,
    parseDesignTokens,
    resolveToken,
    resolveVarChain,
    TOKEN_CATEGORIES,
    TOKEN_SCHEMA,
    TOKEN_SCHEMA_VERSION,
    validateTokens,
    BROWSER_CAPABILITIES,
    DEFAULT_EVALUATION_CATEGORIES,
    DEVICE_PROFILE_REGISTRY,
    THEME_REGISTRY,
    UI_LINT_PROFILES,
};