//
// tools/ui-lint/lib/design-tokens/runtime/runtime.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { createTokenCache } from './cache.mjs';
import { buildRuntimeDiagnostics } from './diagnostics.mjs';
import { createTokenSnapshot } from './snapshots.mjs';
import { createCssTokenProvider, DEFAULT_TOKENS_CSS_PATH } from '../providers/css-provider.mjs';
import { validateTokens } from '../schema/validation.mjs';
import { deriveTokenValues } from '../resolver/derived-values.mjs';
import { resolveToken } from '../resolver/resolve-token.mjs';
import { createThemeRuntime } from '../themes/theme-runtime.mjs';

function buildResolvedValues(rawSnapshot, theme = 'base') {
    const index = rawSnapshot.index;

    const resolve = (tokenName, options = {}) => resolveToken(tokenName, {
        index,
        theme,
        ...options,
    });

    const values = {
        spacing: {
            xs: resolve('--wb-spacing-xs', { type: 'dimension' }).value,
            sm: resolve('--wb-spacing-sm', { type: 'dimension' }).value,
            md: resolve('--wb-spacing-md', { type: 'dimension' }).value,
            lg: resolve('--wb-spacing-lg', { type: 'dimension' }).value,
            xl: resolve('--wb-spacing-xl', { type: 'dimension' }).value,
        },
        radius: {
            none: 0,
            sm: resolve('--wb-radius-sm', { type: 'dimension' }).value,
            md: resolve('--wb-radius-md', { type: 'dimension' }).value,
            lg: resolve('--wb-radius-lg', { type: 'dimension' }).value,
            pill: 9999,
        },
        colors: {
            danger: resolve('--wb-danger').value,
            warning: resolve('--wb-warning').value,
            success: resolve('--wb-success').value,
            info: resolve('--wb-info').value,
        },
        interaction: {
            touchTargetMin: resolve('--wb-touch-target-min', { type: 'dimension' }).value,
            touchTargetMinMobile: resolve('--wb-touch-target-min-mobile', { type: 'dimension', fallback: resolve('--wb-touch-target-min', { type: 'dimension' }).value }).value,
            touchTargetMinTablet: resolve('--wb-touch-target-min-tablet', { type: 'dimension', fallback: resolve('--wb-touch-target-min', { type: 'dimension' }).value }).value,
            touchTargetMinDesktop: resolve('--wb-touch-target-min-desktop', { type: 'dimension', fallback: resolve('--wb-touch-target-min', { type: 'dimension' }).value }).value,
            touchTargetComfortable: resolve('--wb-touch-target-comfortable', { type: 'dimension' }).value,
            focusRingWidth: resolve('--wb-focus-ring-width', { type: 'dimension' }).value,
        },
        animation: {
            fast: resolve('--wb-transition-fast', { type: 'duration' }).value,
            base: resolve('--wb-transition-base', { type: 'duration' }).value,
            slow: resolve('--wb-transition-slow', { type: 'duration' }).value,
        },
        breakpoints: {
            sm: resolve('--wb-breakpoint-sm', { type: 'dimension' }).value,
            md: resolve('--wb-breakpoint-md', { type: 'dimension' }).value,
            lg: resolve('--wb-breakpoint-lg', { type: 'dimension' }).value,
            xl: resolve('--wb-breakpoint-xl', { type: 'dimension' }).value,
            xxl: resolve('--wb-breakpoint-xxl', { type: 'dimension' }).value,
        },
        badge: {
            paddingY: resolve('--wb-badge-padding-y').value,
            paddingX: resolve('--wb-badge-padding-x').value,
            radius: resolve('--wb-badge-radius', { type: 'dimension' }).value,
            fontSize: resolve('--wb-badge-font-size').value,
            fontWeight: resolve('--wb-badge-font-weight').value,
        },
        card: {
            padding: resolve('--wb-card-padding', { type: 'dimension' }).value,
            radius: resolve('--wb-card-radius', { type: 'dimension' }).value,
            borderWidth: resolve('--wb-card-border-width', { type: 'dimension' }).value,
        },
        modal: {
            backdropBlur: resolve('--wb-modal-backdrop-blur', { type: 'dimension' }).value,
            backdropOpacity: resolve('--wb-modal-backdrop-opacity', { type: 'number' }).value,
            radius: resolve('--wb-modal-radius', { type: 'dimension' }).value,
            padding: resolve('--wb-modal-padding', { type: 'dimension' }).value,
        },
        form: {
            inputHeight: resolve('--wb-input-height', { type: 'dimension' }).value,
            inputRadius: resolve('--wb-input-radius', { type: 'dimension' }).value,
            switchHeight: resolve('--wb-switch-height', { type: 'dimension' }).value,
        },
        wcag: {
            contrastAA: resolve('--wb-contrast-aa-normal', { type: 'number', fallback: 4.5 }).value,
            contrastAALarge: resolve('--wb-contrast-aa-large', { type: 'number', fallback: 3 }).value,
            contrastAAA: resolve('--wb-contrast-aaa-normal', { type: 'number', fallback: 7 }).value,
            contrastAAALarge: resolve('--wb-contrast-aaa-large', { type: 'number', fallback: 4.5 }).value,
        },
    };

    const derivedValues = deriveTokenValues(values);
    const validation = validateTokens(values);

    return {
        values,
        derived: derivedValues,
        categories: deepMerge(structuredClone(values), derivedValues),
        diagnostics: {
            fallbackUsage: collectFallbackUsage(rawSnapshot.index, theme),
            missingTokens: validation.missingTokens,
            unknownTokens: validation.unknownTokens,
            unresolvedVars: collectUnresolvedVars(rawSnapshot),
            deprecatedAliases: [],
        },
    };
}

function collectFallbackUsage(index, theme) {
    const fallbackUsage = [];
    for (const [tokenName, themeEntries] of index.entries()) {
        if (!themeEntries.has(theme) && !themeEntries.has('base')) {
            fallbackUsage.push(tokenName);
        }
    }
    return fallbackUsage;
}

function collectUnresolvedVars(rawSnapshot) {
    return rawSnapshot.circularDependencies || [];
}

function deepMerge(target, source) {
    for (const [key, value] of Object.entries(source || {})) {
        if (value && typeof value === 'object' && !Array.isArray(value)) {
            target[key] = deepMerge(target[key] && typeof target[key] === 'object' ? target[key] : {}, value);
            continue;
        }
        target[key] = value;
    }
    return target;
}

function buildSnapshotFromProvider(providerSnapshot, theme = 'base') {
    const resolved = buildResolvedValues(providerSnapshot, theme);
    return createTokenSnapshot({
        provider: providerSnapshot.provider,
        source: providerSnapshot.source,
        sourceHash: providerSnapshot.sourceHash,
        theme,
        values: resolved.values,
        derived: resolved.derived,
        categories: resolved.categories,
        diagnostics: resolved.diagnostics,
        declarations: providerSnapshot.declarations,
        dependencyGraph: providerSnapshot.dependencyGraph,
        circularDependencies: providerSnapshot.circularDependencies,
    });
}

export function createTokenRuntime({ providers = [createCssTokenProvider()] } = {}) {
    const cache = createTokenCache();
    const themeRuntime = createThemeRuntime();
    let activeTheme = 'base';
    let loadedSnapshot = null;

    const loadProvidersSync = () => providers.map((provider) => {
        if (typeof provider.loadSync === 'function') return provider.loadSync();
        throw new Error(`Provider ${provider.name || provider.type || 'unknown'} does not support synchronous loading`);
    });

    const buildCombinedSnapshot = (providerSnapshots, themeName = 'base') => {
        const snapshots = providerSnapshots.map((providerSnapshot) => buildSnapshotFromProvider(providerSnapshot, themeName));
        const combined = snapshots.reduce((accumulator, snapshot) => deepMerge(accumulator, snapshot.values), {});
        const derived = snapshots.reduce((accumulator, snapshot) => deepMerge(accumulator, snapshot.derived || {}), {});
        const categories = snapshots.reduce((accumulator, snapshot) => deepMerge(accumulator, snapshot.categories), {});
        const diagnostics = snapshots.flatMap((snapshot) => snapshot.diagnostics?.fallbackUsage || []);
        const combinedSnapshot = {
            provider: snapshots.map((snapshot) => snapshot.provider).join('+'),
            source: snapshots.map((snapshot) => snapshot.source).join(','),
            sourceHash: snapshots.map((snapshot) => snapshot.sourceHash).join(','),
            theme: themeName,
            values: combined,
            derived,
            categories,
            diagnostics: {
                fallbackUsage: diagnostics,
                missingTokens: snapshots.flatMap((snapshot) => snapshot.diagnostics?.missingTokens || []),
                unknownTokens: snapshots.flatMap((snapshot) => snapshot.diagnostics?.unknownTokens || []),
                unresolvedVars: snapshots.flatMap((snapshot) => snapshot.diagnostics?.unresolvedVars || []),
                deprecatedAliases: snapshots.flatMap((snapshot) => snapshot.diagnostics?.deprecatedAliases || []),
            },
            declarations: snapshots.flatMap((snapshot) => snapshot.declarations || []),
            dependencyGraph: snapshots.reduce((accumulator, snapshot) => mergeGraphs(accumulator, snapshot.dependencyGraph), new Map()),
            circularDependencies: snapshots.flatMap((snapshot) => snapshot.circularDependencies || []),
        };

        combinedSnapshot.runtimeDiagnostics = buildRuntimeDiagnostics(combinedSnapshot);
        return createTokenSnapshot(combinedSnapshot);
    };

    return {
        async load() {
            const providerSnapshots = [];
            for (const provider of providers) {
                const snapshot = typeof provider.load === 'function' ? await provider.load() : provider.loadSync();
                providerSnapshots.push(snapshot);
            }
            loadedSnapshot = buildCombinedSnapshot(providerSnapshots, activeTheme);
            cache.set(activeTheme, loadedSnapshot);
            return loadedSnapshot;
        },
        loadSync() {
            const providerSnapshots = loadProvidersSync();
            loadedSnapshot = buildCombinedSnapshot(providerSnapshots, activeTheme);
            cache.set(activeTheme, loadedSnapshot);
            return loadedSnapshot;
        },
        loadTheme(themeName) {
            themeRuntime.loadTheme(themeName);
            activeTheme = themeName;
            const cachedSnapshot = cache.get(themeName);
            if (cachedSnapshot) {
                loadedSnapshot = cachedSnapshot;
                return cachedSnapshot;
            }
            return this.loadSync();
        },
        snapshot() {
            if (!loadedSnapshot) {
                return this.loadSync();
            }
            return loadedSnapshot;
        },
        cache() {
            return cache.entries();
        },
        invalidate() {
            cache.clear();
            loadedSnapshot = null;
        },
        diagnostics() {
            return buildRuntimeDiagnostics(this.snapshot());
        },
        export({ category } = {}) {
            const currentSnapshot = this.snapshot();
            if (!category) {
                return currentSnapshot.values;
            }
            if (category === 'derived') {
                return currentSnapshot.derived || {};
            }
            return currentSnapshot.categories?.[category] || currentSnapshot.values?.[category] || {};
        },
        getCategory(category) {
            return this.export({ category });
        },
        get activeTheme() {
            return activeTheme;
        },
        get providers() {
            return [...providers];
        },
    };
}

function mergeGraphs(targetGraph, sourceGraph) {
    for (const [tokenName, dependencies] of sourceGraph.entries()) {
        if (!targetGraph.has(tokenName)) {
            targetGraph.set(tokenName, new Set());
        }
        for (const dependency of dependencies) {
            targetGraph.get(tokenName).add(dependency);
        }
    }
    return targetGraph;
}

export { DEFAULT_TOKENS_CSS_PATH };