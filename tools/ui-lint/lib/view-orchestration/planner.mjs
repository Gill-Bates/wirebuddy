//
// tools/ui-lint/lib/view-orchestration/planner.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { THEMES } from '../config/themes/themes.mjs';
import { DEFAULT_DEVICE_COVERAGE, DEFAULT_THEME_COVERAGE, DEVICE_ORDER, LOGIN_DEVICE_ORDER, VIEW_DEFS, VIEW_RUNTIME_VERSION } from './catalog.mjs';

const viewProviders = new Set();

function cloneDefinition(definition) {
    return {
        ...definition,
        coverage: { ...(definition.coverage || DEFAULT_DEVICE_COVERAGE) },
        themeCoverage: { ...(definition.themeCoverage || DEFAULT_THEME_COVERAGE) },
        requires: { ...definition.requires },
        browserPolicies: { ...definition.browserPolicies },
        metadata: { ...definition.metadata },
        auth: { ...definition.auth },
        navigation: { ...definition.navigation },
        heuristics: { ...definition.heuristics },
        retryPolicy: { ...definition.retryPolicy },
        snapshots: { ...definition.snapshots },
        resourceBudget: { ...definition.resourceBudget },
        requiredFeatures: [...(definition.requiredFeatures || [])],
        preconditions: [...(definition.preconditions || [])],
        cleanup: { ...definition.cleanup },
        tags: [...(definition.tags || [])],
        isolation: { ...definition.isolation },
        dependsOn: [...(definition.dependsOn || [])],
        environments: [...(definition.environments || ['ci', 'nightly', 'local'])],
        executionModes: [...(definition.executionModes || [])],
    };
}

export function validateViewDefinition(definition) {
    if (!definition || typeof definition !== 'object') {
        throw new Error('View definition must be an object');
    }

    for (const key of ['id', 'name', 'url', 'scope', 'family']) {
        if (typeof definition[key] !== 'string' || definition[key].trim() === '') {
            throw new Error(`View definition is missing required field: ${key}`);
        }
    }

    if (!Array.isArray(definition.executionModes) || definition.executionModes.length === 0) {
        throw new Error(`View definition ${definition.id} must declare at least one execution mode`);
    }

    if (typeof definition.priority !== 'number' || Number.isNaN(definition.priority)) {
        throw new Error(`View definition ${definition.id} must declare a numeric priority`);
    }

    if (!['critical', 'medium', 'low'].includes(definition.risk)) {
        throw new Error(`View definition ${definition.id} must declare a valid risk level`);
    }

    return definition;
}

function normalizeViewDefinition(definition) {
    const normalized = validateViewDefinition(cloneDefinition(definition));

    return {
        ...normalized,
        executionModes: Object.freeze([...new Set(normalized.executionModes)]),
        coverage: Object.freeze({ ...normalized.coverage }),
        themeCoverage: Object.freeze({ ...normalized.themeCoverage }),
        requires: Object.freeze({ ...normalized.requires }),
        browserPolicies: Object.freeze({ ...normalized.browserPolicies }),
        metadata: Object.freeze({ ...normalized.metadata }),
        auth: Object.freeze({ ...normalized.auth }),
        navigation: Object.freeze({ ...normalized.navigation }),
        heuristics: Object.freeze({ ...normalized.heuristics }),
        retryPolicy: Object.freeze({ ...normalized.retryPolicy }),
        snapshots: Object.freeze({ ...normalized.snapshots }),
        resourceBudget: Object.freeze({ ...normalized.resourceBudget }),
        requiredFeatures: Object.freeze([...normalized.requiredFeatures]),
        preconditions: Object.freeze([...normalized.preconditions]),
        cleanup: Object.freeze({ ...normalized.cleanup }),
        tags: Object.freeze([...normalized.tags]),
        isolation: Object.freeze({ ...normalized.isolation }),
        dependsOn: Object.freeze([...normalized.dependsOn]),
        environments: Object.freeze([...normalized.environments]),
    };
}

function providerToViews(provider) {
    const result = typeof provider === 'function' ? provider() : provider;

    if (!result) {
        return [];
    }

    if (Array.isArray(result)) {
        return result;
    }

    if (Array.isArray(result.views)) {
        return result.views;
    }

    return [result];
}

function dedupeById(viewDefs) {
    const seen = new Set();
    const result = [];

    for (const definition of viewDefs) {
        if (!definition || seen.has(definition.id)) {
            continue;
        }

        seen.add(definition.id);
        result.push(definition);
    }

    return result;
}

function matchesExecutionMode(definition, runtimeContext) {
    if (!runtimeContext.mode) {
        return true;
    }

    return definition.executionModes.includes(runtimeContext.mode);
}

function matchesEnvironment(definition, runtimeContext) {
    return !runtimeContext.environment || definition.environments.includes(runtimeContext.environment);
}

function matchesDevice(definition, device) {
    if (!device) {
        return true;
    }

    return definition.coverage[device] !== false;
}

function matchesTheme(definition, theme) {
    if (!theme) {
        return true;
    }

    return definition.themeCoverage[theme] !== 'skip';
}

function matchesCondition(definition, runtimeContext) {
    if (typeof definition.condition === 'function' && definition.condition(runtimeContext) === false) {
        return false;
    }

    if (typeof definition.skipIf === 'function' && definition.skipIf(runtimeContext)) {
        return false;
    }

    if (runtimeContext.enforceCapabilities && definition.requires) {
        for (const [capability, required] of Object.entries(definition.requires)) {
            if (required && runtimeContext.capabilities?.[capability] !== true) {
                return false;
            }
            if (required === false && runtimeContext.capabilities?.[capability] === true) {
                return false;
            }
        }
    }

    return true;
}

function getCandidateDevices(definition, runtimeContext) {
    const devices = runtimeContext.device
        ? [runtimeContext.device]
        : (definition.family === 'auth' ? LOGIN_DEVICE_ORDER : DEVICE_ORDER);

    return devices.filter((device) => matchesDevice(definition, device));
}

function getCandidateThemes(definition, runtimeContext) {
    const themes = runtimeContext.theme ? [runtimeContext.theme] : THEMES;
    return themes.filter((theme) => matchesTheme(definition, theme));
}

function riskScore(risk) {
    return risk === 'critical' ? 3 : risk === 'medium' ? 2 : 1;
}

function computeStabilityScore(definition, runtimeContext) {
    const failureHistory = runtimeContext.historicalFailures?.[definition.id] || 0;
    const flakyPenalty = definition.heuristics.flaky ? 20 : 0;
    const score = 100 - (failureHistory * 10) - flakyPenalty - (definition.criticalPath ? 5 : 0);

    return Math.max(0, score);
}

function createExpandedView(definition, device, theme, runtimeContext) {
    const executionId = `${definition.id}::${device}::${theme}`;

    return {
        ...definition,
        name: `${device}-${definition.name}-${theme}`,
        executionId,
        variantId: executionId,
        device,
        theme,
        themePolicy: definition.themeCoverage[theme],
        devicePolicy: definition.coverage[device] === false ? 'skip' : 'required',
        runtimeVersion: VIEW_RUNTIME_VERSION,
        runtimeMode: runtimeContext.mode || 'all',
        runtimeEnvironment: runtimeContext.environment || 'local',
        runtimeBrowser: runtimeContext.browser || null,
        runtimeDevice: device,
        runtimeTheme: theme,
        stabilityScore: computeStabilityScore(definition, runtimeContext),
        telemetry: {
            viewId: definition.id,
            executionId,
        },
    };
}

export function registerViewProvider(provider) {
    if (typeof provider !== 'function') {
        throw new Error('View provider must be a function');
    }

    viewProviders.add(provider);
    return provider;
}

export function clearViewProviders() {
    viewProviders.clear();
}

export function discoverViews({ providers = [], includeDefaults = true } = {}) {
    const resolvedProviders = [
        ...(includeDefaults ? VIEW_DEFS : []),
        ...viewProviders,
        ...providers,
    ];

    const discovered = [];

    for (const provider of resolvedProviders) {
        for (const definition of providerToViews(provider)) {
            discovered.push(normalizeViewDefinition(definition));
        }
    }

    return dedupeById(discovered);
}

export function expandCoverage(viewDefs, runtimeContext = {}) {
    const expanded = [];

    for (const definition of viewDefs.map(normalizeViewDefinition)) {
        if (!matchesEnvironment(definition, runtimeContext)) {
            continue;
        }

        if (!matchesExecutionMode(definition, runtimeContext)) {
            continue;
        }

        if (!matchesCondition(definition, runtimeContext)) {
            continue;
        }

        const themes = getCandidateThemes(definition, runtimeContext);
        const devices = getCandidateDevices(definition, runtimeContext);

        for (const theme of themes) {
            for (const device of devices) {
                expanded.push(createExpandedView(definition, device, theme, runtimeContext));
            }
        }
    }

    return expanded;
}

export function adaptiveCoverageExpansion(viewDefs, runtimeContext = {}) {
    return expandCoverage(viewDefs, runtimeContext);
}

export function createViewExecutionGraph(views, runtimeContext = {}) {
    const nodes = [];
    const edges = [];
    const nodeById = new Map();

    for (const view of views) {
        const node = {
            id: view.executionId || view.id,
            viewId: view.id,
            family: view.family,
            risk: view.risk,
            priority: view.priority,
            parallelGroup: view.parallelGroup,
            criticalPath: view.criticalPath,
        };

        nodeById.set(node.viewId, node);
        nodes.push(node);
    }

    for (const view of views) {
        for (const dependency of view.dependsOn || []) {
            edges.push({
                from: dependency,
                to: view.executionId || view.id,
                type: nodeById.has(dependency) ? 'view' : 'precondition',
            });
        }
    }

    return {
        runtimeVersion: VIEW_RUNTIME_VERSION,
        runtimeMode: runtimeContext.mode || 'all',
        nodes,
        edges,
    };
}

export function buildViewExecutionAnalytics(views, runtimeContext = {}) {
    const byFamily = {};
    const byRisk = { critical: 0, medium: 0, low: 0 };
    const byDevice = {};
    const byTheme = {};
    let estimatedRuntimeMs = 0;

    for (const view of views) {
        byFamily[view.family] = (byFamily[view.family] || 0) + 1;
        byRisk[view.risk] = (byRisk[view.risk] || 0) + 1;
        byDevice[view.device] = (byDevice[view.device] || 0) + 1;
        byTheme[view.theme] = (byTheme[view.theme] || 0) + 1;
        estimatedRuntimeMs += view.estimatedRuntimeMs || 0;
    }

    return {
        totalViews: views.length,
        estimatedRuntimeMs,
        byFamily,
        byRisk,
        byDevice,
        byTheme,
        mode: runtimeContext.mode || 'all',
        environment: runtimeContext.environment || 'local',
        browser: runtimeContext.browser || null,
    };
}

export function whyWasViewScheduled(view, runtimeContext = {}) {
    const reasons = [];

    if (view.criticalPath) {
        reasons.push('critical-path');
    }

    reasons.push(`priority:${view.priority}`);
    reasons.push(`risk:${view.risk}`);
    reasons.push(`family:${view.family}`);
    reasons.push(`device:${view.device}`);
    reasons.push(`theme:${view.theme}`);

    if (view.dependsOn?.length) {
        reasons.push(`dependsOn:${view.dependsOn.join(',')}`);
    }

    if (runtimeContext.mode) {
        reasons.push(`mode:${runtimeContext.mode}`);
    }

    if (runtimeContext.environment) {
        reasons.push(`environment:${runtimeContext.environment}`);
    }

    return {
        viewId: view.id,
        executionId: view.executionId || view.id,
        reasons,
        stabilityScore: view.stabilityScore,
        estimatedRuntimeMs: view.estimatedRuntimeMs,
        parallelGroup: view.parallelGroup,
    };
}

function sortByOrchestrationScore(left, right) {
    if (left.criticalPath !== right.criticalPath) {
        return Number(right.criticalPath) - Number(left.criticalPath);
    }

    const riskDelta = riskScore(right.risk) - riskScore(left.risk);
    if (riskDelta !== 0) {
        return riskDelta;
    }

    const priorityDelta = right.priority - left.priority;
    if (priorityDelta !== 0) {
        return priorityDelta;
    }

    const runtimeDelta = (left.estimatedRuntimeMs || 0) - (right.estimatedRuntimeMs || 0);
    if (runtimeDelta !== 0) {
        return runtimeDelta;
    }

    return left.executionId.localeCompare(right.executionId);
}

export function composeViewExecutionPlan({
    viewDefs = VIEW_DEFS,
    providers = [],
    runtimeContext = {},
} = {}) {
    const discovered = [...viewDefs, ...discoverViews({ providers, includeDefaults: false })];
    const expandedViews = expandCoverage(deduplicateViewDefinitions(discovered), runtimeContext).sort(sortByOrchestrationScore);
    const executionGraph = createViewExecutionGraph(expandedViews, runtimeContext);
    const viewExecutionAnalytics = buildViewExecutionAnalytics(expandedViews, runtimeContext);

    return {
        runtimeVersion: VIEW_RUNTIME_VERSION,
        runtimeContext: {
            mode: runtimeContext.mode || 'all',
            environment: runtimeContext.environment || 'local',
            browser: runtimeContext.browser || null,
            device: runtimeContext.device || null,
            theme: runtimeContext.theme || null,
        },
        views: expandedViews,
        executionGraph,
        viewExecutionAnalytics,
    };
}

function deduplicateViewDefinitions(viewDefs) {
    const normalized = [];
    const seen = new Set();

    for (const definition of viewDefs) {
        const candidate = normalizeViewDefinition(definition);
        if (seen.has(candidate.id)) {
            continue;
        }

        seen.add(candidate.id);
        normalized.push(candidate);
    }

    return normalized;
}
