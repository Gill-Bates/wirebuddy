//
// tools/ui-lint/lib/rule-orchestration/registry-engine.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { buildRuleExplanation, whyDidRuleFail } from './explainability.mjs';
import { createResourceManager } from './resource-manager.mjs';
import { createRuleTelemetry, finalizeRuleTelemetry, classifyFailure } from './telemetry.mjs';
import { normalizeSeverity, normalizeSeverityByBrowser, severityWeight } from './severity-normalizer.mjs';
import { planExecution } from './execution-planner.mjs';

function normalizeArray(value) {
    return Array.isArray(value) ? value.filter(Boolean) : [];
}

function clampConfidence(value) {
    if (typeof value !== 'number' || Number.isNaN(value)) return 0.8;
    return Math.max(0, Math.min(1, value));
}

function uniqueStrings(values) {
    return [...new Set(normalizeArray(values).map((value) => String(value)))];
}

function createTrackingPage(page, telemetry) {
    if (!page) return page;
    return new Proxy(page, {
        get(target, property, receiver) {
            const value = Reflect.get(target, property, receiver);
            if (typeof value !== 'function') {
                return value;
            }

            if (property === 'evaluate' || property === 'evaluateHandle') {
                return async (...args) => {
                    telemetry.pageEvaluations += 1;
                    telemetry.domReads += 1;
                    return value.apply(target, args);
                };
            }

            return value.bind(target);
        },
    });
}

function normalizeRuleMeta(rule) {
    const meta = rule.meta || {};
    const requirements = normalizeArray(meta.requires);
    const normalized = {
        id: meta.id || rule.id,
        name: rule.name || meta.name || rule.id,
        version: meta.version || rule.version || '1.0.0',
        category: meta.category || rule.category || null,
        subcategory: meta.subcategory || null,
        severity: meta.severity || null,
        severityByBrowser: meta.severityByBrowser || {},
        wcag: uniqueStrings(meta.wcag || meta.wcags || rule.wcag),
        impacts: uniqueStrings(meta.impacts || rule.impacts),
        affects: uniqueStrings(meta.affects || rule.affects),
        tags: uniqueStrings(meta.tags || rule.tags),
        owner: meta.owner || rule.owner || 'ui-lint',
        cost: meta.cost || meta.performanceCost || rule.cost || 'medium',
        performanceCost: meta.performanceCost || meta.cost || rule.performanceCost || 'medium',
        stability: meta.stability || rule.stability || 'stable',
        confidence: clampConfidence(meta.confidence ?? rule.confidence),
        requiresSnapshot: meta.requiresSnapshot ?? requirements.includes('dom-snapshot') ?? false,
        requiresPage: meta.requiresPage ?? requirements.includes('page') ?? false,
        requiresInteraction: meta.requiresInteraction ?? requirements.includes('interaction') ?? false,
        experimental: Boolean(meta.experimental ?? rule.experimental ?? false),
        deprecated: Boolean(meta.deprecated ?? rule.deprecated ?? false),
        dependencies: uniqueStrings(meta.dependencies || rule.dependencies),
        conflictsWith: uniqueStrings(meta.conflictsWith || rule.conflictsWith),
        remediation: uniqueStrings(meta.remediation || rule.remediation),
        featureFlags: uniqueStrings(meta.featureFlags || rule.featureFlags),
        environments: uniqueStrings(meta.environments || rule.environments),
        supportsRegressionTracking: Boolean(meta.supportsRegressionTracking ?? rule.supportsRegressionTracking ?? true),
        historicalWeight: typeof meta.historicalWeight === 'number' ? meta.historicalWeight : typeof rule.historicalWeight === 'number' ? rule.historicalWeight : 1,
        priority: meta.priority || rule.priority || 'standard',
        executionMode: meta.executionMode || 'parallel',
        browsers: uniqueStrings(meta.browsers || rule.browsers),
        devices: uniqueStrings(meta.devices || rule.devices),
        requires: uniqueStrings(requirements),
        optional: uniqueStrings(meta.optional || rule.optional),
        capabilities: uniqueStrings(meta.capabilities || rule.capabilities),
        ciPolicy: meta.ciPolicy || { failBuild: true, allowWarnings: 3 },
        failurePolicy: meta.failurePolicy || { retryable: false, fatal: true, flaky: false },
    };

    normalized.requiresSnapshot = Boolean(normalized.requiresSnapshot || normalized.requires.includes('dom-snapshot'));
    normalized.requiresPage = Boolean(normalized.requiresPage || normalized.requires.includes('page'));
    normalized.requiresInteraction = Boolean(normalized.requiresInteraction || normalized.requires.includes('interaction'));
    return normalized;
}

function normalizeFinding(rule, finding, context, telemetry) {
    const normalizedSeverity = normalizeSeverityByBrowser(rule.meta, context.browser, finding.severity || rule.meta.severity || 'warning');
    const confidence = clampConfidence(finding.confidence ?? rule.meta.confidence);
    const remediation = finding.remediation || finding.suggestion || rule.meta.remediation[0] || null;

    return {
        ...finding,
        rule: rule.id,
        ruleId: rule.id,
        category: finding.category || rule.meta.category || rule.category || null,
        severity: normalizeSeverity(normalizedSeverity, 'warning'),
        severityWeight: severityWeight(normalizedSeverity),
        confidence,
        owner: finding.owner || rule.meta.owner,
        version: finding.version || rule.meta.version,
        tags: uniqueStrings([...(finding.tags || []), ...rule.meta.tags]),
        wcag: uniqueStrings([...(finding.wcag || []), ...rule.meta.wcag]),
        impacts: uniqueStrings([...(finding.impacts || []), ...rule.meta.impacts]),
        affects: uniqueStrings([...(finding.affects || []), ...rule.meta.affects]),
        priority: finding.priority || rule.meta.priority,
        cost: finding.cost || rule.meta.cost,
        stability: finding.stability || rule.meta.stability,
        experimental: Boolean(finding.experimental ?? rule.meta.experimental),
        deprecated: Boolean(finding.deprecated ?? rule.meta.deprecated),
        dependencies: uniqueStrings([...(finding.dependencies || []), ...rule.meta.dependencies]),
        conflictsWith: uniqueStrings([...(finding.conflictsWith || []), ...rule.meta.conflictsWith]),
        remediation,
        suggestion: finding.suggestion || remediation,
        explanation: finding.explanation || finding.details?.explanation || rule.description || null,
        artifacts: finding.artifacts || context.artifacts || null,
        failurePolicy: rule.meta.failurePolicy,
        ciPolicy: rule.meta.ciPolicy,
        telemetry: {
            durationMs: telemetry.lastDurationMs,
            pageEvaluations: telemetry.pageEvaluations,
            domReads: telemetry.domReads,
            memoryDeltaBytes: telemetry.memoryDeltaBytes,
            health: telemetry.health,
            failureRate: telemetry.failureRate,
        },
        normalizedAt: new Date().toISOString(),
    };
}

function normalizeFindings(rule, findings, context, telemetry) {
    const list = Array.isArray(findings) ? findings : findings ? [findings] : [];
    return list
        .filter(Boolean)
        .map((finding) => normalizeFinding(rule, finding, context, telemetry));
}

function getRuleRecord(state, ruleId) {
    return state.rules.get(ruleId) || null;
}

function getTelemetryRecord(state, ruleId) {
    if (!state.telemetry.has(ruleId)) {
        state.telemetry.set(ruleId, createRuleTelemetry());
    }
    return state.telemetry.get(ruleId);
}

function updateIndexes(state, rule) {
    const meta = rule.meta;
    if (meta.category) {
        state.categories.add(meta.category);
    }
    for (const capability of meta.capabilities) {
        if (!state.capabilityIndex.has(capability)) {
            state.capabilityIndex.set(capability, new Set());
        }
        state.capabilityIndex.get(capability).add(rule.id);
    }
    if (meta.owner) {
        if (!state.ownerIndex.has(meta.owner)) {
            state.ownerIndex.set(meta.owner, new Set());
        }
        state.ownerIndex.get(meta.owner).add(rule.id);
    }
}

export function createRuleRegistryState() {
    return {
        rules: new Map(),
        ruleCatalog: new Map(),
        categories: new Set(),
        capabilityIndex: new Map(),
        ownerIndex: new Map(),
        plugins: new Map(),
        telemetry: new Map(),
        version: '2026.05',
    };
}

export function registerRuleWithState(state, rule) {
    if (!rule?.id || typeof rule.run !== 'function') {
        throw new Error('Rule must have id and run function');
    }

    const normalizedRule = {
        ...rule,
        meta: normalizeRuleMeta(rule),
    };

    state.rules.set(normalizedRule.id, normalizedRule);
    state.ruleCatalog.set(normalizedRule.id, {
        ...normalizedRule.meta,
        id: normalizedRule.id,
        name: normalizedRule.name || normalizedRule.meta.name,
        category: normalizedRule.category || normalizedRule.meta.category,
        description: normalizedRule.description || null,
    });
    updateIndexes(state, normalizedRule);
    return normalizedRule;
}

export function unregisterRuleWithState(state, ruleId) {
    const rule = state.rules.get(ruleId);
    if (!rule) return false;

    state.rules.delete(ruleId);
    state.ruleCatalog.delete(ruleId);
    state.telemetry.delete(ruleId);
    for (const [capability, ruleIds] of state.capabilityIndex.entries()) {
        ruleIds.delete(ruleId);
        if (!ruleIds.size) state.capabilityIndex.delete(capability);
    }
    for (const [owner, ruleIds] of state.ownerIndex.entries()) {
        ruleIds.delete(ruleId);
        if (!ruleIds.size) state.ownerIndex.delete(owner);
    }
    for (const category of state.categories) {
        if (![...state.ruleCatalog.values()].some((meta) => meta.category === category)) {
            state.categories.delete(category);
        }
    }
    return true;
}

export function getRulesByCapabilityWithState(state, capability) {
    return [...(state.capabilityIndex.get(capability) || [])].map((ruleId) => state.rules.get(ruleId)).filter(Boolean);
}

export function getRulesByOwnerWithState(state, owner) {
    return [...(state.ownerIndex.get(owner) || [])].map((ruleId) => state.rules.get(ruleId)).filter(Boolean);
}

export function createExecutionGraphWithState(state, ruleIds, context) {
    return planExecution(ruleIds, state, context);
}

export async function runRuleWithState(state, ruleId, context) {
    const rule = getRuleRecord(state, ruleId);
    if (!rule) {
        throw new Error(`Rule not found: ${ruleId}`);
    }

    const telemetry = getTelemetryRecord(state, ruleId);
    const runtimeContext = prepareContext(context, telemetry);
    const plan = planExecution([ruleId], state, runtimeContext);
    if (!plan.activeRuleIds.includes(ruleId)) {
        finalizeRuleTelemetry(telemetry, {
            durationMs: 0,
            finishedAt: new Date().toISOString(),
            status: 'skipped',
            severity: rule.meta.severity || 'warning',
        });
        return [];
    }

    const startedAt = performance.now();
    const memoryBefore = process.memoryUsage().heapUsed;
    let rawFindings = [];
    let status = 'passed';
    let error = null;

    try {
        if (typeof rule.beforeRun === 'function') {
            await rule.beforeRun(runtimeContext);
        }
        const result = await rule.run(runtimeContext);
        rawFindings = normalizeFindings(rule, result, runtimeContext, telemetry);
        status = rawFindings.length ? 'completed' : 'passed';
        if (typeof rule.afterRun === 'function') {
            await rule.afterRun(runtimeContext, rawFindings);
        }
        return rawFindings;
    } catch (caughtError) {
        error = caughtError;
        status = 'failed';
        const failureKind = classifyFailure(caughtError);
        return [{
            rule: rule.id,
            ruleId: rule.id,
            severity: 'error',
            kind: 'rule-execution-failed',
            message: `Rule execution failed: ${caughtError.message}`,
            details: {
                error: caughtError.message,
                failurePolicy: failureKind,
                owner: rule.meta.owner,
                category: rule.meta.category,
            },
            confidence: 0.1,
            remediation: 'Inspect the rule implementation and runtime dependencies.',
        }];
    } finally {
        finalizeRuleTelemetry(telemetry, {
            durationMs: performance.now() - startedAt,
            finishedAt: new Date().toISOString(),
            status,
            error: error ? String(error.message || error) : null,
            severity: rule.meta.severity || 'warning',
            pageEvaluations: runtimeContext.telemetry?.pageEvaluations || 0,
            domReads: runtimeContext.telemetry?.domReads || 0,
            memoryDeltaBytes: process.memoryUsage().heapUsed - memoryBefore,
        });
    }
}

export async function runRulesWithState(state, ruleIds, context) {
    const plan = planExecution(ruleIds, state, context);
    const findings = [];

    for (const batch of plan.batches) {
        const batchFindings = await Promise.all(batch.map((rule) => runRuleWithState(state, rule.id, context)));
        findings.push(...batchFindings.flat());
    }

    return findings;
}

export async function runCategoryWithState(state, category, context) {
    const ruleIds = [...state.ruleCatalog.values()].filter((meta) => meta.category === category).map((meta) => meta.id);
    return runRulesWithState(state, ruleIds, context);
}

export async function runAllRulesWithState(state, context) {
    return runRulesWithState(state, [...state.rules.keys()], context);
}

function prepareContext(context = {}, telemetry = createRuleTelemetry()) {
    const resourceManager = context.resourceManager || createResourceManager({
        snapshot: context.snapshot,
        tokens: context.tokens,
        page: context.page,
    });
    const page = createTrackingPage(context.page, telemetry);
    return {
        ...context,
        page,
        resourceManager,
        resources: resourceManager,
        acquireResource: resourceManager.acquire,
        telemetry,
        environment: context.environment || context.options?.environment || 'local',
        browser: context.browser || context.options?.browser || null,
        device: context.device || context.options?.device || null,
        capabilities: normalizeArray(context.capabilities || context.options?.capabilities),
    };
}

export function createContextWithState(state, { page, snapshot, tokens, scope, options = {} }) {
    return prepareContext({
        page,
        snapshot,
        tokens,
        scope,
        options,
        browser: options.browser || null,
        device: options.device || null,
        environment: options.environment || 'local',
        capabilities: options.capabilities || [],
        resourceManager: options.resourceManager || null,
    }, createRuleTelemetry());
}

export function getRuleWithState(state, ruleId) {
    return state.rules.get(ruleId) || undefined;
}

export function getAllRulesWithState(state) {
    return [...state.rules.values()];
}

export function getRuleCatalogWithState(state) {
    return [...state.ruleCatalog.values()];
}

export function getRuleMetadataWithState(state, ruleId) {
    return state.ruleCatalog.get(ruleId);
}

export function getRulesByCategoryWithState(state, category) {
    return [...state.rules.values()].filter((rule) => rule.category === category);
}

export function getCategoriesWithState(state) {
    return [...state.categories];
}

export function exportRegistryWithState(state) {
    return {
        version: state.version,
        categories: [...state.categories].sort(),
        rules: [...state.ruleCatalog.values()].sort((left, right) => left.id.localeCompare(right.id)),
        capabilities: Object.fromEntries([...state.capabilityIndex.entries()].map(([capability, ruleIds]) => [capability, [...ruleIds].sort()])),
        owners: Object.fromEntries([...state.ownerIndex.entries()].map(([owner, ruleIds]) => [owner, [...ruleIds].sort()])),
        telemetry: Object.fromEntries([...state.telemetry.entries()].map(([ruleId, record]) => [ruleId, { ...record }])),
        plugins: [...state.plugins.values()].map((plugin) => ({ ...plugin })),
    };
}

export function registerPluginWithState(state, plugin) {
    if (!plugin || !plugin.name) {
        throw new Error('Plugin must have a name');
    }

    const record = {
        name: plugin.name,
        version: plugin.version || '1.0.0',
        description: plugin.description || null,
        status: 'registered',
        capabilities: normalizeArray(plugin.capabilities),
    };

    state.plugins.set(plugin.name, record);
    if (typeof plugin.register === 'function') {
        const api = {
            registerRule: (rule) => registerRuleWithState(state, rule),
            unregisterRule: (ruleId) => unregisterRuleWithState(state, ruleId),
            getAllRules: () => [...state.rules.values()],
            getRuleCatalog: () => [...state.ruleCatalog.values()],
            getExecutionGraph: (ruleIds, context) => createExecutionGraphWithState(state, ruleIds, context),
            runRule: (ruleId, context) => runRuleWithState(state, ruleId, context),
            runRules: (ruleIds, context) => runRulesWithState(state, ruleIds, context),
            exportRegistry: () => exportRegistryWithState(state),
        };
        const pluginResult = plugin.register(api);
        if (typeof pluginResult === 'function') {
            record.cleanup = pluginResult;
        } else if (pluginResult && typeof pluginResult.cleanup === 'function') {
            record.cleanup = pluginResult.cleanup;
        }
    }

    return record;
}

export function getRuleTelemetryWithState(state, ruleId) {
    return state.telemetry.get(ruleId) || null;
}

export function getRuleHealthWithState(state, ruleId) {
    const telemetry = getRuleTelemetryWithState(state, ruleId);
    if (!telemetry) return 'stable';
    return telemetry.health;
}

export { whyDidRuleFail, buildRuleExplanation };
