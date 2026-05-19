//
// tools/ui-lint/lib/rule-registry.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import {
    RuleBuilder,
    createRuleRegistryState,
    registerRuleWithState,
    unregisterRuleWithState,
    getRuleWithState,
    getAllRulesWithState,
    getRuleCatalogWithState,
    getRuleMetadataWithState,
    getRulesByCategoryWithState,
    getCategoriesWithState,
    getRulesByCapabilityWithState,
    getRulesByOwnerWithState,
    createExecutionGraphWithState,
    createContextWithState,
    runRuleWithState,
    runRulesWithState,
    runCategoryWithState,
    runAllRulesWithState,
    exportRegistryWithState,
    registerPluginWithState,
    getRuleTelemetryWithState,
    getRuleHealthWithState,
    whyDidRuleFail,
} from './rule-orchestration/index.mjs';

const registryState = createRuleRegistryState();

export { RuleBuilder };

export function registerRule(rule) {
    return registerRuleWithState(registryState, rule);
}

export function unregisterRule(ruleId) {
    return unregisterRuleWithState(registryState, ruleId);
}

export function registerPlugin(plugin) {
    return registerPluginWithState(registryState, plugin);
}

export function getRule(id) {
    return getRuleWithState(registryState, id);
}

export function getAllRules() {
    return getAllRulesWithState(registryState);
}

export function getRuleCatalog() {
    return getRuleCatalogWithState(registryState);
}

export function getRuleMetadata(id) {
    return getRuleMetadataWithState(registryState, id);
}

export function getRulesByCategory(category) {
    return getRulesByCategoryWithState(registryState, category);
}

export function getCategories() {
    return getCategoriesWithState(registryState);
}

export function getRulesByCapability(capability) {
    return getRulesByCapabilityWithState(registryState, capability);
}

export function getRulesByOwner(owner) {
    return getRulesByOwnerWithState(registryState, owner);
}

export function getExecutionGraph(ruleIds, context) {
    return createExecutionGraphWithState(registryState, ruleIds, context);
}

export function createContext({ page, snapshot, tokens, scope, options = {} }) {
    return createContextWithState(registryState, { page, snapshot, tokens, scope, options });
}

export async function runRule(ruleId, context) {
    return runRuleWithState(registryState, ruleId, context);
}

export async function runRules(ruleIds, context) {
    return runRulesWithState(registryState, ruleIds, context);
}

export async function runCategory(category, context) {
    return runCategoryWithState(registryState, category, context);
}

export async function runAllRules(context) {
    return runAllRulesWithState(registryState, context);
}

export function getRuleTelemetry(ruleId) {
    return getRuleTelemetryWithState(registryState, ruleId);
}

export function getRuleHealth(ruleId) {
    return getRuleHealthWithState(registryState, ruleId);
}

export function exportRegistry() {
    return exportRegistryWithState(registryState);
}

export function explainRuleFailure(ruleId, context, findings = []) {
    const rule = getRuleWithState(registryState, ruleId);
    if (!rule) {
        return {
            ruleId,
            found: false,
            explanation: `Rule not found: ${ruleId}`,
        };
    }

    const telemetry = getRuleTelemetryWithState(registryState, ruleId) || {
        lastDurationMs: 0,
        pageEvaluations: 0,
        domReads: 0,
        health: 'stable',
        failureRate: 0,
    };
    return whyDidRuleFail(rule, findings, telemetry, context);
}

export { whyDidRuleFail };
