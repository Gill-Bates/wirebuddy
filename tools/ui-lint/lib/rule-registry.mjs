//
// tools/ui-lint/lib/rule-registry.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import {
    RuleBuilder,
    createRuleRegistryState,
    registerRuleWithState,
    unregisterRuleWithState,
    getAllRulesWithState,
    getRuleCatalogWithState,
    getRuleMetadataWithState,
    getRulesByCategoryWithState,
    getCategoriesWithState,
    getRulesByCapabilityWithState,
    createExecutionGraphWithState,
    createContextWithState,
    runRuleWithState,
    runRulesWithState,
    runCategoryWithState,
    runAllRulesWithState,
    exportRegistryWithState,
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

export { whyDidRuleFail };
