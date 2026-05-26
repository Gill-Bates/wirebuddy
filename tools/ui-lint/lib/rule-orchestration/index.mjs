//
// tools/ui-lint/lib/rule-orchestration/index.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export { RuleBuilder } from './rule-builder.mjs';
export { normalizeSeverity, normalizeSeverityByBrowser, severityWeight } from './severity-normalizer.mjs';
export { createResourceManager } from './resource-manager.mjs';
export { createRuleTelemetry, finalizeRuleTelemetry, classifyFailure } from './telemetry.mjs';
export { planExecution, sortRuleEntries, isCompatibleWithContext } from './execution-planner.mjs';
export { buildRuleExplanation, whyDidRuleFail } from './explainability.mjs';
export {
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
} from './registry-engine.mjs';
