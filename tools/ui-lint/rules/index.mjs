//
// tools/ui-lint/rules/index.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Rule index - imports and registers all lint rules.
//

import { getAllRules, getCategories, getRuleCatalog, getRulesByCategory, runAllRules, runCategory, runRule, runRules, createContext } from '../lib/rule-registry.mjs';
import { RULE_MANIFEST } from './manifest.mjs';

let ruleLoadPromise = null;

export async function loadRules({ manifest = RULE_MANIFEST } = {}) {
    if (!ruleLoadPromise) {
        ruleLoadPromise = Promise.all(
            manifest.map((entry) => import(new URL(entry.path, import.meta.url)))
        ).then(() => getRuleCatalog());
    }

    return ruleLoadPromise;
}

export const loadedRules = await loadRules();

// Export registry functions for convenience
export {
    getAllRules,
    getCategories,
    getRuleCatalog,
    getRulesByCategory,
    runRule,
    runRules,
    runCategory,
    runAllRules,
    createContext,
    RULE_MANIFEST,
};

export { collectDOMSnapshot } from '../lib/dom-snapshot.mjs';
export { tokens, loadDesignTokens } from '../lib/design-tokens.mjs';
