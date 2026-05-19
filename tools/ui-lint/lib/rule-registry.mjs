//
// tools/ui-lint/lib/rule-registry.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Rule registry system for modular lint rules.
// Each rule is isolated and can be run independently.
//

/**
 * @typedef {Object} RuleContext
 * @property {Object} snapshot - DOM snapshot with elements, styles, rects
 * @property {Object} tokens - Design tokens from CSS
 * @property {Object} page - Playwright page object
 * @property {string} scope - View scope (e.g., 'dashboard', 'settings')
 * @property {Object} options - Rule-specific options
 */

/**
 * @typedef {Object} RuleFinding
 * @property {string} rule - Rule identifier
 * @property {string} severity - 'error' | 'warning' | 'info'
 * @property {string} message - Human-readable message
 * @property {string} [selector] - CSS selector or element identifier
 * @property {Object} [details] - Additional context
 */

/**
 * @typedef {Object} Rule
 * @property {string} id - Unique rule identifier
 * @property {string} name - Human-readable name
 * @property {string} category - Rule category (accessibility, layout, mobile, etc.)
 * @property {string} description - What the rule checks
 * @property {Function} run - Async function (context) => RuleFinding[]
 */

const rules = new Map();
const categories = new Set();
const ruleCatalog = new Map();

function normalizeArray(value) {
    return Array.isArray(value) ? value.filter(Boolean) : [];
}

function normalizeRuleMeta(rule) {
    const meta = rule.meta || {};
    return {
        id: meta.id || rule.id,
        category: meta.category || rule.category || null,
        severity: meta.severity || null,
        browsers: normalizeArray(meta.browsers),
        devices: normalizeArray(meta.devices),
        requires: normalizeArray(meta.requires),
        optional: normalizeArray(meta.optional),
        capabilities: normalizeArray(meta.capabilities),
        performanceCost: meta.performanceCost || 'medium',
        tags: normalizeArray(meta.tags),
        executionMode: meta.executionMode || 'parallel',
        severityByBrowser: meta.severityByBrowser || {},
    };
}

/**
 * Register a lint rule.
 * @param {Rule} rule
 */
export function registerRule(rule) {
    if (!rule.id || !rule.run) {
        throw new Error('Rule must have id and run function');
    }
    rule.meta = normalizeRuleMeta(rule);
    rules.set(rule.id, rule);
    ruleCatalog.set(rule.id, rule.meta);
    if (rule.category) {
        categories.add(rule.category);
    }
}

/**
 * Get a rule by ID.
 * @param {string} id
 * @returns {Rule|undefined}
 */
export function getRule(id) {
    return rules.get(id);
}

/**
 * Get all registered rules.
 * @returns {Rule[]}
 */
export function getAllRules() {
    return Array.from(rules.values());
}

/**
 * Get the registered rule catalog.
 * @returns {Object[]}
 */
export function getRuleCatalog() {
    return Array.from(ruleCatalog.values());
}

/**
 * Get metadata for a single rule.
 * @param {string} id
 * @returns {Object|undefined}
 */
export function getRuleMetadata(id) {
    return ruleCatalog.get(id);
}

/**
 * Get rules by category.
 * @param {string} category
 * @returns {Rule[]}
 */
export function getRulesByCategory(category) {
    return Array.from(rules.values()).filter(r => r.category === category);
}

/**
 * Get all categories.
 * @returns {string[]}
 */
export function getCategories() {
    return Array.from(categories);
}

/**
 * Run a single rule.
 * @param {string} ruleId
 * @param {RuleContext} context
 * @returns {Promise<RuleFinding[]>}
 */
export async function runRule(ruleId, context) {
    const rule = rules.get(ruleId);
    if (!rule) {
        throw new Error(`Rule not found: ${ruleId}`);
    }

    try {
        const findings = await rule.run(context);
        return findings.map(f => ({
            ...f,
            rule: rule.id,
        }));
    } catch (err) {
        console.error(`Rule ${ruleId} failed:`, err.message);
        return [{
            rule: ruleId,
            severity: 'error',
            message: `Rule execution failed: ${err.message}`,
        }];
    }
}

/**
 * Run multiple rules in parallel.
 * @param {string[]} ruleIds
 * @param {RuleContext} context
 * @returns {Promise<RuleFinding[]>}
 */
export async function runRules(ruleIds, context) {
    const results = await Promise.all(
        ruleIds.map(id => runRule(id, context))
    );
    return results.flat();
}

/**
 * Run all rules in a category.
 * @param {string} category
 * @param {RuleContext} context
 * @returns {Promise<RuleFinding[]>}
 */
export async function runCategory(category, context) {
    const categoryRules = getRulesByCategory(category);
    const ruleIds = categoryRules.map(r => r.id);
    return runRules(ruleIds, context);
}

/**
 * Run all registered rules.
 * @param {RuleContext} context
 * @returns {Promise<RuleFinding[]>}
 */
export async function runAllRules(context) {
    const ruleIds = Array.from(rules.keys());
    return runRules(ruleIds, context);
}

/**
 * Create a rule context from page and tokens.
 * @param {Object} options
 * @param {Object} options.page - Playwright page
 * @param {Object} options.snapshot - DOM snapshot
 * @param {Object} options.tokens - Design tokens
 * @param {string} options.scope - View scope
 * @returns {RuleContext}
 */
export function createContext({ page, snapshot, tokens, scope, options = {} }) {
    return {
        page,
        snapshot,
        tokens,
        scope,
        options,
    };
}

/**
 * Rule builder helper for common patterns.
 */
export const RuleBuilder = {
    /**
     * Create an accessibility rule.
     * @param {string} id
     * @param {string} name
     * @param {Function} run
     * @returns {Rule}
     */
    accessibility(id, name, run) {
        return {
            id,
            name,
            category: 'accessibility',
            description: `Accessibility check: ${name}`,
            run,
        };
    },

    /**
     * Create a layout rule.
     * @param {string} id
     * @param {string} name
     * @param {Function} run
     * @returns {Rule}
     */
    layout(id, name, run) {
        return {
            id,
            name,
            category: 'layout',
            description: `Layout check: ${name}`,
            run,
        };
    },

    /**
     * Create a mobile rule.
     * @param {string} id
     * @param {string} name
     * @param {Function} run
     * @returns {Rule}
     */
    mobile(id, name, run) {
        return {
            id,
            name,
            category: 'mobile',
            description: `Mobile/iOS check: ${name}`,
            run,
        };
    },

    /**
     * Create a component rule.
     * @param {string} id
     * @param {string} name
     * @param {Function} run
     * @returns {Rule}
     */
    component(id, name, run) {
        return {
            id,
            name,
            category: 'component',
            description: `Component check: ${name}`,
            run,
        };
    },

    /**
     * Create a performance rule.
     * @param {string} id
     * @param {string} name
     * @param {Function} run
     * @returns {Rule}
     */
    performance(id, name, run) {
        return {
            id,
            name,
            category: 'performance',
            description: `Performance check: ${name}`,
            run,
        };
    },
};
