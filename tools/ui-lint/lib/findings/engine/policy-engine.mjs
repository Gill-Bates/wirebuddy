//
// tools/ui-lint/lib/findings/engine/policy-engine.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const POLICY_VERSION = '2026.04';

export function getPath(object, path, fallback = undefined) {
    if (!path) return fallback;
    const parts = Array.isArray(path) ? path : String(path).split('.');
    let value = object;
    for (const part of parts) {
        if (value == null) return fallback;
        value = value[part];
    }
    return value ?? fallback;
}

export function createFinding(partial) {
    return {
        id: partial.id,
        type: partial.type,
        category: partial.category,
        severity: partial.severity,
        riskLevel: partial.riskLevel,
        scope: partial.scope,
        owner: partial.owner || 'ui-lint',
        wcag: partial.wcag || [],
        confidence: partial.confidence ?? 0.85,
        score: partial.score ?? 0,
        count: partial.count ?? null,
        value: partial.value ?? null,
        threshold: partial.threshold ?? null,
        message: partial.message,
        explanation: partial.explanation,
        remediation: partial.remediation,
        suggestion: partial.suggestion || partial.remediation || null,
        regression: partial.regression || null,
        artifacts: partial.artifacts || null,
        rootCauseChain: partial.rootCauseChain || [],
        source: partial.source || 'policy',
        legacyKey: partial.legacyKey || partial.id,
    };
}

export function countFindingRule(definition) {
    return {
        kind: 'count',
        ...definition,
    };
}

export function flagFindingRule(definition) {
    return {
        kind: 'flag',
        ...definition,
    };
}

export function thresholdFindingRule(definition) {
    return {
        kind: 'threshold',
        ...definition,
    };
}

export function customFindingRule(definition) {
    return {
        kind: 'custom',
        ...definition,
    };
}

function isScopeAllowed(ruleScopes, scope) {
    if (!ruleScopes || ruleScopes.length === 0 || ruleScopes.includes('any')) {
        return true;
    }
    return ruleScopes.includes(scope);
}

function toCount(value) {
    if (Array.isArray(value)) return value.length;
    if (typeof value === 'number') return value;
    if (value && typeof value === 'object') return Number(value.count ?? value.length ?? 0) || 0;
    return value ? 1 : 0;
}

export function evaluatePolicyRules(context, policy) {
    const findings = [];

    for (const rule of policy.rules || []) {
        if (!isScopeAllowed(rule.scopes, context.scope)) {
            continue;
        }
        if (typeof rule.when === 'function' && !rule.when(context)) {
            continue;
        }

        if (rule.kind === 'custom') {
            const customFindings = rule.build(context) || [];
            findings.push(...customFindings.map((finding) => createFinding({
                scope: context.scope,
                owner: rule.owner || policy.owner,
                source: policy.id,
                ...rule,
                ...finding,
            })));
            continue;
        }

        if (rule.kind === 'count') {
            const raw = getPath(context, rule.metricPath);
            const count = toCount(raw);
            if (count <= 0) continue;
            findings.push(createFinding({
                id: rule.id,
                type: rule.type || rule.id,
                category: rule.category,
                severity: rule.severity,
                riskLevel: rule.riskLevel,
                scope: context.scope,
                owner: rule.owner || policy.owner,
                wcag: rule.wcag,
                confidence: rule.confidence,
                count,
                value: raw,
                threshold: rule.threshold ?? null,
                message: typeof rule.message === 'function' ? rule.message(context, count, raw) : rule.message,
                explanation: typeof rule.explanation === 'function' ? rule.explanation(context, count, raw) : rule.explanation,
                remediation: typeof rule.remediation === 'function' ? rule.remediation(context, count, raw) : rule.remediation,
                suggestion: rule.suggestion,
                regression: typeof rule.regression === 'function' ? rule.regression(context, count, raw) : rule.regression,
                artifacts: typeof rule.artifacts === 'function' ? rule.artifacts(context, count, raw) : rule.artifacts,
                rootCauseChain: typeof rule.rootCauseChain === 'function' ? rule.rootCauseChain(context, count, raw) : rule.rootCauseChain,
                source: policy.id,
                legacyKey: typeof rule.legacyKey === 'function' ? rule.legacyKey(context, count, raw) : rule.legacyKey,
            }));
            continue;
        }

        if (rule.kind === 'flag') {
            const value = getPath(context, rule.metricPath);
            if (!value || (Array.isArray(value) && value.length === 0)) continue;
            const count = toCount(value);
            findings.push(createFinding({
                id: rule.id,
                type: rule.type || rule.id,
                category: rule.category,
                severity: rule.severity,
                riskLevel: rule.riskLevel,
                scope: context.scope,
                owner: rule.owner || policy.owner,
                wcag: rule.wcag,
                confidence: rule.confidence,
                count,
                value,
                threshold: rule.threshold ?? null,
                message: typeof rule.message === 'function' ? rule.message(context, count, value) : rule.message,
                explanation: typeof rule.explanation === 'function' ? rule.explanation(context, count, value) : rule.explanation,
                remediation: typeof rule.remediation === 'function' ? rule.remediation(context, count, value) : rule.remediation,
                suggestion: rule.suggestion,
                regression: typeof rule.regression === 'function' ? rule.regression(context, count, value) : rule.regression,
                artifacts: typeof rule.artifacts === 'function' ? rule.artifacts(context, count, value) : rule.artifacts,
                rootCauseChain: typeof rule.rootCauseChain === 'function' ? rule.rootCauseChain(context, count, value) : rule.rootCauseChain,
                source: policy.id,
                legacyKey: typeof rule.legacyKey === 'function' ? rule.legacyKey(context, count, value) : rule.legacyKey,
            }));
            continue;
        }

        if (rule.kind === 'threshold') {
            const value = getPath(context, rule.metricPath);
            if (typeof value !== 'number') continue;
            const threshold = typeof rule.threshold === 'function' ? rule.threshold(context) : rule.threshold;
            const isBreached = rule.direction === 'lt' ? value < threshold : value > threshold;
            if (!isBreached) continue;
            findings.push(createFinding({
                id: rule.id,
                type: rule.type || rule.id,
                category: rule.category,
                severity: rule.severity,
                riskLevel: rule.riskLevel,
                scope: context.scope,
                owner: rule.owner || policy.owner,
                wcag: rule.wcag,
                confidence: rule.confidence,
                count: rule.count ?? null,
                value,
                threshold,
                message: typeof rule.message === 'function' ? rule.message(context, value, threshold) : rule.message,
                explanation: typeof rule.explanation === 'function' ? rule.explanation(context, value, threshold) : rule.explanation,
                remediation: typeof rule.remediation === 'function' ? rule.remediation(context, value, threshold) : rule.remediation,
                suggestion: rule.suggestion,
                regression: typeof rule.regression === 'function' ? rule.regression(context, value, threshold) : rule.regression,
                artifacts: typeof rule.artifacts === 'function' ? rule.artifacts(context, value, threshold) : rule.artifacts,
                rootCauseChain: typeof rule.rootCauseChain === 'function' ? rule.rootCauseChain(context, value, threshold) : rule.rootCauseChain,
                source: policy.id,
                legacyKey: typeof rule.legacyKey === 'function' ? rule.legacyKey(context, value, threshold) : rule.legacyKey,
            }));
        }
    }

    return findings;
}

export function deduplicateFindings(findings) {
    const seen = new Map();

    for (const finding of findings) {
        const key = [finding.id, finding.scope, finding.legacyKey, finding.count, finding.value, finding.threshold].join('|');
        if (!seen.has(key)) {
            seen.set(key, finding);
        }
    }

    return [...seen.values()];
}
