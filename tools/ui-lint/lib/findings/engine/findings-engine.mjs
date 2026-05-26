//
// tools/ui-lint/lib/findings/engine/findings-engine.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { correlateFindings } from './decision-tree.mjs';
import { evaluatePolicyRules, deduplicateFindings, POLICY_VERSION } from './policy-engine.mjs';
import { evaluateSeverity, severityToRiskLevel } from './severity-engine.mjs';
import { buildSummary } from './scoring-engine.mjs';
import { buildFindingPolicies } from '../policies/index.mjs';

export function createFindingsContext(result) {
    const name = result?.name || '';
    return {
        result,
        name,
        scope: inferScope(name),
        device: inferDevice(name),
        metrics: result?.metrics || {},
        network: result?.network || {},
        diff: result?.diff || { ratio: 0, sizeMismatch: false },
        statusUnavailableExpected: Boolean(result?.statusUnavailableExpected),
        artifacts: {
            screenshot: result?.screenshot || null,
            domSnapshot: result?.domSnapshot || null,
            diffImage: result?.diffImage || null,
        },
    };
}

function inferScope(name) {
    if (name.includes('dashboard')) return 'dashboard';
    if (name.includes('dns')) return 'dns';
    if (name.includes('users')) return 'users';
    if (name.includes('status')) return 'status';
    if (name.includes('nodes')) return 'nodes';
    if (name.includes('settings')) return 'settings';
    if (name.includes('about')) return 'about';
    if (name.includes('peers')) return 'peers';
    if (name.includes('login')) return 'auth';
    return 'general';
}

function inferDevice(name) {
    if (name.includes('mobile')) return 'mobile';
    if (name.includes('tablet')) return 'tablet';
    if (name.includes('large-desktop')) return 'large-desktop';
    return 'desktop';
}

export function evaluateFindings(result) {
    const context = createFindingsContext(result);
    const policies = buildFindingPolicies();
    const rawFindings = policies.flatMap((policy) => evaluatePolicyRules(context, policy));
    const findings = correlateFindings(deduplicateFindings(rawFindings), context).map((finding) => {
        const severity = evaluateSeverity(finding, context);
        return {
            ...finding,
            severity,
            riskLevel: finding.riskLevel || severityToRiskLevel(severity),
        };
    });

    return {
        policyVersion: POLICY_VERSION,
        context,
        findings,
        summary: buildSummary(findings),
    };
}
