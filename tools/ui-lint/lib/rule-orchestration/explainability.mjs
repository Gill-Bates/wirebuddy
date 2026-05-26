//
// tools/ui-lint/lib/rule-orchestration/explainability.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildRuleExplanation(rule, findings, telemetry, context) {
    const findingCount = findings.length;
    const firstFinding = findings[0] || null;

    return {
        ruleId: rule.id,
        ruleVersion: rule.meta?.version || '1.0.0',
        owner: rule.meta?.owner || 'ui-lint',
        category: rule.meta?.category || rule.category || null,
        severity: rule.meta?.severity || null,
        findingCount,
        confidence: rule.meta?.confidence ?? 0.8,
        message: firstFinding?.message || rule.description || rule.name,
        explanation: firstFinding?.details?.explanation || firstFinding?.explanation || rule.description || null,
        remediation: firstFinding?.details?.remediation || firstFinding?.remediation || rule.meta?.remediation?.[0] || null,
        scope: context.scope,
        device: context.device || null,
        browser: context.browser || null,
        telemetry: {
            durationMs: telemetry.lastDurationMs,
            pageEvaluations: telemetry.pageEvaluations,
            domReads: telemetry.domReads,
            health: telemetry.health,
            failureRate: telemetry.failureRate,
        },
    };
}

export function whyDidRuleFail(rule, findings, telemetry, context) {
    return buildRuleExplanation(rule, findings, telemetry, context);
}
