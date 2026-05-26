//
// tools/ui-lint/lib/findings/explainability/machine-summary.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildMachineSummary(finding) {
    return {
        id: finding.id,
        type: finding.type,
        category: finding.category,
        severity: finding.severity,
        riskLevel: finding.riskLevel,
        scope: finding.scope,
        count: finding.count,
        value: finding.value,
        threshold: finding.threshold,
        confidence: finding.confidence,
        score: finding.score,
        wcag: finding.wcag,
        regression: finding.regression,
        artifacts: finding.artifacts,
        rootCauseChain: finding.rootCauseChain,
    };
}
