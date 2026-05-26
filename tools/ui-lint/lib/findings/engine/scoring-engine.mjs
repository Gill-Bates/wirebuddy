//
// tools/ui-lint/lib/findings/engine/scoring-engine.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { severityWeight } from './severity-engine.mjs';

export function scoreFindings(findings) {
    return findings.reduce((total, finding) => total + severityWeight(finding.severity, finding.category) * Math.max(finding.count || 1, 1), 0);
}

export function buildSummary(findings) {
    const score = scoreFindings(findings);
    const categories = [...new Set(findings.map((finding) => finding.category).filter(Boolean))].sort();
    return {
        score,
        riskLevel: score >= 100 ? 'blocker' : score >= 40 ? 'degraded' : 'cosmetic',
        categories,
        regressions: findings.filter((finding) => finding.regression),
    };
}
